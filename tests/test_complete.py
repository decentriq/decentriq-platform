import pytest
import datetime
import os
import random
from typing import Tuple, List
from decentriq_platform import (
        Client,
        Schema, Key, Auth,
        Session, SessionOptions, VerificationOptions, PollingOptions
)
from decentriq_platform.proto.data_room_pb2 import (
        DataRoom, Table, 
        Query, Role,
        Permission
)
from decentriq_platform.proto.waterfront_pb2 import (
        CreateDataRoomResponse, DataRoomValidationError
)
from decentriq_platform.authentication import generate_key
from collections import Counter
from io import StringIO
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
client_id = os.environ["DECENTRIQ_CLIENT_ID"]

def create_session(email: str, api_token: str, custom_auth: Auth = None) -> Tuple[Client, Session]:
    analyst = Client(api_token=api_token, client_id=client_id)
    if custom_auth == None:
        analyst_auth = analyst.create_auth(email)
    else:
        analyst_auth = custom_auth
    enclave_identifiers = analyst.get_enclave_identifiers()
    analyst_session = analyst.create_session(
            enclave_identifiers[0],
            analyst_auth,
            SessionOptions(
                VerificationOptions(
                    accept_debug=True,
                    accept_configuration_needed=True,
                    accept_group_out_of_date=True
                )
            )
    )
    return analyst, analyst_session


@pytest.mark.skip(reason="helper function")
def get_containers_create_table(table_name) -> str:
    return \
        f"CREATE TABLE {table_name} (" \
        f"equipment_number TEXT NOT NULL," \
        f"commodities_description TEXT NOT NULL," \
        f"commodities_group TEXT NOT NULL," \
        f"commodities_agglomerated_group TEXT NOT NULL," \
        f"origin_port TEXT NOT NULL," \
        f"destination_port TEXT NOT NULL," \
        f"start BIGINT NOT NULL," \
        f"end BIGINT NOT NULL," \
        f"dwell_time BIGINT NOT NULL," \
        f"direction TEXT NOT NULL," \
        f")"


@pytest.mark.skip(reason="helper function")
def get_events_create_table(table_name) -> str:
    return \
        f"CREATE TABLE {table_name} (" \
        f"consignment_id TEXT NOT NULL," \
        f"container_id TEXT NOT NULL," \
        f"consignment_owner TEXT NOT NULL," \
        f"shipping_line TEXT NOT NULL," \
        f"origin_port TEXT NOT NULL," \
        f"destination_port TEXT NOT NULL," \
        f"commodities_description TEXT NOT NULL," \
        f"weight_kg BIGINT NOT NULL," \
        f"event_timestamp BIGINT NOT NULL," \
        f"event_type TEXT NOT NULL," \
        f"event_location TEXT NOT NULL," \
        f")"


@pytest.mark.skip(reason="helper function")
def create_events_data_room(events_table_name: str, root_ca_cert: bytes, distributed: bool) -> DataRoom:
    client = Client(api_token=os.environ["TEST_API_TOKEN_1"], client_id=client_id)
    enclave_identifiers = client.get_enclave_identifiers()

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = enclave_identifiers[0]

    if distributed:
        # force distributed queries.. 
        data_room.queryExecutionMode.distributedExecutionMode.targetParallelism = 64
        data_room.queryExecutionMode.distributedExecutionMode.chunkSize = 8388608
        data_room.queryExecutionMode.distributedExecutionMode.maxChunkCountInMemory = 64

    events_table = Table()
    events_table.sqlCreateTableStatement = get_events_create_table(events_table_name)
    data_room.tables.append(events_table)

    analyst_role = Role()
    analyst_role.roleName = "analyst"
    analyst_role.emailRegex = ".*"
    analyst_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    for query_name, get_query_function in [
        ("dwelltime_deltas", get_dwelltime_deltas_query),
        ("delta_weights_containers", get_delta_weights_containers_query),
        ("initial_weights_containers", get_initial_weights_containers_query),
    ]:
        query = Query()
        query.queryName = query_name
        query.sqlSelectStatement = get_query_function(events_table_name)

        data_room.queries.append(query)

        query_permission = Permission()
        query_permission.submitQueryPermission.queryName = query_name

        analyst_role.permissions.append(query_permission)

    data_room.roles.append(analyst_role)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = events_table_name

    data_provider_role = Role()
    data_provider_role.roleName = "data_provider"
    data_provider_role.emailRegex = ".*"
    data_provider_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert
    data_provider_role.permissions.append(upload_permission)

    data_room.roles.append(data_provider_role)

    return data_room


@pytest.mark.skip(reason="helper function")
def get_is_seaborne_departure():
    return "event_type = 'Seaborne departure at port'"


@pytest.mark.skip(reason="helper function")
def get_is_seaborne_arrival():
    return "event_type = 'Seaborne arrival at port'"


@pytest.mark.skip(reason="helper function")
def get_is_departure():
    return f"(({get_is_seaborne_departure()}) OR (event_type = 'Inland departure at port'))"


@pytest.mark.skip(reason="helper function")
def get_is_arrival():
    return f"(({get_is_seaborne_arrival()}) OR (event_type = 'Inland arrival at port'))"


@pytest.mark.skip(reason="helper function")
def get_data_per_container_query(table: str) -> str:
    multiplier = f"(CASE WHEN {get_is_departure()} THEN -1 WHEN {get_is_arrival()} THEN 1 ELSE 0 END)"
    return f"(SELECT\n" \
           f" event_location AS port,\n" \
           f" container_id,\n" \
           f" SUM({multiplier} * weight_kg) AS delta_weight,\n" \
           f" SUM({multiplier}) AS delta_container_number,\n" \
           f" MAX(commodities_description) AS cargo_type,\n" \
           f" MAX(CASE WHEN {get_is_arrival()} THEN event_timestamp ELSE -1 END) AS arrival_datetime,\n" \
           f" MAX(CASE WHEN {get_is_departure()} THEN event_timestamp ELSE -1 END) AS departure_datetime,\n" \
           f" MAX(CASE WHEN {get_is_seaborne_arrival()} THEN origin_port ELSE '' END) AS origin_port,\n" \
           f" MAX(CASE WHEN {get_is_seaborne_departure()} THEN destination_port ELSE '' END) AS destination_port \n" \
           f"FROM \"{table}\" \n" \
           f"GROUP BY event_location, container_id\n" \
           f") AS data_per_container"


@pytest.mark.skip(reason="helper function")
def get_date(datetime):
    return f"({datetime} / (24 * 60 * 60))"


@pytest.mark.skip(reason="helper function")
def get_delta_weights_containers_query(table: str) -> str:
    multiplier = f"(CASE WHEN {get_is_departure()} THEN -1 WHEN {get_is_arrival()} THEN 1 ELSE 0 END)"
    return f"SELECT\n" \
           f" event_location AS port,\n" \
           f" commodities_description AS cargo_type,\n" \
           f" {get_date('event_timestamp')} AS date,\n" \
           f" SUM({multiplier} * weight_kg) AS delta_weight,\n" \
           f" SUM({multiplier}) AS delta_container_number \n" \
           f"FROM \"{table}\" \n" \
           f"GROUP BY event_location, commodities_description, {get_date('event_timestamp')}"


@pytest.mark.skip(reason="helper function")
def get_initial_weights_containers_query(table: str) -> str:
    data_per_container = get_data_per_container_query(table)
    return f"SELECT\n" \
           f" port,\n" \
           f" cargo_type,\n" \
           f" SUM(CASE WHEN delta_weight < 0 THEN -1 * delta_weight ELSE 0 END),\n" \
           f" SUM(CASE WHEN delta_container_number < 0 THEN -1 * delta_container_number ELSE 0 END) \n" \
           f"FROM {data_per_container} \n" \
           f"GROUP BY port, cargo_type"


@pytest.mark.skip(reason="helper function")
def get_dwelltime_deltas_query(table):
    data_per_container = get_data_per_container_query(table)
    multiplier = f"(CASE WHEN {get_is_departure()} THEN -1 WHEN {get_is_arrival()} THEN 1 ELSE 0 END)"
    joined = f"SELECT\n" \
             f" left.event_location AS port,\n" \
             f" {get_date('event_timestamp')} AS date,\n" \
             f" (CASE WHEN\n" \
             f"   0 <= data_per_container.arrival_datetime AND\n" \
             f"   0 <= data_per_container.departure_datetime\n" \
             f"  THEN data_per_container.departure_datetime - data_per_container.arrival_datetime\n" \
             f"  ELSE -1 END) AS dwelltime,\n" \
             f" {multiplier} AS delta_multiplier \n" \
             f"FROM \"{table}\" AS left INNER JOIN {data_per_container} ON\n" \
             f" left.container_id = data_per_container.container_id AND\n" \
             f" left.event_location = data_per_container.port"
    return f"SELECT\n" \
           f" port,\n" \
           f" date,\n" \
           f" SUM(delta_multiplier * dwelltime),\n" \
           f" SUM(delta_multiplier) \n" \
           f"FROM ({joined}) AS joined \n" \
           f"GROUP BY port, date"

def expect_create_data_room_response_hash(response: CreateDataRoomResponse) -> bytes:
    if response.HasField("dataRoomValidationError"):
        raise Exception(response.dataRoomValidationError)
    else:
        return response.dataRoomHash

def expect_create_data_room_response_error(response: CreateDataRoomResponse) -> DataRoomValidationError:
    if response.HasField("dataRoomHash"):
        raise Exception("Expected validation error, got data room hash")
    else:
        return response.dataRoomValidationError


def test_get_initial_weights_containers_distrib():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, True)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "initial_weights_containers",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_get_initial_weights_containers():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, True)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "initial_weights_containers",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_get_delta_weights_containers():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "delta_weights_containers",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_get_delta_weights_containers_distrib():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key,
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, True)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "delta_weights_containers",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_get_delta_dwelltime_distrib():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, True)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "dwelltime_deltas",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_get_delta_dwelltime():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(get_events_create_table("my_events"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))

    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "dr_events",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "dwelltime_deltas",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_valid_data_room_creation():
    # Create session
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))


def test_invalid_data_room_duplicate_table():
    # Create session
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])

    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    second_events_table = Table()
    second_events_table.sqlCreateTableStatement = get_events_create_table("dr_events")
    data_room.tables.append(second_events_table)

    validation_error = expect_create_data_room_response_error(analyst_session.create_data_room(data_room))
    assert validation_error.tableIndex == 1


def test_invalid_data_room_invalid_query():
    # Create session
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])

    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    invalid_query = Query()
    invalid_query.queryName = "asd"
    invalid_query.sqlSelectStatement = "SELECT * FROM nonexistent"
    data_room.queries.append(invalid_query)

    validation_error = expect_create_data_room_response_error(analyst_session.create_data_room(data_room))
    assert validation_error.queryIndex == 3;

    invalid_query.sqlSelectStatement = "Robert'); DROP TABLE Students;--"
    validation_error = expect_create_data_room_response_error(analyst_session.create_data_room(data_room))
    assert validation_error.queryIndex == 3;


def test_invalid_data_room_invalid_role():
    # Create session
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])

    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    invalid_permission = Permission()
    invalid_permission.submitQueryPermission.queryName = "nonexistent"
    invalid_role = Role()
    invalid_role.roleName = "asd"
    invalid_role.emailRegex = ".*"
    invalid_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert
    invalid_role.permissions.append(invalid_permission)
    data_room.roles.append(invalid_role)

    validation_error = expect_create_data_room_response_error(analyst_session.create_data_room(data_room))
    assert validation_error.roleIndex == 2;


def test_multiple_data_providers():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client_1, data_provider_session_1 = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    data_provider_client_2, data_provider_session_2 = create_session(os.environ["TEST_USER_ID_3"], os.environ["TEST_API_TOKEN_3"])

    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session_1.create_data_room(data_room))

    conf: List[Tuple[Client, Session, str, str]] = [
        (data_provider_client_1, data_provider_session_1, os.environ["TEST_USER_ID_2"], "my_events_1"),
        (data_provider_client_2, data_provider_session_2, os.environ["TEST_USER_ID_3"], "my_events_2"),
    ]
    for client, session, email, table_name in conf:
        schema = Schema(get_events_create_table(table_name))
        encryption_key = Key()
        with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
            manifest_hash = client.upload_dataset(
                email,
                schema.table_name,
                events_stream,
                schema,
                encryption_key
            )
        # Publish dataset to data room
        session.publish_dataset_to_data_room(
                manifest_hash,
                data_room_hash,
                "dr_events",
                encryption_key
        )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "dwelltime_deltas",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100

def test_multiple_data_providers_distrib():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client_1, data_provider_session_1 = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    data_provider_client_2, data_provider_session_2 = create_session(os.environ["TEST_USER_ID_3"], os.environ["TEST_API_TOKEN_3"])

    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = create_events_data_room("dr_events", root_ca_cert, False)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session_1.create_data_room(data_room))

    conf: List[Tuple[Client, Session, str, str]] = [
        (data_provider_client_1, data_provider_session_1, os.environ["TEST_USER_ID_2"], "my_events_1"),
        (data_provider_client_2, data_provider_session_2, os.environ["TEST_USER_ID_3"], "my_events_2"),
    ]
    for client, session, email, table_name in conf:
        schema = Schema(get_events_create_table(table_name))
        encryption_key = Key()
        with open(os.path.join(fixtures_dir, "events.csv"), "r", buffering=1024 ** 2) as events_stream:
            manifest_hash = client.upload_dataset(
                email,
                schema.table_name,
                events_stream,
                schema,
                encryption_key
            )

        # Publish dataset to data room
        session.publish_dataset_to_data_room(
                manifest_hash,
                data_room_hash,
                "dr_events",
                encryption_key
        )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "dwelltime_deltas",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100


def test_synthetic_user_id():
    # Create sessions
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    root_ca_cert = analyst_client.get_ca_root_certificate()

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = analyst_session.enclave_identifier

    table = Table()
    table.sqlCreateTableStatement = \
        "CREATE TABLE something (_$uploader_user_id TEXT NOT NULL, a BIGINT NOT NULL, b TEXT NOT NULL)"

    data_room.tables.append(table)

    query = Query()
    query.queryName = "positivea"
    query.sqlSelectStatement = "SELECT _$uploader_user_id FROM something WHERE a > 0"

    data_room.queries.append(query)

    role = Role()
    role.roleName = "role"
    role.emailRegex = ".*"
    role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    query_permission = Permission()
    query_permission.submitQueryPermission.queryName = "positivea"

    role.permissions.append(query_permission)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "something"

    role.permissions.append(upload_permission)

    data_room.roles.append(role)

    data_room_hash = expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))

    # Provider 1
    provider_1_client, provider_1_session = create_session(
        os.environ["TEST_USER_ID_2"],
        os.environ["TEST_API_TOKEN_2"]
    )
    schema = Schema("CREATE TABLE mydataset (b TEXT NOT NULL, a BIGINT NOT NULL)")
    encryption_key = Key()

    manifest_hash = provider_1_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema.table_name,
        StringIO("hello,1\nbello,2\nyellow,-1\nchello,-2"),
        schema,
        encryption_key
    )
    provider_1_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    # Provider 2
    provider_2_client, provider_2_session = create_session(
        os.environ["TEST_USER_ID_3"],
        os.environ["TEST_API_TOKEN_3"]
    )
    schema = Schema(
        "CREATE TABLE abc (a BIGINT NOT NULL, b TEXT NOT NULL, c REAL NOT NULL)"
    )
    encryption_key = Key()

    manifest_hash = provider_2_client.upload_dataset(
        os.environ["TEST_USER_ID_3"],
        schema.table_name,
        StringIO("1,asd,0.0\n2,fgh,1.0\n-3,hrr,3.14"),
        schema,
        encryption_key
    )

    provider_2_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "positivea",
            PollingOptions(interval=1000)
    )
    users = map(lambda l: l[0].split(':')[0], results)
    assert Counter(users) == Counter([os.environ["TEST_USER_ID_2"]] * 2 + [os.environ["TEST_USER_ID_3"]] * 2)

@pytest.mark.skip(reason="helper function")
def create_custom_root_pki() -> Auth:
    pkey = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Custom PKI")
    ])
    cert_builder = x509.CertificateBuilder()
    cert = cert_builder.subject_name(
        subject
    ).issuer_name(
        issuer
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(seconds=31536000)
    ).serial_number(
        x509.random_serial_number()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).public_key(
        pkey.public_key()
    ).sign(pkey, hashes.SHA512())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    auth = Auth(cert_pem, pkey, "rootadmin@decentriq.ch")
    return auth


@pytest.mark.skip(reason="helper function")
def create_custom_user_pki(root_pki: Auth, email: str) -> Auth:
    pkey = generate_key()
    root_cert = x509.load_pem_x509_certificate(root_pki.get_certificate_chain_pem())

    cert_builder = x509.CertificateBuilder()
    cert = cert_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, email)
    ])).issuer_name(
        root_cert.issuer
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(seconds=31536000)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        pkey.public_key()
    ).sign(root_pki.kp, hashes.SHA512())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_chain = b'\n'.join([cert_pem, root_pki.get_certificate_chain_pem()])
    return Auth(cert_chain, pkey, email)


def test_non_default_pki():
    custom_root_pki = create_custom_root_pki()
    root_ca_cert = custom_root_pki.get_certificate_chain_pem()

    custom_analyst_pki = create_custom_user_pki(custom_root_pki, os.environ["TEST_USER_ID_1"])
    _, analyst_session = create_session(
            os.environ["TEST_USER_ID_1"],
            os.environ["TEST_API_TOKEN_1"],
            custom_analyst_pki
    )

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = analyst_session.enclave_identifier

    table = Table()
    table.sqlCreateTableStatement = \
        "CREATE TABLE something (_$uploader_user_id TEXT NOT NULL, a BIGINT NOT NULL, b TEXT NOT NULL)"

    data_room.tables.append(table)

    query = Query()
    query.queryName = "positivea"
    query.sqlSelectStatement = "SELECT _$uploader_user_id FROM something WHERE a > 0"

    data_room.queries.append(query)

    role = Role()
    role.roleName = "role"
    role.emailRegex = ".*"
    role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    query_permission = Permission()
    query_permission.submitQueryPermission.queryName = "positivea"

    role.permissions.append(query_permission)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "something"

    role.permissions.append(upload_permission)

    data_room.roles.append(role)

    data_room_hash = expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))

    # Provider 1
    custom_provider_1_pki = create_custom_user_pki(custom_root_pki, os.environ["TEST_USER_ID_2"])
    provider_1_client, provider_1_session = create_session(
        os.environ["TEST_USER_ID_2"],
        os.environ["TEST_API_TOKEN_2"],
        custom_provider_1_pki
    )
    schema = Schema("CREATE TABLE mydataset (b TEXT NOT NULL, a BIGINT NOT NULL)")
    encryption_key = Key()

    manifest_hash = provider_1_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema.table_name,
        StringIO("hello,1\nbello,2\nyellow,-1\nchello,-2"),
        schema,
        encryption_key
    )
    provider_1_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    # Provider 2
    custom_provider_2_pki = create_custom_user_pki(custom_root_pki, os.environ["TEST_USER_ID_3"])
    provider_2_client, provider_2_session = create_session(
        os.environ["TEST_USER_ID_3"],
        os.environ["TEST_API_TOKEN_3"],
        custom_provider_2_pki
    )

    schema = Schema("CREATE TABLE abc (a BIGINT NOT NULL, b TEXT NOT NULL, c REAL NOT NULL)")
    encryption_key = Key()

    manifest_hash = provider_2_client.upload_dataset(
        os.environ["TEST_USER_ID_3"],
        schema.table_name,
        StringIO("1,asd,0.0\n2,fgh,1.0\n-3,hrr,3.14"),
        schema,
        encryption_key
    )

    provider_2_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "positivea",
            PollingOptions(interval=1000)
    )
    roots = map(lambda l: l[0].split(':')[1], results)
    assert len(Counter(roots)) == 1


def test_different_root_same_user():
    custom_root_pki = create_custom_root_pki()
    root_ca_cert = custom_root_pki.get_certificate_chain_pem()

    custom_analyst_pki = create_custom_user_pki(custom_root_pki, os.environ["TEST_USER_ID_1"])
    analyst_client, analyst_session = create_session(
            os.environ["TEST_USER_ID_1"],
            os.environ["TEST_API_TOKEN_1"],
            custom_analyst_pki
    )

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = analyst_session.enclave_identifier

    table = Table()
    table.sqlCreateTableStatement = \
        "CREATE TABLE something (_$uploader_user_id TEXT NOT NULL, a BIGINT NOT NULL, b TEXT NOT NULL)"

    data_room.tables.append(table)

    query = Query()
    query.queryName = "positivea"
    query.sqlSelectStatement = "SELECT _$uploader_user_id FROM something WHERE a > 0"

    data_room.queries.append(query)

    query_permission = Permission()
    query_permission.submitQueryPermission.queryName = "positivea"
    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "something"


    role1 = Role()
    role1.roleName = "role1"
    role1.emailRegex = ".*"
    role1.authenticationMethod.trustedPki.rootCertificate = root_ca_cert
    role1.permissions.append(query_permission)
    role1.permissions.append(upload_permission)
    data_room.roles.append(role1)

    role2 = Role()
    role2.roleName = "role2"
    role2.emailRegex = ".*"
    role2.authenticationMethod.trustedPki.rootCertificate = analyst_client.get_ca_root_certificate()
    role2.permissions.append(query_permission)
    role2.permissions.append(upload_permission)
    data_room.roles.append(role2)

    data_room_hash = expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))

    # Provider 1, use custom PKI
    custom_provider_1_pki = create_custom_user_pki(custom_root_pki, os.environ["TEST_USER_ID_2"])
    provider_1_client, provider_1_session = create_session(
        os.environ["TEST_USER_ID_2"],
        os.environ["TEST_API_TOKEN_2"],
        custom_provider_1_pki
    )
    schema = Schema(
        "CREATE TABLE mydataset (b TEXT NOT NULL, a BIGINT NOT NULL)"
    )
    encryption_key = Key()

    manifest_hash = provider_1_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema.table_name,
        StringIO("hello,1\nbello,2\nyellow,-1\nchello,-2"),
        schema,
        encryption_key,
    )
    provider_1_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    # Provider 2, use default PKI, but same user
    provider_2_client, provider_2_session = create_session(
        os.environ["TEST_USER_ID_2"],
        os.environ["TEST_API_TOKEN_2"]
    )

    schema = Schema(
        "CREATE TABLE abc (a BIGINT NOT NULL, b TEXT NOT NULL, c REAL NOT NULL)")
    encryption_key = Key()

    manifest_hash = provider_2_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema.table_name,
        StringIO("1,asd,0.0\n2,fgh,1.0\n-3,hrr,3.14"),
        schema,
        encryption_key
    )

    provider_2_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "something",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "positivea",
            PollingOptions(interval=1000)
    )
    user_ids = map(lambda l: l[0], results)
    assert len(Counter(user_ids)) == 2

def test_dataroom_retrieval():
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    root_ca_cert = analyst_client.get_ca_root_certificate()

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = analyst_session.enclave_identifier

    table = Table()
    table.sqlCreateTableStatement = \
        "CREATE TABLE simple (a BIGINT NOT NULL)"
    data_room.tables.append(table)

    query = Query()
    query.queryName = "simple_query"
    query.sqlSelectStatement = "SELECT a FROM simple WHERE a > 0"
    data_room.queries.append(query)

    role = Role()
    role.roleName = "role"
    role.emailRegex = ".*"
    role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    query_permission = Permission()
    query_permission.submitQueryPermission.queryName = "simple_query"
    role.permissions.append(query_permission)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "simple"
    role.permissions.append(upload_permission)

    dataroom_retrieval_permission = Permission()
    dataroom_retrieval_permission.dataRoomRetrievalPermission.SetInParent()
    role.permissions.append(dataroom_retrieval_permission)

    data_room.roles.append(role)

    data_room_hash = expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))

    retrieved_data_room = analyst_session.retrieve_data_room(data_room_hash)
    assert data_room == retrieved_data_room

# generate some large slow queries for testing polling
# query b, some joins as well
@pytest.mark.skip(reason="helper function")
def get_big_slow_query_a(table):
    level_a = f"SELECT \n" \
              f" foo,\n" \
              f" bar,\n" \
              f" SUM(foo / 45) AS zorch\n" \
              f"FROM \"{table}\" \n"  \
              f"GROUP BY foo, bar\n"
    level_b = f"SELECT \n" \
              f" baz,\n" \
              f" blorf,\n" \
              f" SUM(baz / 45) AS yorch\n" \
              f"FROM \"{table}\" \n"  \
              f"GROUP BY baz, blorf\n"
    level_c = f"SELECT \n" \
              f" a.foo AS foo,\n" \
              f" a.bar AS bar,\n" \
              f" b.baz AS baz,\n" \
              f" b.blorf AS blorf\n" \
              f"FROM ({level_a}) AS a JOIN ({level_b}) AS b ON a.zorch = b.yorch\n"
    level_d = f"SELECT \n" \
              f" foo,\n" \
              f" bar,\n" \
              f" baz,\n" \
              f" blorf,\n" \
              f" SUM(foo / 88) AS zorch\n" \
              f"FROM ({level_c}) \n"  \
              f"GROUP BY foo, bar, baz, blorf\n"
    level_e = f"SELECT \n" \
              f" foo,\n" \
              f" bar,\n" \
              f" baz,\n" \
              f" blorf,\n" \
              f" SUM(blorf / 88) AS yorch\n" \
              f"FROM ({level_c}) \n"  \
              f"GROUP BY foo, bar, baz, blorf\n"
    level_f = f"SELECT \n" \
              f" a.foo,\n" \
              f" a.bar,\n" \
              f" b.baz,\n" \
              f" b.blorf\n" \
              f"FROM ({level_d}) AS a JOIN ({level_e}) AS b ON a.zorch = b.yorch\n"
    level_g = f"SELECT \n" \
              f" foo,\n" \
              f" bar,\n" \
              f" baz,\n" \
              f" blorf,\n" \
              f" SUM(bar/ 1337) AS zorch\n" \
              f"FROM ({level_f}) \n"  \
              f"GROUP BY foo, bar, baz, blorf\n"
    level_h = f"SELECT \n" \
              f" foo,\n" \
              f" bar,\n" \
              f" baz,\n" \
              f" blorf,\n" \
              f" SUM(baz / 64) AS zorch\n" \
              f"FROM ({level_g}) \n"  \
              f"GROUP BY foo, bar, baz, blorf\n"
    return f"SELECT\n" \
           f" foo,\n" \
           f" bar,\n" \
           f" baz,\n" \
           f" blorf,\n" \
           f" zorch\n" \
           f"FROM ( " \
           f" {level_h} "\
           f") \n" \
           f"GROUP BY foo, bar, baz, blorf, zorch\n"

@pytest.mark.skip(reason="helper function")
def slow_query_create_table(table_name) -> str:
    return \
        f"CREATE TABLE {table_name} (" \
        f"foo BIGINT NOT NULL," \
        f"bar BIGINT NOT NULL," \
        f"baz BIGINT NOT NULL," \
        f"blorf BIGINT NOT NULL" \
        f")"

def test_malformed_input_validation():
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    enclave_identifiers = analyst_client.get_enclave_identifiers()

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(slow_query_create_table("slow_table"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "malformed.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # validate it
    reply = data_provider_session.validate_dataset(
            manifest_hash,
            encryption_key
    )

    assert reply.failure.row == 20


def test_correct_input_validation():
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    enclave_identifiers = analyst_client.get_enclave_identifiers()

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(slow_query_create_table("slow_table"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "slow_boat.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # validate it
    reply = data_provider_session.validate_dataset(
            manifest_hash,
            encryption_key
    )

    assert reply.HasField("failure") == False


def test_slow_boat_to_nagasaki_distrib():
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    enclave_identifiers = analyst_client.get_enclave_identifiers()

    # Upload dataset. Note the different name. This is referring to the user-specific table, and is used to
    # identify an upload for the user. The dataroom table name is shared between users.
    schema = Schema(slow_query_create_table("slow_table"))
    encryption_key = Key()
    with open(os.path.join(fixtures_dir, "slow_boat.csv"), "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = data_provider_client.upload_dataset(
            os.environ["TEST_USER_ID_2"],
            schema.table_name,
            events_stream,
            schema,
            encryption_key
        )

    # Create data room
    root_ca_cert = analyst_client.get_ca_root_certificate()
    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = enclave_identifiers[0]

    # force distributed queries..
    data_room.queryExecutionMode.distributedExecutionMode.targetParallelism = 64
    data_room.queryExecutionMode.distributedExecutionMode.chunkSize = 8388608
    data_room.queryExecutionMode.distributedExecutionMode.maxChunkCountInMemory = 64

    slow_table = Table()
    slow_table.sqlCreateTableStatement = slow_query_create_table("slow_table")

    data_room.tables.append(slow_table)

    analyst_role = Role()
    analyst_role.roleName = "analyst"
    analyst_role.emailRegex = ".*"
    analyst_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    for query_name, get_query_function in [
        ("slow_boat", get_big_slow_query_a),
    ]:
        query = Query()
        query.queryName = query_name
        query.sqlSelectStatement = get_query_function("slow_table")

        data_room.queries.append(query)

        query_permission = Permission()
        query_permission.submitQueryPermission.queryName = query_name

        analyst_role.permissions.append(query_permission)

    data_room.roles.append(analyst_role)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "slow_table"

    data_provider_role = Role()
    data_provider_role.roleName = "data_provider"
    data_provider_role.emailRegex = ".*"
    data_provider_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert
    data_provider_role.permissions.append(upload_permission)

    data_room.roles.append(data_provider_role)
    data_room_hash = expect_create_data_room_response_hash(data_provider_session.create_data_room(data_room))


    # Publish dataset to data room
    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "slow_table",
            encryption_key
    )

    results = analyst_session.make_sql_query(
            data_room_hash,
            "slow_boat",
            PollingOptions(interval=1000)
    )
    assert len(results) > 100

def test_fuzzy_matching():
    analyst_client, analyst_session = create_session(os.environ["TEST_USER_ID_1"], os.environ["TEST_API_TOKEN_1"])
    data_provider_client, data_provider_session = create_session(os.environ["TEST_USER_ID_2"], os.environ["TEST_API_TOKEN_2"])
    enclave_identifiers = analyst_client.get_enclave_identifiers()
    root_ca_cert = analyst_client.get_ca_root_certificate()

    data_room = DataRoom()
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
    data_room.mrenclave = enclave_identifiers[0]

    table1 = Table()
    table1.sqlCreateTableStatement = \
        "CREATE TABLE customer1 (name TEXT NOT NULL, company TEXT NOT NULL)"
    data_room.tables.append(table1)

    table2 = Table()
    table2.sqlCreateTableStatement = \
        "CREATE TABLE customer2 (name TEXT NOT NULL, role TEXT NOT NULL)"
    data_room.tables.append(table2)

    query = Query()
    query.queryName = "simple_query"
    query.sqlSelectStatement = "SELECT customer2.role FROM customer1 INNER JOIN customer2 ON fuzzystrmatch(customer1.name, customer2.name, 2)"
    data_room.queries.append(query)

    role = Role()
    role.roleName = "role"
    role.emailRegex = ".*"
    role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    query_permission = Permission()
    query_permission.submitQueryPermission.queryName = "simple_query"
    role.permissions.append(query_permission)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "customer1"
    role.permissions.append(upload_permission)

    upload_permission = Permission()
    upload_permission.tableCrudPermission.tableName = "customer2"
    role.permissions.append(upload_permission)

    dataroom_retrieval_permission = Permission()
    dataroom_retrieval_permission.dataRoomRetrievalPermission.SetInParent()
    role.permissions.append(dataroom_retrieval_permission)
    data_room.roles.append(role)
    data_room.queryExecutionMode.distributedExecutionMode.targetParallelism = 2
    data_room.queryExecutionMode.distributedExecutionMode.chunkSize = 1048576
    data_room.queryExecutionMode.distributedExecutionMode.maxChunkCountInMemory = 16

    data_room_hash = expect_create_data_room_response_hash(analyst_session.create_data_room(data_room))

    schema1 = Schema(
        "CREATE TABLE customer1 (name TEXT NOT NULL, company TEXT NOT NULL)")
    encryption_key1 = Key()

    manifest_hash = data_provider_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema1.table_name,
        StringIO("aaa,bbb\nhhh,nnn"),
        schema1,
        encryption_key1
    )

    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "customer1",
            encryption_key1
    )

    schema2 = Schema(
        "CREATE TABLE customer2 (name TEXT NOT NULL, role TEXT NOT NULL)")
    encryption_key2 = Key()
    manifest_hash = data_provider_client.upload_dataset(
        os.environ["TEST_USER_ID_2"],
        schema2.table_name,
        StringIO("aac,fff\nccc,aaa"),
        schema2,
        encryption_key2
    )

    data_provider_session.publish_dataset_to_data_room(
            manifest_hash,
            data_room_hash,
            "customer2",
            encryption_key2
    )


    results = analyst_session.make_sql_query(
            data_room_hash,
            "simple_query",
            PollingOptions(interval=1000)
    )

    assert len(results) == 1
