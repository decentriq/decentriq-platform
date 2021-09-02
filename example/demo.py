#!/usr/bin/env python

import os
from decentriq_platform import (Client, Schema, Key)
from decentriq_platform import VerificationOptions, SessionOptions, PollingOptions
import random

from decentriq_platform.proto.data_room_pb2 import (
    DataRoom, Table,
    Query, Role,
    Permission
)

# ============================================================================================================================
# 0. INTRO
# An insurance and a bank decide to collaborate in a privacy-preserving on their customer data using the Decentriq platform.
# For the purpose of this demo, both users are represented in the same script. In a production setup, the users would of course
# operate from different locations.

# Get credentials from previously set environment variables
email_i = os.environ["USER_MAIL_1"]
api_token_i = os.environ["API_TOKEN_1"]

email_b = os.environ["USER_MAIL_2"]
api_token_b = os.environ["API_TOKEN_2"]

print("Insurance user: {}".format(email_i))
print("Bank user: {}".format(email_b))

# ============================================================================================================================
# 1. CREATE CLIENT & SESSION
# First, both each create a client and open a session with the enclave.
#
# The purpose of the client is to enstablish the connection to the backend and allow then
# the communication with the enclaves (the confidential computing system).
#
# Using the client it is possible to create a session object, which enables communication
# with the enclave, so that the user can create a data room, provision data or send queries.


def create_client_and_session(email, api_token, role):

    client = Client(api_token=api_token)

    # The auth object contains the information required to open a secure connection with the enclave
    auth = client.create_auth(email)

    # NOTE:
    # We take the first available enclave identifier (hash of the binary, also referred to as "mrenclave") for the demo.
    # In a production scenario, the identifier here should be a value of an enclave for which the user audited or trusts the code.
    enclave_identifiers = client.get_enclave_identifiers()
    mrenclave = enclave_identifiers[0]

    session = client.create_session(
        mrenclave,
        {role: auth},
        SessionOptions(
            VerificationOptions(
                accept_debug=True,  # Accept enclaves quotes with the DEBUG flag (demo only)
                # Accept quotes with the CONFIGURATION_NEEDED status (demo only)
                accept_configuration_needed=True,
                # Accept quotest with the GROUP_OUT_OF_DATE status (demo only)
                accept_group_out_of_date=True
            )
        )
    )

    return client, session, mrenclave


client_i, session_i, mrenclave = create_client_and_session(email_i, api_token_i, "insurance_data_owner")
client_b, session_b, _ = create_client_and_session(email_b, api_token_b, "bank_data_owner")

print("Created insurance and bank clients and sessions.")

# ============================================================================================================================
# 2. CREATE DATA ROOM
# The insurance company creates a data room. A data room is a declaration of how a particular data collaboration
# between the users looks like. It declares who should provide what data (SQL schemas and upload permissions) and
# who can run and access which queries (SQL and query permissions).


def build_insurance_bank_data_room(mrenclave, create_table_i, create_table_b, query_name_overlap, query_overlap_select_statement, email_i, email_b, root_ca_cert):

    data_room = DataRoom()

    # set a random ID
    data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()

    # set mrenclave
    data_room.mrenclave = mrenclave["enclaveIdentifier"]

    # add tables
    table_i = Table()
    schema_i = Schema(create_table_i)
    table_i.sqlCreateTableStatement = create_table_i
    data_room.tables.append(table_i)

    table_b = Table()
    schema_b = Schema(create_table_b)
    table_b.sqlCreateTableStatement = create_table_b
    data_room.tables.append(table_b)

    # add queries
    query_overlap = Query()
    query_overlap.queryName = query_name_overlap
    query_overlap.sqlSelectStatement = query_overlap_select_statement
    data_room.queries.append(query_overlap)

    # add roles

    # role_b (can upload the bank_customers table and run query_overlap)
    role_b = Role()
    role_b.roleName = "bank_data_owner"
    role_b.emailRegex = email_b
    role_b.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    upload_permission_b = Permission()
    upload_permission_b.tableCrudPermission.tableName = schema_b.table_name
    role_b.permissions.append(upload_permission_b)

    query_overlap_permission = Permission()
    query_overlap_permission.submitQueryPermission.queryName = query_name_overlap
    role_b.permissions.append(query_overlap_permission)

    data_room.roles.append(role_b)

    # role_i (can only upload to the insurance_customers table)
    role_i = Role()
    role_i.roleName = "insurance_data_owner"
    role_i.emailRegex = email_i
    role_i.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

    upload_permission_i = Permission()
    upload_permission_i.tableCrudPermission.tableName = schema_i.table_name
    role_i.permissions.append(upload_permission_i)

    data_room.roles.append(role_i)

    return data_room


# insurance_customers table
create_table_i = """
    CREATE TABLE insurance_customers (
        first_name TEXT NOT NULL,
        surname TEXT NOT NULL,
        zipcode INT NOT NULL,
        age TEXT NOT NULL,
        gender TEXT NOT NULL,
        insurproduct TEXT NOT NULL
    );"""

# bank_customers table
create_table_b = """
    CREATE TABLE bank_customers (
        first_name TEXT NOT NULL,
        surname TEXT NOT NULL,
        zipcode INT NOT NULL,
        age TEXT NOT NULL,
        gender TEXT NOT NULL,
        bankproduct TEXT NOT NULL,
        income TEXT NOT NULL
    );"""

# overlap_query
query_name_overlap = "overlap_query"
query_overlap_select_statement = """
    SELECT insurance_customers.zipcode, COUNT(*)
    FROM insurance_customers INNER JOIN bank_customers
        ON insurance_customers.first_name = bank_customers.first_name AND
           insurance_customers.surname = bank_customers.surname AND
           insurance_customers.zipcode = bank_customers.zipcode
    GROUP BY insurance_customers.zipcode
 """

# This is the root certificate of an identity provider that is trusted with signing user certificates
# Currently, Decentriq's identity provider is used - but custom providers can be used.
root_ca_cert = client_i.get_ca_root_certificate()

# build the data room
data_room = build_insurance_bank_data_room(mrenclave, create_table_i, create_table_b, query_name_overlap,
                                           query_overlap_select_statement, email_i, email_b, root_ca_cert)

# create the dataroom in the enclave
data_room_hash = session_i.create_data_room(data_room).dataRoomHash

print("Successfully published data room with hash: {}".format(data_room_hash.hex()))

# ============================================================================================================================
# 3. UPLOAD AND PUBLISH DATA
# Now the data room has been created, the insurance and the bank can provision their datasets. They do this in two steps.
# First they encrypt their data locally and upload it to the Decentriq platform. Then in a second step, they provision the
# decryption key to the enclave.

# Encrypt & upload data


def encrypt_and_upload_dataset(client, schema, email, path):
    key = Key()
    with open(path, "r", buffering=1024 ** 2) as events_stream:
        manifest_hash = client.upload_dataset(
            email,
            schema.table_name,
            events_stream,
            schema,
            key
        )
    return manifest_hash, key


path_i = "./fixtures/B+I-v2_Insurance_1000.csv"
schema_i = Schema(create_table_i)
manifest_hash_i, key_i = encrypt_and_upload_dataset(
    client_i, schema_i, email_i, path_i)

path_b = "./fixtures/B+I-v2_Bank_1000.csv"
schema_b = Schema(create_table_b)
manifest_hash_b, key_b = encrypt_and_upload_dataset(client_b, schema_b, email_b, path_b)

# Publish datasets by providing the encryption keys to the enclave
session_i.publish_dataset_to_data_room(
    email_i,
    manifest_hash_i,
    data_room_hash,
    schema_i.table_name,
    key_i
)

session_b.publish_dataset_to_data_room(
    email_b,
    manifest_hash_b,
    data_room_hash,
    schema_b.table_name,
    key_b
)

print("Encrypted, uploaded and provisioned insurance and bank data sets to data room.")

# ============================================================================================================================
# 4. RUN THE QUERY
# The bank runs the overlap query and prints the results

results = session_b.make_sql_query(
    data_room_hash,
    query_name_overlap,
    PollingOptions(interval=1000)
)

print("Submitted query and received results:")
print(results)
