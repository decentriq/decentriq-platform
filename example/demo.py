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

# Credentials
insurance_email = os.environ["USER_MAIL_1"]
api_token1 = os.environ["API_TOKEN_1"]

bank_email = os.environ["USER_MAIL_2"]
api_token2 = os.environ["API_TOKEN_2"]

# =========================================================================================

# 1. Create Client & Session
# The insurance company and the bank decide to collaborate sing their data and agrees
# to use DecentriQ platform. First of all they run a client each and open a session with
# the enclave.

# Creates a new client and initializes an API inside it with host, port, use_tls and the token
# The purpouse of the client is to enstablish the connection to our backend and allow then
# the communication with the enclaves.
# The API itself initializes a requests session by setting the base URL, the token, etc.
# In the API, also the endpoints are defined.

# Client for the insurance company
client_insurance = Client(api_token=api_token1)
# Client for the bank
client_bank = Client(api_token=api_token2)

# This returns the root cert of the client
root_ca_cert_insurance = client_insurance.get_ca_root_certificate()
root_ca_cert_bank = client_bank.get_ca_root_certificate()

# Generates an RSA (asymmetric) keypair
# Generates a certificate signing request (email address + public key,
# signed over with private part of the newly generated key).
# Posts it to the USER_CERTIFICATES endpoint (replaced by the user id) to get the signed certificate
# Creates and returns an Auth object that can (get user id, get certificate chain, sign data)

auth_insurance = client_insurance.create_auth(insurance_email)
auth_bank = client_bank.create_auth(bank_email)

# Posts enclave identifier (aka MRENCLAVE) to SESSIONS endpoint and parses a session id from the response
# Creates and returns a Sessions object
# - GET SESSION_FATQUOTE returns (certificate, message, signature, fatquote)
# - verifies (certificate, message, signature) against enclave identifier

enclave_identifiers = client_bank.get_enclave_identifiers()
# We take the fist enclave identifier for the demo, since the version we use is not important.
# In a production scenario, the identifier here should be a value of an enclave
# for which the client audited or trusts the code.
# When enclaves share the same identifier, they are part of the same cluster
# and queries executed in distribued execution mode
# will be divided in tasks to be solved indipendently inside the cluster.
mrenclave = enclave_identifiers[0]


# Using the client it is possible to create a Session object, which allow the communication
# with the enclave, so that the user can create a dataroom, upload data to it or send queries
session_insurance = client_insurance.create_session(
        mrenclave,
        auth_insurance,  # The auth object contains the information required to open a secure connection with the enclave
        SessionOptions(
            VerificationOptions(
                accept_debug=True,  # Accept enclaves quotes with the DEBUG flag
                accept_configuration_needed=True,  # Accept quotes with the CONFIGURATION_NEEDED status
                accept_group_out_of_date=True  # Accept quotest with the GROUP_OUT_OF_DATE status
            )
        )
    )

session_bank = client_bank.create_session(
    mrenclave,
    auth_bank,
    SessionOptions(
        VerificationOptions(
            accept_debug=True,
            accept_configuration_needed=True,
            accept_group_out_of_date=True
        )
    )
)


# =========================================================================================

# 2. Create DataRoom
# Both the insurance company and the bank have an open session with our enclave
# The insurance company creates a dataroom

# A dataroom is a declaration of how a particular data collaboration between different users looks like.
# It declares the shape of the shared data (SQL schemas) and defines access control over
# how the data can be uploaded and queried.
data_room = DataRoom()
# set a random ID
data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()
# set the MRENCLAVE
data_room.mrenclave = mrenclave

# query execution mode
# if distributed:
#     # force distributed queries..
#     data_room.queryExecutionMode.distributedExecutionMode.targetParallelism = 64
#     data_room.queryExecutionMode.distributedExecutionMode.chunkSize = 8388608
#     data_room.queryExecutionMode.distributedExecutionMode.maxChunkCountInMemory = 64

# add insurance table
create_table_i = "CREATE TABLE insurance_customers (first_name TEXT NOT NULL, \
surname TEXT NOT NULL,zipcode INT NOT NULL,age TEXT NOT NULL,gender TEXT NOT NULL,\
insurproduct TEXT NOT NULL);"
schema_i = Schema(create_table_i)
table_i = Table()
table_i.sqlCreateTableStatement = create_table_i
data_room.tables.append(table_i)

# add banking table
create_table_b = "CREATE TABLE bank_customers (first_name TEXT NOT NULL,surname TEXT NOT NULL\
,zipcode INT NOT NULL,age TEXT NOT NULL,gender TEXT NOT NULL,bankproduct TEXT NOT NULL,\
income TEXT NOT NULL);"
schema_b = Schema(create_table_b)
table_b = Table()
table_b.sqlCreateTableStatement = create_table_b
data_room.tables.append(table_b)

# add queries
# The query regards the geographical overlap of common customers.
query_name_overlap = "overlap_query"
query_overlap_select_statement = "SELECT insurance_customers.zipcode, COUNT(*)\nFROM insurance_customers\
 INNER JOIN bank_customers ON insurance_customers.first_name = bank_customers.first_name AND \
  \tinsurance_customers.surname = bank_customers.surname AND\tinsurance_customers.zipcode = bank_customers.zipcode \
  \nGROUP BY insurance_customers.zipcode"
query_overlap = Query()
query_overlap.queryName = query_name_overlap
query_overlap.sqlSelectStatement = query_overlap_select_statement
data_room.queries.append(query_overlap)

# add roles
# Data owner from the bank
bank_role = Role()
bank_role.roleName = "bank_data_owner"
bank_role.emailRegex = bank_email
bank_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert_bank

# Can upload the bank table
upload_permission_b = Permission()
upload_permission_b.tableCrudPermission.tableName = schema_b.table_name
bank_role.permissions.append(upload_permission_b)

# Has permition for query 1
query_overlap_permission = Permission()
query_overlap_permission.submitQueryPermission.queryName = query_name_overlap
bank_role.permissions.append(query_overlap_permission)

data_room.roles.append(bank_role)

# Data owner from the insurance company
insurance_role = Role()
insurance_role.roleName = "insurance_data_owner"
insurance_role.emailRegex = insurance_email
insurance_role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert_insurance

# Can upload the insurance table
upload_permission_i = Permission()
upload_permission_i.tableCrudPermission.tableName = schema_i.table_name
insurance_role.permissions.append(upload_permission_i)

# Has permition for the query
insurance_role.permissions.append(query_overlap_permission)

data_room.roles.append(insurance_role)

# create dataroom
data_room_hash = session_insurance.create_data_room(data_room).dataRoomHash


# =========================================================================================

# 3. Upload and publish data
# Now the insurance company and the bank can upload their datasets to the dataroom


# Insurance Dataset
create_table_i = "CREATE TABLE insurance_customers (first_name TEXT NOT NULL, \
surname TEXT NOT NULL,zipcode INT NOT NULL,age TEXT NOT NULL,gender TEXT NOT NULL,\
insurproduct TEXT NOT NULL);"
schema_i = Schema(create_table_i)
key_i = Key()
path_i = "./fixtures/B+I-v2_Insurance_1000.csv"
with open(path_i, "r", buffering=1024 ** 2) as events_stream:
    manifest_hash_i = client_insurance.upload_dataset(
        insurance_email,
        schema_i.table_name,
        events_stream,
        schema_i,
        key_i
    )

# Bank Dataset
create_table_b = "CREATE TABLE bank_customers (first_name TEXT NOT NULL,surname TEXT NOT NULL\
,zipcode INT NOT NULL,age TEXT NOT NULL,gender TEXT NOT NULL,bankproduct TEXT NOT NULL,\
income TEXT NOT NULL);"
schema_b = Schema(create_table_b)
key_b = Key()
path_b = "./fixtures/B+I-v2_Bank_1000.csv"
with open(path_b, "r", buffering=1024 ** 2) as events_stream:
    manifest_hash_b = client_bank.upload_dataset(
        bank_email,
        schema_b.table_name,
        events_stream,
        schema_b,
        key_b
    )

# publish bank dataset
session_bank.publish_dataset_to_data_room(
        manifest_hash_b,
        data_room_hash,
        schema_b.table_name,
        key_b
)

# publish insurance dataset
session_insurance.publish_dataset_to_data_room(
        manifest_hash_i,
        data_room_hash,
        schema_i.table_name,
        key_i
)


# =========================================================================================

# 4. Running the query
# The insurance company runs the overlap query

results = session_insurance.make_sql_query(
        data_room_hash,
        "overlap_query",
        PollingOptions(interval=1000)
)

print(results)
