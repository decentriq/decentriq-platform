# What is decentriq_platform?

`decentriq_platform` is the Python SDK for working with Decentriq's platform. It can be used to:
* create DCRs (Data Clean Rooms)
* encrypt and upload input data
* trigger computation of authorized queries

For a complete reference of the SDK check the *Reference* section on the left.

**Limitation**  
Currently not every feature which is available on the Decentriq platform UI is accessible via the Python SDK. 
Known limitations are:
* no support to fetch all data rooms created for a given user

**Installation**  
Make sure you are running at least on Python 3.7 and have a clean environment. Then run:
```
pip install decentriq_platform
```

# Quick start
This short introduction uses the SDK to:
* establish a connection to an enclave running on decentriq's platform
* create a DCR (Data Clean Room) instance given a specific configuration
* upload and publish data to the DCR
* run a query for the given DCR and fetch the results
* inspect the tamper-proof audit log

To follow this tutorial first install the SDK (see above) and then run the following code from a Python file.

First we need to authenticate with the platform. Please specify your user email as well as a valid access token for that account. You can find your access tokens, create new ones, or delete existing ones on your *Account* page in the platform UI.
```python
user_email = "test_user@company.com"
api_token = "@@ YOUR TOKEN HERE @@"
```

### Establish connection to an enclave 
We import the necessary dependencies into our program:
```python
import random
from io import StringIO
from decentriq_platform import Client
from decentriq_platform.storage import Schema, Key
from decentriq_platform.session import (
    VerificationOptions, SessionOptions, PollingOptions
)
from decentriq_platform.proto.data_room_pb2 import (
    DataRoom, Table,
    Query, Role,
    Permission
)
```

Then we create a client and define the enclave identifier to connect to (hash of the binary, also referred to as "mrenclave"):
```python
client = Client(api_token=api_token)
auth = client.create_auth(user_email)
enclave_identifiers = client.get_enclave_identifiers()
mrenclave = enclave_identifiers[0] # in this tutorial we just pick the first available identifier (demo only)
```

This allows us to establish an active session to the enclave:
```python
session = client.create_session(
    mrenclave,
    {"example_role": auth},
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
```
This session object will be used from now on to communicate with the secure enclave.

### Creation of a Data Clean Room (DCR)
A clean data room running on the platform can be seen as an instantiation of a DCR configuration. This config strictly defines the schemas of all  data being associated with a DCR as well as declares the exact type of computations that can be executed, including permissions and enforced privacy policies.  
For this tutorial we assume the following example table definition and query:
```python
create_table_statement = """
CREATE TABLE example_table (
    name TEXT NOT NULL,
    salary DOUBLE NOT NULL,
);"""

query_statement = """
SELECT SUM(salary) FROM example_table;
"""
```

We can now define a simple DCR configuration using the Python SDK builder:
```python
data_room = DataRoom()

# set a random ID
data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()

# set mrenclave
data_room.mrenclave = mrenclave["enclaveIdentifier"]

# add tables
table = Table()
schema = Schema(create_table_statement)
table.sqlCreateTableStatement = create_table_statement
data_room.tables.append(table)

# add queries
query = Query()
query.queryName = "example_query"
query.sqlSelectStatement = query_statement 
data_room.queries.append(query)

# add role
role = Role()
role.roleName = "example_role"
role.emailRegex = user_email
# This is the root certificate of an identity provider that is trusted with signing user certificates
# Currently, Decentriq's identity provider is used - but custom providers can be used.
root_ca_cert = client.get_ca_root_certificate()
role.authenticationMethod.trustedPki.rootCertificate = root_ca_cert

## defining permissions
### permission to upload data
upload_permission = Permission()
upload_permission.tableCrudPermission.tableName = schema.table_name
role.permissions.append(upload_permission)

### permission to run the query
query_permission = Permission()
query_permission.submitQueryPermission.queryName = "example_query"
role.permissions.append(query_permission)

### permission to access the audit log
audit_log_retrieval_permission = Permission()
audit_log_retrieval_permission.auditLogRetrievalPermission.SetInParent()
role.permissions.append(audit_log_retrieval_permission)

data_room.roles.append(role)
```

Now we can finally create a DCR instance for the given configuration:
```python
data_room_hash = session.create_data_room(data_room).dataRoomHash
```

### Upload and publish data to a DCR
Let's create some example data which we want to ingest. Given our table schmea from above we define some names and salaries:
| name  | salary |
| ----- | ------ |
| Bob   | 12.1   |
| Alice | 412.2  |
| Jack  | 13.1   |

We can define this table as a CSV string in Python:
```python
data = """Bob,12.2
Alice,412.2
Jack,13.1
"""
```

and upload the encrypted data to the platform:
```python
key = Key()
input_data = StringIO()
input_data.write(data)
input_data.seek(0)
manifest_hash  = client.upload_dataset(
    user_email,
    schema.table_name,
    input_data,
    schema,
    key
)
```

Finally we publish the dataset to a specific DCR by providing the encryption key for that DCR instance:
```python
session.publish_dataset_to_data_room(
    user_email,
    manifest_hash,
    data_room_hash,
    schema.table_name,
    key
)
```

### Run query on a DCR and collect results
After ingesting, we can now run the pre-defined query on the DCR: 
```python
result = session.make_sql_query(
    data_room_hash,
    "example_query",
    PollingOptions(interval=1000)
)
```

### Inspect audit log
At any time we can also obtain a tamper-proof audit log of all events that happened with the corresponding DCR:
```python
audit_log = session.retrieve_audit_log(data_room_hash)
```
