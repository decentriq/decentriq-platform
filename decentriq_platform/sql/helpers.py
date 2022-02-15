import zipfile
import io
import csv
from typing import List, Tuple, Any
from .compute import SqlSchemaVerifier
from .. import Permissions, Session, Key, DataRoomBuilder
from ..compute import Noop
from .proto import TableSchema
from ..proto import Permission
from ..proto.length_delimited import parse_length_delimited


class ValidatedDataNode:
    """
    Helper class to construct the triplet of nodes required for data nodes with schema validation.

    In a data clean room computations and the data they depend on are expressed in terms
    of graphs where computations are represented by *compute nodes* and input datasets are
    represented by *data nodes*.
    With tabular input data, it is possible to validate the input data and check whether it
    corresponds to a pre-defined schema. This validation is a computation in itself so in
    order to validate the input data, we need to add an additional compute node on top of the
    data node. Because it must be possible to trigger this validation *while restricting access
    to the resulting data*, another special node, the *noop node* needs to be added.

    This class will add the necessary nodes to your data clean room.

    After having constructed an object of this class, pass its `add_to_builder` method to
    decentriq_platform.DataRoomBuilder.add_using_function` or pass the builder object to
    `add_to_builder` directly.
    When creating the data clean room, don't forget to also grant the `validation_permission`
    permission as well as the `leaf_crud_permission`. Both permissions should usually be granted
    at the same time.

    Data should be published to the node named `input_node_name` and be read from `output_node_name`.
    The name of the validation computation can be accessed using the field `validation_computation_name`.

    The helper function `upload_and_publish_dataset` will upload, publish, and validate your data
    automatically.
    """
    def __init__(
            self,
            table_name: str,
            schema: List[Tuple[str, Any, bool]],
            *,
            is_required: bool = False
        ):
        """
        Create a `ValidatedDataNode`.

        **Parameters**:
        - `table_name`: What your dataset should be called. This is the name you will later use in
            your SQL queries.
        - `schema`: The list of columns. This is a list of tuples, each containing the name of the column,
            the data type (`decentriq_compute_sql.PrimitiveType`), and whether the column is nullable (can have empty values).
            The data type is an enum like object with values `PrimitiveType.STRING`, `PrimitiveType.INT64`,
            `PrimitiveType.FLOAT64`.
        - `is_required`: Whether the dataset needs to be present for computations to be triggered.
        """
        self.is_required = is_required
        self._leaf_node_name = f"@table/${table_name}/dataset"
        self._verifier_node_name = table_name

        self.validation_computation_name = f"@table/${table_name}/validation"
        """The name of the computation that will perform the data validation."""

        self._verifier = SqlSchemaVerifier(schema)

    def add_to_builder(self, builder: DataRoomBuilder):
        """
        Configure the given `DataRoomBuilder` to build te final data clean room with the necessary
        compute and data nodes.

        Remember that you still have to add the `validation_permission` and `leaf_crud_permission`
        in order for a user to be able to upload and validate the input data.
        """
        builder.add_data_node(self._leaf_node_name, is_required=self.is_required)
        builder.add_compute_node(self._verifier_node_name, self._verifier, dependencies=[self._leaf_node_name])
        builder.add_compute_node(self.validation_computation_name, Noop(), dependencies=[self._verifier_node_name])

    @property
    def validation_permission(self) -> Permission:
        """The permission required to trigger the data validation."""
        return Permissions.execute_compute(self.validation_computation_name)

    @property
    def leaf_crud_permission(self) -> Permission:
        """The permission required to upload the raw, non-validated data."""
        return Permissions.leaf_crud(self._leaf_node_name)

    @property
    def input_node_name(self) -> str:
        """The node name to which data should be uploaded."""
        return self._leaf_node_name

    @property
    def output_node_name(self) -> str:
        """The node name from which data can be read, e.g. the name to use in any downstream SQL queries."""
        return self._verifier_node_name


def read_input_csv_file(
        path: str,
        /, *,
        has_header: bool = True,
        check_header: bool = True,
        encoding="utf-8",
        **kwargs
) -> io.BytesIO:
    """
    Read CSV from a file and turn it into a bytes array of the correct format so that it can be uploaded
    to the Decentriq platform.

    **Parameters**:
    - `path`: The path to the CSV file.
    - `has_header`: Whether the string contains a header row.
    - `check_header`: Whether the function should try to determine whether the file has a header.
        If the file has a header row but you didn't set the `has_header` flag, an
        exception will be raised. If you're sure that the way you use the function
        is correct, you can disable this check using this parameter.
    - `encoding`: The encoding of the CSV file. If you wrote the CSV file using a library like pandas,
        you need to check the documentation to see what encoding they use by default
        when writing files (likely `"utf-8"` in which case this can be left at its default value).
    - `delimiter`: What delimiter is used in the the CSV file. Default is the comma.
    - `**kwargs`: Additional keyword arguments passed to the Python CSV parser. Refer to the
        [official documentation](https://docs.python.org/3/library/csv.html#csv-fmt-params)
        for a list of supported arguments.

    **Returns**:
    A BytesIO object that can be passed to the methods resposible for uploading data.
    """
    lines = []
    with open(path, 'r', encoding=encoding) as csvfile:
        return _read_input_csv(
            csvfile,
            has_header=has_header,
            check_header=check_header,
            **kwargs,
        )


def read_input_csv_string(
        content: str,
        /, *,
        has_header: bool = True,
        check_header: bool = True,
        **kwargs
) -> io.BytesIO:
    """
    Read CSV from a string and turn it into a bytes array of the correct format so that it can be uploaded
    to the Decentriq platform.

    **Parameters**:
    - `content`: The string containing the CSV file.
    - `has_header`: Whether the string contains a header row.
    - `check_header`: Whether the function should try to determine whether the file has a header.
        If the file has a header row but you didn't set the `has_header` flag, an
        exception will be raised. If you're sure that the way you use the function
        is correct, you can disable this check using this parameter.
    - `encoding`: The encoding of the source file. If you wrote the CSV file using a library like pandas,
        you need to check the documentation to see what encoding they use by default
        when writing files.
    - `delimiter`: What delimiter is used in the the CSV file. Default is the comma.
    - `**kwargs`: Additional keyword arguments passed to the Python CSV parser. What flags can be passed can be
        seen [here](https://docs.python.org/3/library/csv.html#csv-fmt-params).

    **Returns**:
    A BytesIO object that can be passed to the methods resposible for uploading data.
    """
    return _read_input_csv(
        io.StringIO(content.strip()),
        has_header=has_header,
        check_header=check_header,
        **kwargs
    )


def _read_input_csv(
        data: io.TextIOBase,
        /, *,
        has_header: bool = True,
        check_header: bool = True,
        **kwargs
) -> io.BytesIO:
    lines = []
    if check_header:
        sample = '\n'.join(data.readline() for _ in range(20))
        file_has_header = csv.Sniffer().has_header(sample)
        if file_has_header and has_header is False:
            raise Exception(
                "Warning: the file seems to have a header but the header flag is not set to true!"
                " This flag needs to be set correctly in order for the data to be uploaded."
            )
        elif not file_has_header and has_header is True:
            raise Exception(
                "Warning: the file doesn't seem to have a header but the header flag is set!"
                " This flag needs to be set correctly in order for the data to be uploaded."
            )
        data.seek(0)
    reader = csv.reader(data, **kwargs)
    if has_header:
        next(reader)
    for row in reader:
        lines.append(','.join(row))
    return io.BytesIO('\n'.join(lines).encode())


def upload_and_publish_dataset(
        data: io.BytesIO,
        key: Key,
        data_room_id: str,
        *,
        data_node: ValidatedDataNode,
        session: Session,
        description: str,
        validate: bool = True,
        **kwargs
) -> str:
    """
    Convenience function for uploading data and validating the schema of the uploaded
    data.

    Validation of tabular data is a separate computation for which specific compute nodes
    need to be present in the compute graph defined by the data room definition.
    This function will take care of triggering the validation action for you.
    In case validation fails, an exception will be raised. Validation can be turned off
    using the `validate` parameter.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `data_node`: The data node object added to the data room builder.
    - `session`: The session with which to communicate with the enclave.
    - `description`: An identifier to the dataset.
    - `validate`: Whether to perform the validation operation.

    **Returns**:
    The manifest hash (dataset id) in case the upload and validation succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        description=description,
    )
    session.publish_dataset(
        data_room_id, manifest_hash,
        leaf_name=data_node.input_node_name,
        key=key
    )

    if validate:
        try:
            session.run_computation_and_get_results(
                data_room_id,
                data_node.validation_computation_name,
                **kwargs
            )
        except Exception as e:
            raise Exception("Validation of dataset failed! Reason: {}".format(e))

    return manifest_hash


def _read_sql_query_result(result: bytes) -> Tuple[str, TableSchema]:
    archive = zipfile.ZipFile(io.BytesIO(result), "r")

    if set(archive.namelist()) != {"dataset.csv", "types"}:
        raise Exception(
            "The given result cannot be read as it doesn't contain all the required files."
            " Expected files: 'dataset.csv' and 'types', only found: [{}]".format(
                ', '.join(archive.namelist())
            )
        )

    csv = archive.read("dataset.csv").decode()
    schema = TableSchema()
    parse_length_delimited(archive.read("types"), schema)

    return (csv, schema)


def read_sql_query_result_as_list(result: bytes) -> Tuple[List[List[str]], TableSchema]:
    """
    Read the given raw CSV output from an SQL query result and transform it into a list of
    lists, where each inner list corresponds to a row in the tabular output data.
    The header row won't be contained in the resulting output and all the inner values
    will be of type string.
    The actual column types as well as their names will be returned as part of the schema
    value.
    """
    csv_content, schema = _read_sql_query_result(result)
    reader = csv.reader(io.StringIO(csv_content))
    return list(reader), schema


def read_sql_query_result_as_string(
        result: bytes,
        include_header: bool = True
) -> str:
    """
    Read the given raw CSV output from an SQL query result and transform it into a string
    containing the full CSV file including the header row.
    The resulting string can be written directly to a file from where it can be read
    using your data analysis library of choice.

    **Parameters**:
    - `result`: The result from which to extract a CSV file as a string.
    - `include_header`: Whether to include an additional header row that contains
        column names (provided for example by using alias expressions
        in SELECT statements). If this setting is true, but no column
        names could be found, the names "V1", "V2" and so will be used.
    """
    content, schema = _read_sql_query_result(result)

    if include_header:
        opt_columns = [col.name for col in schema.namedColumns]
        # Use V1, V2, ... for unknown column names => same format as R uses.
        replacement_columns = [f"V{ix}" for ix in range(1, len(opt_columns) + 1)]
        columns = [ c1 if c1 else c2 for c1, c2 in zip(opt_columns, replacement_columns)]
        returned_content = ','.join(columns) + '\n' + content
    else:
        returned_content = content

    # Remove trailing newlines
    return returned_content.strip()
