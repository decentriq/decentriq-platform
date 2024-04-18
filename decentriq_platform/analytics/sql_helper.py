import csv
import io
import zipfile
from typing import List, Tuple

from ..proto.compute_sql_pb2 import TableSchema
from ..proto.length_delimited import parse_length_delimited


def read_input_csv_file(
    path: str,
    /,
    *,
    has_header: bool = True,
    check_header: bool = True,
    encoding="utf-8",
    **kwargs,
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
    with open(path, "r", encoding=encoding) as csvfile:
        return _read_input_csv(
            csvfile,
            has_header=has_header,
            check_header=check_header,
            **kwargs,
        )


def read_input_csv_string(
    content: str, /, *, has_header: bool = True, check_header: bool = True, **kwargs
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
        **kwargs,
    )


def _read_input_csv(
    data: io.TextIOBase,
    /,
    *,
    has_header: bool = True,
    check_header: bool = True,
    **kwargs,
) -> io.BytesIO:
    if check_header:
        sample = "\n".join(data.readline() for _ in range(20))
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
    output = io.StringIO(newline="")
    writer = csv.writer(
        output, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL, dialect="unix"
    )
    if has_header:
        next(reader)
    # This will write the full file into memory and encode it in bulk.
    # Could be wrapped in a IO buffer-style class that would perform the
    # read/write csv lines operation in a streaming fashion.
    for row in reader:
        writer.writerow(row)
    output.seek(0)
    return io.BytesIO(output.read().encode("utf-8"))


def _read_sql_query_result(result: bytes) -> Tuple[str, TableSchema]:
    archive = zipfile.ZipFile(io.BytesIO(result), "r")

    if not {"dataset.csv", "types"}.issubset(archive.namelist()):
        raise Exception(
            "The given result cannot be read as it doesn't contain all the required files."
            " Expected files: 'dataset.csv' and 'types', only found: [{}]".format(
                ", ".join(archive.namelist())
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


def read_sql_query_result_as_string(result: bytes, include_header: bool = True) -> str:
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
        columns = [c1 if c1 else c2 for c1, c2 in zip(opt_columns, replacement_columns)]
        returned_content = ",".join(columns) + "\n" + content
    else:
        returned_content = content

    # Remove trailing newlines
    return returned_content.strip()
