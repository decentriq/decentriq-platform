import zipfile, io


def read_result_as_zipfile(
    result: bytes
):
    """
    Read the given raw computation result as a `zipfile.ZipFile` object.
    Use the `read(name: str)` method on the returned object to read a specific
    file contained in the archive.

    Refer to the [official documentation](https://docs.python.org/3/library/zipfile.html)
    of the zipfile library for all the available methods.
    """
    return zipfile.ZipFile(io.BytesIO(result), "r")
