# Decentriq - Python SDK

The Decentriq Python SDK exposes the [Decentriq platform](platform.decentriq.com)'s functionality via easy-to-use programming constructs and, as such, allows
users to interact with the platform in a programmatic way.

Releases of this library are hosted on [https://pypi.org/project/decentriq-platform/](pypi) and can be installed via the Python package manager `pip`.

Please refer to the [official documentation](https://docs.decentriq.com/python) for tutorials on how to install and use the
Decentriq Python SDK, as well as for detailed API documentation.

## Development

### Known Issues

#### Poetry cannot find recently released package
If you release a new `decentriq_dcr_compiler` package and want to run
`poetry lock --no-update` to update the lock file, then you might need to
`poetry cache clear --all .` first in order to have poetry be able to pick
up the recently released version.
