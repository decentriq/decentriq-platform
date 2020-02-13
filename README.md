# avato-python-client

Python client library for the Avato platform.

## Installation

After cloning the repository you can use different installation methods:

### Poetry

To install with poetry just run:
```
poetry install
```

#### Notes:

1. If you get an error during the installation try to delete the `poetry.lock` file

2. Poetry installs the library in its own virtualenv, if you want to use it in your
global python installation disable virtualenvs in poetry

```
poetry config settings.virtualenvs.create false
```

### Pip

To install with pip just run:

```
pip install .
```

## Usage:

This library is just the entrypoint to the avato platform. You will need one of 
instance libraries to play around with the platform.


## Testing

To start the testing process install `nox` with `pip install nox` and the run it
in the project directory. *N.B. make sure you have an available avato-backend*

**nox**
```
nox
```
