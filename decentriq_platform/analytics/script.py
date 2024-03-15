from enum import Enum


class ScriptingLanguage(str, Enum):
    python = "python"
    r = "r"


class FileContent:
    def __init__(self, name: str, content: str) -> None:
        self.name = name
        self.content = content


class Script(FileContent):
    def __init__(self, name: str, content: str, language: ScriptingLanguage) -> None:
        super().__init__(name, content)
        self.language = language


class PythonScript(Script):
    """
    Class representing a Python script.
    """

    def __init__(self, name: str, content: str) -> None:
        super().__init__(name, content, ScriptingLanguage.python)


class RScript(Script):
    """
    Class representing an R script.
    """

    def __init__(self, name: str, content: str) -> None:
        super().__init__(name, content, ScriptingLanguage.r)
