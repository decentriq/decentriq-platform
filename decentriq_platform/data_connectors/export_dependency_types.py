from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from decentriq_dcr_compiler._schemas.data_science_data_room import (
    ExportNodeDependency as ExportNodeDependencySchema,
)


class ExportDependency:
    def __init__(
        self, high_level: Dict[str, Any], object_key: Optional[str] = None
    ) -> None:
        self.high_level = high_level
        self.object_key = object_key


class ExportNodeDependency:
    """
    Factory for creating the desired `ExportNodeDependency` type.
    """

    @staticmethod
    def raw(name: str, object_key: str) -> ExportDependency:
        """
        Construct an export dependency node which will export a raw file.

        **Parameters**:
        - `name`: Name of the export node dependency.
        - `object_key`: The name of the object when exported.
        """
        return ExportDependency({"name": name, "exportType": {"raw": ()}}, object_key)

    @staticmethod
    def all(name: str) -> ExportDependency:
        """
        Construct an export dependency node which will export all files in a zip.
        The names of the files in the zip will be used as the object names when exported.
        
        **Parameters**:
        - `name`: Name of the export node dependency.
        """
        return ExportDependency({"name": name, "exportType": {"zipAllFiles": ()}})

    @staticmethod
    def file(name: str, file: str, object_key: str) -> ExportDependency:
        """
        Construct an export dependency node which will export a single file in a zip.
        
        **Parameters**:
        - `name`: Name of the export node dependency.
        - `file`: Name of the file within the zip to be exported.
        - `object_key`: The name of the object when exported.
        """
        return ExportDependency(
            {"name": name, "exportType": {"zipSingleFile": file}}, object_key
        )


def _get_export_node_dependency_from_high_level(
    dependency: ExportNodeDependencySchema, object_key: str
):
    dependency_name = dependency.name
    dependency_export_type = dependency.exportType.root
    dependency_export_type_fields = dependency_export_type.model_fields

    if "raw" in dependency_export_type_fields:
        return ExportNodeDependency.raw(dependency_name, object_key)
    elif "zipSingleFile" in dependency_export_type_fields:
        return ExportNodeDependency.file(
            dependency_name, dependency_export_type.zipSingleFile, object_key
        )
    elif "zipAllFiles" in dependency_export_type_fields:
        return ExportNodeDependency.all(dependency_name)
    else:
        raise Exception(
            f"Unknown dependency export type field {dependency_export_type_fields}"
        )
