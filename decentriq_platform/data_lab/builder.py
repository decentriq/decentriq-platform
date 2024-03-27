from ..client import Client
from ..types import MatchingId
from . import DataLab, DataLabConfig, ExistingDataLab
from ..keychain import Keychain


class DataLabBuilder:
    """
    A helper class to build a Data Lab.
    """

    def __init__(
        self,
        client: Client,
    ):
        self.name = None
        self.has_demographics = False
        self.has_embeddings = False
        self.num_embeddings = 0
        self.matching_id = MatchingId.STRING
        self.validation_id = None
        self.client = client
        self.existing = False
        self.data_lab_id = None

    def with_name(self, name: str):
        """
        Set the name of the DataLab.

        **Parameters**:
        - `name`: Name to be used for the DataLab.
        """
        self.name = name

    def with_matching_id_format(self, matching_id: MatchingId):
        """
        Set the matching ID format.

        **Parameters**:
        - `matching_id`: The type of matching ID to use.
        """
        self.matching_id = matching_id

    def with_demographics(self):
        """
        Enable demographics in the DataLab.
        """
        self.has_demographics = True

    def with_embeddings(self, num_embeddings: int):
        """
        Enable embeddings in the DataLab.

        **Parameters**:
        - `num_embeddings`: The number of embeddings the DataLab should use.
        """
        self.has_embeddings = True
        self.num_embeddings = num_embeddings

    def from_existing(self, data_lab_id: str, keychain: Keychain):
        """
        Construct a new DataLab from an existing DataLab with the given ID.

        **Parameters**:
        - `data_lab_id`: The ID of the existing DataLab.
        - `keychain`: The keychain to use to provision datasets from the old DataLab to the new DataLab.
        """
        self.existing = True
        self.data_lab_id = data_lab_id
        self.keychain = keychain

    def build(self) -> DataLab:
        """
        Build the DataLab.
        """
        if self.existing:
            # Build a new DataLab from an existing one.
            # The new DataLab will have the same configuration as the existing one.
            data_lab_definition = self.client.get_data_lab(self.data_lab_id)
            cfg = DataLabConfig(
                data_lab_definition["name"],
                data_lab_definition["requireDemographicsDataset"],
                data_lab_definition["requireEmbeddingsDataset"],
                data_lab_definition["numEmbeddings"],
                data_lab_definition["matchingIdFormat"],
            )
            existing_data_lab = ExistingDataLab(data_lab_definition, self.keychain)
            return DataLab(self.client, cfg, existing_data_lab)
        else:
            # Build a new DataLab using the specified enclave specifications.
            cfg = DataLabConfig(
                self.name,
                self.has_demographics,
                self.has_embeddings,
                self.num_embeddings,
                self.matching_id,
            )
            return DataLab(self.client, cfg)
