from typing_extensions import Self
from .audience_definitions import (
    LookalikeAudienceDefinition,
    AudienceStatus,
    AudienceDefinitions,
    audience_id_from_name,
)


class LookalikeAudienceBuilder:
    """
    Builder for constructing lookalike audience definitions.
    """

    def __init__(
        self,
        *,
        name: str,
        reach: int,
        source_audience_name: str,
        audiences: AudienceDefinitions,
    ) -> None:
        """
        Initialise the lookalike audience builder.

        **Parameters**:
        - `name`: Name of the lookalike audience.
        - `reach`: The desired reach of the lookalike audience expressed as a percentage between 1-30.
        - `source_audience_name`: Name of the source audience that the lookalike audience will be built from.
        - `audiences`: Definitions of all existing audiences.
        """
        if not (0 <= reach <= 30):
            raise Exception(f"Reach value {reach} is not in range 0 to 30")

        self.name = name
        self.reach = reach
        self.source_audience_name = source_audience_name
        self.audiences = audiences
        self.exclude_seed_audience = False
        self.make_available_to_publisher = False

    def with_exclude_seed_audience(self) -> Self:
        """
        Exclude the seed audience from the lookalike audience.
        """
        self.exclude_seed_audience = True
        return self

    def with_make_available_to_publisher(self) -> Self:
        """
        Make the lookalike audience available to the publisher.
        """
        self.make_available_to_publisher = True
        return self

    def build(self) -> LookalikeAudienceDefinition:
        """
        Build the lookalike audience definition.
        """
        source_ref_id = audience_id_from_name(self.source_audience_name, self.audiences)
        return LookalikeAudienceDefinition(
            name=self.name,
            reach=self.reach,
            seed_audience_name=self.source_audience_name,
            source_ref_id=source_ref_id,
            exclude_seed_audience=self.exclude_seed_audience,
            status=(
                AudienceStatus.PUBLISHED
                if self.make_available_to_publisher
                else AudienceStatus.READY
            ),
        )
