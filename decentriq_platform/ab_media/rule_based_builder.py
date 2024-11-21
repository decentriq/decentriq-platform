from typing import List
from typing_extensions import Self
from .audience_definitions import (
    AudienceFilters,
    AudienceCombinator,
    RuleBasedAudienceDefinition,
    AudienceStatus,
    AudienceDefinitions,
    audience_id_from_name,
    CombineOperator,
)


class RuleBasedAudienceBuilder:
    """
    Builder for constructing rule-based audience definitions.
    """

    def __init__(
        self, *, name: str, source_audience_name: str, audiences: AudienceDefinitions
    ) -> None:
        """
        Initialise the rule-based audience builder.

        **Parameters**:
        - `name`: Name of the rule-based audience.
        - `source_audience_name`: Name of the source audience that the rule-based audience will be built from.
        - `audiences`: Definitions of all existing audiences.
        """
        self.name = name
        self.source_audience_name = source_audience_name
        self.audiences = audiences
        self.make_available_to_publisher = False
        self.filters = None
        self.combinators = None

    def with_make_available_to_publisher(self) -> Self:
        """
        Make the rule-based audience available to the publisher.
        """
        self.make_available_to_publisher = True
        return self

    def with_filters(self, filters: AudienceFilters) -> Self:
        """
        Set the filters to be applied to the source audience.

        **Parameters**:
        - `filters`: Filters to be applied to the source audience.
        """
        self.filters = filters
        return self

    def with_combinator(self, combinators: List[AudienceCombinator]) -> Self:
        """
        Set the combinators to be applied to the audiences.
        This defines how multiple audiences can be combined.

        **Parameters**:
        - `combinators`: The list of combinators used to combine audiences.
        """
        self.combinators = combinators
        return self

    def build(self) -> RuleBasedAudienceDefinition:
        """
        Build the rule-based audience definition.
        """
        source_ref_id = audience_id_from_name(self.source_audience_name, self.audiences)
        return RuleBasedAudienceDefinition(
            name=self.name,
            source_ref_name=self.source_audience_name,
            source_ref_id=source_ref_id,
            status=(
                AudienceStatus.PUBLISHED
                if self.make_available_to_publisher
                else AudienceStatus.READY
            ),
            filters=self.filters,
            combinators=self.combinators,
        )


class AudienceCombinatorBuilder:
    """
    Builder for constructing an `AudienceCombinator`.
    """

    def __init__(
        self,
        *,
        operator: CombineOperator,
        source_audience_name: str,
        audiences: AudienceDefinitions
    ) -> None:
        """
        Initialise the audience combinator builder.

        **Parameters**:
        - `operator`: The operator used to combine audiences.
        - `source_audience_name`: Name of the source audience to combine with.
        - `audiences`: Definitions of all existing audiences.
        """
        self.operator = operator
        self.source_audience_name = source_audience_name
        self.audiences = audiences
        self.filters = None

    def with_filters(self, filters: AudienceFilters) -> Self:
        """
        Set the filters to be applied to the source audience.

        **Parameters**:
        - `filters`: Filters to be applied to the source audience.
        """
        self.filters = filters
        return self

    def build(self) -> AudienceCombinator:
        """
        Build the audience combinator.
        """
        source_audience_id = audience_id_from_name(
            self.source_audience_name, audiences=self.audiences
        )
        return AudienceCombinator(
            operator=self.operator,
            source_audience_name=self.source_audience_name,
            source_audience_id=source_audience_id,
            filters=self.filters,
        )
