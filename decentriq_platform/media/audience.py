from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any


class ActivationType(str, Enum):
    LOOKALIKE = "lookalike"
    RETARGET = "retarget"
    EXCLUSION_TARGETING = "exclusion_targeting"


@dataclass
class Audience:
    audience_type: str
    activation_type: ActivationType
    is_published: bool
    # `reach` only required when `activation_type` is lookalike.
    reach: Optional[int] = None
    exclude_seed_audience: bool = False

    def as_dict(self) -> Dict[str, Any]:
        if self.reach:
            return {
                "audience_type": self.audience_type,
                "activation_type": self.activation_type.value,
                "is_published": self.is_published,
                "reach": self.reach,
                "exclude_seed_audience": self.exclude_seed_audience,
            }
        else:
            return {
                "audience_type": self.audience_type,
                "activation_type": self.activation_type.value,
                "is_published": self.is_published,
                "exclude_seed_audience": False, # Can only be set for Lookalike activateion types.
            }
