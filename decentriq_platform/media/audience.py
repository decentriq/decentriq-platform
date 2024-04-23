from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any


class ActivationType(str, Enum):
    LOOKALIKE = "lookalike"
    RETARGET = "retarget"


@dataclass
class Audience:
    audience_type: str
    activation_type: ActivationType
    is_published: bool
    # `reach` only required when `activation_type` is lookalike.
    reach: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        if self.reach:
            return {
                "audience_type": self.audience_type,
                "activation_type": self.activation_type.value,
                "is_published": self.is_published,
                "reach": self.reach,
            }
        else:
            return {
                "audience_type": self.audience_type,
                "activation_type": self.activation_type.value,
                "is_published": self.is_published,
            }
