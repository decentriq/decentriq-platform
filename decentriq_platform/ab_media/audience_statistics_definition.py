from typing import Any, Dict, List
from typing_extensions import Self


class LalAudienceStatistics:
    """
    Class representing the statistics of a given lookalike audience.
    """

    def __init__(
        self,
        auc: float,
        fpr: List[float],
        tpr: List[float],
    ) -> None:
        """
        Initialise an instance of the `LalAudienceStatistics`

        **Parameters**:
        - `auc`: The area under the ROC curve.
        - `fpr`: The list of false postive rates (in order of decreasing discrimination threshold).
        - `tpr`: The list of true positive rates (in order of decreasing discrimination threshold).
        """
        self.auc = auc
        self.fpr = fpr
        self.tpr = tpr

    def as_dict(self) -> Dict[str, Any]:
        return {
            "quality": {
                "roc_curve": {"auc": self.auc, "fpr": self.fpr, "tpr": self.tpr}
            }
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Self:
        roc_curve = d["quality"]["roc_curve"]
        return cls(
            auc=roc_curve["auc"],
            fpr=roc_curve["fpr"],
            tpr=roc_curve["tpr"],
        )
