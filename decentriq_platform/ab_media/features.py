from typing import List
from ..logger import logger


class AbMediaDcrFeatures:
    def __init__(self, features: List[str]) -> None:
        self.features = features

    def has_enable_rate_limiting_on_publish_dataset(self) -> bool:
        return self._features_contain("ENABLE_RATE_LIMITING_ON_PUBLISH_DATASET")

    def has_enable_timer_report(self) -> bool:
        return self._features_contain("ENABLE_TIMER_REPORT")

    def has_enable_model_performance_evaluation(self) -> bool:
        return self._features_contain("ENABLE_MODEL_PERFORMANCE_EVALUATION")

    def has_enable_debug_mode(self) -> bool:
        debug_enabled = self._features_contain("ENABLE_DEBUG_MODE")
        if debug_enabled:
            logger.warning("!!!WARNING!!!: DEBUG MODE IS ENABLED")
        return debug_enabled

    def has_enable_insights(self) -> bool:
        return self._features_contain("ENABLE_INSIGHTS")

    def has_enable_lookalike_audiences(self) -> bool:
        return self._features_contain("ENABLE_LOOKALIKE_AUDIENCES")

    def has_enable_rule_based_audiences(self) -> bool:
        return self._features_contain("ENABLE_RULE_BASED_AUDIENCES")

    def has_enable_remarketing(self) -> bool:
        return self._features_contain("ENABLE_REMARKETING")

    def has_enable_exclude_seed_audience(self) -> bool:
        return self._features_contain("ENABLE_EXCLUDE_SEED_AUDIENCE")

    def has_enable_hide_absolute_audience_sizes(self) -> bool:
        return self._features_contain("ENABLE_HIDE_ABSOLUTE_AUDIENCE_SIZES")

    def has_enable_data_partner(self) -> bool:
        return self._features_contain("ENABLE_DATA_PARTNER")

    def has_enable_advertiser_audience_download(self) -> bool:
        return self._features_contain("ENABLE_ADVERTISER_AUDIENCE_DOWNLOAD")

    def _features_contain(self, flag: str) -> bool:
        return flag in self.features
