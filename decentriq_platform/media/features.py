from typing import List


class MediaInsightFeatures:
    def __init__(self, features: List[str]) -> None:
        self.features = features

    def has_enable_lookalike(self) -> bool:
        return self._features_contain("ENABLE_LOOKALIKE")

    def has_enable_insights(self) -> bool:
        return self._features_contain("ENABLE_INSIGHTS")

    def has_enable_retargeting(self) -> bool:
        return self._features_contain("ENABLE_RETARGETING")

    def has_enable_exclusion_targeting(self) -> bool:
        return self._features_contain("ENABLE_EXCLUSION_TARGETING")

    def has_enable_rate_limiting_on_publish_dataset(self) -> bool:
        return self._features_contain("ENABLE_RATE_LIMITING_ON_PUBLISH_DATASET")

    def has_enable_model_performance_evaluation(self) -> bool:
        return self._features_contain("ENABLE_MODEL_PERFORMANCE_EVALUATION")

    def has_enable_timer_report(self) -> bool:
        return self._features_contain("ENABLE_TIMER_REPORT")

    def has_enable_noisy_output(self) -> bool:
        return self._features_contain("NOISY_OUTPUTS")

    def has_enable_advertiser_audience_download(self) -> bool:
        return self._features_contain("ENABLE_ADVERTISER_AUDIENCE_DOWNLOAD")

    def _features_contain(self, flag: str) -> bool:
        return flag in self.features
