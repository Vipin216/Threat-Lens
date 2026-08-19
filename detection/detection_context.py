from dataclasses import dataclass, field
from datetime import datetime, timedelta

from detection.feature_vector import FeatureVector


@dataclass
class DetectionContext:

    window_seconds: int = 60

    feature_vectors: list[FeatureVector] = field(
        default_factory=list
    )

    _timestamps: dict[int, datetime] = field(
        default_factory=dict,
        init=False,
    )

    def add(
        self,
        feature_vector: FeatureVector,
        timestamp: datetime,
    ) -> None:

        self.feature_vectors.append(
            feature_vector
        )

        self._timestamps[
            id(feature_vector)
        ] = timestamp

        self._expire_old(timestamp)

    def get_source_vectors(
        self,
        source_ip: str,
    ) -> list[FeatureVector]:

        return [
            vector
            for vector in self.feature_vectors
            if vector.source_ip == source_ip
        ]

    def get_all_sources(self) -> set[str]:

        return {
            vector.source_ip
            for vector in self.feature_vectors
        }

    def _expire_old(
        self,
        current_time: datetime,
    ) -> None:

        cutoff = (
            current_time
            - timedelta(
                seconds=self.window_seconds
            )
        )

        active_vectors = []

        for vector in self.feature_vectors:

            timestamp = self._timestamps[
                id(vector)
            ]

            if timestamp >= cutoff:
                active_vectors.append(
                    vector
                )

            else:
                del self._timestamps[
                    id(vector)
                ]

        self.feature_vectors = active_vectors