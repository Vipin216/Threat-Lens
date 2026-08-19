import time


class DetectionScheduler:

    def __init__(
        self,
        interval_seconds: int = 1,
        packet_threshold: int = 50,
    ):
        self.interval_seconds = interval_seconds
        self.packet_threshold = packet_threshold
        self._last_run: float | None = None
        self._packet_count = 0

    def should_run(self) -> bool:
        self._packet_count += 1

        current_time = time.monotonic()

        if self._last_run is None:
            self._last_run = current_time
            self._packet_count = 0
            return True

        elapsed = (
            current_time
            - self._last_run
        )

        if (
            elapsed >= self.interval_seconds
            or self._packet_count >= self.packet_threshold
        ):
            self._last_run = current_time
            self._packet_count = 0
            return True

        return False