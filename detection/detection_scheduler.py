from datetime import datetime, timedelta


class DetectionScheduler:

    def __init__(self, interval_seconds: int = 5):
        self.interval_seconds = interval_seconds
        self._last_run: datetime | None = None

    def should_run(self, current_time: datetime) -> bool:

        if self._last_run is None:
            self._last_run = current_time
            return True

        elapsed = (
            current_time - self._last_run
        ).total_seconds()

        if elapsed >= self.interval_seconds:
            self._last_run = current_time
            return True

        return False