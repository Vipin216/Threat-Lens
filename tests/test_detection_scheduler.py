from datetime import datetime, timedelta

from detection.detection_scheduler import DetectionScheduler


def main():

    scheduler = DetectionScheduler(
        interval_seconds=5
    )

    start = datetime.now()

    # First call should run
    assert scheduler.should_run(start) is True

    # 1 second later → no
    assert scheduler.should_run(
        start + timedelta(seconds=1)
    ) is False

    # 4 seconds later → still no
    assert scheduler.should_run(
        start + timedelta(seconds=4)
    ) is False

    # 5 seconds later → yes
    assert scheduler.should_run(
        start + timedelta(seconds=5)
    ) is True

    # 2 seconds after previous run → no
    assert scheduler.should_run(
        start + timedelta(seconds=7)
    ) is False

    # 5 seconds after previous run → yes
    assert scheduler.should_run(
        start + timedelta(seconds=10)
    ) is True

    print(
        "Detection scheduler test passed"
    )


if __name__ == "__main__":
    main()