from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SecurityAlert:
    alert_id: str
    source_ip: str
    detection_type: str
    severity: str
    risk_score: int
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    reasons: list[str] = field(
        default_factory=list
    )
    status: str = "OPEN"