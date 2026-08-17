from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    detected: bool
    severity: str
    score: int
    source_ip: str
    reasons: list[str] = field(default_factory=list)