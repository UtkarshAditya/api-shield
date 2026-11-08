from dataclasses import dataclass, field, asdict


@dataclass
class Endpoint:
    method: str
    path: str
    params: list = field(default_factory=list)
    requires_auth: bool = False


@dataclass
class Finding:
    id: str
    endpoint: str
    method: str
    owasp_cat: str
    title: str
    severity: str
    risk_score: float
    evidence: dict
    fix: str
    suggested_rule: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)