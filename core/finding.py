from datetime import datetime
import uuid


class Finding:
    def __init__(
        self,
        module,
        title,
        severity="info",
        description="",
        endpoint="",
        parameter="",
        evidence=None,
    ):
        self.id = str(uuid.uuid4())
        self.module = module
        self.title = title

        self.severity = severity.lower()  
        self.exploitability = "Unknown"

        self.description = description
        self.endpoint = endpoint
        self.parameter = parameter
        self.evidence = evidence or []
        self.category = "general"

        self.notes = ""
        self.business_impact = ""
        self.remediation = ""
        self.timestamp = datetime.utcnow().isoformat()
        self.status = "new"
        self.is_new = True
        self.first_seen = self.timestamp
        self.last_seen = self.timestamp

        self.cvss_score = None
        self.cvss_vector = ""

    def to_dict(self):
        return {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "exploitability": self.exploitability,
            "description": self.description,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "notes": self.notes,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "status": self.status,
            "is_new": self.is_new,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "timestamp": self.timestamp,
        }
