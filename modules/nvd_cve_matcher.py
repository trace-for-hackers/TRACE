"""Correlates normalized technology facts against NVD CVEs."""
from __future__ import annotations

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from knowledge.fact import fact
from core.nvd_db import cpe_candidates, vulnerabilities_for_cpe, vulnerabilities_for_product, normalize_cve


def _severity(value: str | None) -> str:
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "info"


@discovery_module(
    requires=[Requirement("tech.product.*", min_confidence=0.7)],
    produces=[Produces("vulnerability.cve.*", durable=False)],
    cost=1,
    max_reentries=1,
    category="vulnerability_matching",
    display_name="Correlação de CVE via NVD",
    summary="Cruza produtos e versões detectados pelo TRACE com CPEs e vulnerabilidades publicadas na NVD.",
)
class NvdCveMatcher:
    name = "nvd_cve_matcher"

    def run(self, target: str, facts):
        products = facts.get("tech.product.*", [])
        findings = []
        facts = []
        seen = set()

        for product_fact in products:
            if product_fact.confidence < 0.7 or not isinstance(product_fact.value, dict):
                continue
            vendor = product_fact.value.get("vendor")
            product = product_fact.value.get("product")
            version = product_fact.value.get("version")
            if not vendor or not product or not version:
                continue

            candidate_records: list[tuple[dict, list[str]]] = []
            for cpe in cpe_candidates(vendor, product, version):
                for raw in vulnerabilities_for_cpe(cpe):
                    candidate_records.append((raw, [cpe]))

            # Crucial fallback: NVD often stores old products as deprecated CPEs
            # or as wildcard CPEs with explicit version ranges. Exact CPE lookup
            # can therefore legitimately return nothing.
            candidate_records.extend(vulnerabilities_for_product(vendor, product, version))

            for raw, matched_cpes in candidate_records:
                cve = normalize_cve(raw)
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)
                matched_cpes = sorted(set(matched_cpes))
                cpe = matched_cpes[0] if matched_cpes else None
                facts.append(fact(
                    key=f"vulnerability.cve.{cve_id}", value={"cve": cve_id, "cpe": cpe, "cpe_matches": matched_cpes, "product": product, "version": version},
                    confidence=min(1.0, product_fact.confidence), produced_by=self.name, target=target,
                ))
                findings.append({
                    "title": f"{cve_id} — {product} {version}",
                    "severity": _severity(cve.get("severity")),
                    "module": self.name,
                    "category": "vulnerable_components",
                    "endpoint": target,
                    "description": cve.get("description", ""),
                    "business_impact": f"A versão detectada de {product} está associada a {cve_id} na NVD.",
                    "remediation": f"Atualizar {product} de {version} para uma versão não afetada por {cve_id}.",
                    "exploitability": "See NVD/CPE applicability",
                    "evidence": {"vendor": vendor, "product": product, "version": version, "cpe": cpe, "cpe_matches": matched_cpes, "cve": cve},
                })

        if not findings and not facts:
            return None
        return ModuleResult(findings=findings, facts=facts)
