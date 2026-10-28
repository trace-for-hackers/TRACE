"""
modules/sensitive_data_over_http.py

Passivo, uma requisição: página servida em HTTP puro (não HTTPS) com
formulário contendo campo sensível (senha, cartão, CPF/SSN) -- o dado é
submetido em texto claro, capturável por qualquer um na mesma rede.

Também cobre o caso do formulário ter `action` apontando explicitamente
pra um destino HTTP (mesmo que a página em si seja HTTPS) -- é menos
comum, mas é o MESMO problema: dado sensível ainda vai sem criptografia
até o servidor, só que dessa vez apesar da página parecer segura.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_SENSITIVE_INPUT_TYPES = {"password"}
_SENSITIVE_FIELD_NAME_KEYWORDS = (
    "password", "senha", "pwd", "creditcard", "credit_card", "card_number",
    "cardnumber", "cvv", "ssn", "cpf", "social_security",
)


def is_sensitive_field(input_type: str, field_name: str) -> bool:
    if (input_type or "").lower() in _SENSITIVE_INPUT_TYPES:
        return True
    name_lower = (field_name or "").lower()
    return any(kw in name_lower for kw in _SENSITIVE_FIELD_NAME_KEYWORDS)


def find_sensitive_forms(html: str, page_url: str) -> list[dict]:
    """Função pura -- recebe HTML já baixado, devolve lista de
    formulário com campo sensível E destino (action resolvido) em HTTP
    puro. Testável sem rede."""
    soup = BeautifulSoup(html or "", "html.parser")
    results = []

    for form in soup.find_all("form"):
        sensitive_fields = []
        for field in form.find_all(["input"]):
            field_type = field.get("type", "text")
            field_name = field.get("name", "")
            if is_sensitive_field(field_type, field_name):
                sensitive_fields.append(field_name or f"(tipo={field_type})")

        if not sensitive_fields:
            continue

        action = form.get("action") or page_url
        resolved_action = urljoin(page_url, action)

        if urlparse(resolved_action).scheme == "http":
            results.append({
                "action": resolved_action, "fields": sensitive_fields,
                "page_is_https": urlparse(page_url).scheme == "https",
            })

    return results


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="cryptographic_failures",
    display_name="Dado Sensível Submetido Sobre HTTP",
    summary="Acha formulário com campo sensível (senha, cartão, CPF) cujo destino de submissão é HTTP puro -- passivo, uma requisição só.",
)
class SensitiveDataOverHTTP:
    name = "sensitive_data_over_http"

    def run(self, target: str):
        r = get(target)
        if r is None:
            return None

        forms = find_sensitive_forms(r.text, target)
        if not forms:
            return None

        findings = []
        for form in forms:
            findings.append({
                "title": f"Dado sensível submetido sobre HTTP: {', '.join(form['fields'])}",
                "severity": "critical" if not form["page_is_https"] else "high",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": form["action"],
                "description": (
                    f"Formulário com campo sensível ({', '.join(form['fields'])}) submete pra "
                    f"'{form['action']}', em HTTP puro -- o dado trafega sem criptografia, "
                    f"capturável por qualquer um na mesma rede (Wi-Fi público, proxy, etc.)."
                ),
                "business_impact": "Credencial ou dado sensível pode ser interceptado em trânsito, sem precisar comprometer o servidor.",
                "remediation": "Servir a página inteira e o destino de submissão do formulário via HTTPS, com redirect automático de HTTP para HTTPS.",
                "evidence": {"form_action": form["action"], "sensitive_fields": form["fields"], "page_served_over_https": form["page_is_https"]},
            })

        return ModuleResult(findings=findings)
