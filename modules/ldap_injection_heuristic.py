"""
modules/ldap_injection_heuristic.py

Mesmo padrao de modules/injection_heuristics.py::ErrorBasedHeuristic,
adaptado pra assinatura de erro de LDAP em vez de SQL. Envia caractere
especial de filtro LDAP (parenteses desbalanceados, asterisco) e procura
mensagem de erro de biblioteca LDAP conhecida na resposta -- comparando
contra o baseline, pra nao confundir com pagina que ja menciona "ldap"
normalmente (documentacao, por exemplo).
"""

from __future__ import annotations

from utils.requester import get, post, is_intrusive_confirmed
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

# payload -- parenteses desbalanceados e caractere de filtro LDAP quebram
# a sintaxe de busca (RFC 4515) da mesma forma que aspas simples quebram
# SQL. "*)(uid=*" e o classico teste de bypass de filtro; sozinho ja e
# o suficiente pra quebrar sintaxe se o campo for concatenado sem escape.
_PROBE_PAYLOAD = "*)(uid=*"

# assinatura de biblioteca LDAP conhecida -- poucas, especificas,
# baixa chance de falso positivo (mesmo espirito de
# _SQL_ERROR_SIGNATURES em injection_heuristics.py)
_LDAP_ERROR_SIGNATURES = [
    (r"javax\.naming\.(directory|naming)exception", "Java JNDI/LDAP"),
    (r"com\.sun\.jndi\.ldap", "Java JNDI/LDAP"),
    (r"system\.directoryservices\.protocols", "ASP.NET LDAP"),
    (r"ldapexception", "genérico"),
    (r"invalid dn syntax", "genérico"),
    (r"bad search filter", "genérico"),
    (r"unbalanced parenthes", "genérico"),
    (r"ldap: error code", "genérico"),
    (r"supplied argument is not a valid ldap", "PHP ldap_*"),
    (r"python-ldap", "python-ldap"),
]


def detect_ldap_error_signature(baseline_text: str, test_text: str) -> tuple[bool, str]:
    """Mesma logica do error-based de SQLi: so conta se a assinatura
    aparece no TESTE e nao aparecia no BASELINE."""
    baseline_lower = (baseline_text or "").lower()
    test_lower = (test_text or "").lower()

    import re
    for pattern, library in _LDAP_ERROR_SIGNATURES:
        if re.search(pattern, test_lower) and not re.search(pattern, baseline_lower):
            return True, library
    return False, ""


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[Requirement("surface.param.*", min_confidence=0.5)],
    produces=[],
    cost=1,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heuristica de LDAP Injection",
    summary="Envia filtro LDAP malformado e procura assinatura de erro de biblioteca LDAP conhecida na resposta, comparado contra o baseline -- mesmo padrao do error-based de SQLi.",
)
class LDAPInjectionHeuristic:
    name = "ldap_injection_heuristic"
    _tested: set[tuple] = set()

    def run(self, target, facts_in):
        if not is_intrusive_confirmed():
            return None  # --confirm-intrusive nao foi passado -- payload real nao enviado

        params = facts_in.get("surface.param.*", [])
        findings = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]
            hash_id = _hash_from_key(f.key)
            if (target, hash_id) in self._tested:
                continue
            self._tested.add((target, hash_id))

            baseline = _send(url, method, {param: "usuarioteste"})
            test = _send(url, method, {param: _PROBE_PAYLOAD})
            if baseline is None or test is None:
                continue

            found, library = detect_ldap_error_signature(baseline.text, test.text)
            if found:
                findings.append({
                    "title": f"Candidato a LDAP Injection: parametro '{param}' em {url}",
                    "severity": "high",
                    "module": self.name,
                    "category": "ldap_injection",
                    "endpoint": url,
                    "description": (
                        f"O parametro '{param}' (via {method}) causou erro de biblioteca LDAP "
                        f"({library}) ao receber filtro malformado ('{_PROBE_PAYLOAD}') -- "
                        f"indica que o valor e concatenado direto num filtro LDAP sem escape."
                    ),
                    "business_impact": (
                        "LDAP injection pode permitir bypass de autenticacao ou extracao de "
                        "dado do diretorio (usuario, grupo, atributo) fora do escopo pretendido."
                    ),
                    "remediation": "Escapar caractere especial de filtro LDAP (RFC 4515) antes de concatenar entrada do usuario, ou usar biblioteca que faca isso automaticamente.",
                    "evidence": {"url": url, "method": method, "param": param, "library_detected": library, "payload": _PROBE_PAYLOAD},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)
