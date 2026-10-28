"""
modules/unauthenticated_access_correlator.py

Categoria diferente de IDOR: em vez de "identidade B acessando recurso
de A", testa "NINGUÉM autenticado acessando recurso que deveria exigir
sessão". Achado real que motivou este módulo: GET /users/v1/_debug no
VAmPI devolve dado sensível de todo usuário sem checar Authorization
nenhum -- "Excessive Data Exposure", item documentado oficialmente na
lista de vulnerabilidades do VAmPI.

Reaproveita os mesmos fatos surface.resource.*.owned_by.* que
auth_crawler.py e api_resource_provisioner.py já produzem -- nenhuma
descoberta nova precisa ser escrita. A diferença é o "atacante": em vez
de outra identidade registrada, é uma sessão SEM credencial nenhuma.

Mesma técnica de comparação semântica do idor_correlator.py (baseline
de "negado" com ID fabricado, não confiar só em status code) -- por
isso importa as mesmas funções em vez de duplicar a lógica.
"""

from __future__ import annotations

import requests

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.idor_correlator import (
    _group_by_resource, _fabricate_bogus_id, _build_url,
    _response_signature, _significantly_different,
)

_anonymous_session = requests.Session()
_anonymous_session.headers.update({"User-Agent": "surfacer/0.1", "Accept": "*/*"})


def _get_anonymous(url: str):
    """Sessão sem NENHUM cookie/header de identidade -- é isso que
    simula um atacante que nunca fez login."""
    try:
        return _anonymous_session.request("GET", url, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[unauthenticated_access_correlator] erro em GET {url} (anônimo): {type(e).__name__}: {e}")
        return None


@discovery_module(
    requires=[Requirement("surface.resource.*", min_confidence=0.1)],
    produces=[],
    cost=0,
    max_reentries=25,
    category="access_control",
    display_name="Correlação de Acesso Não Autenticado",
    summary="Testa se um recurso que exige identidade também responde a requisição sem NENHUMA credencial -- categoria diferente de IDOR (falta de autenticação, não autorização entre duas identidades).",
)
class UnauthenticatedAccessCorrelator:
    name = "unauthenticated_access_correlator"

    # de classe de propósito -- mesmo motivo de sempre (instância nova a
    # cada reentrância, ver idor_correlator.py)
    _reported: set[tuple] = set()
    _baseline_cache: dict[tuple, dict] = {}

    def _get_anonymous_baseline(self, url_template: str, id_location: str, sample_id: str):
        cache_key = (url_template, id_location)
        if cache_key not in self._baseline_cache:
            bogus_url = _build_url(url_template, id_location, _fabricate_bogus_id(sample_id))
            self._baseline_cache[cache_key] = _response_signature(_get_anonymous(bogus_url))
        return self._baseline_cache[cache_key]

    def run(self, target, facts_in):
        resource_facts = facts_in.get("surface.resource.*", [])
        if not resource_facts:
            return None

        grouped = _group_by_resource(resource_facts)
        findings = []

        for (url_template, resource_id), owners in grouped.items():
            owner_identities = {o["identity"] for o in owners}
            concrete_url = owners[0]["concrete_url"]
            id_location = owners[0]["id_location"]

            dedup_key = (target, url_template, resource_id)
            if dedup_key in self._reported:
                continue
            self._reported.add(dedup_key)

            baseline_sig = self._get_anonymous_baseline(url_template, id_location, resource_id)
            test_sig = _response_signature(_get_anonymous(concrete_url))

            if not _significantly_different(test_sig, baseline_sig):
                continue

            findings.append({
                "title": "Candidato a exposição sem autenticação: recurso acessível sem nenhuma credencial",
                "severity": "high",
                "module": self.name,
                "category": "broken_authentication",
                "endpoint": concrete_url,
                "description": (
                    f"O recurso de ID '{resource_id}' (via {id_location}), que pertence a "
                    f"{sorted(owner_identities)} e deveria exigir sessão autenticada, respondeu "
                    f"a uma requisição SEM NENHUMA credencial (status={test_sig['status']}) "
                    f"de forma diferente do baseline de 'negado sem autenticação' "
                    f"(status={baseline_sig['status']}) nesse mesmo endpoint."
                ),
                "business_impact": (
                    "Dado potencialmente sensível acessível por qualquer pessoa na internet, "
                    "sem precisar de credencial nenhuma -- Excessive Data Exposure / falta de "
                    "checagem de autenticação."
                ),
                "remediation": (
                    "Validar manualmente antes de reportar como confirmado. Se confirmado, "
                    "adicionar checagem de autenticação obrigatória neste endpoint."
                ),
                "evidence": {
                    "url_template": url_template, "resource_id": resource_id,
                    "id_location": id_location, "owner_identities": sorted(owner_identities),
                    "baseline_denied_signature": {"status": baseline_sig["status"], "length": baseline_sig["length"]},
                    "test_signature": {"status": test_sig["status"], "length": test_sig["length"]},
                },
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)
