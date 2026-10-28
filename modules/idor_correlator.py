"""
modules/idor_correlator.py

Para cada recurso identificado (com ID) como pertencente a uma identidade
(via auth_crawler.py), testa se OUTRA identidade recebe uma resposta
diferente do PRÓPRIO baseline de "negado" dela ao tentar acessar o mesmo
recurso concreto.

Por que comparar contra o baseline da própria identidade, e não contra
status 200/403 genérico: um app mal construído pode devolver 200 OK com
uma página de "Acesso Negado" pro caso negado -- comparar só status code
diria "sucesso" errado. O baseline é construído testando um ID
FABRICADO (claramente inexistente) com a MESMA identidade, no MESMO
endpoint -- isso captura a "assinatura de negado" real daquele endpoint
específico, seja ela 403, 200 com corpo de erro, redirect, o que for.
Só then compara a resposta ao recurso REAL de outra pessoa contra essa
assinatura -- diferença significativa é o sinal de IDOR.
"""

from __future__ import annotations

from utils.requester import get_as, registered_identities
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult


def _group_by_resource(resource_facts: list) -> dict:
    """Agrupa por (url_template, resource_id), IGNORANDO identidade -- é
    assim que descobrimos quem é "dono" de cada recurso concreto (uma ou
    mais identidades podem ter tocado o mesmo recurso organicamente)."""
    grouped: dict[tuple, list] = {}
    for f in resource_facts:
        v = f.value
        key = (v["url_template"], v["resource_id"])
        grouped.setdefault(key, []).append(v)
    return grouped


def _fabricate_bogus_id(sample_id: str) -> str:
    """Gera um ID claramente inexistente, no mesmo formato do original --
    inteiro vira inteiro absurdo, UUID vira UUID nulo, qualquer outra
    coisa vira string opaca óbvia."""
    if sample_id.isdigit():
        return str(int(sample_id) + 987_654_321)
    if len(sample_id) == 36 and sample_id.count("-") == 4:
        return "00000000-0000-0000-0000-000000000000"
    return "zzz_bogus_id_zzz"


def _build_url(url_template: str, id_location: str, resource_id: str) -> str:
    if id_location == "path":
        return url_template.replace("{id}", resource_id)
    if id_location.startswith("query:"):
        param = id_location.split(":", 1)[1]
        sep = "&" if "?" in url_template else "?"
        return f"{url_template}{sep}{param}={resource_id}"
    return url_template


def _response_signature(resp) -> dict | None:
    if resp is None:
        return None
    return {"status": resp.status_code, "length": len(resp.text), "text": resp.text}


def _word_overlap(text_a: str, text_b: str) -> float:
    """Similaridade de Jaccard por PALAVRA (não por caractere). BUG REAL
    encontrado testando ponta a ponta (29/08/2026): comparar por tamanho
    de resposta falha quando a mensagem de "negado" e o dado vazado têm
    tamanho parecido por coincidência -- no teste real, "Acesso Negado -
    fatura nao encontrada" (37 chars) e "Invoice #100: Total R$500,00 for
    Alice" (38 chars) são quase do mesmo tamanho apesar de conteúdo
    completamente diferente, e o IDOR real passou batido. Comparação por
    caractere (difflib.SequenceMatcher) também não separava bem o
    suficiente em texto curto (0.24 vs 0.46 -- gap real, mas apertado
    demais pra confiar). Jaccard por palavra separa muito mais claro no
    mesmo caso real (0.0 vs 0.42), porque duas mensagens de erro do MESMO
    endpoint tendem a compartilhar vocabulário ("negado", "acesso"),
    enquanto dado vazado de verdade não compartilha nada com a mensagem
    de erro."""
    words_a = set(text_a.lower().split())
    words_b = set(text_b.lower().split())
    if not words_a and not words_b:
        return 1.0
    if not words_a or not words_b:
        return 0.0
    return len(words_a & words_b) / len(words_a | words_b)


def _significantly_different(sig_test: dict | None, sig_baseline: dict | None, similarity_threshold: float = 0.2) -> bool:
    if sig_test is None or sig_baseline is None:
        return False  # request falhou de verdade -- não vira sinal, só ausência de dado
    if sig_test["status"] != sig_baseline["status"]:
        return True
    overlap = _word_overlap(sig_test["text"], sig_baseline["text"])
    return overlap < similarity_threshold


@discovery_module(
    requires=[Requirement("surface.resource.*", min_confidence=0.1)],
    produces=[],
    cost=0,
    max_reentries=25,
    category="access_control",
    display_name="Correlação de IDOR",
    summary="Testa cruzado: identidade B acessando recurso descoberto como pertencente à identidade A, comparado contra o baseline de 'negado' da própria B.",
)
class IdorCorrelator:
    name = "idor_correlator"

    # de classe de propósito -- mesma razão de sempre (instância nova a
    # cada reentrância). _baseline_cache evita re-testar o mesmo endpoint
    # com ID fabricado toda vez -- o "shape de negado" de um endpoint não
    # muda entre recursos diferentes do mesmo template.
    _reported: set[tuple] = set()
    _baseline_cache: dict[tuple, tuple] = {}

    def _get_baseline(self, identity: str, url_template: str, id_location: str, sample_id: str):
        cache_key = (identity, url_template, id_location)
        if cache_key not in self._baseline_cache:
            bogus_url = _build_url(url_template, id_location, _fabricate_bogus_id(sample_id))
            self._baseline_cache[cache_key] = _response_signature(get_as(identity, bogus_url))
        return self._baseline_cache[cache_key]

    def run(self, target, facts_in):
        resource_facts = facts_in.get("surface.resource.*", [])
        if not resource_facts:
            return None

        grouped = _group_by_resource(resource_facts)
        identities = registered_identities()
        findings = []

        for (url_template, resource_id), owners in grouped.items():
            owner_identities = {o["identity"] for o in owners}
            concrete_url = owners[0]["concrete_url"]
            id_location = owners[0]["id_location"]

            for other in identities:
                if other in owner_identities:
                    continue

                dedup_key = (target, url_template, resource_id, other)
                if dedup_key in self._reported:
                    continue
                self._reported.add(dedup_key)

                baseline_sig = self._get_baseline(other, url_template, id_location, resource_id)
                test_sig = _response_signature(get_as(other, concrete_url))

                if not _significantly_different(test_sig, baseline_sig):
                    continue

                findings.append({
                    "title": f"Candidato a IDOR: '{other}' obteve resposta diferente do próprio baseline de negado",
                    "severity": "high",
                    "module": self.name,
                    "category": "broken_access_control",
                    "endpoint": concrete_url,
                    "description": (
                        f"O recurso de ID '{resource_id}' (via {id_location}) foi observado "
                        f"pertencendo a {sorted(owner_identities)} durante navegação normal. "
                        f"A identidade '{other}' recebeu uma resposta (status={test_sig['status']}, "
                        f"tamanho={test_sig['length']}) com pouquíssima sobreposição de vocabulário "
                        f"em relação ao próprio baseline de acesso negado dela nesse mesmo endpoint "
                        f"(status={baseline_sig['status']}, tamanho={baseline_sig['length']})."
                    ),
                    "business_impact": (
                        "Possível acesso não autorizado a dado pertencente a outro usuário "
                        "(Insecure Direct Object Reference / Broken Access Control)."
                    ),
                    "remediation": (
                        "Validar manualmente antes de reportar como confirmado. Se confirmado, "
                        "implementar checagem de posse/autorização no backend para este endpoint, "
                        "não confiar no ID vindo do cliente."
                    ),
                    "evidence": {
                        "url_template": url_template, "resource_id": resource_id,
                        "id_location": id_location, "owner_identities": sorted(owner_identities),
                        "tested_identity": other,
                        "baseline_denied_signature": {"status": baseline_sig["status"], "length": baseline_sig["length"]},
                        "test_signature": {"status": test_sig["status"], "length": test_sig["length"]},
                        "word_overlap_with_own_denied_baseline": round(_word_overlap(test_sig["text"], baseline_sig["text"]), 2),
                    },
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)
