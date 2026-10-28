"""
modules/webhook_ssrf_correlator.py

Especifico pra API que aceita URL de webhook/callback configuravel
pelo usuario (padrao comum: "me avisa nesse endpoint quando o pedido
mudar de status"). Muita implementacao faz um PING sincrono na URL
registrada pra confirmar que ela e alcancavel ANTES de salvar -- e
exatamente esse ping que confirma SSRF aqui, via o mesmo coletor
out-of-band de callback_ssrf_heuristic.py.

Descoberta via spec OpenAPI (mesmo padrao de mass_assignment_prober.py
e write_idor_correlator.py): acha endpoint POST/PUT/PATCH cujo schema
tenha propriedade com nome sugerindo campo de webhook.
"""

from __future__ import annotations

import time
import uuid

from utils.requester import post_as, request_as, registered_identities
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.api_resource_provisioner import build_request_body
from modules.callback_ssrf_heuristic import _CallbackCollector, configure_callback_host as _configure_callback_host

_WEBHOOK_FIELD_KEYWORDS = ("webhook_url", "callback_url", "notification_url", "webhook", "callback", "notify_url", "hook_url")
_WEBHOOK_WAIT_SECONDS = 3.0

_callback_host: str | None = None
_callback_port: int = 0


def configure_callback_host(host: str, port: int = 0) -> None:
    global _callback_host, _callback_port
    _callback_host = host
    _callback_port = port
    _configure_callback_host(host, port)


def find_webhook_fields(schema: dict) -> list[str]:
    return [p for p in schema.get("properties", {}) if any(kw in p.lower() for kw in _WEBHOOK_FIELD_KEYWORDS)]


def find_webhook_endpoints(spec: dict) -> list[dict]:
    results = []
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        for method in ("post", "put", "patch"):
            op = ops.get(method)
            if not op:
                continue
            schema = (
                op.get("requestBody", {}).get("content", {})
                .get("application/json", {}).get("schema", {})
            )
            webhook_fields = find_webhook_fields(schema)
            if webhook_fields:
                results.append({"path": path, "method": method.upper(),
                                 "webhook_fields": webhook_fields, "request_schema": schema})
    return results


@discovery_module(
    requires=[
        Requirement("config.identity_available", min_confidence=0.5),
        Requirement("config.openapi_spec_available", min_confidence=0.5),
        Requirement("config.callback_host_available", min_confidence=0.5),
    ],
    produces=[],
    cost=5,
    category="ssrf_generic",
    display_name="Correlator de SSRF via Webhook",
    summary="Acha endpoint com campo de webhook/callback configurável (via spec OpenAPI), registra com URL do coletor, e confirma SSRF se a aplicação fizer ping real na hora do cadastro.",
)
class WebhookSSRFCorrelator:
    name = "webhook_ssrf_correlator"
    _collector: _CallbackCollector | None = None

    @classmethod
    def _get_collector(cls):
        if _callback_host is None:
            return None
        if cls._collector is None:
            cls._collector = _CallbackCollector(_callback_host, _callback_port)
        return cls._collector

    def run(self, target: str):
        collector = self._get_collector()
        if collector is None:
            print("[webhook_ssrf_correlator] nenhum --callback-host configurado -- módulo não roda.")
            return None

        identities = registered_identities()
        if not identities:
            print("[webhook_ssrf_correlator] nenhuma identidade registrada -- nada a fazer.")
            return None

        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[webhook_ssrf_correlator] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[webhook_ssrf_correlator] não consegui carregar o spec: {e}")
            return None

        webhook_endpoints = find_webhook_endpoints(spec)
        if not webhook_endpoints:
            return None

        identity = identities[0]
        findings = []

        for ep in webhook_endpoints:
            for webhook_field in ep["webhook_fields"]:
                token = uuid.uuid4().hex[:16]
                callback_url = f"http://{_callback_host}:{collector.port}/{token}"

                body = build_request_body(ep["request_schema"], webhook_field, callback_url)
                body[webhook_field] = callback_url  # garante que é exatamente essa URL, não um dummy

                url = target.rstrip("/") + ep["path"]
                if ep["method"] == "POST":
                    resp = post_as(identity, url, json_body=body)
                else:
                    resp = request_as(identity, ep["method"], url, json_body=body)

                if resp is None:
                    continue

                time.sleep(_WEBHOOK_WAIT_SECONDS)

                if collector.was_hit(token):
                    findings.append({
                        "title": f"SSRF via webhook confirmado: campo '{webhook_field}' em {ep['method']} {ep['path']}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "ssrf",
                        "endpoint": url,
                        "description": (
                            f"O campo '{webhook_field}' em {ep['method']} {ep['path']} aceitou "
                            f"a URL do coletor e a aplicação fez uma requisição real de volta -- "
                            f"provavelmente um ping de verificação síncrono no momento do cadastro."
                        ),
                        "business_impact": (
                            "Campo de webhook é um vetor de SSRF particularmente perigoso: o "
                            "atacante não precisa nem esperar o evento real disparar, o simples "
                            "cadastro já confirma alcance a recurso interno."
                        ),
                        "remediation": "Validar destino do webhook contra allowlist antes do ping de verificação, bloquear faixa de IP interno/link-local no nível de rede também.",
                        "evidence": {"endpoint": ep["path"], "method": ep["method"],
                                     "webhook_field": webhook_field, "callback_token": token},
                    })

        if not findings:
            return None
        return ModuleResult(findings=findings)
