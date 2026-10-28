"""
modules/password_reset_token_predictability.py

Mesma tecnica de entropia/padrao sequencial de
predictable_token_analyzer.py (que analisa cookie de sessao/CSRF),
aplicada especificamente a TOKEN DE RESET DE SENHA -- categoria
separada porque a forma de COLETAR a amostra e diferente (chamar um
endpoint de "esqueci minha senha" repetidamente, não observar cookie
espontaneo).

Descoberta via spec OpenAPI: acha endpoint POST cujo path/operationId
sugira reset/esqueci senha, com campo de email/username no corpo.

LIMITACAO HONESTA: só funciona quando o endpoint devolve o token
DIRETAMENTE na resposta (comum em ambiente de dev/teste, mas MA
PRATICA em produção -- token de reset deveria ir só por email). Em
produção bem feita, este módulo simplesmente não encontra o que
analisar e não roda -- o que é o comportamento correto quando a prática seria
segura por padrão (não expor o token de outro jeito que não seja o
canal privado).
"""

from __future__ import annotations

from utils.requester import post
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.mass_assignment_prober import _extract_field_value
from modules.predictable_token_analyzer import (
    calculate_shannon_entropy, detect_sequential_pattern, _LOW_ENTROPY_THRESHOLD_BITS_PER_CHAR,
)

_RESET_KEYWORDS = ("reset", "forgot", "recover", "esqueci")
_TOKEN_FIELD_NAMES = ("reset_token", "token", "code", "reset_code")
_SAMPLE_COUNT = 5


def find_password_reset_endpoint(spec: dict) -> dict | None:
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        post_op = ops.get("post")
        if not post_op:
            continue
        operation_id = str(post_op.get("operationId", "")).lower()
        if not any(kw in path.lower() or kw in operation_id for kw in _RESET_KEYWORDS):
            continue
        schema = post_op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
        props = {p.lower() for p in schema.get("properties", {})}
        if "email" in props or "username" in props:
            return {"path": path, "request_schema": schema, "identifier_field": "email" if "email" in props else "username"}
    return None


def extract_token_from_response(response_json) -> str | None:
    for field_name in _TOKEN_FIELD_NAMES:
        value = _extract_field_value(response_json, field_name)
        if value:
            return str(value)
    return None


@discovery_module(
    requires=[Requirement("config.openapi_spec_available", min_confidence=0.5)],
    produces=[],
    cost=_SAMPLE_COUNT,
    category="authentication_generic",
    display_name="Previsibilidade de Token de Reset de Senha",
    summary="Chama o endpoint de reset de senha várias vezes e analisa entropia/padrão sequencial do token retornado -- só funciona quando o token vem na resposta (não deveria, em produção bem feita).",
)
class PasswordResetTokenPredictability:
    name = "password_reset_token_predictability"

    def run(self, target: str):
        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[password_reset_token_predictability] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[password_reset_token_predictability] não consegui carregar o spec: {e}")
            return None

        reset_ep = find_password_reset_endpoint(spec)
        if not reset_ep:
            return None

        url = target.rstrip("/") + reset_ep["path"]
        identifier_field = reset_ep["identifier_field"]

        samples = []
        for _ in range(_SAMPLE_COUNT):
            body = {identifier_field: f"surfacer_reset_test@example.com" if identifier_field == "email" else "surfacer_reset_test"}
            resp = post(url, data=body)
            if resp is None:
                continue
            try:
                response_json = resp.json()
            except ValueError:
                continue
            token = extract_token_from_response(response_json)
            if token:
                samples.append(token)

        if len(samples) < 3:
            return None  # token não vem na resposta (bom sinal!) ou poucas amostras coletadas

        findings = []

        sequential = detect_sequential_pattern(samples)
        if sequential:
            findings.append({
                "title": "Token de reset de senha com padrão SEQUENCIAL detectado",
                "severity": "critical",
                "module": self.name,
                "category": "predictable_token",
                "endpoint": url,
                "description": (
                    f"As {len(samples)} amostras de token de reset coletadas sobem por um passo "
                    f"constante ({sequential['step']}) -- token de reset de OUTRA conta é "
                    f"trivialmente adivinhável a partir de um token próprio."
                ),
                "business_impact": "Qualquer conta pode ter a senha resetada por um atacante, sem precisar de acesso ao email da vítima -- basta adivinhar o próximo token sequencial.",
                "remediation": "Gerar token de reset com biblioteca de aleatoriedade criptográfica, nunca com contador.",
                "evidence": {"samples": samples, "detected_step": sequential["step"]},
            })
        else:
            avg_entropy = sum(calculate_shannon_entropy(s) for s in samples) / len(samples)
            if avg_entropy < _LOW_ENTROPY_THRESHOLD_BITS_PER_CHAR:
                findings.append({
                    "title": "Token de reset de senha com entropia baixa",
                    "severity": "high",
                    "module": self.name,
                    "category": "predictable_token",
                    "endpoint": url,
                    "description": (
                        f"As amostras de token de reset coletadas têm entropia média de "
                        f"{avg_entropy:.2f} bits/caractere -- abaixo do esperado pra gerador "
                        f"aleatório de verdade."
                    ),
                    "business_impact": "Espaço de busca menor que o esperado facilita força bruta do token de reset de outra conta.",
                    "remediation": "Gerar token de reset com biblioteca de aleatoriedade criptográfica, com 128+ bits de entropia total.",
                    "evidence": {"samples": samples, "average_entropy_bits_per_char": round(avg_entropy, 2)},
                })

        # NOTA: se o token nem aparece na resposta, isso é o comportamento
        # CORRETO (token deveria ir só por email) -- não vira achado, e o
        # `len(samples) < 3` acima já retorna None nesse caso.

        if not findings:
            return None
        return ModuleResult(findings=findings)
