"""
modules/jwt_weak_signature_detector.py

Testa o token de cada identidade registrada (--identity-header) por dois
problemas clássicos de JWT, os dois PUROS -- sem rede nenhuma pra
confirmar, só decodificação e criptografia local:

  1. alg=none -- o servidor emitiu um token sem assinatura nenhuma. Isso
     sozinho já é achado crítico, não precisa forjar nada pra confirmar:
     se o token ORIGINAL do usuário já não tem assinatura, o servidor
     não está verificando integridade de jeito nenhum.
  2. Segredo HS256 fraco -- calcula HMAC-SHA256 localmente contra uma
     wordlist curta de segredo comum e compara byte a byte com a
     assinatura real do token. Se bater, o segredo está confirmado (não
     é suposição) -- e com ele em mãos, dá pra forjar QUALQUER claim,
     inclusive admin=true.

LIMITAÇÃO HONESTA: não tenta ATIVAMENTE forjar um token e reenviar pra
confirmar que o servidor aceita (isso exigiria saber de antemão qual
endpoint testar, que varia por alvo). O que este módulo confirma é mais
forte que "suspeito" -- é "a assinatura bate com esse segredo", fato
matemático, não achado a mais checar depois -- só não prova o passo
seguinte (usar o segredo forjado pra escalar privilégio), que fica pro
usuário ou pra um módulo futuro de exploração.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from utils.requester import registered_identities, _identity_sessions


# lista curta, específica, de segredo comum de exemplo/tutorial/config
# padrão -- não é wordlist de força bruta genérica (isso seria caro e
# ruidoso), é só o "será que esqueceram de trocar o valor de exemplo".
_COMMON_WEAK_SECRETS = [
    "secret", "random", "changeme", "password", "123456", "test",
    "your-256-bit-secret", "jwt_secret", "jwtsecret", "supersecret",
    "admin", "", "secretkey", "my-secret-key",
]


def base64url_decode(segment: str) -> bytes:
    """JWT usa base64url SEM padding -- precisa completar antes de decodificar."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def parse_jwt(token: str) -> tuple[dict, dict, bytes, str, str] | None:
    """Retorna (header, payload, signature_bytes, header_b64, payload_b64)
    ou None se não parecer um JWT válido de 3 partes."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        signature = base64url_decode(parts[2]) if parts[2] else b""
    except Exception:
        return None
    return header, payload, signature, parts[0], parts[1]


def is_alg_none(header: dict) -> bool:
    return str(header.get("alg", "")).lower() == "none"


def find_weak_hs256_secret(header_b64: str, payload_b64: str, signature: bytes,
                            candidates: list[str] = _COMMON_WEAK_SECRETS) -> str | None:
    """Calcula HMAC-SHA256 localmente pra cada candidato e compara com a
    assinatura real do token, byte a byte (hmac.compare_digest -- não
    usa == direto de propósito, pra não introduzir timing side-channel
    na própria ferramenta de segurança). Retorna o segredo que bateu, ou
    None se nenhum candidato bateu (não prova que o segredo é forte, só
    que não é um dos comuns testados)."""
    if not signature:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    for secret in candidates:
        computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(computed, signature):
            return secret
    return None


def _extract_bearer_token(identity: str) -> str | None:
    session = _identity_sessions.get(identity)
    if session is None:
        return None
    auth_header = session.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):]


@discovery_module(
    requires=[Requirement("config.identity_available", min_confidence=0.5)],
    produces=[],
    cost=1,
    category="authentication",
    display_name="Detector de Assinatura JWT Fraca",
    summary="Para cada identidade com token Bearer, checa alg=none (achado direto) e testa segredo HS256 fraco por comparação criptográfica local -- sem rede, sem adivinhação, confirmação matemática.",
)
class JWTWeakSignatureDetector:
    name = "jwt_weak_signature_detector"

    def run(self, target: str):
        identities = registered_identities()
        if not identities:
            return None

        findings = []

        for identity in identities:
            token = _extract_bearer_token(identity)
            if not token:
                continue

            parsed = parse_jwt(token)
            if parsed is None:
                continue
            header, payload, signature, header_b64, payload_b64 = parsed

            if is_alg_none(header):
                findings.append({
                    "title": f"JWT sem assinatura (alg=none) na identidade '{identity}'",
                    "severity": "critical",
                    "module": self.name,
                    "category": "broken_authentication",
                    "endpoint": target,
                    "description": (
                        f"O token da identidade '{identity}' foi emitido com alg=none -- "
                        f"o servidor não está verificando integridade do token de jeito nenhum."
                    ),
                    "business_impact": "Qualquer um pode forjar um token com claim arbitrária (ex.: admin=true) sem precisar de segredo nenhum.",
                    "remediation": "Configurar a biblioteca de JWT pra rejeitar explicitamente alg=none, e sempre validar o algoritmo esperado no lado do servidor.",
                    "evidence": {"identity": identity, "header": header, "payload": payload},
                })
                continue  # já é o pior caso possível, não faz sentido testar segredo também

            if str(header.get("alg", "")).upper() == "HS256":
                secret = find_weak_hs256_secret(header_b64, payload_b64, signature)
                if secret is not None:
                    findings.append({
                        "title": f"Segredo HS256 fraco confirmado na identidade '{identity}'",
                        "severity": "critical",
                        "module": self.name,
                        "category": "broken_authentication",
                        "endpoint": target,
                        "description": (
                            f"O token da identidade '{identity}' está assinado com HS256 usando "
                            f"o segredo '{secret}' -- confirmado por comparação criptográfica local "
                            f"(HMAC-SHA256 recalculado bate byte a byte com a assinatura real)."
                        ),
                        "business_impact": (
                            "Com o segredo em mãos, qualquer claim do token pode ser forjada -- "
                            "inclusive elevar privilégio (ex.: admin=true) sem precisar de senha nenhuma."
                        ),
                        "remediation": "Trocar o segredo de assinatura por um valor aleatório de alta entropia (32+ bytes), nunca um valor de exemplo/tutorial.",
                        "evidence": {"identity": identity, "weak_secret": secret, "payload": payload},
                    })

        if not findings:
            return None
        return ModuleResult(findings=findings)
