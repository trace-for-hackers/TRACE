"""
modules/predictable_token_analyzer.py

Coleta VARIAS amostras do token de sessao que o alvo emite (uma
requisicao anonima por amostra, olhando o cookie de sessao que volta) e
analisa o CONJUNTO por dois problemas classicos:

  1. Entropia baixa -- token "aleatorio" de verdade tem alta entropia
     (perto do maximo teorico do alfabeto usado). Entropia baixa sugere
     gerador fraco (ex.: baseado em timestamp, contador, hash de dado
     previsivel).
  2. Padrao sequencial -- se o valor NUMERICO (ou hexadecimal) do token
     sobe por um passo constante entre amostras, e virtualmente certeza
     de que e um contador, nao um gerador aleatorio -- sinal muito mais
     forte que so entropia baixa isolada.

So roda contra token que o PROPRIO alvo emite pra visitante anonimo
(nunca pede credencial nem testa login) -- e por isso, sozinho, nao
prova em que fluxo esse token e usado (sessao? CSRF? reset de senha?) --
o achado documenta o valor observado, mas confirmar ONDE esse token
concede acesso e passo manual.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_SESSION_COOKIE_NAME_HINTS = ("session", "sess", "token", "sid", "csrf", "auth")
_SAMPLE_COUNT = 6
_LOW_ENTROPY_THRESHOLD_BITS_PER_CHAR = 3.0


def calculate_shannon_entropy(s: str) -> float:
    """Bits de entropia POR CARACTERE -- nao da string inteira. Permite
    comparar token de tamanho diferente de forma justa. Alfabeto
    hexadecimal aleatorio de verdade fica perto de 4.0; base64 aleatorio
    de verdade fica perto de 6.0. Valor bem abaixo disso sugere alfabeto
    pequeno demais OU caractere repetido/previsivel."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_low_entropy(token: str, threshold: float = _LOW_ENTROPY_THRESHOLD_BITS_PER_CHAR) -> bool:
    return calculate_shannon_entropy(token) < threshold


def _extract_numeric_value(token: str) -> int | None:
    """Tenta interpretar o token inteiro como hexadecimal ou decimal --
    usado pra checar padrao sequencial. Retorna None se o token nao for
    puramente numerico/hex (a maioria dos tokens de verdade nao e, o que
    ja e um bom sinal -- padrao sequencial so faz sentido pra esse
    subconjunto de formato)."""
    cleaned = token.strip()
    if re.fullmatch(r"[0-9]+", cleaned):
        return int(cleaned)
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) >= 6:
        return int(cleaned, 16)
    return None


def detect_sequential_pattern(tokens: list[str]) -> dict | None:
    """Retorna {"step": N} se as amostras, na ORDEM EM QUE FORAM
    COLETADAS, sobem por um passo constante -- None se nao der pra
    interpretar como numero, ou se o passo nao for constante."""
    values = [_extract_numeric_value(t) for t in tokens]
    if any(v is None for v in values) or len(values) < 3:
        return None

    steps = [values[i + 1] - values[i] for i in range(len(values) - 1)]
    if len(set(steps)) == 1 and steps[0] != 0:
        return {"step": steps[0]}
    return None


def find_session_like_cookie(cookies: dict) -> str | None:
    """Acha o nome de cookie mais provavel de ser token de sessao/CSRF,
    por substring no NOME (nao no valor) -- lista curta de propósito."""
    for name in cookies:
        lower = name.lower()
        if any(hint in lower for hint in _SESSION_COOKIE_NAME_HINTS):
            return name
    return None


@discovery_module(
    requires=(),
    produces=[],
    cost=_SAMPLE_COUNT,
    category="cryptographic_failures",
    display_name="Analisador de Previsibilidade de Token",
    summary="Coleta varias amostras do cookie de sessao/CSRF emitido pra visitante anonimo e analisa entropia e padrao sequencial -- nao testa login, so observa o que o alvo emite espontaneamente.",
)
class PredictableTokenAnalyzer:
    name = "predictable_token_analyzer"

    def run(self, target: str):
        samples = []

        for _ in range(_SAMPLE_COUNT):
            r = get(target)
            if r is None:
                continue
            cookie_name = find_session_like_cookie(r.cookies.get_dict() if hasattr(r, "cookies") else {})
            if cookie_name:
                samples.append(r.cookies.get_dict()[cookie_name])

        if len(samples) < 3:
            return None  # alvo nao emite cookie de sessao/CSRF pra anonimo, ou poucas amostras coletadas

        findings = []

        sequential = detect_sequential_pattern(samples)
        if sequential:
            findings.append({
                "title": "Token de sessao com padrao SEQUENCIAL detectado",
                "severity": "critical",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": target,
                "description": (
                    f"As {len(samples)} amostras coletadas do token sobem por um passo "
                    f"constante ({sequential['step']}) -- isso e virtualmente certeza de "
                    f"contador, nao gerador aleatorio. Um token de outro usuario e "
                    f"trivialmente adivinhavel a partir do proprio."
                ),
                "business_impact": "Sessao de outro usuario pode ser sequestrada so incrementando/decrementando o proprio token -- nao precisa quebrar criptografia nenhuma.",
                "remediation": "Gerar token com biblioteca de aleatoriedade criptografica (ex.: secrets.token_urlsafe em Python), nunca com contador ou timestamp.",
                "evidence": {"samples": samples, "detected_step": sequential["step"]},
            })

        media_entropia = sum(calculate_shannon_entropy(s) for s in samples) / len(samples)
        if not sequential and media_entropia < _LOW_ENTROPY_THRESHOLD_BITS_PER_CHAR:
            findings.append({
                "title": "Token de sessao com entropia baixa",
                "severity": "high",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": target,
                "description": (
                    f"As amostras coletadas tem entropia media de {media_entropia:.2f} bits/caractere -- "
                    f"abaixo do esperado pra gerador aleatorio de verdade, sugerindo alfabeto pequeno "
                    f"ou valor parcialmente previsivel."
                ),
                "business_impact": "Espaço de busca menor que o esperado facilita ataque de forca bruta contra token de outro usuario.",
                "remediation": "Gerar token com biblioteca de aleatoriedade criptografica, com tamanho e alfabeto adequados (128+ bits de entropia total).",
                "evidence": {"samples": samples, "average_entropy_bits_per_char": round(media_entropia, 2)},
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)
