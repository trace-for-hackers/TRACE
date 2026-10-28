"""
modules/ssti_heuristic.py

Server-Side Template Injection -- manda expressao matematica em
sintaxe de VARIOS motores de template diferentes e confere se o
resultado CALCULADO aparece na resposta (nao o payload literal).

Por que produto de dois numeros de 3 digitos em vez de "{{7*7}}" fixo:
"49" e comum demais, pode aparecer na pagina por coincidencia (ano,
preco, ID). Usando dois numeros escolhidos por chamada, o produto e
praticamente unico o suficiente pra nao aparecer por acaso -- mesmo
principio do marcador unico do xss_reflection_heuristic.py, adaptado
pra expressao matematica em vez de string livre.

Motores cobertos (sintaxe mais comum de cada um):
  Jinja2/Twig/Nunjucks/Mako .... {{ a*b }}
  Freemarker ................... ${ a*b }
  Smarty ........................ { a*b }
  ERB (Ruby) .................... <%= a*b %>
  Velocity ....................... #set($x=a*b)$x
"""

from __future__ import annotations

import random

from utils.requester import get, post, is_intrusive_confirmed
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

_TEMPLATE_PAYLOADS = {
    "jinja2_twig_nunjucks": "{{{{{a}*{b}}}}}",
    "freemarker": "${{{a}*{b}}}",
    "smarty": "{{{a}*{b}}}",
    "erb": "<%= {a}*{b} %>",
    "velocity": "#set($surfacerx={a}*{b})$surfacerx",
}


def build_payloads(a: int, b: int) -> dict[str, str]:
    return {engine: template.format(a=a, b=b) for engine, template in _TEMPLATE_PAYLOADS.items()}


def is_evaluated(response_text: str, expected_product: int, baseline_text: str) -> bool:
    """True so se o PRODUTO CALCULADO aparece na resposta de teste e nao
    aparecia no baseline -- confirma que foi avaliado, nao so refletido
    como texto (nesse caso o literal "a*b" apareceria, nao o resultado)."""
    if response_text is None:
        return False
    marker = str(expected_product)
    return marker in response_text and marker not in (baseline_text or "")


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[Requirement("surface.param.*", min_confidence=0.5)],
    produces=[],
    cost=5,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heuristica de Server-Side Template Injection",
    summary="Envia produto de dois numeros em sintaxe de 5 motores de template diferentes e confirma se o resultado CALCULADO aparece na resposta -- nao so o payload literal refletido.",
)
class SSTIHeuristic:
    name = "ssti_heuristic"
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

            baseline_resp = _send(url, method, {param: "surfacerbaseline"})
            if baseline_resp is None:
                continue
            baseline_text = baseline_resp.text

            a, b = random.randint(100, 999), random.randint(100, 999)
            expected = a * b
            payloads = build_payloads(a, b)

            for engine, payload in payloads.items():
                resp = _send(url, method, {param: payload})
                if resp is None:
                    continue

                if is_evaluated(resp.text, expected, baseline_text):
                    findings.append({
                        "title": f"Candidato a SSTI ({engine}): parametro '{param}' em {url}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "server_side_template_injection",
                        "endpoint": url,
                        "description": (
                            f"O parametro '{param}' (via {method}) avaliou a expressao "
                            f"'{a}*{b}' enviada em sintaxe de {engine} -- o resultado calculado "
                            f"({expected}) apareceu na resposta, e nao aparecia no baseline."
                        ),
                        "business_impact": (
                            "SSTI confirmado geralmente permite execucao de codigo arbitrario "
                            "no servidor, dependendo do motor de template e das funcoes "
                            "acessiveis a partir da sandbox (ou ausencia de sandbox) dele."
                        ),
                        "remediation": (
                            "Nunca renderizar entrada do usuario diretamente como template -- "
                            "tratar como dado, nunca como codigo/markup de template."
                        ),
                        "evidence": {"url": url, "method": method, "param": param, "engine": engine,
                                     "payload": payload, "expected_result": expected},
                    })
                    break  # um motor confirmado ja basta pra esse parametro

        if not findings:
            return None
        return ModuleResult(findings=findings)
