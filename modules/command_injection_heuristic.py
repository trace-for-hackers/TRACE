"""
modules/command_injection_heuristic.py

Injecao de comando de SO via atraso temporal -- mesmo principio do
modulo time-based de SQLi que voce ja adicionou: manda um comando que
demora um tempo CONHECIDO pra rodar (sleep), mede se a resposta demorou
proporcionalmente mais que o baseline. Nao depende de conteudo nenhum
na resposta (diferente de erro-based), so do RELOGIO -- por isso
funciona mesmo quando a saida do comando nunca aparece na pagina
(injecao "cega").

Testa varias sintaxes de encadeamento de comando (o separador certo
depende do shell e de como a aplicacao concatena o input):
  ; sleep 5       -- encadeamento sequencial (sh/bash)
  | sleep 5       -- pipe (sempre executa, mesmo se o comando anterior falhar)
  && sleep 5      -- só executa se o comando anterior teve sucesso
  || sleep 5      -- só executa se o comando anterior FALHOU
  ` sleep 5 `     -- substituicao de comando (backtick, shell antigo)
  $(sleep 5)      -- substituicao de comando (sintaxe moderna)

MARGEM DE SEGURANCA: usa sleep curto (5s) e um LIMIAR de confirmacao
(4s) com folga generosa pra latencia de rede normal -- long_conversation
com timeout de 10s no requester ja limita o dano de qualquer request
que trave de verdade.
"""

from __future__ import annotations

import time

from utils.requester import get, post, is_intrusive_confirmed
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

_SLEEP_SECONDS = 5
_CONFIRMATION_THRESHOLD_SECONDS = 4.0  # folga de 1s pra jitter de rede

_PAYLOAD_TEMPLATES = {
    "sequential_semicolon": "; sleep {n}",
    "pipe": "| sleep {n}",
    "and_chain": "&& sleep {n}",
    "or_chain": "|| sleep {n}",
    "backtick_substitution": "`sleep {n}`",
    "dollar_substitution": "$(sleep {n})",
}


def build_payloads(sleep_seconds: int = _SLEEP_SECONDS) -> dict[str, str]:
    return {name: template.format(n=sleep_seconds) for name, template in _PAYLOAD_TEMPLATES.items()}


def indicates_command_injection(baseline_elapsed: float, test_elapsed: float,
                                 sleep_seconds: int = _SLEEP_SECONDS,
                                 threshold: float = _CONFIRMATION_THRESHOLD_SECONDS) -> bool:
    """Confirma só se o atraso adicional (teste menos baseline) for pelo
    menos o LIMIAR -- nao o tempo de sleep inteiro, pra tolerar jitter,
    mas perto o suficiente do valor esperado pra nao confundir com
    lentidao aleatoria do servidor."""
    extra_delay = test_elapsed - baseline_elapsed
    return extra_delay >= threshold


def _send_timed(url: str, method: str, params: dict) -> float | None:
    """Retorna o tempo decorrido em segundos, ou None se a requisicao
    falhou de verdade (nesse caso nao da pra afirmar nada sobre atraso)."""
    start = time.monotonic()
    if method.upper() == "GET":
        resp = get(url, params=params)
    else:
        resp = post(url, data=params)
    elapsed = time.monotonic() - start
    return elapsed if resp is not None else None


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[Requirement("surface.param.*", min_confidence=0.5)],
    produces=[],
    cost=7,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heuristica de Command Injection (Time-Based)",
    summary="Mede atraso de resposta com payload de sleep em 6 sintaxes de encadeamento de comando diferentes -- funciona mesmo em injecao cega, sem depender de conteudo na resposta.",
)
class CommandInjectionHeuristic:
    name = "command_injection_heuristic"
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

            baseline_elapsed = _send_timed(url, method, {param: "surfacerbaseline"})
            if baseline_elapsed is None:
                continue

            payloads = build_payloads()
            for technique, payload in payloads.items():
                test_elapsed = _send_timed(url, method, {param: payload})
                if test_elapsed is None:
                    continue

                if indicates_command_injection(baseline_elapsed, test_elapsed):
                    findings.append({
                        "title": f"Candidato a Command Injection ({technique}): parametro '{param}' em {url}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "command_injection",
                        "endpoint": url,
                        "description": (
                            f"O parametro '{param}' (via {method}), com payload de encadeamento "
                            f"'{technique}' ('{payload}'), causou atraso de {test_elapsed:.1f}s "
                            f"contra baseline de {baseline_elapsed:.1f}s -- consistente com "
                            f"execucao real do comando 'sleep {_SLEEP_SECONDS}' no servidor."
                        ),
                        "business_impact": (
                            "Execucao arbitraria de comando no servidor -- geralmente o achado "
                            "de maior severidade possivel, permite comprometimento total do host."
                        ),
                        "remediation": (
                            "Nunca passar entrada do usuario pra shell (os.system, subprocess "
                            "com shell=True, exec/popen de linguagem nenhuma). Usar API "
                            "especifica da linguagem em vez de montar comando de shell."
                        ),
                        "evidence": {
                            "url": url, "method": method, "param": param, "technique": technique,
                            "payload": payload, "baseline_seconds": round(baseline_elapsed, 2),
                            "test_seconds": round(test_elapsed, 2),
                        },
                    })
                    break  # uma tecnica confirmada ja basta pra esse parametro

        if not findings:
            return None
        return ModuleResult(findings=findings)
