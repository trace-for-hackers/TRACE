"""
modules/verbose_error_scanner.py

Provoca um erro (caminho inexistente, garantidamente 404 na maioria dos
apps) e procura assinatura de pagina de erro DE DESENVOLVIMENTO --
stack trace, caminho de sistema de arquivo, nome de framework em modo
debug -- que nao deveria aparecer pra visitante comum em producao.

Compara contra o BASELINE (a home normal) pra nao confundir com pagina
que por acaso menciona um termo tecnico -- mesmo padrao de
ldap_injection_heuristic.py e do error-based de SQLi.

LIMITACAO HONESTA, encontrada testando contra Flask real em modo debug:
um caminho aleatorio simplesmente inexistente gera 404 LIMPO na maioria
dos framework bem comportados (Flask, Django) -- NAO dispara o
traceback verboso, porque nao houve excecao nenhuma, so rota nao
encontrada. O traceback so aparece quando uma rota EXISTENTE lanca
excecao de verdade. Por isso, alem do path aleatorio, tambem manda um
segundo probe com caractere de encoding conhecido por quebrar
roteamento mal implementado (null byte, path traversal cru) -- aumenta
a chance de achar uma rota real que trate mal esse tipo de entrada, mas
NAO substitui testar excecao de aplicacao especifica (isso exigiria
mandar valor malformado pra PARAMETRO descoberto, nao pra path -- ver
injection_heuristics.py pra esse padrao aplicado a SQLi/XSS/SSTI).
"""

from __future__ import annotations

import re
import uuid

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_VERBOSE_ERROR_SIGNATURES = [
    (r"traceback \(most recent call last\)", "Python traceback"),
    (r"werkzeug", "Flask/Werkzeug debugger"),
    (r"django version", "Django debug page"),
    (r"fatal error:.{0,80}on line \d+", "PHP fatal error"),
    (r"warning:.{0,80}on line \d+", "PHP warning"),
    (r"server error in '/' application", "ASP.NET Yellow Screen of Death"),
    (r"at system\.[a-z]", ".NET stack trace"),
    (r"exception in thread", "Java exception"),
    (r"stack trace:", "genérico"),
    (r"/var/www/[a-z0-9_./-]+", "caminho de servidor Unix"),
    (r"/home/[a-z_][a-z0-9_-]*/", "caminho de servidor Unix"),
    (r"c:\\\\(users|inetpub|windows)", "caminho de servidor Windows"),
]


def detect_verbose_error(baseline_text: str, test_text: str) -> tuple[bool, str]:
    """Mesma logica dos outros heuristicos de assinatura: so conta se
    aparece no TESTE e nao aparecia no BASELINE."""
    baseline_lower = (baseline_text or "").lower()
    test_lower = (test_text or "").lower()

    for pattern, kind in _VERBOSE_ERROR_SIGNATURES:
        if re.search(pattern, test_lower) and not re.search(pattern, baseline_lower):
            return True, kind
    return False, ""


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="misconfiguration_general",
    display_name="Scanner de Erro Verboso",
    summary="Provoca 404 num caminho inexistente e procura assinatura de pagina de erro de desenvolvimento (stack trace, caminho de servidor, framework em modo debug) comparado contra o baseline.",
)
class VerboseErrorScanner:
    name = "verbose_error_scanner"

    def run(self, target: str):
        baseline = get(target)
        if baseline is None:
            return None

        probe_paths = [
            f"/surfacer_probe_{uuid.uuid4().hex[:12]}",
            f"/surfacer_probe_{uuid.uuid4().hex[:12]}%00.php",  # null byte -- quebra roteamento antigo/mal feito
        ]

        for probe_path in probe_paths:
            test = get(target.rstrip("/") + probe_path)
            if test is None:
                continue

            found, kind = detect_verbose_error(baseline.text, test.text)
            if found:
                return ModuleResult(findings=[{
                    "title": f"Erro verboso vazando informação de desenvolvimento: {kind}",
                    "severity": "medium",
                    "module": self.name,
                    "category": "security_misconfiguration",
                    "endpoint": target.rstrip("/") + probe_path,
                    "description": (
                        f"Requisição a '{probe_path}' devolveu página de erro com "
                        f"assinatura de '{kind}' -- comportamento típico de ambiente de "
                        f"desenvolvimento/debug, não deveria aparecer em produção."
                    ),
                    "business_impact": (
                        "Stack trace ou caminho de servidor exposto ajuda um atacante a mapear "
                        "estrutura interna, versão de framework, e às vezes até trecho de código-fonte."
                    ),
                    "remediation": "Desabilitar modo debug/desenvolvimento em produção; configurar página de erro genérica sem detalhe técnico.",
                    "evidence": {"probe_path": probe_path, "signature_kind": kind, "status": test.status_code},
                }])

        return None
