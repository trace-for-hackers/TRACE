"""
modules/xss_reflection_heuristic.py

Heurística de XSS refletido -- mesma família de modules/
injection_heuristics.py (sinal barato, uma requisição por parâmetro,
consome surface.param.* que o crawler.py já produz).

DECISÃO DE DESIGN IMPORTANTE: diferente dos heurísticas de SQLi, este
módulo reporta Finding DIRETO, sem passar por um correlator de sinais
combinados. Motivo: cheguei a desenhar isso emitindo fato
`injection.signal.<hash>.xss_reflection` pro injection_correlator.py
consumir (mesmo padrão do SQLi) -- e percebi um bug de design antes de
testar: injection_correlator.py agrupa sinais só pelo hash do
parâmetro, sem saber a CLASSE de vulnerabilidade. Se um parâmetro
tivesse sinal de XSS E sinal fraco de SQLi ao mesmo tempo, os dois
seriam combinados como se fossem evidência do MESMO problema --
misturando evidência de XSS dentro de um achado rotulado "candidato a
SQL injection". Uma reflexão sem escape confirmada já é evidência forte
sozinha (diferente das heurísticas de SQLi, que são fracas
individualmente e SÓ fazem sentido combinadas) -- não precisa de
correlação, então reporta direto.

DECISÃO DE DESIGN: o payload usa um MARCADOR ÚNICO por chamada (não uma
tag <script> fixa) -- isso importa por dois motivos:
  1. Evita falso positivo se a própria página, por coincidência, já
     contém o texto do payload em algum lugar (ex.: documentação técnica
     mostrando exemplo de payload de XSS).
  2. Permite diferenciar REFLETIDO SEM ESCAPE (o marcador aparece cru,
     com < e > literais) de REFLETIDO COM ESCAPE (aparece como &lt;/&gt;,
     que é o comportamento SEGURO -- a maioria dos frameworks modernos
     escapa por padrão, então "aparece no HTML" sozinho não é sinal
     nenhum, só "aparece SEM escapar" é.
"""

from __future__ import annotations

import uuid

from utils.requester import get, post, post_json, is_intrusive_confirmed
from knowledge.contracts import discovery_module, Requirement, RequirementMode, Produces
from knowledge.result import ModuleResult


def make_marker() -> str:
    """UUID curto, sem caractere de HTML nele mesmo -- o marcador em si
    tem que ser inócuo, só o WRAPPER (a tag ao redor) é que testa
    injeção. Evita o próprio marcador acidentalmente quebrar alguma
    outra coisa na página antes mesmo de chegar no teste."""
    return "xss" + uuid.uuid4().hex[:8]


def build_payload(marker: str) -> str:
    return f"<{marker}>"


def is_unescaped_reflection(response_text: str, marker: str) -> bool:
    """True só se o marcador aparece com < e > LITERAIS ao redor -- se
    aparece como &lt;marcador&gt;, a aplicação escapou corretamente e
    isso NÃO é achado, é o comportamento certo. Também não conta se o
    marcador nem aparece (parâmetro pode ser ignorado, sanitizado e
    removido, etc. -- ausência total não é evidência de vulnerabilidade)."""
    if response_text is None:
        return False
    return f"<{marker}>" in response_text


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _send_json(url: str, method: str, body_template: dict, field: str, payload):
    body = dict(body_template)
    body[field] = payload
    if method.upper() == "GET":
        return get(url, params=body)
    return post_json(url, json_body=body)


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[
        Requirement("surface.param.*", min_confidence=0.5),
        Requirement("surface.json_param.*", min_confidence=0.5),
    ],
    requirement_mode=RequirementMode.ANY,
    produces=[],
    cost=1,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heurística de XSS Refletido",
    summary="Envia um marcador único por parâmetro descoberto (querystring ou campo de corpo JSON) e verifica se ele volta na resposta SEM escapar (< e > literais) -- reflexão escapada corretamente não conta como achado.",
)
class XSSReflectionHeuristic:
    name = "xss_reflection_heuristic"
    _tested: set[tuple] = set()  # de classe -- mesmo motivo de injection_heuristics.py

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

            marker = make_marker()
            payload = build_payload(marker)
            resp = _send(url, method, {param: payload})
            if resp is None:
                continue

            if is_unescaped_reflection(resp.text, marker):
                findings.append({
                    "title": f"Candidato a XSS Refletido: parâmetro '{param}' em {url}",
                    "severity": "high",
                    "module": self.name,
                    "category": "reflected_xss",
                    "endpoint": url,
                    "description": (
                        f"O parâmetro '{param}' (via {method}) refletiu o marcador de teste "
                        f"'<{marker}>' na resposta SEM escapar os caracteres < e > -- indica "
                        f"que o valor do parâmetro é inserido na página sem sanitização."
                    ),
                    "business_impact": (
                        "XSS refletido pode permitir roubo de sessão, phishing dentro do "
                        "próprio domínio confiável, ou execução de ação em nome da vítima."
                    ),
                    "remediation": (
                        "Escapar (HTML-encode) todo valor de entrada antes de inserir na "
                        "resposta HTML, ou usar template engine com auto-escape habilitado."
                    ),
                    "evidence": {"url": url, "method": method, "param": param, "marker_used": marker},
                })

        # mesma técnica pra campo de corpo JSON (ver
        # modules/js_rendering_crawler.py) -- cobre o padrão "API-only
        # XSS" (a API REST reflete o valor cru na resposta JSON, e uma
        # tela em outro lugar do app renderiza esse campo sem escapar)
        json_params = facts_in.get("surface.json_param.*", [])
        for f in json_params:
            info = f.value
            url, method = info["url"], info["method"]
            body_template, fields = info["body_template"], info["fields"]
            hash_id = _hash_from_key(f.key)

            for field in fields:
                dedup_key = (target, hash_id, field)
                if dedup_key in self._tested:
                    continue
                self._tested.add(dedup_key)

                marker = make_marker()
                payload = build_payload(marker)
                resp = _send_json(url, method, body_template, field, payload)
                if resp is None:
                    continue

                if is_unescaped_reflection(resp.text, marker):
                    findings.append({
                        "title": f"Candidato a XSS Refletido (API JSON): campo '{field}' em {url}",
                        "severity": "high",
                        "module": self.name,
                        "category": "reflected_xss",
                        "endpoint": url,
                        "description": (
                            f"O campo '{field}' do corpo JSON (via {method}) refletiu o marcador "
                            f"de teste '<{marker}>' na resposta SEM escapar -- padrão \"API-only "
                            f"XSS\": a API devolve o valor cru, e uma tela em outro lugar do app "
                            f"pode renderizar esse campo sem sanitizar."
                        ),
                        "business_impact": (
                            "XSS refletido pode permitir roubo de sessão, phishing dentro do "
                            "próprio domínio confiável, ou execução de ação em nome da vítima."
                        ),
                        "remediation": (
                            "Escapar (HTML-encode) todo valor de entrada antes de renderizar em "
                            "qualquer tela, mesmo quando o valor vem de uma resposta de API JSON."
                        ),
                        "evidence": {"url": url, "method": method, "param": field, "marker_used": marker, "body_format": "json"},
                    })

        if not findings:
            return None
        return ModuleResult(findings=findings)
