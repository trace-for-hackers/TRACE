"""
modules/injection_heuristics.py

Três sinais independentes e baratos de possível injeção -- nenhum deles
sozinho confirma nada, é por isso que existe o injection_correlator.py
depois: só quando sinais concordam é que vira Finding de verdade.

A lógica de DECISÃO de cada heurística (as funções score_*/detect_*) é
pura -- recebe texto/número, devolve confiança -- de propósito, pra ser
testável sem precisar de um alvo real no ar. A parte de I/O (send_and_compare)
fica isolada e fina.

BUG REAL encontrado testando ponta a ponta contra um alvo de verdade
(29/08/2026): sem o `_tested` de classe abaixo, cada heurística re-testava
o MESMO parâmetro toda vez que ficava elegível de novo (o que acontece a
cada onda, já que o Requirement é wildcard e facilmente satisfeito) --
gerando o mesmo fato repetidamente e queimando requisição à toa até
estourar max_waves, sem nunca convergir. Mesmo padrão de dedup por
atributo de CLASSE do injection_correlator.py (instância nova a cada
reentrância, então dedup teria que ser de instância pra não funcionar).

SEGUNDO BUG REAL, mais sutil, encontrado no mesmo teste: os checks
`if not response: continue` pareciam verificar "a requisição falhou", mas
`requests.Response.__bool__()` é False quando o STATUS é de erro (4xx/5xx)
-- não só quando a requisição falhou de verdade (timeout, conexão
recusada). Isso significa que `if not test: continue` descartava
SILENCIOSAMENTE toda resposta com erro 500 -- que é EXATAMENTE a resposta
que a heurística de erro existe pra analisar. O parâmetro genuinamente
vulnerável do alvo de teste nunca foi detectado por causa disso, até essa
comparação `is None` explícita substituir a checagem de truthiness.
"""

from __future__ import annotations

import re
import statistics

from utils.requester import get, post, post_json, is_intrusive_confirmed
from knowledge.contracts import discovery_module, Requirement, RequirementMode, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult


# assinaturas de erro de SQL conhecidas, por SGBD -- lista curta de
# propósito (poucas, específicas, baixa chance de falso positivo) em vez
# de tentar cobrir tudo que o sqlmap cobre. Objetivo é sinalizar candidato,
# não ser exaustivo.
_SQL_ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL", 0.9),
    (r"warning:\s*mysql_", "MySQL", 0.85),
    (r"unclosed quotation mark after the character string", "MSSQL", 0.9),
    (r"microsoft ole db provider for sql server", "MSSQL", 0.85),
    (r"pg_query\(\)|postgresql query failed", "PostgreSQL", 0.9),
    (r"ora-\d{5}", "Oracle", 0.9),
    (r"sqlite3?\.(operationalerror|programmingerror)", "SQLite", 0.85),
    (r"sqlstate\[", "genérico (PDO)", 0.7),
]


def detect_error_signature(baseline_text: str, test_text: str) -> tuple[bool, str, float]:
    """True se um padrão de erro de SQL aparece no texto de teste mas NÃO
    no baseline -- a comparação com o baseline existe pra evitar falso
    positivo quando a página já tem a palavra "sql" em conteúdo normal."""
    baseline_lower = (baseline_text or "").lower()
    test_lower = (test_text or "").lower()

    for pattern, engine, confidence in _SQL_ERROR_SIGNATURES:
        if re.search(pattern, test_lower) and not re.search(pattern, baseline_lower):
            return True, engine, confidence
    return False, "", 0.0


def score_boolean_difference(true_len: int, false_len: int, true_status: int, false_status: int) -> float:
    """Confiança baseada em quão diferente a resposta 'verdadeira'
    (' OR '1'='1) é da 'falsa' (' OR '1'='2). Diferença de status code é
    sinal mais forte que diferença de tamanho (tamanho pode variar por
    motivo não relacionado -- timestamp, contador, anúncio rotativo)."""
    if true_status != false_status:
        return 0.75

    if false_len == 0:
        return 0.0

    diff_ratio = abs(true_len - false_len) / false_len
    if diff_ratio > 0.20:
        return 0.65
    if diff_ratio > 0.05:
        return 0.35
    return 0.0


def score_differential(benign_lengths: list[int], test_length: int) -> float:
    """Compara a variação NORMAL de tamanho entre respostas benignas
    (várias strings aleatórias inofensivas) contra o quanto a resposta do
    payload de teste (aspas simples) foge dessa faixa. Isso é mais barato
    e mais seguro que os dois de cima, mas também o sinal mais fraco --
    puramente estatístico, sem olhar CONTEÚDO nenhum."""
    if len(benign_lengths) < 2:
        return 0.0

    media = statistics.mean(benign_lengths)
    desvio = statistics.pstdev(benign_lengths) or 1  # evita divisão por zero se todas iguais

    desvios_do_teste = abs(test_length - media) / desvio

    if desvios_do_teste > 5:
        return 0.5
    if desvios_do_teste > 3:
        return 0.3
    return 0.0


def _build_params(baseline_params: dict, target_param: str, value: str) -> dict:
    """Substitui só o parâmetro sob teste, mantendo os outros como estavam
    (mesmo que vazios) -- não sabemos a semântica de nenhum parâmetro
    aqui, então a estratégia mais segura é sempre a mais simples: um
    valor de teste por vez, isolado."""
    params = dict(baseline_params)
    params[target_param] = value
    return params


def _hash_from_key(key) -> str:
    """surface.param.<hash> -> <hash>. Sempre o último segmento, não uma
    posição fixa -- mais robusto que assumir índice [2]."""
    return str(key).split(".")[-1]


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _send_json(url: str, method: str, body_template: dict, field: str, payload):
    """Equivalente a _send(), mas pra corpo JSON de API REST -- monta
    uma CÓPIA do corpo original (descoberto por
    modules/js_rendering_crawler.py) trocando só o campo sendo testado,
    mantendo os outros campos com valor original (necessário pra
    requisição continuar válida o bastante pra alcançar o código
    vulnerável -- ex.: /rest/user/login precisa de EMAIL e SENHA
    presentes, mesmo testando só o campo email)."""
    body = dict(body_template)
    body[field] = payload
    if method.upper() == "GET":
        return get(url, params=body)  # raro (GET com corpo), mas não quebra se acontecer
    return post_json(url, json_body=body)


def _emit_signal(hash_id: str, technique: str, param_info: dict, confidence: float, evidence: str, produced_by: str, target: str):
    key = f"injection.signal.{hash_id}.{technique}"
    value = {**param_info, "technique": technique, "evidence": evidence}
    return fact(key, value, confidence, produced_by, target)


@discovery_module(
    requires=[
        Requirement("surface.param.*", min_confidence=0.5),
        Requirement("surface.json_param.*", min_confidence=0.5),
    ],
    requirement_mode=RequirementMode.ANY,
    produces=[Produces("injection.signal.*", durable=True)],
    cost=2,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heurística de Erro SQL",
    summary="Envia aspas simples em cada parâmetro descoberto (querystring ou campo de corpo JSON) e procura assinatura de erro de SQL na resposta que não existia no baseline.",
)
class ErrorBasedHeuristic:
    name = "heuristic_error_based"
    _tested: set[tuple] = set()  # de classe, ver injection_correlator.py pro motivo

    def run(self, target, facts_in):
        if not is_intrusive_confirmed():
            return None  # --confirm-intrusive nao foi passado -- payload real nao enviado

        params = facts_in.get("surface.param.*", [])
        results = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]
            hash_id = _hash_from_key(f.key)
            if (target, hash_id) in self._tested:
                continue
            self._tested.add((target, hash_id))

            baseline = _send(url, method, {param: "1"})
            test = _send(url, method, {param: "1'"})
            if baseline is None or test is None:
                continue

            found, engine, confidence = detect_error_signature(baseline.text, test.text)
            if found:
                results.append(_emit_signal(
                    hash_id, "error_based", info, confidence,
                    f"assinatura de erro {engine} detectada com payload de aspas simples",
                    self.name, target,
                ))

        # mesma técnica, aplicada a cada CAMPO de corpo JSON descoberto
        # (ver modules/js_rendering_crawler.py) -- API REST de SPA que
        # nunca aparece como querystring, ex.: POST /rest/user/login
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

                baseline = _send_json(url, method, body_template, field, "1")
                test = _send_json(url, method, body_template, field, "1'")
                if baseline is None or test is None:
                    continue

                found, engine, confidence = detect_error_signature(baseline.text, test.text)
                if found:
                    field_info = {"url": url, "method": method, "param": field, "body_format": "json"}
                    results.append(_emit_signal(
                        f"{hash_id}_{field}", "error_based", field_info, confidence,
                        f"assinatura de erro {engine} detectada com payload de aspas simples (campo JSON '{field}')",
                        self.name, target,
                    ))

        if not results:
            return None
        return ModuleResult(facts=results)


@discovery_module(
    requires=[
        Requirement("surface.param.*", min_confidence=0.5),
        Requirement("surface.json_param.*", min_confidence=0.5),
    ],
    requirement_mode=RequirementMode.ANY,
    produces=[Produces("injection.signal.*", durable=True)],
    cost=3,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heurística Booleana",
    summary="Compara resposta de condição verdadeira (' OR '1'='1) vs falsa (' OR '1'='2) no mesmo parâmetro (querystring ou campo de corpo JSON).",
)
class BooleanBasedHeuristic:
    name = "heuristic_boolean_based"
    _tested: set[tuple] = set()

    def run(self, target, facts_in):
        if not is_intrusive_confirmed():
            return None  # --confirm-intrusive nao foi passado -- payload real nao enviado

        params = facts_in.get("surface.param.*", [])
        results = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]
            hash_id = _hash_from_key(f.key)
            if (target, hash_id) in self._tested:
                continue
            self._tested.add((target, hash_id))

            true_resp = _send(url, method, {param: "1' OR '1'='1"})
            false_resp = _send(url, method, {param: "1' OR '1'='2"})
            if true_resp is None or false_resp is None:
                continue

            confidence = score_boolean_difference(
                len(true_resp.text), len(false_resp.text),
                true_resp.status_code, false_resp.status_code,
            )
            if confidence > 0:
                results.append(_emit_signal(
                    hash_id, "boolean_based", info, confidence,
                    f"resposta muda entre condição verdadeira e falsa (status {true_resp.status_code} vs {false_resp.status_code})",
                    self.name, target,
                ))

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

                true_resp = _send_json(url, method, body_template, field, "1' OR '1'='1")
                false_resp = _send_json(url, method, body_template, field, "1' OR '1'='2")
                if true_resp is None or false_resp is None:
                    continue

                confidence = score_boolean_difference(
                    len(true_resp.text), len(false_resp.text),
                    true_resp.status_code, false_resp.status_code,
                )
                if confidence > 0:
                    field_info = {"url": url, "method": method, "param": field, "body_format": "json"}
                    results.append(_emit_signal(
                        f"{hash_id}_{field}", "boolean_based", field_info, confidence,
                        f"resposta muda entre condição verdadeira e falsa no campo JSON '{field}' "
                        f"(status {true_resp.status_code} vs {false_resp.status_code})",
                        self.name, target,
                    ))

        if not results:
            return None
        return ModuleResult(facts=results)


@discovery_module(
    requires=[
        Requirement("surface.param.*", min_confidence=0.5),
        Requirement("surface.json_param.*", min_confidence=0.5),
    ],
    requirement_mode=RequirementMode.ANY,
    produces=[Produces("injection.signal.*", durable=True)],
    cost=4,
    max_reentries=20,
    category="injection_heuristics",
    display_name="Heurística Diferencial",
    summary="Calibra a variação normal de tamanho de resposta com valores benignos, depois verifica se um payload de aspas foge dessa faixa (querystring ou campo de corpo JSON).",
)
class DifferentialHeuristic:
    name = "heuristic_differential"
    _tested: set[tuple] = set()

    def run(self, target, facts_in):
        if not is_intrusive_confirmed():
            return None  # --confirm-intrusive nao foi passado -- payload real nao enviado

        params = facts_in.get("surface.param.*", [])
        results = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]
            hash_id = _hash_from_key(f.key)
            if (target, hash_id) in self._tested:
                continue
            self._tested.add((target, hash_id))

            benign_values = ["a8f3k2", "q9z1mx", "p4wexy"]
            benign_lengths = []
            for v in benign_values:
                r = _send(url, method, {param: v})
                if r is not None:
                    benign_lengths.append(len(r.text))

            test = _send(url, method, {param: "1'"})
            if test is None or len(benign_lengths) < 2:
                continue

            confidence = score_differential(benign_lengths, len(test.text))
            if confidence > 0:
                results.append(_emit_signal(
                    hash_id, "differential", info, confidence,
                    "tamanho de resposta com payload de aspas foge da variação normal calibrada com valores benignos",
                    self.name, target,
                ))

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

                benign_values = ["a8f3k2", "q9z1mx", "p4wexy"]
                benign_lengths = []
                for v in benign_values:
                    r = _send_json(url, method, body_template, field, v)
                    if r is not None:
                        benign_lengths.append(len(r.text))

                test = _send_json(url, method, body_template, field, "1'")
                if test is None or len(benign_lengths) < 2:
                    continue

                confidence = score_differential(benign_lengths, len(test.text))
                if confidence > 0:
                    field_info = {"url": url, "method": method, "param": field, "body_format": "json"}
                    results.append(_emit_signal(
                        f"{hash_id}_{field}", "differential", field_info, confidence,
                        f"tamanho de resposta com payload de aspas no campo JSON '{field}' foge da "
                        f"variação normal calibrada com valores benignos",
                        self.name, target,
                    ))

        if not results:
            return None
        return ModuleResult(facts=results)
