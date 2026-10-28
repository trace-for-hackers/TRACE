"""
knowledge/store.py

O Knowledge Store é o Blackboard do TRACE: o espaço de fatos compartilhado
que todos os módulos leem e escrevem, sem se conhecerem entre si.

Camadas de armazenamento (reaproveitando a infra já existente em core/memory.py):

    L1 — em memória do processo (dict)     -> acesso O(1) durante o scan, zero I/O
    L2 — Redis (sessão atual)               -> sobrevive a retomada de scan interrompido
    L3 — Postgres (memória de longo prazo)  -> fatos "duráveis" sobre o alvo entre scans

Toda escrita vai para L1+L2 imediatamente (síncrono, é local).
A persistência em L3 é seletiva: só fatos marcados como `durable=True` na
declaração do módulo (ver FactSpec em knowledge/contracts.py) viram registro
no Postgres — não queremos poluir a memória de longo prazo com fatos efêmeros
de baixa confiança.

Por que não usar só o Postgres? Performance. O scheduler consulta o Knowledge
Store a cada fato novo produzido (para recalcular elegibilidade de módulos) —
isso pode ser centenas de consultas por scan. Precisa ser memória, não round-trip
de rede a cada chamada.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from knowledge.fact import Fact, FactSource


class KnowledgeStore:
    """
    Blackboard thread-safe. Uma instância por sessão de scan (não é singleton
    global — múltiplos scans concorrentes em alvos diferentes têm stores
    independentes, evitando contaminação cruzada de conhecimento).
    """

    def __init__(self, target: str, memory_manager=None):
        self.target = target
        self.memory = memory_manager  # core.memory.MemoryManager, opcional

        self._lock = threading.RLock()
        # histórico completo, só para auditoria/explicabilidade -- NUNCA lido
        # para decidir qual é o fato "atual" (ver bug corrigido em assert_fact/get)
        self._facts: dict[str, list[Fact]] = defaultdict(list)
        # a fonte da verdade sobre qual é o fato atual de cada chave -- é
        # assert_fact() que decide isso UMA VEZ, na hora da escrita; get()
        # só lê essa decisão, nunca recalcula por conta própria.
        self._current: dict[str, Fact] = {}
        # revisão monotônica da versão ATUAL de cada fato. A revisão só muda
        # quando assert_fact() aceita a nova versão como current. O engine usa
        # isso para saber se um módulo viu conhecimento novo desde a última
        # execução, evitando reentrâncias espúrias causadas apenas porque a
        # requirement continua satisfeita.
        self._current_revisions: dict[str, int] = {}
        self._revision_counter: int = 0
        # listeners para o scheduler: callback(fact) chamado a cada write
        self._subscribers: list[callable] = []

    # ── escrita ──────────────────────────────────────────────────────────────

    def assert_fact(self, new_fact: Fact, durable: bool = False, force: bool = False) -> None:
        """
        Adiciona um fato ao blackboard. Se já existir um fato com a mesma key,
        a versão anterior é preservada no histórico (auditoria / explicabilidade),
        e a nova versão passa a ser a "atual" — EXCETO se a nova confiança for
        estritamente menor que a existente E a existente não estiver expirada.
        Isso evita que uma heurística fraca sobrescreva uma confirmação forte.

        `force=True` ignora essa proteção -- existe especificamente para
        retract() abaixo, uma correção deliberada, não uma heurística
        concorrente competindo por confiança.

        BUG REAL descoberto via teste (29/08/2026), corrigido junto com o
        `force`: get() usava max(confidence, timestamp) sobre TODO o
        histórico pra decidir o "atual", recalculando do zero a cada
        leitura -- então mesmo com force=True aqui, get() ignorava essa
        decisão e voltava a escolher o fato de maior confiança já visto
        (a retração, com confiança 0.0, nunca vencia contra um fato antigo
        de 0.9 que continuava no histórico). O "atual" agora é decidido
        UMA VEZ, aqui, e guardado em self._current -- get() só lê essa
        decisão, nunca recalcula. self._facts continua existindo só para
        histórico/auditoria (explain(), history()).
        """
        with self._lock:
            key_str = str(new_fact.key)
            existing = self._current.get(key_str)

            self._facts[key_str].append(new_fact)  # histórico sempre recebe, decidido ou não

            if not force and existing and not existing.is_expired() and new_fact.confidence < existing.confidence:
                # fato mais fraco não rebaixa um fato mais forte ainda válido
                return

            self._current[key_str] = new_fact
            self._revision_counter += 1
            self._current_revisions[key_str] = self._revision_counter

            if durable and self.memory:
                self.memory.save_fact(new_fact)  # ver extensão de MemoryManager na seção 7

            for callback in list(self._subscribers):
                callback(new_fact)

    def retract(self, key_str: str, reason: str = "") -> None:
        """
        Remove a validade de um fato sem apagar o histórico — usado quando uma
        verificação posterior CONTRADIZ um fato anterior (ex.: WAF bloqueou a
        primeira tentativa de detectar WooCommerce, gerando falso negativo;
        uma segunda rota confirma e o fato antigo precisa ser invalidado).
        Implementado como um fato sintético de confiança 0 e fonte INFERENCE.

        force=True é necessário aqui -- ver docstring de assert_fact.
        """
        from knowledge.fact import fact as make_fact
        with self._lock:
            self.assert_fact(make_fact(
                key=key_str, value=None, confidence=0.0,
                produced_by=f"retraction:{reason}", target=self.target,
                source=FactSource.INFERENCE,
            ), force=True)

    # ── leitura ──────────────────────────────────────────────────────────────

    def get(self, key_str: str) -> Fact | None:
        """Retorna o fato "atual" da chave -- a decisão já foi tomada em
        assert_fact(), aqui só lemos. Fatos expirados deixam de contar
        como atuais mesmo sem uma nova escrita (checagem lazy, na leitura)."""
        with self._lock:
            current = self._current.get(key_str)
            if current is None or current.is_expired():
                return None
            return current

    def get_value(self, key_str: str, default=None):
        f = self.get(key_str)
        return f.value if f is not None else default

    def exists(self, key_str: str, min_confidence: float = 0.0) -> bool:
        f = self.get(key_str)
        return f is not None and f.confidence >= min_confidence and bool(f.value)

    def query_prefix(self, prefix: str) -> list[Fact]:
        """Todos os fatos atuais cuja key começa com o prefixo dado. Usado por
        módulos que querem reagir a 'qualquer coisa em tech.*', por exemplo."""
        with self._lock:
            results = []
            for key_str in self._facts:
                f = self.get(key_str)
                if f and f.key.matches_prefix(prefix):
                    results.append(f)
            return results

    def current_revision(self, key_str: str) -> int | None:
        """Retorna a revisão da versão atual de um fato.

        None significa que nunca houve uma versão atual aceita para a chave.
        A revisão é local à sessão e monotônica; não é um timestamp nem um ID
        persistente. Ela existe para detecção barata de mudança de conhecimento.
        """
        with self._lock:
            return self._current_revisions.get(key_str)

    def current_revision_prefix(self, prefix: str) -> tuple[tuple[str, int], ...]:
        """Retorna (fact_key, revision) ordenado para todos os fatos atuais
        abaixo de um prefixo. Usado por requirements wildcard (ex.: tech.*)."""
        with self._lock:
            pairs = [
                (key, self._current_revisions[key])
                for key in self._current
                if key.startswith(prefix + ".") or key == prefix
            ]
            return tuple(sorted(pairs))

    def history(self, key_str: str) -> list[Fact]:
        """Todas as versões de um fato, em ordem cronológica — para explicabilidade."""
        with self._lock:
            return list(self._facts.get(key_str, []))

    def snapshot(self) -> dict[str, dict]:
        """Estado atual completo do blackboard, serializável — usado para
        persistir o snapshot de sessão no Redis e para o relatório final
        explicar 'o que sabíamos quando decidimos o quê'."""
        with self._lock:
            return {k: self.get(k).to_dict() for k in self._facts if self.get(k)}

    # ── reatividade (para o scheduler) ──────────────────────────────────────

    def subscribe(self, callback) -> None:
        """O scheduler se inscreve aqui para ser notificado a cada fato novo,
        e recalcular a fronteira de módulos elegíveis incrementalmente,
        em vez de re-escanear todos os fatos a cada módulo concluído."""
        self._subscribers.append(callback)
