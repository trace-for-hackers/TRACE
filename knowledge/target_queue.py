"""
knowledge/target_queue.py

Fila de alvos: escanear várias URLs numa execução, cada uma com seu
próprio estado, sem que um alvo problemático (timeout, erro) derrube o
lote inteiro.

Isto NÃO é orquestração distribuída (ver a conversa que originou este
módulo -- decisão deliberada de manter tudo num processo só). É uma fila
em memória, processada sequencialmente ou com um pool pequeno de threads,
onde cada alvo roda o MESMO motor de fatos isolado (um KnowledgeStore por
alvo -- fatos de um alvo nunca vazam pro outro). O que é COMPARTILHADO
entre alvos é só a memória de longo prazo (SQLite): o hit_rate aprendido
escaneando o alvo A informa a priorização no alvo B, que é exatamente o
"aprender junto" que a gente queria, sem precisar de scanner nenhum
conversando com outro em tempo real.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class TargetStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class TargetJob:
    url: str
    packs: list[str] = field(default_factory=list)   # vazio = todos
    status: TargetStatus = TargetStatus.PENDING
    findings: list[dict] = field(default_factory=list)
    error: str | None = None
    site_type: str | None = None
    # ScanReport completo do alvo; usado apenas para saídas enriquecidas
    # (ex.: possibilidades de SQLi e grafo de decisão). Não entra no estado
    # serializado da fila.
    report: Any = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "packs": self.packs,
            "status": self.status.value,
            "finding_count": len(self.findings),
            "error": self.error,
            "site_type": self.site_type,
        }


class TargetQueue:
    """Fila simples com estado por alvo. Não é thread-safe pra escrita
    concorrente de fora -- o processamento com pool (se usado) só escreve
    no TargetJob que aquela thread possui, nunca no de outra."""

    def __init__(self):
        self._jobs: list[TargetJob] = []

    def add(self, url: str, packs: list[str] | None = None) -> None:
        self._jobs.append(TargetJob(url=url, packs=packs or []))

    def add_many(self, urls: list[str], packs: list[str] | None = None) -> None:
        for url in urls:
            self.add(url, packs)

    def pending(self) -> list[TargetJob]:
        return [j for j in self._jobs if j.status == TargetStatus.PENDING]

    def all_jobs(self) -> list[TargetJob]:
        return list(self._jobs)

    def summary(self) -> dict:
        counts = {s: 0 for s in TargetStatus}
        total_findings = 0
        for j in self._jobs:
            counts[j.status] += 1
            total_findings += len(j.findings)
        return {
            "total": len(self._jobs),
            "pending": counts[TargetStatus.PENDING],
            "running": counts[TargetStatus.RUNNING],
            "done": counts[TargetStatus.DONE],
            "failed": counts[TargetStatus.FAILED],
            "total_findings": total_findings,
        }


def load_targets_from_file(path: str) -> list[str]:
    """Lê uma URL por linha, ignorando linha em branco e comentário (#).
    Formato deliberadamente burro -- o caso comum é `cat urls.txt | ...`
    ou um arquivo colado à mão, não precisa de CSV/JSON."""
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls
