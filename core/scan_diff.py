"""
core/scan_diff.py

Compara os dois scans mais recentes de um alvo e reporta o que mudou entre
eles: achados NOVOS (não existiam no scan anterior), achados RESOLVIDOS
(existiam antes e não aparecem mais agora -- indício de correção, mas
também pode ser um módulo pulado por cache, ver `has_baseline`/uso abaixo)
e achados PERSISTENTES (continuam presentes nos dois scans).

Usa MemoryManager.get_scans_for_target() e get_findings_for_scan_id(), que
já existem em core/memory.py -- nenhuma tabela nova, nenhuma migração.

Identidade de um finding entre scans: o `id` não serve (é um uuid novo a
cada scan). Usamos (module_name, title, endpoint) como chave estável --
um módulo sempre produz o mesmo título/endpoint para o mesmo problema
quando o encontra de novo.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _endpoint_of(finding: dict) -> str:
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and evidence.get("endpoint"):
        return str(evidence["endpoint"])
    return str(finding.get("endpoint", ""))


def _identity(finding: dict) -> tuple:
    module = finding.get("module_name") or finding.get("module", "")
    return (module, finding.get("title", ""), _endpoint_of(finding))


@dataclass
class ScanDiff:
    target: str
    previous_scan_id: int | None
    current_scan_id: int
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    persistent_findings: list[dict] = field(default_factory=list)

    @property
    def has_baseline(self) -> bool:
        """False no primeiro scan de um alvo (nada para comparar) -- nesse
        caso new_findings contém todos os achados atuais, sem que isso
        signifique que "tudo é novidade", apenas que não há histórico."""
        return self.previous_scan_id is not None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "previous_scan_id": self.previous_scan_id,
            "current_scan_id": self.current_scan_id,
            "has_baseline": self.has_baseline,
            "new_count": len(self.new_findings),
            "resolved_count": len(self.resolved_findings),
            "persistent_count": len(self.persistent_findings),
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "persistent_findings": self.persistent_findings,
        }


def diff_last_two_scans(memory, target: str) -> ScanDiff | None:
    """
    memory: MemoryManager já conectado (None-safe: chamador deve checar
    antes, igual ao resto do código já faz com `self.memory`).

    Retorna None se não houver nenhum scan finalizado para o alvo ainda.
    """
    if memory is None:
        return None

    scans = memory.get_scans_for_target(target, limit=2)
    if not scans:
        return None

    current = scans[0]
    current_findings = memory.get_findings_for_scan_id(current["scan_id"])

    if len(scans) < 2:
        return ScanDiff(
            target=target,
            previous_scan_id=None,
            current_scan_id=current["scan_id"],
            new_findings=current_findings,
        )

    previous = scans[1]
    previous_findings = memory.get_findings_for_scan_id(previous["scan_id"])

    current_by_id = {_identity(f): f for f in current_findings}
    previous_by_id = {_identity(f): f for f in previous_findings}

    new = [f for key, f in current_by_id.items() if key not in previous_by_id]
    resolved = [f for key, f in previous_by_id.items() if key not in current_by_id]
    persistent = [f for key, f in current_by_id.items() if key in previous_by_id]

    return ScanDiff(
        target=target,
        previous_scan_id=previous["scan_id"],
        current_scan_id=current["scan_id"],
        new_findings=new,
        resolved_findings=resolved,
        persistent_findings=persistent,
    )
