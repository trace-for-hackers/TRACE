"""
core/vuln_history.py

Ciclo de vida de cada vulnerabilidade ao longo de TODOS os scans de um
alvo -- pedido específico de um CTO externo (Adilson) depois de ver o
projeto: distinguir não só "novo" e "resolvido" (que já existia em
core/scan_diff.py), mas também "voltou" de "novo".

Por que precisa olhar mais que 2 scans: comparando só (atual, anterior),
um finding ausente no scan N-1 e presente de novo no scan N é
indistinguível de um finding genuinamente inédito -- só vira visível
olhando pra história completa. core/scan_diff.py continua existindo e
sendo usado nos relatórios (é mais barato, só 2 scans, e "novo" vs "voltou"
não muda o que vai no PDF/HTML) -- este módulo é para uma visão mais rica
(ex.: uma aba de histórico/dashboard), não substitui o diff simples.

Reaproveita _identity() de core/scan_diff.py -- mesma noção de "é o mesmo
finding" nos dois lugares, de propósito: se um dia a lógica de identidade
mudar (por exemplo, passar a incluir o slug do plugin em vez de só o
título), muda num lugar só.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from core.scan_diff import _identity


@dataclass
class VulnerabilityTimeline:
    target: str
    latest_scan_id: int
    total_scans_analisados: int
    novos: list[dict] = field(default_factory=list)          # nunca apareceram antes deste scan
    persistentes: list[dict] = field(default_factory=list)   # presentes agora E no scan imediatamente anterior
    retornaram: list[dict] = field(default_factory=list)     # sumiram em algum momento, presentes agora de novo
    resolvidos: list[dict] = field(default_factory=list)     # presentes no scan anterior, ausentes agora

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "latest_scan_id": self.latest_scan_id,
            "total_scans_analisados": self.total_scans_analisados,
            "novos_count": len(self.novos),
            "persistentes_count": len(self.persistentes),
            "retornaram_count": len(self.retornaram),
            "resolvidos_count": len(self.resolvidos),
            "novos": self.novos,
            "persistentes": self.persistentes,
            "retornaram": self.retornaram,
            "resolvidos": self.resolvidos,
        }


def build_vulnerability_timeline(memory, target: str, max_scans: int = 20) -> VulnerabilityTimeline | None:
    """
    memory: MemoryManager já conectado.
    max_scans: quantos scans finalizados olhar pra trás (get_scans_for_target
    já só retorna scans finalizados, do mais recente pro mais antigo -- ver
    core/memory.py). 20 é generoso o suficiente pra maioria dos alvos
    monitorados sem carregar histórico desnecessário.

    Retorna None se não houver nenhum scan finalizado para o alvo ainda.
    """
    if memory is None:
        return None

    scans = memory.get_scans_for_target(target, limit=max_scans)
    if not scans:
        return None

    scans_chronological = list(reversed(scans))  # do mais antigo pro mais recente

    # identidade do finding -> conjunto de scan_ids onde ele apareceu
    appearances: dict[tuple, set] = defaultdict(set)
    for scan in scans_chronological:
        findings = memory.get_findings_for_scan_id(scan["scan_id"])
        for f in findings:
            appearances[_identity(f)].add(scan["scan_id"])

    current_scan_id = scans[0]["scan_id"]
    previous_scan_id = scans[1]["scan_id"] if len(scans) > 1 else None

    current_findings = memory.get_findings_for_scan_id(current_scan_id)

    timeline = VulnerabilityTimeline(
        target=target,
        latest_scan_id=current_scan_id,
        total_scans_analisados=len(scans),
    )

    for f in current_findings:
        scan_ids_seen = appearances[_identity(f)]
        esteve_no_anterior = previous_scan_id is not None and previous_scan_id in scan_ids_seen
        esteve_em_algum_scan_mais_antigo = any(
            sid != current_scan_id and sid != previous_scan_id for sid in scan_ids_seen
        )

        if esteve_no_anterior:
            timeline.persistentes.append(f)
        elif esteve_em_algum_scan_mais_antigo:
            timeline.retornaram.append(f)
        else:
            timeline.novos.append(f)

    if previous_scan_id is not None:
        current_identities = {_identity(f) for f in current_findings}
        previous_findings = memory.get_findings_for_scan_id(previous_scan_id)
        for f in previous_findings:
            if _identity(f) not in current_identities:
                timeline.resolvidos.append(f)

    return timeline
