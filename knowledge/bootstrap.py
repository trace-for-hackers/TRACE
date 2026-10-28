"""
knowledge/bootstrap.py

ScanSession orquestra o ciclo de vida completo de um scan, na ordem:

    1. Classificar o site (reaproveita SiteClassifier + cache de perfil já existentes)
    3. Abrir sessão na memória (reaproveita MemoryManager.start_session)
    4. Criar o KnowledgeStore da sessão
    5. Semear o KnowledgeStore com fatos duráveis de scans anteriores
    6. Descobrir e registrar módulos (reaproveita load_modules() de main_gui.py)
    7. Detectar ciclos estruturais (ActivationEngine.register -- falha rápido)
    8. Calcular prioridades (hit_rate vem de MemoryManager.get_module_priority)
    9. Rodar o DiscoveryScheduler em ondas até estabilizar ou esgotar orçamento
    10. Persistir findings (reaproveita MemoryManager.save_finding)
    11. Fechar sessão (reaproveita MemoryManager.finish_session)
    12. Devolver findings + relatório de explicabilidade (ondas, fatos, decisões)

Este módulo é o ÚNICO ponto que precisa ser plugado em main_gui.py.
Nenhum módulo em modules/ precisa ser tocado para o sistema funcionar -- os
que não tiverem @discovery_module continuam rodando como módulos raiz
(sempre elegíveis, sem produzir fatos).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.classifier import SiteClassifier
from core.memory import MemoryManager
from knowledge.engine import ActivationEngine
from knowledge.priority import PriorityCalculator
from knowledge.scheduler import DiscoveryScheduler, ScanBudget
from knowledge.store import KnowledgeStore
from core.audit import write_session_artifact
from observability import span, target_identity, record_exception


@dataclass
class ScanReport:
    target: str
    site_type: str
    session_id: str
    findings: list[dict] = field(default_factory=list)
    wave_count: int = 0
    # lista completa de WaveReport (knowledge/scheduler.py), incluindo
    # triggered_by (causalidade fato->módulo) e new_facts (módulo->fato) --
    # antes só o COUNT chegava até aqui; o dado completo é necessário para
    # qualquer consumidor que precise reconstruir a cadeia de decisão, como
    # knowledge/decision_graph.py.
    wave_reports: list = field(default_factory=list)
    # module_name -> ModuleSpec.describe(module_class) -- resolvido AQUI,
    # com acesso direto às classes registradas no ActivationEngine, porque
    # wave_reports só guarda nomes (str), não as classes. Resolver depois
    # (em decision_graph.py, por exemplo) exigiria acoplar esse módulo de
    # apresentação ao engine só para reobter a classe a partir do nome --
    # mais simples resolver uma vez aqui e carregar o dict já pronto.
    module_metadata: dict = field(default_factory=dict)
    facts_seeded_from_memory: int = 0
    knowledge_snapshot: dict = field(default_factory=dict)


class ScanSession:
    def __init__(
        self,
        target: str,
        module_classes: list[type],
        memory: MemoryManager | None = None,
        budget: ScanBudget | None = None,
        max_workers: int = 5,
        on_log=None,
        on_progress=None,
        resume: bool = True,
        initial_facts: list | None = None,
    ):
        self.target = target.rstrip("/")
        self.module_classes = module_classes
        # diferente do ScanWorker original (que assumia memory sempre presente
        # e quebraria com AttributeError se Redis/Postgres estivessem fora do
        # ar), aqui memory=None é um modo de operação válido: o scan roda sem
        # persistência, sem cache de perfil/findings, e sem hit_rate aprendido
        # -- mas roda. self.memory continua None nesse caso (não criamos um
        # MemoryManager() de fallback, porque isso tentaria conectar e falharia
        # do mesmo jeito).
        self.memory = memory
        self.budget = budget or ScanBudget()
        self.max_workers = max_workers
        self._external_on_log = on_log or print
        self._audit_records: list[dict] = []
        self.on_log = self._record_log
        self.on_progress = on_progress or (lambda done, total: None)
        # resume=True (default): se existir uma sessão deste alvo iniciada e
        # nunca finalizada nas últimas 24h, retoma em vez de começar do zero.
        # resume=False força um scan novo mesmo que haja uma sessão pendente
        # -- útil quando o usuário sabe que quer reavaliar tudo do início.
        self.resume = resume
        # fatos que precisam existir ANTES da primeira onda -- hoje usado
        # pra sinalizar configuração externa disponível (identidade
        # registrada, spec OpenAPI, callback host), pra que módulo que
        # dependa disso possa declarar Requirement de verdade em vez de
        # ser sempre elegível na onda 0 e se autoabortar dentro do run()
        # quando a config não existe (ver main.py, seção de config facts).
        self.initial_facts = initial_facts or []

    def _record_log(self, message: str) -> None:
        from datetime import datetime, timezone
        self._audit_records.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": "log",
            "event": "log",
            "payload": {"message": str(message)},
        })
        self._external_on_log(message)

    def _persist_audit(self, report: ScanReport | None) -> None:
        if self.memory is None or not getattr(self, "_session_id", None):
            return
        from datetime import datetime, timezone
        if report is not None:
            self._audit_records.extend([
                {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": "output", "event": "findings", "payload": report.findings},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": "output", "event": "wave_reports", "payload": report.wave_reports},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": "output", "event": "knowledge_snapshot", "payload": report.knowledge_snapshot},
            ])
            session_row = self.memory.get_session(self._session_id)
            started_value = (session_row or {}).get("started_at") or datetime.now(timezone.utc).isoformat()
        else:
            started_value = datetime.now(timezone.utc).isoformat()
        root = Path(self.memory.db_path).parent / "audit"
        artifact = write_session_artifact(
            root=root, target=self.target, session_id=self._session_id,
            started_at=started_value, records=self._audit_records,
        )
        self.memory.save_audit_artifact(self._session_id, self.target, artifact)
        self._external_on_log(f"[i] Auditoria Parquet: {artifact['path']} (sha256={artifact['sha256']})")

    def run(self) -> ScanReport:
        attrs = {"trace.operation": "scan", "session.target_hash": target_identity(self.target)["target.hash"], "scan.max_workers": self.max_workers}
        with span("trace.scan", attrs) as scan_span:
            try:
                result = self._run_in_span()
                if scan_span is not None:
                    scan_span.set_attribute("scan.findings", len(result.findings))
                    scan_span.set_attribute("scan.waves", result.wave_count)
                    scan_span.set_attribute("scan.site_type", result.site_type)
                    scan_span.set_attribute("scan.session_id", result.session_id)
                return result
            except Exception as exc:
                record_exception(scan_span, exc)
                raise

    def _run_in_span(self) -> ScanReport:
        if self.memory is None:
            return self._run_without_memory()

        # 2. classificação (cache de 7 dias já existente em MemoryManager)
        profile = self.memory.get_site_profile(self.target)
        if profile:
            site_type = profile["site_type"]
            self.on_log(f"[i] Perfil em cache: {site_type}")
        else:
            classifier = SiteClassifier()
            site_type, indicators = classifier.classify(self.target)
            self.memory.save_site_profile(self.target, site_type, indicators)
            self.on_log(f"[i] Site detectado como: {site_type}")

        # 3. sessão de memória -- nova ou retomada de uma interrompida
        scan_id, session_id, already_executed = self._open_session(site_type)
        self._session_id = session_id

        # 4. knowledge store da sessão
        store = KnowledgeStore(self.target, memory_manager=self.memory)
        for f in self.initial_facts:
            store.assert_fact(f)

        # 5. seed com conhecimento de scans anteriores (cobre tanto histórico
        # de scans antigos completos quanto fatos duráveis da PRÓPRIA tentativa
        # interrompida que está sendo retomada agora -- ver limitação sobre
        # fatos não-duráveis documentada em knowledge/scheduler.py)
        seeded = self.memory.seed_knowledge_store(store, self.target)
        if seeded:
            self.on_log(f"[i] {seeded} fato(s) recuperado(s) da memória de longo prazo.")

        # 6+7. registrar módulos e detectar ciclos estruturais
        engine = ActivationEngine(store, site_type=site_type)
        engine.register(self.module_classes)  # levanta CyclicDependencyError se houver ciclo

        # 8. prioridade (reaproveita hit_rate aprendido)
        hit_rates = self.memory.get_module_priority(site_type)
        priority_calc = PriorityCalculator(store, hit_rates)

        # 9. execução em ondas -- persistência de findings e marcação de módulos
        # executados agora acontece DENTRO do scheduler, incrementalmente, não
        # mais aqui no fim (ver knowledge/scheduler.py, _execute_wave)
        scheduler = DiscoveryScheduler(
            target=self.target,
            store=store,
            engine=engine,
            priority_calc=priority_calc,
            budget=self.budget,
            max_workers=self.max_workers,
            on_log=self.on_log,
            on_progress=self.on_progress,
            memory=self.memory,
            scan_id=scan_id,
            session_id=session_id,
            already_executed=already_executed,
        )
        # 9-11. executar + SEMPRE fechar a sessão, mesmo se o scheduler
        # levantar exceção (crash de módulo não capturado, erro de DB,
        # KeyboardInterrupt etc). Sem esse try/finally, uma falha aqui
        # deixava `scans.finished_at` NULL para sempre nessa linha --
        # e get_scans_for_target() filtra `WHERE finished_at IS NOT NULL`,
        # então o scan (e seus findings já salvos) sumia do Histórico
        # permanentemente, mesmo em tentativas futuras.
        report = None
        try:
            findings = scheduler.run()
            self.memory.finalize_finding_statuses(self.target, session_id)
            report = ScanReport(
                target=self.target,
                site_type=site_type,
                session_id=session_id,
                findings=findings,
                wave_count=len(scheduler.wave_reports),
                wave_reports=scheduler.wave_reports,
                module_metadata=self._build_module_metadata(engine),
                facts_seeded_from_memory=seeded,
                knowledge_snapshot=store.snapshot(),
            )
            return report
        finally:
            try:
                self.memory.finish_session(session_id)
            finally:
                try:
                    self._persist_audit(report)
                except Exception as audit_exc:
                    self._external_on_log(f"[!] Auditoria Parquet indisponível: {audit_exc}")

    def _open_session(self, site_type: str) -> tuple[int, str, set[str]]:
        """
        Decide entre retomar uma sessão interrompida ou abrir uma nova.

        Retorna (scan_id, session_id, already_executed) -- already_executed
        é um set vazio para sessão nova, ou o conjunto de módulos já
        executados na tentativa anterior, lido do Postgres (durável, não do
        Redis efêmero), para sessão retomada.
        """
        if self.resume:
            resumable = self.memory.get_resumable_session(self.target)
            if resumable:
                self.on_log(
                    f"[i] Sessão interrompida encontrada (iniciada em "
                    f"{resumable['started_at']}) -- retomando em vez de reiniciar."
                )
                already_executed = self.memory.get_executed_modules(resumable["session_id"])
                return resumable["scan_id"], resumable["session_id"], already_executed

        session_id = self.memory.start_session(self.target, site_type)
        # start_session original não retorna scan_id (id numérico da linha em
        # `scans`) -- precisamos dele para save_finding/mark_module_done_durable,
        # então buscamos pelo session_id recém-criado via método da extensão
        # (1 query extra, barata, só acontece uma vez no início do scan).
        scan_id = self.memory.get_scan_id_for_session(session_id)
        return scan_id, session_id, set()

    def _run_without_memory(self) -> ScanReport:
        """Modo degradado: sem MemoryManager não há cache de perfil, sem
        persistência de fatos duráveis, sem hit_rate aprendido, sem cache de
        findings recentes. O scan ainda assim descobre a cadeia DENTRO da
        própria sessão (a classificação e o encadeamento requires/produces
        continuam funcionando — só não atravessam para o próximo scan)."""
        self.on_log("[!] Memória indisponível — scan roda sem histórico nem persistência.")

        classifier = SiteClassifier()
        site_type, _indicators = classifier.classify(self.target)
        self.on_log(f"[i] Site detectado como: {site_type}")

        store = KnowledgeStore(self.target, memory_manager=None)
        for f in self.initial_facts:
            store.assert_fact(f)

        engine = ActivationEngine(store, site_type=site_type)
        engine.register(self.module_classes)

        priority_calc = PriorityCalculator(store, hit_rates={})
        scheduler = DiscoveryScheduler(
            target=self.target,
            store=store,
            engine=engine,
            priority_calc=priority_calc,
            budget=self.budget,
            max_workers=self.max_workers,
            on_log=self.on_log,
            on_progress=self.on_progress,
            memory=None,
        )
        findings = scheduler.run()

        return ScanReport(
            target=self.target,
            site_type=site_type,
            session_id="",
            findings=findings,
            wave_count=len(scheduler.wave_reports),
            wave_reports=scheduler.wave_reports,
            module_metadata=self._build_module_metadata(engine),
            facts_seeded_from_memory=0,
            knowledge_snapshot=store.snapshot(),
        )

    def _build_module_metadata(self, engine: ActivationEngine) -> dict:
        """Resolve ModuleSpec.describe() para cada módulo registrado no
        engine -- chamado uma vez, no fim do scan, com acesso direto às
        classes (engine._registry guarda RegisteredModule.module_class)."""
        return {
            rm.name: rm.spec.describe(rm.module_class)
            for rm in engine._registry.values()
        }