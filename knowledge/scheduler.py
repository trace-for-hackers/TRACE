"""
knowledge/scheduler.py

O DiscoveryScheduler substitui a lógica hoje embutida em main_gui.py
(ScanWorker.run), que ordenava os módulos uma vez por hit_rate e disparava
todos de uma vez via ThreadPoolExecutor.

Modelo novo: execução em ONDAS.

    Onda 0: todos os módulos "raiz" (is_root() == True) -- os que hoje
            chamaríamos de "detectores básicos". Rodam sempre, em paralelo.
    Onda N: a fronteira de módulos que se tornaram elegíveis por causa dos
            fatos produzidos nas ondas anteriores.

O loop termina quando uma onda não produz nenhum módulo novo elegível
(fronteira vazia) -- ou quando o orçamento global de requisições/tempo
é atingido (circuit breaker, seção 9).

Cada onda roda módulos em paralelo entre si (não há dependência DENTRO da
mesma onda, por definição -- se houvesse, um dependeria do fato que o outro
ainda não produziu, e ficaria pra próxima onda). Isso preserva e até
melhora o paralelismo que já existe hoje via ThreadPoolExecutor.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from knowledge.engine import ActivationEngine, RegisteredModule
from knowledge.priority import PriorityCalculator
from knowledge.result import normalize_result, ModuleResult
from knowledge.store import KnowledgeStore
from observability import span, target_identity, record_exception, init_metrics
import time


@dataclass
class ScanBudget:
    """Circuit breaker global -- garante que mesmo num cenário inesperado
    (bug de spec, fato oscilando) o scan tem um teto duro de trabalho."""
    max_requests_estimated: int = 500     # soma de spec.cost dos módulos executados
    max_waves: int = 25
    requests_used: int = 0
    waves_used: int = 0

    def can_afford(self, cost: int) -> bool:
        return self.requests_used + cost <= self.max_requests_estimated

    def register_execution(self, cost: int) -> None:
        self.requests_used += cost

    def has_wave_budget(self) -> bool:
        return self.waves_used < self.max_waves


@dataclass
class WaveReport:
    wave_number: int
    modules_run: list[str] = field(default_factory=list)
    # cada entrada: (fact_key, produced_by) -- preserva proveniência exata
    # (o próprio Fact já sabe quem o produziu) em vez de descartar essa
    # informação e tentar adivinhar depois por timing de onda.
    new_facts: list[tuple[str, str]] = field(default_factory=list)
    # causalidade explícita: para cada módulo executado nesta onda, quais
    # fact_keys (já presentes no KnowledgeStore NO MOMENTO da seleção, antes
    # de qualquer fato novo desta própria onda) satisfizeram seu Requirement.
    # Sem isso, reconstruir "por que esse módulo rodou" depois do fato
    # significa adivinhar por timing/ordem de onda -- frágil e pode mentir
    # se dois fatos relevantes aparecerem na mesma onda. Capturado no
    # instante da decisão (ver DiscoveryScheduler.run(), antes de _execute_wave),
    # não reconstruído depois.
    triggered_by: dict[str, list[str]] = field(default_factory=dict)


class DiscoveryScheduler:
    def __init__(
        self,
        target: str,
        store: KnowledgeStore,
        engine: ActivationEngine,
        priority_calc: PriorityCalculator,
        budget: ScanBudget | None = None,
        max_workers: int = 5,
        on_log=None,
        on_progress=None,
        memory=None,
        scan_id: int | None = None,
        session_id: str | None = None,
        already_executed: set[str] | None = None,
    ):
        self.target = target
        self.store = store
        self.engine = engine
        self.priority_calc = priority_calc
        self.budget = budget or ScanBudget()
        self.max_workers = max_workers
        self.on_log = on_log or (lambda msg: None)
        # on_progress(done, estimated_total) -- chamado após cada módulo concluído.
        # estimated_total é reestimado a cada onda (nº de módulos registrados que
        # ainda têm orçamento de execução restante), já que o total real só se
        # revela conforme a cadeia se desenrola -- diferente de um loop fixo, não
        # há como saber "quantos módulos vão rodar" antes do scan terminar.
        self.on_progress = on_progress or (lambda done, total: None)
        self.memory = memory  # opcional: se presente, habilita skip por finding recente
                              # e persistência incremental (findings + módulos executados)
        self.scan_id = scan_id        # id numérico em `scans`, exigido para save_finding/
                                       # mark_module_done_durable -- None desabilita persistência
                                       # incremental mesmo se memory estiver presente
        self.session_id = session_id
        # módulos que já rodaram numa tentativa ANTERIOR deste mesmo scan
        # (retomada após interrupção) -- são pulados sem reexecutar, e seus
        # findings já salvos no Postgres são recuperados em vez de perdidos.
        # Ver ScanSession._try_resume() em bootstrap.py para como isso é populado.
        self.already_executed = already_executed or set()

        self.findings: list[dict] = []
        self.wave_reports: list[WaveReport] = []
        self._done_count = 0
        self._wave_estimated_total = 1
        # módulos que JÁ rodaram (de verdade ou via cache) nesta tentativa de
        # scan -- ver uso em _execute_wave. BUG REAL encontrado testando
        # ponta a ponta um sistema irmão que reaproveita este mesmo scheduler
        # (29/08/2026): o skip por "achado recente" foi pensado pra pular
        # módulo caro entre SCANS DIFERENTES do mesmo alvo (dias de
        # intervalo) -- mas um módulo altamente reentrante DENTRO do mesmo
        # scan (ex.: wp_known_vulnerable_assets, max_reentries=15) fica
        # "recente" já na sua PRÓPRIA segunda invocação, segundos depois da
        # primeira. Sem essa distinção, cada reentrância subsequente tomava
        # o atalho de cache e reanexava o MESMO achado de novo -- 1 achado
        # real virava 3 no relatório final, mesmo com o dedup interno do
        # módulo (o `_reported` de classe) funcionando perfeitamente -- o
        # dedup nunca chegava a rodar, porque o atalho de cache intercepta
        # ANTES de chamar run().
        self._ran_at_least_once_this_scan: set[str] = set(self.already_executed)
        self._metrics = init_metrics()

    def _log(self, msg: str) -> None:
        self.on_log(msg)

    def run(self) -> list[dict]:
        wave_number = 0
        total_registered = len(self.engine._registry)

        if self.already_executed:
            self._log(
                f"[i] Retomando scan: {len(self.already_executed)} módulo(s) já "
                f"executado(s) em tentativa anterior, serão pulados."
            )
            # LIMITAÇÃO CONHECIDA: fatos DURÁVEIS (Produces.durable=True) de
            # módulos já executados são recarregados automaticamente por
            # ScanSession via memory.seed_knowledge_store() ANTES do scheduler
            # começar (ver bootstrap.py) -- então a cadeia continua corretamente
            # para esses casos. Fatos NÃO-duráveis (ex.: surface.rest_api.present,
            # que tem durable=False) nunca foram persistidos, então não há como
            # recuperá-los aqui: módulos que dependiam deles podem ficar
            # bloqueados nesta retomada, mesmo que o módulo produtor já tenha
            # rodado de fato na tentativa anterior. Isso é uma degradação
            # aceitável (a cadeia para mais cedo do que o ideal), não um erro --
            # mas vale considerar, ao decorar um módulo, se o fato que ele
            # produz deveria ser durable=True quando a retomada importa.
            for module_name in self.already_executed:
                self.engine.mark_executed(module_name)
            if self.memory and self.scan_id:
                # get_findings_for_scan() -- versão MÍNIMA, propósito
                # específico pra retomada (não get_findings_for_scan_id,
                # que é a versão rica usada por scan_diff/vuln_history/
                # histórico da GUI). As duas coexistem de propósito -- ver
                # core/memory.py.
                recovered = self.memory.get_findings_for_scan(self.scan_id)
                self.findings.extend(recovered)
                self._log(f"[i] {len(recovered)} achado(s) recuperado(s) da tentativa anterior.")
            self._done_count = len(self.already_executed)

        while self.budget.has_wave_budget():
            eligible = self.engine.get_eligible_modules()
            runnable = [
                rm for rm in eligible
                if rm.name not in self._currently_or_already_running()
                and self.budget.can_afford(rm.spec.cost)
            ]

            if not runnable:
                self._log(f"[i] Onda {wave_number}: nenhum módulo novo elegível. Scan estabilizado.")
                break

            ranked = self.priority_calc.rank(runnable)
            self._log(
                f"[i] Onda {wave_number}: {len(ranked)} módulo(s) elegível(is) -> "
                + ", ".join(rm.name for rm in ranked)
            )

            # captura a causalidade ANTES de executar -- quais fact_keys
            # satisfizeram o Requirement de cada módulo nesta seleção. Módulos
            # raiz (requires=[]) não têm causa de fato, ficam com lista vazia
            # (representados no grafo como "ponto de entrada", não como
            # filhos de nenhum nó).
            triggered_by = {
                rm.name: [r.fact_key for r in rm.spec.requires if self.engine._requirement_satisfied(r)]
                for rm in ranked
            }
            # Capturado ANTES da onda começar. Se outro módulo da mesma onda
            # produzir conhecimento novo, o módulo atual não o viu; portanto a
            # assinatura antiga precisa permanecer registrada para permitir uma
            # reentrada correta na próxima onda.
            trigger_signatures = {
                rm.name: self.engine.requirement_signature(rm)
                for rm in ranked
            }

            # estimativa de progresso: nunca sabemos o total real até o fim
            # (o total só se revela conforme a cadeia se desenrola), então
            # usamos "executados até agora + nesta onda" como piso, e
            # "total registrado" como teto -- a barra sobe de forma
            # monotônica e nunca recua, mesmo que a estimativa seja grosseira.
            self._wave_estimated_total = max(total_registered, self._done_count + len(ranked))

            wave_started = time.perf_counter()
            with span("trace.wave", {
                "scan.wave": wave_number,
                "scan.module_count": len(ranked),
                **target_identity(self.target),
            }) as wave_span:
                report = self._execute_wave(wave_number, ranked, triggered_by, trigger_signatures, wave_span)
            if self._metrics:
                self._metrics["wave_duration"].record(time.perf_counter() - wave_started, {"target.host": target_identity(self.target)["target.host"]})
            self.wave_reports.append(report)

            wave_number += 1
            self.budget.waves_used += 1

        self.on_progress(self._done_count, max(self._done_count, 1))
        return self.findings


    def _currently_or_already_running(self) -> set[str]:
        """Módulos que já consumiram todo o orçamento de reentrância não devem
        ser re-selecionados -- get_eligible_modules já filtra isso via
        can_still_run(), mas mantemos a checagem explícita aqui por clareza
        e como salvaguarda redundante (defesa em profundidade contra bugs
        futuros no engine)."""
        return {
            rm.name for rm in self.engine._registry.values()
            if not rm.can_still_run()
        }

    def _execute_wave(self, wave_number: int, ranked: list[RegisteredModule], triggered_by: dict[str, list[str]], trigger_signatures: dict[str, tuple], wave_span=None) -> WaveReport:
        report = WaveReport(wave_number=wave_number, triggered_by=triggered_by)
        to_run = []

        # ── skip por finding recente (comportamento que já existia no
        # ScanWorker.run() de main_gui.py — preservado aqui para não regredir
        # a UX: módulos com achado recente devolvem o resultado em cache em
        # vez de bater na rede de novo) ──────────────────────────────────────
        for rm in ranked:
            # o atalho de cache só vale pra um módulo que ainda NÃO rodou
            # nesta tentativa de scan -- ver docstring de
            # _ran_at_least_once_this_scan no __init__. Uma vez que já rodou
            # aqui, qualquer reentrância subsequente vai direto pra run() de
            # verdade, deixando o dedup interno do próprio módulo (se houver)
            # decidir se há algo novo -- em vez do scheduler reanexar
            # cegamente o mesmo achado salvo na execução anterior.
            if (
                rm.name not in self._ran_at_least_once_this_scan
                and self.memory
                and self.memory.finding_exists_recently(self.target, rm.name)
            ):
                cached = self.memory.get_recent_findings(self.target, rm.name)
                if cached:
                    self.findings.extend(cached)
                    self._log(f"[~] {rm.name}: achado recente recuperado do cache ({cached[0].get('cached_date', '?')}) — não re-executado.")
                else:
                    self._log(f"[~] {rm.name}: pulado (achado recente, sem dados em cache para recuperar).")
                # consome o orçamento de reentrância mesmo sem rodar de fato —
                # senão ficaria "elegível" para sempre e nunca estabilizaria,
                # já que nenhum fato novo seria produzido para tirá-lo da fronteira.
                self.engine.mark_executed(rm.name, trigger_signatures.get(rm.name))
                self._ran_at_least_once_this_scan.add(rm.name)
                report.modules_run.append(rm.name)
                self._done_count += 1
                self.on_progress(self._done_count, self._wave_estimated_total)
                if self.memory and self.scan_id and self.session_id:
                    self.memory.mark_module_done_durable(self.scan_id, self.session_id, rm.name, via_cache=True)
                continue
            to_run.append(rm)

        if not to_run:
            return report

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for rm in to_run:
                self.budget.register_execution(rm.spec.cost)
                instance = rm.module_class()
                futures[executor.submit(self._invoke_in_span, instance, rm, wave_number)] = rm

            for future in as_completed(futures):
                rm = futures[future]
                errored = False
                try:
                    raw = future.result()
                    result: ModuleResult = normalize_result(raw)

                    if result.findings:
                        self.findings.extend(result.findings)
                        self._log(f"[✓] {rm.name}: {len(result.findings)} achado(s).")

                        # PERSISTÊNCIA INCREMENTAL: salva cada finding assim que
                        # é produzido, não no fim do scan inteiro (knowledge/
                        # bootstrap.py antes salvava tudo de uma vez só depois de
                        # scheduler.run() retornar -- se o processo morresse no
                        # meio da onda 3, os achados das ondas 0-2 já confirmados
                        # se perdiam completamente, mesmo já estando prontos).
                        if self._metrics:
                            self._metrics["findings"].add(len(result.findings), {"module.name": rm.name})
                        if self.memory and self.session_id:
                            for finding in result.findings:
                                self.memory.save_finding(finding, self.target, self.session_id)
                    else:
                        self._log(f"[-] {rm.name}: nada detectado.")

                    for produced_fact in result.facts:
                        self.store.assert_fact(
                            produced_fact,
                            durable=self._is_durable(rm, str(produced_fact.key)),
                        )
                        report.new_facts.append((str(produced_fact.key), produced_fact.produced_by))
                        self._log(f"    -> fato produzido: {produced_fact.key} = {produced_fact.value} (conf={produced_fact.confidence})")

                except Exception as e:
                    self._log(f"[!] Erro em {rm.name}: {e}")
                    errored = True
                finally:
                    if self._metrics:
                        self._metrics["module_runs"].add(1, {"module.name": rm.name})
                        if errored:
                            self._metrics["module_errors"].add(1, {"module.name": rm.name})
                    self.engine.mark_executed(rm.name, trigger_signatures.get(rm.name))
                    self._ran_at_least_once_this_scan.add(rm.name)
                    report.modules_run.append(rm.name)
                    self._done_count += 1
                    self.on_progress(self._done_count, self._wave_estimated_total)
                    if self.memory and self.scan_id and self.session_id:
                        self.memory.mark_module_done_durable(
                            self.scan_id, self.session_id, rm.name, errored=errored,
                        )

        return report


    def _invoke_in_span(self, instance, rm: RegisteredModule, wave_number: int):
        attrs = {
            "module.name": rm.name,
            "module.category": getattr(rm.spec, "category", "unknown"),
            "module.cost": rm.spec.cost,
            "scan.wave": wave_number,
            "module.reentry": rm.executions_used > 0,
            **target_identity(self.target),
        }
        with span("trace.module", attrs) as current:
            try:
                result = self._invoke_module(instance, rm)
                if current is not None:
                    normalized = normalize_result(result)
                    current.set_attribute("module.findings", len(normalized.findings))
                    current.set_attribute("module.facts", len(normalized.facts))
                return result
            except Exception as exc:
                record_exception(current, exc)
                raise

    def _invoke_module(self, instance, rm: RegisteredModule):
        """
        Chama instance.run() com a assinatura correta, de forma retrocompatível.

        A esmagadora maioria dos módulos (todos os 44 atuais) tem a assinatura
        run(self, target) -- só checam PRESENÇA/CONFIANÇA de fatos via
        Requirement, nunca precisam ler o VALOR de um fato. Esses continuam
        chamados exatamente como sempre.

        Módulos que precisam ler o valor completo de um fato (ex.:
        wp_known_vulnerable_assets.py, que precisa de todos os fatos
        tech.<slug>.version já conhecidos) declaram run(self, target, facts)
        -- o segundo parâmetro recebe um dict {fact_key: Fact | list[Fact]}
        com exatamente os fatos listados no `requires` do ModuleSpec.

        Requirement com wildcard (fact_key terminando em ".*", ex.: "tech.*")
        resolve para uma LISTA de Facts via store.query_prefix() -- é assim
        que wp_known_vulnerable_assets enxerga "todos os fatos tech.* que já
        apareceram até agora", não só um. Requirement de chave exata continua
        resolvendo pra um Fact único (ou None). Esse branch não existia até
        29/08/2026: sem ele, um módulo com Requirement("tech.*") era elegível
        corretamente, mas recebia facts={"tech.*": None} -- eligível, porém
        cego, porque store.get("tech.*") busca a chave LITERAL "tech.*", que
        nunca existe. Descoberto ao implementar o primeiro módulo que
        realmente precisava disso.

        Detectado via inspect.signature, não por convenção de nome -- um
        módulo legado nunca precisa saber que esse parâmetro existe.
        """
        import inspect

        sig = inspect.signature(instance.run)
        if len(sig.parameters) <= 1:  # só 'target' (self já não conta em bound method)
            return instance.run(self.target)

        facts = {}
        for req in rm.spec.requires:
            if req.fact_key.endswith(".*"):
                facts[req.fact_key] = self.store.query_prefix(req.fact_key[:-2])
            else:
                facts[req.fact_key] = self.store.get(req.fact_key)
        return instance.run(self.target, facts)

    def _is_durable(self, rm: RegisteredModule, fact_key: str) -> bool:
        for p in rm.spec.produces:
            if p.fact_key == fact_key:
                return p.durable
        return False