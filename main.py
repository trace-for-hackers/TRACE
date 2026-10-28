#!/usr/bin/env python3
"""
main.py

CLI do TRACE -- sem PySide6 em lugar nenhum da cadeia de import, de
propósito (empacotado via pyproject.toml, comando `trace` instalável).
Orquestra knowledge/engine + scheduler + priority em cima do KnowledgeStore e do
MemoryManager SQLite.

Uso:
    python3 main.py <alvo>
    python3 main.py https://exemplo.com --db ./meu_scan.db
    python3 main.py https://exemplo.com --output achados.txt
    python3 main.py https://exemplo.com --report relatorio.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# BUG REAL encontrado com usuário real (07/09/2026): core/vuln_db.py
# instrui a colocar a chave da Wordfence no .env "igual as credenciais
# do Postgres/Redis" -- mas nada no projeto de fato LIA um .env. python-
# dotenv já estava instalado (é dependência transitiva comum), só nunca
# foi chamado -- colocar a variável no arquivo não fazia diferença
# nenhuma, o processo nunca via ela. load_dotenv() precisa rodar ANTES
# de qualquer módulo que leia os.getenv(...) na hora do import (ver
# core/vuln_db.py, core/memory.py) -- por isso fica logo no topo do
# entrypoint, antes de qualquer outro import do projeto.
from dotenv import load_dotenv
load_dotenv()

from observability import configure_telemetry, shutdown_telemetry
configure_telemetry()

from knowledge.discovery import load_modules
from knowledge.bootstrap import ScanSession
from knowledge.scheduler import ScanBudget
from knowledge.fact import fact
from core.memory import MemoryManager
from utils.requester import register_identity, set_session_cookies, set_intrusive_confirmed, cleanup_test_artifacts, get_test_artifacts
from modules.api_resource_provisioner import configure_openapi_spec
from modules.callback_ssrf_heuristic import configure_callback_host
from utils.html_reporter import generate_html_report
from knowledge.decision_graph import build_decision_graph_html
from core.report_generator import generate_client_report


def _parse_identity_arg(raw: str) -> tuple[str, dict]:
    """Formato: NOME:chave1=valor1;chave2=valor2 -- usado tanto por
    --identity (cookie) quanto --identity-header (header), o parsing é
    idêntico, só muda pra onde o resultado vai depois.

    Ex.: --identity alice:session=A
         --identity-header alice:Authorization=Bearer eyJhbGc...

    Erra alto e claro (ValueError com mensagem específica) em vez de
    silenciosamente registrar uma identidade sem cookie/header nenhum --
    uma identidade mal configurada faria os módulos de BAC/IDOR
    (auth_crawler, idor_correlator, api_resource_provisioner) rodarem
    como se fossem anônimos, sem avisar, e o resultado pareceria "nada
    encontrado" em vez de "configuração errada".
    """
    if ":" not in raw:
        raise ValueError(
            f"'{raw}' inválido -- formato esperado é NOME:chave=valor "
            f"(ex.: alice:session=A ou alice:Authorization=Bearer xyz)"
        )
    name, kv_part = raw.split(":", 1)
    pairs = {}
    for pair in kv_part.split(";"):
        if "=" not in pair:
            raise ValueError(f"'{raw}' inválido -- '{pair}' não é chave=valor")
        k, v = pair.split("=", 1)
        pairs[k.strip()] = v.strip()
    if not pairs:
        raise ValueError(f"'{raw}' não tem nenhum cookie/header -- identidade sem credencial não serve pra nada")
    return name.strip(), pairs


def run_scan(target: str, db_path: str | None, max_requests: int, max_waves: int,
             packs: list[str] | None = None, memory=None, quiet: bool = False,
             resume: bool = True, return_report: bool = False, initial_facts: list | None = None):
    """Escaneia UM alvo usando ScanSession (knowledge/bootstrap.py) --
    a MESMA orquestração que o WRAITH original usa: classificação de
    site, retomada de sessão interrompida, prioridade por hit_rate
    aprendido. Antes desta unificação, o surfacer tinha uma versão
    manual e mais simples disso (engine+scheduler wireados direto aqui),
    e o WRAITH tinha esta -- eram dois motores de fato fazendo a mesma
    coisa de dois jeitos, cada um só sabendo escanear seu próprio
    conjunto de módulos. Agora os dois usam a mesma orquestração.

    `packs` filtra quais famílias de módulo entram no scan ANTES de
    montar a ScanSession -- é por isso que dá pra ter WordPress, SQLi e
    BAC no mesmo motor sem um atrapalhar o outro quando não pedido.

    `memory` pode ser reaproveitado entre alvos de uma fila -- é o que
    faz o hit_rate aprendido num alvo valer no próximo; se None, cria
    um próprio (caso de alvo único).
    """
    from knowledge.packs import filter_modules_by_packs

    own_memory = memory is None
    if own_memory:
        memory = MemoryManager(db_path=db_path)

    module_classes = load_modules()
    module_classes = filter_modules_by_packs(module_classes, packs or [])
    if not module_classes:
        print("[!] Nenhum módulo após filtro de pacote -- nada a fazer.")
        return []

    if not quiet:
        pack_label = f" (pacotes: {', '.join(packs)})" if packs else ""
        print(f"[i] {len(module_classes)} módulo(s) registrado(s){pack_label}.")

    session = ScanSession(
        target=target,
        module_classes=module_classes,
        memory=memory,
        budget=ScanBudget(max_requests_estimated=max_requests, max_waves=max_waves),
        on_log=(lambda m: None) if quiet else print,
        resume=resume,
        initial_facts=initial_facts,
    )

    if not quiet:
        print(f"[i] Iniciando varredura em {target}\n")
    report = session.run()

    if not quiet:
        print(f"\n[i] {target}: {len(report.findings)} achado(s), "
              f"{report.wave_count} onda(s), tipo de site: {report.site_type}.")
    return report if return_report else report.findings


def run_queue(urls: list[str], db_path: str | None, max_requests: int, max_waves: int,
              packs: list[str] | None = None, export_graph: str | None = None,
              initial_facts: list | None = None) -> "TargetQueue":
    """Processa vários alvos em sequência, com memória COMPARTILHADA entre
    eles (um MemoryManager só) -- assim o hit_rate aprendido no alvo N
    prioriza melhor o alvo N+1, e o site_profile de cada alvo fica
    salvo pra reaproveitar numa fila futura. Um alvo que falha (exceção)
    vira status FAILED e o lote continua, em vez de derrubar tudo."""
    from knowledge.target_queue import TargetQueue, TargetStatus

    memory = MemoryManager(db_path=db_path)
    queue = TargetQueue()
    queue.add_many(urls, packs=packs)

    jobs = queue.all_jobs()
    total = len(jobs)
    for i, job in enumerate(jobs, 1):
        print(f"\n{'='*70}\n[{i}/{total}] {job.url}\n{'='*70}")
        job.status = TargetStatus.RUNNING
        try:
            report = run_scan(
                job.url, db_path=None, max_requests=max_requests, max_waves=max_waves,
                packs=job.packs or packs, memory=memory, quiet=False, return_report=True,
                initial_facts=initial_facts,
            )
            job.findings = report.findings
            job.site_type = report.site_type
            job.report = report
            if export_graph:
                from pathlib import Path
                graph_path = Path(export_graph) / f"{i:03d}_{_safe_filename(job.url)}.html"
                write_graph_file(report, str(graph_path))
            job.status = TargetStatus.DONE
        except Exception as e:
            job.status = TargetStatus.FAILED
            job.error = str(e)
            print(f"[!] {job.url} falhou: {e} -- seguindo para o próximo alvo.")

    s = queue.summary()
    print(f"\n{'='*70}\n[i] Fila concluída: {s['done']} ok, {s['failed']} falha(s), "
          f"{s['total_findings']} achado(s) no total.\n{'='*70}")
    return queue


def format_findings(findings: list[dict]) -> str:
    """Monta o texto do relatório -- usado tanto pra imprimir no terminal
    quanto pra gravar em arquivo, uma função só pra não deixar as duas
    saídas divergirem com o tempo."""
    if not findings:
        return "Nenhum achado.\n"

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    lines = ["=" * 70]
    for f in findings_sorted:
        lines.append(f"\n[{f.get('severity', 'info').upper()}] {f.get('title')}")
        lines.append(f"  Módulo: {f.get('module') or f.get('module_name')}")
        lines.append(f"  Endpoint: {f.get('endpoint')}")
        lines.append(f"  {f.get('description', '')}")
        evidence = f.get("evidence")
        if isinstance(evidence, dict) and "comando_sugerido" in evidence:
            lines.append(f"  Comando sugerido: {evidence['comando_sugerido']}")
    lines.append("\n" + "=" * 70)
    return "\n".join(lines) + "\n"


def print_findings(findings: list[dict]) -> None:
    print("\n" + format_findings(findings))


def write_findings_file(findings: list[dict], path: str) -> None:
    """Grava o mesmo texto do terminal num .txt -- best-effort: se não
    conseguir escrever (permissão, disco cheio, diretório inexistente),
    avisa no terminal em vez de derrubar o scan inteiro por causa de um
    problema no PASSO FINAL depois de já ter feito todo o trabalho."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(format_findings(findings))
        print(f"[i] Achados gravados em {path}")
    except OSError as e:
        print(f"[!] Não consegui gravar em {path}: {e}", file=sys.stderr)


def write_report_or_output(findings: list[dict], target_label: str, output_path: str | None, report_path: str | None, target_results: list[dict] | None = None) -> None:
    """Decide entre --report (HTML) e --output (.txt) -- --report SEMPRE
    vence quando os dois são passados juntos (ver help de --report no
    argparse). Mesmo tratamento de erro best-effort do write_findings_file:
    falha aqui não pode apagar o trabalho do scan que já rodou."""
    if report_path:
        if output_path:
            print(f"[i] --report e --output foram passados juntos -- gerando só o HTML ({report_path}), --output ignorado.")
        try:
            generate_html_report(findings, report_path, target_label, targets=target_results)
            print(f"[i] Relatório HTML gravado em {report_path}")
        except OSError as e:
            print(f"[!] Não consegui gravar em {report_path}: {e}", file=sys.stderr)
        return

    if output_path:
        write_findings_file(findings, output_path)


def _safe_filename(value: str) -> str:
    """Transforma uma URL em nome de arquivo estável e seguro para o export."""
    import re
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return name[:120] or "target"


def write_graph_file(scan_report, path: str) -> None:
    """Exporta o grafo de decisão do ScanReport para um HTML standalone."""
    try:
        graph_html = build_decision_graph_html(
            scan_report,
            getattr(scan_report, "knowledge_snapshot", None),
            title=f"TRACE — Grafo de Decisão — {scan_report.target}",
        )
        parent = Path(path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(graph_html)
        print(f"[i] Grafo de decisão exportado para {path}")
    except OSError as e:
        print(f"[!] Não consegui gravar o grafo em {path}: {e}", file=sys.stderr)


def write_client_report(report, target_label: str, out_dir: str, client_name: str | None,
                         scope: str | None, pack_names: list[str], include_lgpd: bool = False) -> None:
    """Best-effort, mesmo padrão dos outros writers -- falha aqui não
    pode apagar o trabalho do scan que já rodou."""
    try:
        paths = generate_client_report(
            report,
            client_name=client_name or target_label,
            scope=scope or target_label,
            pack_names=pack_names,
            output_dir=out_dir,
            module_descriptions=getattr(report, "module_metadata", None),
            include_lgpd=include_lgpd,
        )
        print(f"[i] Relatório de cliente gravado em {paths['pdf']} (+ .md e .json no mesmo diretório)")
    except Exception as e:
        print(f"[!] Não consegui gerar o relatório de cliente em {out_dir}: {type(e).__name__}: {e}", file=sys.stderr)


def identity_count_warning(count: int) -> str | None:
    """Retorna a mensagem de aviso quando só 1 identidade foi registrada,
    ou None quando não há nada a avisar (0 ou 2+). Extraído como função
    pura pra ser testável sem precisar rodar main() inteiro."""
    if count != 1:
        return None
    return (
        "[!] Só 1 identidade registrada -- os módulos de BAC/IDOR "
        "(auth_crawler, idor_correlator) precisam de PELO MENOS 2 pra "
        "fazer sentido: eles testam se a identidade B consegue acessar "
        "um recurso que só a identidade A tocou. Com 1 só, o crawler "
        "roda e registra o que ela possui, mas o correlator nunca vai "
        "encontrar nada -- não porque o alvo é seguro, mas porque não "
        "existe ninguém pra testar cruzado. Adicione pelo menos mais "
        "uma --identity (ex.: --identity bob:session=B)."
    )


def main():
    from knowledge.packs import all_pack_names, get_pack
    from knowledge.target_queue import load_targets_from_file

    parser = argparse.ArgumentParser(description="TRACE -- triagem explicável de superfície de ataque")
    parser.add_argument("target", nargs="?", default=None,
                        help="URL do alvo (ex.: https://exemplo.com). Opcional se usar --targets.")
    parser.add_argument("--targets", default=None, metavar="ARQUIVO.txt",
                        help="Arquivo com uma URL por linha (# e linha em branco ignorados). "
                             "Escaneia todos em fila, com memória compartilhada entre eles.")
    parser.add_argument("--pack", default=None, metavar="p1,p2",
                        help=f"Famílias de módulo a rodar, separadas por vírgula. "
                             f"Disponíveis: {', '.join(all_pack_names())}. Sem essa flag, roda todas.")
    parser.add_argument("--list-packs", action="store_true", help="Lista os pacotes disponíveis e sai.")
    parser.add_argument("--db", default=None, help="Caminho do banco SQLite (padrão: ~/.trace/trace.db, ou $TRACE_DB_PATH)")
    parser.add_argument("--no-resume", action="store_true",
                        help="Não retomar sessão interrompida deste alvo, começar do zero.")
    parser.add_argument("--max-requests", type=int, default=500, help="Teto estimado de requisições (padrão: 500)")
    parser.add_argument("--max-waves", type=int, default=25, help="Teto de ondas de execução (padrão: 25)")
    parser.add_argument(
        "--identity", action="append", default=[], metavar="NOME:cookie=valor",
        help="Registra COOKIE de sessão para uma identidade (BAC/IDOR). "
             "Repetível. Ex.: --identity alice:session=A --identity bob:session=B.",
    )
    parser.add_argument(
        "--identity-header", action="append", default=[], metavar="NOME:Header=valor",
        help="Registra HEADER de autenticação para uma identidade (ex.: "
             "APIs com Bearer token, que não usam cookie). Repetível, e pode "
             "combinar com --identity da mesma identidade (os dois se somam, "
             "não se sobrescrevem). Ex.: --identity-header alice:Authorization=\"Bearer eyJ...\".",
    )
    parser.add_argument(
        "-o", "--output", default=None, metavar="ARQUIVO.txt",
        help="Grava os achados também num arquivo .txt, no mesmo formato "
             "que aparece no terminal. Sem essa flag, só imprime na tela. "
             "Ignorado se --report também for passado.",
    )
    parser.add_argument(
        "--report", default=None, metavar="ARQUIVO.html",
        help="Gera um relatório HTML interativo (gráfico de severidade, "
             "cards expansíveis por achado) em vez do .txt simples -- "
             "usa utils/html_reporter.py. Quando presente, ANULA --output: "
             "só o HTML é gerado, mesmo que os dois sejam passados juntos.",
    )
    parser.add_argument(
        "--export-graph", default=None, metavar="ARQUIVO.html",
        help="Exporta o grafo de decisão do scan para um HTML standalone. "
             "Em --targets, use um diretório para gerar um grafo por alvo.",
    )
    parser.add_argument(
        "--client-report", default=None, metavar="DIRETÓRIO",
        help="Gera o relatório de CLIENTE (Análise de Vulnerabilidades "
             "Automatizada e Validada) em JSON + Markdown + PDF dentro "
             "do diretório informado -- diferente de --report/--output, "
             "que geram o relatório técnico simples. Em --targets, gera "
             "um subdiretório por alvo dentro do diretório informado.",
    )
    parser.add_argument(
        "--client-name", default=None, metavar="NOME",
        help="Nome do cliente exibido na capa do --client-report. "
             "Sem essa flag, usa o próprio alvo como nome.",
    )
    parser.add_argument(
        "--scope", default=None, metavar="TEXTO",
        help="Descrição do escopo autorizado, exibida na capa do "
             "--client-report (ex.: 'www.exemplo.com.br e subdomínios'). "
             "Sem essa flag, usa o próprio alvo.",
    )
    parser.add_argument(
        "--include-lgpd", action="store_true",
        help="DESLIGADO por padrão. Adiciona, em cada achado do "
             "--client-report, uma nota associando o tipo de falha a risco "
             "de descumprimento do Art. 46 da LGPD -- linguagem "
             "deliberadamente conservadora ('associado a risco', nunca "
             "'viola'), com disclaimer de que não é parecer jurídico. "
             "Ainda assim, recomenda-se validar a redação com um "
             "advogado ou DPO antes de usar em relatório de cliente real.",
    )
    parser.add_argument(
        "--openapi-spec", default=None, metavar="CAMINHO_OU_URL",
        help="Caminho local ou URL de um spec OpenAPI do alvo. Ativa o "
             "api_resource_provisioner e o unauthenticated_endpoint_scanner "
             "-- necessário para testar BAC/IDOR em API JSON pura. "
             "Ex.: --openapi-spec http://alvo/openapi3.yml",
    )
    parser.add_argument(
        "--callback-host", default=None, metavar="HOST[:PORTA]",
        help="Endereço que o ALVO consegue alcançar de volta -- ativa "
             "callback_ssrf_heuristic, redirect_chain_ssrf_bypass e "
             "webhook_ssrf_correlator (confirmação de SSRF via canal "
             "out-of-band). Em rede interna, é o IP da máquina rodando "
             "o TRACE; contra alvo na internet pública, precisa ser um "
             "endereço publicamente alcançável. Porta é opcional (o SO "
             "escolhe uma livre se omitida). Ex.: --callback-host 10.0.0.5:8000",
    )
    parser.add_argument(
        "--confirm-intrusive", action="store_true",
        help="DESLIGADO por padrão. Confirma explicitamente autorização pra "
             "rodar módulo que manda payload real de exploração (SQLi, XSS, "
             "SSTI, LDAP injection, command injection). Sem essa flag, esses "
             "módulos ficam elegíveis mas retornam sem fazer nada -- proteção "
             "técnica e jurídica: documenta que o teste intrusivo foi "
             "conscientemente autorizado, não só o scan em geral.",
    )
    parser.add_argument(
        "--cookie", action="append", default=[], metavar="nome=valor",
        help="Cookie de sessão pra sessão ANÔNIMA compartilhada -- diferente "
             "de --identity (usado só pelos módulos de BAC). Necessário pra "
             "alvo que exige login pra ver qualquer página vulnerável (ex.: "
             "DVWA) -- sem isso, crawler.py nunca sai da tela de login, e os "
             "módulos de SQLi/XSS/injeção nunca têm parâmetro pra testar. "
             "Repetível. Ex.: --cookie PHPSESSID=abc123 --cookie security=low",
    )
    args = parser.parse_args()

    if args.list_packs:
        print("Pacotes disponíveis:")
        for name in all_pack_names():
            pack = get_pack(name)
            print(f"  {name:12s} {pack.description}")
        sys.exit(0)

    packs = [p.strip() for p in args.pack.split(",")] if args.pack else []
    if packs:
        for p in packs:
            if get_pack(p) is None:
                print(f"[!] Pacote desconhecido: '{p}'. Use --list-packs para ver os válidos.", file=sys.stderr)
                sys.exit(1)

    if not args.target and not args.targets:
        print("[!] Informe um alvo (URL) ou --targets ARQUIVO.txt.", file=sys.stderr)
        sys.exit(1)

    identity_names = set()
    for raw in args.identity:
        try:
            name, cookies = _parse_identity_arg(raw)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
        register_identity(name, cookies=cookies)
        identity_names.add(name)
        print(f"[i] Identidade '{name}' registrada (cookie).")

    for raw in args.identity_header:
        try:
            name, headers = _parse_identity_arg(raw)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
        register_identity(name, headers=headers)
        identity_names.add(name)
        print(f"[i] Identidade '{name}' registrada (header).")

    if 0 < len(identity_names) < 2:
        print(identity_count_warning(len(identity_names)))

    if args.openapi_spec:
        configure_openapi_spec(args.openapi_spec)
        print(f"[i] Spec OpenAPI configurado: {args.openapi_spec}")

    if args.callback_host:
        if ":" in args.callback_host:
            cb_host, cb_port_str = args.callback_host.rsplit(":", 1)
            try:
                cb_port = int(cb_port_str)
            except ValueError:
                print(f"[!] Porta inválida em --callback-host: '{cb_port_str}'.", file=sys.stderr)
                sys.exit(1)
        else:
            cb_host, cb_port = args.callback_host, 0
        configure_callback_host(cb_host, cb_port)
        print(f"[i] Callback host configurado: {cb_host}" + (f":{cb_port}" if cb_port else " (porta escolhida pelo SO)"))

    if args.cookie:
        cookies = {}
        for raw in args.cookie:
            if "=" not in raw:
                print(f"[!] --cookie '{raw}' inválido -- formato esperado é nome=valor.", file=sys.stderr)
                sys.exit(1)
            k, v = raw.split("=", 1)
            cookies[k.strip()] = v.strip()
        set_session_cookies(cookies)
        print(f"[i] Cookie(s) configurado(s) na sessão anônima: {', '.join(cookies.keys())}")

    if args.confirm_intrusive:
        set_intrusive_confirmed(True)
        print("[i] Teste intrusivo confirmado -- SQLi/XSS/SSTI/LDAP/command injection vão mandar payload real.")
    else:
        print("[i] Teste intrusivo NÃO confirmado -- SQLi/XSS/SSTI/LDAP/command injection ficam elegíveis mas não mandam payload (use --confirm-intrusive pra ativar).")

    # ── fatos de configuração externa, injetados ANTES da onda 0 ──────────
    # Sem isso, todo módulo que depende de identidade/spec/callback-host
    # ficava declarado como raiz (requires=()) só porque o motor não tinha
    # como saber dessa configuração de fora -- sempre elegível na onda 0,
    # sempre executado, sempre se autoabortando com um print de "não roda"
    # quando a config não existia. Isso inflava a onda 0 com módulo
    # garantidamente inútil. Agora essa configuração vira FATO real no
    # motor (config.identity_available, config.openapi_spec_available,
    # config.callback_host_available), e os módulos afetados declaram
    # Requirement de verdade em vez de checagem manual dentro do run().
    config_facts = []
    if len(identity_names) >= 1:
        config_facts.append(fact("config.identity_available", True, 1.0, "cli_config", args.target or "fila"))
    if args.openapi_spec:
        config_facts.append(fact("config.openapi_spec_available", True, 1.0, "cli_config", args.target or "fila"))
    if args.callback_host:
        config_facts.append(fact("config.callback_host_available", True, 1.0, "cli_config", args.target or "fila"))

    # ── fila (--targets) tem precedência; senão, alvo único ──────────────
    if args.targets:
        try:
            urls = load_targets_from_file(args.targets)
        except OSError as e:
            print(f"[!] Não consegui ler {args.targets}: {e}", file=sys.stderr)
            sys.exit(1)
        if not urls:
            print(f"[!] {args.targets} não tem nenhuma URL válida.", file=sys.stderr)
            sys.exit(1)
        for u in urls:
            if not u.startswith(("http://", "https://")):
                print(f"[!] URL sem esquema no arquivo de alvos: '{u}'.", file=sys.stderr)
                sys.exit(1)
        if args.export_graph:
            import os
            os.makedirs(args.export_graph, exist_ok=True)
        queue = run_queue(urls, args.db, args.max_requests, args.max_waves, packs=packs,
                          export_graph=args.export_graph, initial_facts=config_facts)
        all_findings = [f for job in queue.all_jobs() for f in job.findings]
        target_results = [
            {"target": job.url, "findings": job.findings, "site_type": job.site_type, "status": job.status.value, "error": job.error, "report": job.report}
            for job in queue.all_jobs()
        ]
        write_report_or_output(all_findings, f"{len(urls)} alvo(s) (fila)", args.output, args.report, target_results=target_results)
        if args.client_report:
            for job in queue.all_jobs():
                if job.report is None:
                    continue
                sub_dir = str(Path(args.client_report) / _safe_filename(job.url))
                write_client_report(job.report, job.url, sub_dir, args.client_name, args.scope, packs, args.include_lgpd)
        return

    if not args.target.startswith(("http://", "https://")):
        print("[!] Alvo precisa incluir o esquema (http:// ou https://).", file=sys.stderr)
        sys.exit(1)

    report = run_scan(args.target, args.db, args.max_requests, args.max_waves,
                      packs=packs, resume=not args.no_resume, return_report=True,
                      initial_facts=config_facts)
    findings = report.findings
    print_findings(findings)

    write_report_or_output(findings, args.target, args.output, args.report, target_results=[{"target": report.target, "findings": findings, "site_type": report.site_type, "status": "done", "error": None, "report": report}])
    if args.export_graph:
        write_graph_file(report, args.export_graph)
    if args.client_report:
        write_client_report(report, args.target, args.client_report, args.client_name, args.scope, packs, args.include_lgpd)

    artifacts = get_test_artifacts()
    if artifacts:
        result = cleanup_test_artifacts()
        print(f"\n[i] Limpeza de artefato de teste: {len(result['removed'])} removido(s), {len(result['failed'])} precisam de remoção manual.")
        for a in result["failed"]:
            print(f"    [!] Não removido -- {a['kind']}: {a['url']}")


if __name__ == "__main__":
    main()
