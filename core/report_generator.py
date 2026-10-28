"""
core/report_generator.py

Orquestra a geração do relatório de cliente em 3 formatos, NESSA ORDEM
de propósito (cada um é o insumo de revisão do próximo):

  1. JSON  -- dado estruturado completo, pra quem quiser auditar/reprocessar
  2. Markdown -- revisão humana rápida antes de mandar pro cliente
  3. PDF   -- entregável final (Jinja2 -> HTML -> WeasyPrint)

Uso típico (ver main.py):
    from core.report_generator import generate_client_report
    generate_client_report(
        scan_report, client_name="Acme Ltda", scope="acme.com.br",
        pack_names=["wordpress"], output_dir="relatorios/acme_2026-09-10",
        module_descriptions=module_descriptions,
    )

DEPENDÊNCIA OPCIONAL: Jinja2 e WeasyPrint (extra `report` do
pyproject.toml). BUG REAL encontrado testando instalação mínima
(09/2026): esse import era incondicional, então instalar o TRACE SEM
o extra `report` quebrava o `trace` INTEIRO na hora de importar
main.py -- mesmo pra rodar um scan simples sem nenhuma intenção de
gerar relatório de cliente. Corrigido pro mesmo padrão de degradação
graciosa que pyarrow/opentelemetry/playwright já usam: falha de import
vira aviso e a função levanta RuntimeError SÓ quando efetivamente
chamada, nunca na hora de importar o módulo.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from weasyprint import HTML as _WeasyHTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

from core.report_data import build_report_context

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def _json_default(obj):
    """Fallback pro json.dumps -- objeto que não é serializável
    diretamente (ex.: algum dataclass esquecido dentro de evidence)
    vira string em vez de quebrar a geração do relatório inteiro."""
    return str(obj)


def render_markdown(context: dict) -> str:
    """Versão Markdown -- pensada pra revisão humana rápida, não pra
    ser bonita. Mesma informação do PDF, sem estilo."""
    meta = context["meta"]
    risk = context["risk"]
    lines = [
        f"# Análise de Vulnerabilidades Automatizada e Validada",
        f"",
        f"**Cliente:** {meta['client_name']}  ",
        f"**Escopo testado:** {meta['scope']}  ",
        f"**Alvo:** {meta['target']}  ",
        f"**Pacote(s):** {', '.join(meta['pack_names']) if meta['pack_names'] else 'Completo'}  ",
        f"**Data:** {meta['scan_date']}",
        f"",
        f"> {meta['disclaimer']}",
        f"",
        f"## Resumo Executivo",
        f"",
        f"**Score de risco: {risk['score']}/100 ({risk['level']})**",
        f"",
        f"| Crítico | Alto | Médio | Baixo |",
        f"|---|---|---|---|",
        f"| {risk['severity_counts'].get('critical', 0)} | {risk['severity_counts'].get('high', 0)} "
        f"| {risk['severity_counts'].get('medium', 0)} | {risk['severity_counts'].get('low', 0)} |",
        f"",
        f"### Principais riscos",
        f"",
    ]

    if context["top_business_risks"]:
        for i, r in enumerate(context["top_business_risks"], 1):
            lines.append(f"{i}. {r['business_risk_description']}")
    else:
        lines.append("Nenhum achado de severidade relevante identificado.")

    lines += ["", "## Metodologia", "", (
        "Análise automatizada com motor de decisão dinâmica -- cada achado listado "
        "foi confirmado por observação de EFEITO REAL, não apenas assinatura ou "
        "status code."
    ), "", "### Módulos executados", ""]

    for item in context["coverage"]:
        lines.append(f"- `{item['module']}` — {item['summary'] or item['display_name']}")

    lines += ["", "**Limitações declaradas:** não cobre lógica de negócio complexa "
                    "nem exploração manual encadeada por um operador humano.", "",
              "## Achados Técnicos Detalhados", ""]

    for f in context["findings"]:
        lines.append(f"### {f['title']} — `{f['severity'].upper()}`")
        lines.append(f"")
        lines.append(f"**{f['owasp']}** · **{f['cwe']}** · Ativo: `{f.get('endpoint', meta['target'])}`")
        lines.append(f"")
        lines.append(f"**Ciclo de vida:** {f['lifecycle_label']} — {f['lifecycle_detail']}")
        lines.append(f"")
        lines.append(f"**Descrição técnica:** {f.get('description', '')}")
        lines.append(f"")
        if f.get("evidence_narrative"):
            lines.append("**Evidência de validação:**")
            for step in f["evidence_narrative"]:
                lines.append(f"1. {step}")
            lines.append("")
        if f.get("evidence_lines"):
            lines.append("**Como o TRACE confirmou (detalhe técnico):**")
            for line in f["evidence_lines"]:
                lines.append(f"- {line}")
            lines.append("")
        lines.append(f"**Recomendação:** {f['remediation']}")
        if f.get("lgpd_note"):
            lines.append("")
            lines.append(f"**LGPD:** {f['lgpd_note']}")
        lines.append("")
        lines.append("---")
        lines.append("")

    if meta.get("lgpd_disclaimer"):
        lines.append(f"> {meta['lgpd_disclaimer']}")
        lines.append("")

    return "\n".join(lines)


def render_html(context: dict) -> str:
    if not JINJA2_AVAILABLE:
        raise RuntimeError(
            "Jinja2 não está instalado -- necessário pra gerar o relatório de cliente "
            "(--client-report). Instale com: pip install trace-scanner[report]"
        )
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")
    return template.render(**context)


def render_pdf(html: str, output_path: str) -> None:
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError(
            "WeasyPrint não está instalado -- necessário pra gerar o relatório de cliente "
            "(--client-report). Instale com: pip install trace-scanner[report]"
        )
    _WeasyHTML(string=html).write_pdf(output_path)


def generate_client_report(
    scan_report,
    *,
    client_name: str,
    scope: str,
    pack_names: list[str],
    output_dir: str,
    scan_date: str | None = None,
    module_descriptions: dict | None = None,
    include_lgpd: bool = False,
) -> dict:
    """Função de topo -- chama isso e recebe de volta os 3 caminhos de
    arquivo gerados. scan_date default é a data de agora (UTC) se não
    informado."""
    scan_date = scan_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    context = build_report_context(
        scan_report, client_name=client_name, scope=scope, pack_names=pack_names,
        scan_date=scan_date, module_descriptions=module_descriptions,
        include_lgpd=include_lgpd,
    )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "relatorio.json"
    md_path = out_dir / "relatorio.md"
    pdf_path = out_dir / "relatorio.pdf"

    json_path.write_text(json.dumps(context, ensure_ascii=False, indent=2, default=_json_default), encoding="utf-8")
    md_path.write_text(render_markdown(context), encoding="utf-8")

    html = render_html(context)
    render_pdf(html, str(pdf_path))

    return {"json": str(json_path), "markdown": str(md_path), "pdf": str(pdf_path)}
