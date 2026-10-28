"""
core/report_data.py

Camada de EXTRAÇÃO E NARRAÇÃO pro relatório de cliente -- transforma
ScanReport (achado bruto + wave_reports com causalidade) em uma
estrutura de dado pronta pra virar Markdown/JSON/PDF. Não gera nenhum
formato final aqui -- isso é report_generator.py. Este arquivo só monta
o CONTEÚDO, testável sem precisar de template nenhum.

Por que precisa do ScanReport "fresco" (não só o que está persistido no
SQLite): a cadeia causal (WaveReport.triggered_by) não é persistida a
longo prazo -- é reconstruída aqui a partir do objeto em memória, logo
depois que ScanSession.run() retorna. Chamar isso dias depois, só com o
banco, ainda funciona pra achado/severidade/CWE, mas a narração da
cadeia de evidência fica mais pobre (ver narrate_causal_chain).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.risk import calculate_risk

_TAXONOMY_PATH = Path(__file__).resolve().parent.parent / "config" / "vulnerability_taxonomy.yaml"
_taxonomy_cache: dict | None = None

# Frase FIXA, deliberadamente conservadora -- "associado a risco de
# descumprimento", nunca "viola". Reaproveita o business_risk_description
# que cada categoria já tem (não duplica 17 frases quase iguais no YAML,
# o que aumentaria a chance de uma delas usar linguagem mais forte por
# acidente). Seção OPT-IN (include_lgpd=False por padrão) -- ver
# main.py --include-lgpd e a ressalva na conversa sobre revisão jurídica
# antes de usar em relatório de cliente de verdade.
_LGPD_NOTE_TEMPLATE = (
    "Esta condição está associada a risco de descumprimento do Art. 46 da LGPD "
    "(dever de adotar medidas de segurança técnicas e administrativas aptas a "
    "proteger dado pessoal), caso o ativo afetado trate dado pessoal de titular: "
    "{risk_description}"
)

_LGPD_DISCLAIMER = (
    "Referências à LGPD nesta seção são indicativas de risco regulatório associado "
    "ao tipo de falha técnica encontrada, e não constituem parecer jurídico nem "
    "determinação de violação. A aplicabilidade depende de fator que este scan não "
    "avalia (se o ativo trata dado pessoal, existência de outra camada de controle, "
    "ocorrência de incidente real). Recomenda-se avaliação por profissional jurídico "
    "ou encarregado (DPO) para conclusão de conformidade."
)


def build_lgpd_note(risk_description: str) -> str:
    return _LGPD_NOTE_TEMPLATE.format(risk_description=risk_description)


def lifecycle_label(finding: dict) -> str:
    """Converte o estado persistido do finding em uma classificação amigável
    para o relatório de cliente.

    A classificação usa o estado do ciclo de vida já calculado pelo
    MemoryManager (is_new/status, ver core/memory.py), sem inventar
    histórico quando ele não existe -- achado sem esses campos (ex.:
    ScanReport reconstruído só do disco, sem persistência ativa) cai em
    "Estado não determinado", não em suposição.
    """
    status = str(finding.get("status") or "").lower()
    is_new = bool(finding.get("is_new"))

    if status == "new" or is_new:
        return "Nova nesta análise"
    if status == "reopened":
        return "Retornou (reaberta)"
    if status == "closed":
        return "Resolvida / fechada"
    if status == "seen":
        return "Já conhecida (persistente)"
    return "Estado não determinado"


def lifecycle_detail(finding: dict) -> str:
    """Gera uma frase curta com a primeira e a última observação conhecida."""
    first_seen = finding.get("first_seen")
    last_seen = finding.get("last_seen")
    if first_seen and last_seen and first_seen != last_seen:
        return f"Primeira observação: {first_seen} · Última observação: {last_seen}"
    if first_seen:
        return f"Primeira observação: {first_seen}"
    return "Sem histórico temporal disponível."


def load_taxonomy() -> dict:
    global _taxonomy_cache
    if _taxonomy_cache is None:
        with open(_TAXONOMY_PATH, "r", encoding="utf-8") as f:
            _taxonomy_cache = yaml.safe_load(f)
    return _taxonomy_cache


def enrich_finding(finding: dict, taxonomy: dict | None = None) -> dict:
    """Combina o achado bruto com a entrada da taxonomia correspondente
    -- category desconhecida cai no `_default` em vez de quebrar."""
    taxonomy = taxonomy or load_taxonomy()
    category = finding.get("category", "_default")
    entry = taxonomy.get(category) or taxonomy["_default"]

    enriched = dict(finding)
    enriched["owasp"] = entry["owasp"]
    enriched["owasp_url"] = entry["owasp_url"]
    enriched["cwe"] = entry["cwe"]
    enriched["cwe_url"] = entry["cwe_url"]
    # remediation ESPECÍFICA do achado (já escrita por cada módulo) tem
    # prioridade sobre o template genérico da categoria -- só cai pro
    # template quando o módulo não forneceu nada.
    if not enriched.get("remediation"):
        enriched["remediation"] = entry["remediation_template"]
    enriched["business_risk_description"] = entry["risk_description_template"]
    return enriched


def _find_module_that_produced(wave_reports, fact_key: str) -> str | None:
    for wave in wave_reports:
        for produced_key, produced_by in getattr(wave, "new_facts", []):
            if produced_key == fact_key:
                return produced_by
    return None


_EVIDENCE_LABELS = {
    "url": "URL testada", "method": "Método", "param": "Parâmetro", "payload": "Payload enviado",
    "technique": "Técnica", "engine": "Motor/biblioteca identificado", "cve": "CVE",
    "detected_version": "Versão detectada", "library": "Biblioteca", "version": "Versão",
    "package_name": "Pacote", "path": "Caminho testado", "status": "Status HTTP",
    "callback_token": "Token de callback", "identity": "Identidade usada",
    "weak_secret": "Segredo fraco confirmado", "internal_target": "Alvo interno testado",
    "library_detected": "Biblioteca detectada", "probe_origin": "Origin de teste enviado",
    "detected_step": "Passo sequencial detectado", "samples": "Amostras coletadas",
    # levantado sistematicamente (09/2026) via varredura de modules/*.py --
    # ver test_report_data.py::test_toda_chave_de_evidence_tem_rotulo
    "affected_range": "Faixa de versão afetada", "all_response_headers": "Headers de resposta completos",
    "attacker_identity": "Identidade atacante", "average_entropy_bits_per_char": "Entropia média (bits/caractere)",
    "baseline_denied_signature": "Assinatura de negação no baseline", "baseline_id": "ID de baseline",
    "baseline_seconds": "Tempo de baseline (s)", "baseline_value": "Valor de baseline",
    "blocked_by_modern_browsers": "Bloqueado por navegador moderno", "body_format": "Formato do corpo",
    "combined_confidence": "Confiança combinada", "confirmation": "Confirmação",
    "cookie_name": "Nome do cookie", "cpe": "CPE", "cpe_matches": "CPEs correspondentes",
    "endpoint": "Endpoint", "error_kind": "Tipo de erro", "expected_result": "Resultado esperado",
    "field": "Campo", "form_action": "Destino do formulário", "header": "Header",
    "header_value": "Valor do header", "headers": "Headers", "id_location": "Localização do ID",
    "installed_version": "Versão instalada", "length": "Tamanho", "login_endpoint": "Endpoint de login",
    "marker_used": "Marcador usado", "missing_header": "Header ausente",
    "negotiated_cipher": "Cifra negociada", "negotiated_protocol": "Protocolo negociado",
    "owner_identities": "Identidade(s) proprietária(s)", "page_served_over_https": "Página servida via HTTPS",
    "poisoned_id": "ID manipulado", "poisoned_value": "Valor manipulado", "probe_path": "Caminho de sondagem",
    "product": "Produto", "raw_error": "Erro bruto", "redirect_via": "Redirecionado via",
    "resource_id": "ID do recurso", "resource_url": "URL do recurso", "response_headers": "Headers de resposta",
    "script_url": "URL do script", "sensitive_fields": "Campos sensíveis",
    "sensitive_fields_confirmed_in_response": "Campos sensíveis confirmados na resposta",
    "sensitive_fields_declared_in_spec": "Campos sensíveis declarados no spec",
    "signals": "Sinais observados", "signature_kind": "Tipo de assinatura", "slug": "Slug",
    "tag": "Tag HTML", "test_seconds": "Tempo de teste (s)", "tested_identity": "Identidade testada",
    "url_template": "Template de URL", "value_unchanged": "Valor que não mudou",
    "vendor": "Fabricante", "victim_id": "ID da vítima", "webhook_field": "Campo de webhook",
    "write_endpoint": "Endpoint de escrita", "comando_sugerido": "Comando sugerido",
}


def _format_evidence_value(value) -> str:
    """Reduz valor complexo (dict, list) a uma linha legível -- sem
    tentar ser exaustivo, só o bastante pra não quebrar renderização
    nem virar despejo de estrutura Python bruta na tela."""
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in list(value.items())[:5])
    if isinstance(value, (list, tuple)):
        shown = value[:5]
        suffix = f" (+{len(value) - 5} outro(s))" if len(value) > 5 else ""
        return ", ".join(str(v) for v in shown) + suffix
    return str(value)


def render_evidence_lines(evidence: dict | None) -> list[str]:
    """Transforma o dict evidence bruto (que cada módulo já anexa ao
    finding, ver modules/*.py) em linha 'Rótulo: valor' pro relatório --
    isso é O DADO TÉCNICO que confirma como o TRACE chegou no achado
    (payload exato, URL, status, etc.), diferente de
    narrate_causal_chain (que explica só a ORDEM de módulo que rodou).
    Genérico o bastante pra funcionar com qualquer um dos 90+ módulos
    sem precisar de caso especial por módulo -- rótulo desconhecido usa
    o próprio nome da chave, capitalizado."""
    if not evidence or not isinstance(evidence, dict):
        return []
    lines = []
    for key, value in evidence.items():
        if value in (None, "", [], {}):
            continue
        label = _EVIDENCE_LABELS.get(key, key.replace("_", " ").capitalize())
        lines.append(f"{label}: {_format_evidence_value(value)}")
    return lines


def narrate_causal_chain(finding: dict, scan_report) -> list[str]:
    """Reconstrói a cadeia 'por que esse achado apareceu', em frases
    simples, a partir de WaveReport.triggered_by -- rastreando pra trás
    do módulo que produziu o achado até os fatos-raiz que o motor
    descobriu sozinho (sem depender de nada). Nunca despeja o grafo
    bruto -- cada elo vira uma frase.

    Retorna lista vazia se scan_report não tiver wave_reports (ex.:
    relatório gerado dias depois, só com dado persistido) -- o chamador
    trata isso como 'narração não disponível', não como erro.
    """
    module_name = finding.get("module") or finding.get("module_name")
    if not module_name or not getattr(scan_report, "wave_reports", None):
        return []

    wave_reports = scan_report.wave_reports
    triggering_facts = None
    for wave in wave_reports:
        if module_name in wave.triggered_by:
            triggering_facts = wave.triggered_by[module_name]
            break

    if not triggering_facts:
        return [f"O módulo '{module_name}' roda de forma independente (não depende de descoberta prévia) e confirmou este achado diretamente."]

    chain = []
    for fact_key in triggering_facts:
        producer = _find_module_that_produced(wave_reports, fact_key)
        if producer:
            chain.append(f"O módulo '{producer}' descobriu '{fact_key}', que habilitou a checagem seguinte.")
        else:
            chain.append(f"O fato '{fact_key}' já estava disponível no início do scan.")

    chain.append(f"Com essa informação disponível, o módulo '{module_name}' rodou e confirmou este achado.")
    return chain


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    """Crítico primeiro, depois alto, médio, baixo, info -- dentro da
    mesma severidade, mantém a ordem em que os achados apareceram
    (sorted() é estável, não reordena empate à toa)."""
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info"), 5))


def select_top_business_risks(enriched_findings: list[dict], limit: int = 5) -> list[dict]:
    """Os N achados de maior impacto, na ordem certa pro resumo
    executivo -- severidade primeiro, depois a ordem em que apareceram
    (estável, não aleatória)."""
    return sort_findings_by_severity(enriched_findings)[:limit]


def modules_actually_run(scan_report) -> list[str]:
    """Lista (sem duplicata, ordem de primeira execução) de todo módulo
    que rodou de verdade nesse scan -- usado na seção de metodologia
    pra descrever cobertura real, não a lista teórica do pacote."""
    seen = []
    for wave in getattr(scan_report, "wave_reports", []):
        for name in wave.modules_run:
            if name not in seen:
                seen.append(name)
    return seen


def build_report_context(
    scan_report,
    *,
    client_name: str,
    scope: str,
    pack_names: list[str],
    scan_date: str,
    module_descriptions: dict | None = None,
    include_lgpd: bool = False,
) -> dict:
    """Monta o dicionário completo de contexto pro relatório -- essa é
    a ÚNICA função que report_generator.py chama pra ter todo o dado
    pronto. module_descriptions é module_name -> ModuleSpec.describe(),
    já resolvido em bootstrap.py (ver ScanReport.module_specs se
    existir, ou None se não disponível -- metodologia fica mais pobre,
    não quebra).

    include_lgpd=False por padrão DE PROPÓSITO -- a seção de LGPD usa
    linguagem conservadora ("associado a risco", nunca "viola"), mas
    ainda assim é conteúdo jurídico-adjacente. Antes de usar num
    relatório de cliente de verdade, vale ter alguém (advogado ou DPO,
    mesmo que revisão pontual/barata) validar a redação uma vez."""
    taxonomy = load_taxonomy()
    findings = list(scan_report.findings)
    enriched = [enrich_finding(f, taxonomy) for f in findings]

    for f in enriched:
        f["evidence_narrative"] = narrate_causal_chain(f, scan_report)
        f["evidence_lines"] = render_evidence_lines(f.get("evidence"))
        f["lifecycle_label"] = lifecycle_label(f)
        f["lifecycle_detail"] = lifecycle_detail(f)
        if include_lgpd:
            f["lgpd_note"] = build_lgpd_note(f["business_risk_description"])

    # Crítico primeiro, depois alto/médio/baixo/info -- afeta tanto o
    # resumo executivo (já ordenava, via select_top_business_risks)
    # quanto a seção "Achados Técnicos Detalhados" completa, que até
    # aqui ficava na ordem bruta em que o scan achou cada coisa.
    enriched = sort_findings_by_severity(enriched)

    risk = calculate_risk(findings, target=scan_report.target)
    top_risks = select_top_business_risks(enriched, limit=5)
    ran_modules = modules_actually_run(scan_report)

    coverage = []
    for name in ran_modules:
        desc = (module_descriptions or {}).get(name, {})
        coverage.append({
            "module": name,
            "display_name": desc.get("display_name", name),
            "summary": desc.get("summary", ""),
        })

    return {
        "meta": {
            "client_name": client_name,
            "scope": scope,
            "pack_names": pack_names,
            "scan_date": scan_date,
            "target": scan_report.target,
            "disclaimer": (
                "Este documento reflete uma análise automatizada com validação de "
                "efeito real, não um teste de intrusão manual completo."
            ),
            "lgpd_disclaimer": _LGPD_DISCLAIMER if include_lgpd else None,
        },
        "risk": risk.to_dict(),
        "top_business_risks": top_risks,
        "findings": enriched,
        "coverage": coverage,
        "site_type": getattr(scan_report, "site_type", "unknown"),
    }
