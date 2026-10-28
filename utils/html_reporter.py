"""Interactive HTML reporter for TRACE."""

from datetime import datetime
import html
import json

from core.risk import calculate_risk


def _extract_sql_injection_possibilities(report) -> list[dict]:
    """Extrai sinais de heurísticas de SQLi do snapshot final do ScanReport.

    Esses sinais são hipóteses técnicas, não findings confirmados. Mantê-los
    separados evita que um sinal isolado vire automaticamente uma
    vulnerabilidade no score, mas também evita perder informação útil para o
    pentester quando a correlação não atingiu o limiar.
    """
    if report is None:
        return []

    snapshot = getattr(report, "knowledge_snapshot", {}) or {}
    possibilities = []
    seen = set()

    for key, fact_data in snapshot.items():
        if not str(key).startswith("injection.signal."):
            continue

        value = fact_data.get("value", {}) if isinstance(fact_data, dict) else {}
        if not isinstance(value, dict):
            continue

        technique = str(value.get("technique", "unknown"))
        endpoint = str(value.get("url", ""))
        method = str(value.get("method", ""))
        param = str(value.get("param", ""))
        dedup = (endpoint, method, param, technique)
        if dedup in seen:
            continue
        seen.add(dedup)

        confidence = fact_data.get("confidence", 0.0) if isinstance(fact_data, dict) else 0.0
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        possibilities.append({
            "technique": technique,
            "endpoint": endpoint,
            "method": method,
            "param": param,
            "confidence": round(confidence, 2),
            "evidence": value.get("evidence", ""),
            "source": fact_data.get("produced_by", "") if isinstance(fact_data, dict) else "",
        })

    order = {"error_based": 0, "boolean_based": 1, "differential": 2}
    possibilities.sort(key=lambda item: (-item["confidence"], order.get(item["technique"], 99), item["endpoint"], item["param"]))
    return possibilities


def generate_html_report(results, path, target, company_logo="", diff=None, targets=None):
    """Generate a standalone HTML report.

    `targets` can contain multiple independent target records. Each target gets
    its own tab and its own finding list/risk chart, so findings are never
    visually mixed between sites. For single-target scans the legacy API
    remains supported by passing only `results` and `target`.
    """
    if targets is None:
        targets = [{
            "target": target,
            "findings": results or [],
            "site_type": None,
            "status": "done",
            "error": None,
        }]

    payload = []
    for index, item in enumerate(targets):
        item_target = item.get("target") or f"Alvo {index + 1}"
        item_findings = item.get("findings") or []
        risk = calculate_risk(item_findings, target=item_target)
        payload.append({
            "id": f"target-{index}",
            "target": item_target,
            "findings": item_findings,
            "sql_injection_possibilities": _extract_sql_injection_possibilities(item.get("report")),
            "site_type": item.get("site_type"),
            "status": item.get("status", "done"),
            "error": item.get("error"),
            "risk_score": risk.score,
            "risk_level": risk.level,
            "severity_counts": dict(risk.severity_counts),
        })

    diff_summary_html = ""
    if diff is not None and diff.has_baseline:
        diff_summary_html = f"""
<section class="diff-summary">
<h2>Changes Since Last Scan (#{diff.previous_scan_id})</h2>
<p><b>{len(diff.new_findings)} new</b> &middot; <b>{len(diff.resolved_findings)} resolved</b> &middot; <b>{len(diff.persistent_findings)} still present</b></p>
</section>
"""

    # Escape target labels before inserting them into HTML. Findings are JSON
    # encoded and rendered into the DOM through textContent/escapeHtml below.
    payload_json = json.dumps(payload, ensure_ascii=False).replace("</script", "<\\/script")

    html_content = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>TRACE Security Assessment</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {
    background: radial-gradient(circle at top, #0f2027, #0d1117);
    color: #e6edf3;
    font-family: Consolas, monospace;
    margin: 0;
    padding: 30px;
}
h1, h2, h3 { color: #00e5ff; }
.header { display:flex; justify-content:space-between; border-bottom:1px solid #30363d; padding-bottom:14px; }
.muted { color:#8b949e; }
#target-tabs { display:flex; flex-wrap:wrap; gap:8px; margin:18px 0; }
.target-tab {
    background:#21262d; border:1px solid #30363d; padding:9px 12px;
    color:#c9d1d9; border-radius:8px; cursor:pointer; max-width:360px;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
}
.target-tab.active { background:#1f6feb; border-color:#1f6feb; color:#fff; }
.target-panel { display:none; }
.target-panel.active { display:block; }
.target-header { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; }
.score-small { font-size:30px; font-weight:bold; text-align:right; white-space:nowrap; }
.score-small span { font-size:14px; color:#8b949e; }
.chart-wrap { max-width:1000px; min-height:280px; }
.card {
    background:#161b22; border-radius:10px; margin-bottom:12px; padding:14px;
    border-left:6px solid; box-shadow:0 0 10px #000;
}
.critical { border-color:#ff1744; }
.high { border-color:#ff9100; }
.medium { border-color:#ffd600; }
.low { border-color:#00e676; }
.info { border-color:#40c4ff; }
.details { display:none; margin-top:10px; }
pre { background:#0d1117; padding:8px; border-radius:6px; white-space:pre-wrap; word-break:break-word; }
.finding-header { cursor:pointer; }
.diff-summary { background:#161b22; border:1px solid #30363d; padding:12px 16px; border-radius:8px; margin:18px 0; }
.lifecycle { display:inline-block; margin-left:8px; padding:3px 8px; border-radius:999px; font-size:11px; border:1px solid #30363d; }
.lifecycle.new { border-color:#1f6feb; color:#58a6ff; }
.lifecycle.seen { border-color:#8b949e; color:#c9d1d9; }
.lifecycle.closed { border-color:#f85149; color:#ff7b72; }
.lifecycle.reopened { border-color:#d29922; color:#e3b341; }
.lifecycle-closed { opacity:.75; }
button { background:#1f6feb; border:none; padding:6px 10px; color:white; border-radius:6px; cursor:pointer; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>TRACE Security Assessment</h1>
    <p><b>Targets:</b> __TARGET_COUNT__</p>
    <p><b>Date:</b> __DATE__</p>
  </div>
</div>
__DIFF__
<div id="target-tabs"></div>
<div id="target-content"></div>
<script>
const targets = __TARGETS_JSON__;

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    const div = document.createElement("div");
    div.textContent = String(value);
    return div.innerHTML;
}

function toggle(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = el.style.display === "none" ? "block" : "none";
}

function activateTarget(index) {
    document.querySelectorAll(".target-tab").forEach((button, i) => {
        button.classList.toggle("active", i === index);
    });
    document.querySelectorAll(".target-panel").forEach((panel, i) => {
        panel.classList.toggle("active", i === index);
    });
}

const tabs = document.getElementById("target-tabs");
const content = document.getElementById("target-content");

targets.forEach((t, index) => {
    const tab = document.createElement("button");
    tab.className = "target-tab";
    tab.textContent = `${index + 1}. ${t.target} (${t.findings.length})`;
    tab.onclick = () => activateTarget(index);
    tabs.appendChild(tab);

    const panel = document.createElement("section");
    panel.className = "target-panel";
    panel.id = `target-panel-${index}`;
    panel.innerHTML = `
        <div class="target-header">
            <div>
                <h2>${escapeHtml(t.target)}</h2>
                <p class="muted">
                    Status: <b>${escapeHtml(t.status)}</b>
                    ${t.site_type ? ` &middot; Tipo: <b>${escapeHtml(t.site_type)}</b>` : ''}
                    ${t.error ? ` &middot; Erro: <b>${escapeHtml(t.error)}</b>` : ''}
                </p>
            </div>
            <div class="score-small">${escapeHtml(t.risk_score)}/100<br><span>${escapeHtml(t.risk_level)}</span></div>
        </div>
        <h3>Severity Overview</h3>
        <div class="chart-wrap"><canvas id="sevChart-${index}"></canvas></div>
        <h3>Possibilidades de SQL Injection</h3>
        <div id="sqli-${index}"></div>
        <h3>Technical Findings</h3>
        <div id="findings-${index}"></div>`;
    content.appendChild(panel);

    const sqliContainer = document.getElementById(`sqli-${index}`);
    const sqliPossibilities = t.sql_injection_possibilities || [];
    if (!sqliPossibilities.length) {
        const emptySqli = document.createElement("p");
        emptySqli.className = "muted";
        emptySqli.textContent = "Nenhum sinal de possível SQL Injection foi registrado pelas heurísticas.";
        sqliContainer.appendChild(emptySqli);
    } else {
        sqliPossibilities.forEach((s, i) => {
            const card = document.createElement("div");
            card.className = "card medium";
            card.innerHTML = `
                <div class="finding-header" onclick="toggle('sqli-d-${index}-${i}')">
                    <b>${escapeHtml(s.technique)}</b> — confiança ${escapeHtml(s.confidence)}
                </div>
                <div id="sqli-d-${index}-${i}" class="details">
                    <p><b>Endpoint:</b> ${escapeHtml(s.endpoint)}</p>
                    <p><b>Método:</b> ${escapeHtml(s.method)}</p>
                    <p><b>Parâmetro:</b> ${escapeHtml(s.param)}</p>
                    <p><b>Módulo:</b> ${escapeHtml(s.source)}</p>
                    <p><b>Evidência:</b><br>${escapeHtml(s.evidence)}</p>
                    <p class="muted">Sinal heurístico; não implica confirmação de exploração isoladamente.</p>
                </div>`;
            sqliContainer.appendChild(card);
        });
    }

    const findingsContainer = document.getElementById(`findings-${index}`);
    if (!t.findings.length) {
        const empty = document.createElement("p");
        empty.className = "muted";
        empty.textContent = "Nenhum achado.";
        findingsContainer.appendChild(empty);
    }

    t.findings.forEach((f, i) => {
        const card = document.createElement("div");
        const sev = (f.severity || "info").toLowerCase();
        card.className = "card " + sev;
        const lifecycle = String(f.status || (f.is_new ? 'new' : 'seen')).toLowerCase();
        const lifecycleLabel = {
            new: 'NOVA',
            seen: 'JÁ VISTA',
            closed: 'FECHADA',
            reopened: 'REABERTA'
        }[lifecycle] || lifecycle.toUpperCase();
        card.className = `card ${sev}${lifecycle === 'closed' ? ' lifecycle-closed' : ''}`;
        card.innerHTML = `
            <div class="finding-header" onclick="toggle('d-${index}-${i}')">
                <b>${escapeHtml(f.title)}</b> — ${escapeHtml(sev.toUpperCase())}
                <span class="lifecycle ${escapeHtml(lifecycle)}">${escapeHtml(lifecycleLabel)}</span>
            </div>
            <div id="d-${index}-${i}" class="details">
                <p><b>Lifecycle:</b> ${escapeHtml(lifecycleLabel)}</p>
                <p><b>First seen:</b> ${escapeHtml(f.first_seen || '-')}</p>
                <p><b>Last seen:</b> ${escapeHtml(f.last_seen || '-')}</p>
                <p><b>Module:</b> ${escapeHtml(f.module || f.module_name)}</p>
                <p><b>Category:</b> ${escapeHtml(f.category)}</p>
                <p><b>Endpoint:</b> ${escapeHtml(f.endpoint)}</p>
                <p><b>Description:</b><br>${escapeHtml(f.description)}</p>
                <p><b>Business Impact:</b><br>${escapeHtml(f.business_impact)}</p>
                <p><b>Remediation:</b><br>${escapeHtml(f.remediation)}</p>
                ${f.notes ? `<p><b>Pentester Notes:</b><br>${escapeHtml(f.notes)}</p>` : ''}
                ${f.evidence ? `<pre>${escapeHtml(JSON.stringify(f.evidence, null, 2))}</pre>` : ''}
            </div>`;
        findingsContainer.appendChild(card);
    });

    new Chart(document.getElementById(`sevChart-${index}`), {
        type: 'bar',
        data: {
            labels: Object.keys(t.severity_counts),
            datasets: [{ data: Object.values(t.severity_counts) }]
        },
        options: { responsive: true }
    });
});

if (targets.length) activateTarget(0);
</script>
</body>
</html>
"""

    html_content = html_content.replace("__TARGET_COUNT__", str(len(payload)))
    html_content = html_content.replace("__DATE__", datetime.now().strftime('%d/%m/%Y %H:%M'))
    html_content = html_content.replace("__DIFF__", diff_summary_html)
    html_content = html_content.replace("__TARGETS_JSON__", payload_json)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
