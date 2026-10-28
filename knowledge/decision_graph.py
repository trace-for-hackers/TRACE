"""
knowledge/decision_graph.py

Transforma o resultado de um scan (ScanReport.wave_reports, que já contém
WaveReport.triggered_by -- a causalidade fato->módulo capturada no momento
exato da decisão, ver knowledge/scheduler.py) em um diagrama Mermaid.

Por que isso importa: a promessa central do TRACE é "o sistema decide,
não um script fixo". Até agora essa promessa só era visível lendo o log de
texto (`[i] Onda 2: ... -> wp_woocommerce_logs`). Este módulo é a primeira
peça que torna essa decisão um artefato visual -- útil tanto para auditoria
de por que um módulo rodou quanto para demonstração (mostrar a um CTO um
grafo onde "WordPress confirmado" se ramifica em WooCommerce, REST API,
XML-RPC, e cada um desses se ramifica de novo, é mais convincente que
qualquer texto).

Este módulo NÃO decide nada e NÃO roda durante o scan -- é puramente uma
camada de apresentação sobre o ScanReport já produzido. Pode ser chamado a
qualquer momento depois que ScanSession.run() retorna.
"""

from __future__ import annotations


import re


def _sanitize_node_id(raw: str) -> str:
    """Mermaid só aceita [A-Za-z0-9_] em IDs de nó crus. Antes trocava só
    alguns caracteres específicos (. / - :) por underscore -- funcionava
    enquanto toda fact_key vinha de módulos concretos ("tech.woocommerce.
    present"). Quebrou quando wp_known_vulnerable_assets introduziu um
    Requirement com wildcard ("tech.*"): o "*" passava direto, o node_id
    saía "fact_tech_*", e Mermaid rejeitava o diagrama inteiro por causa
    de UM nó malformado -- não só aquele nó, o parser falha no arquivo
    todo. Trocado por regex genérica: qualquer caractere fora
    [A-Za-z0-9_] vira underscore, então isso não quebra de novo com o
    próximo caractere especial que aparecer numa fact_key (ex.: "tech.*"
    -> "tech__", sem ambiguidade com nenhum outro nó real)."""
    return re.sub(r"[^A-Za-z0-9_]", "_", raw)


def _truncate_value(value, max_len: int = 40) -> str:
    """Valores de fato podem ser dicts/listas grandes (ex.: tech.assets.detected
    carrega um dict de todos os plugins). No grafo, mostramos só uma versão
    curta -- o valor completo continua disponível em ScanReport.knowledge_snapshot
    para quem quiser inspecionar via texto/JSON."""
    s = str(value)
    return s if len(s) <= max_len else s[:max_len - 1] + "…"


import json


def build_mermaid_decision_graph(scan_report, knowledge_snapshot: dict | None = None) -> str:
    """Gera um grafo causal em camadas temporais:

        conhecimento inicial -> módulo -> conhecimento produzido -> módulo -> ...

    Cada execução do mesmo módulo em ondas diferentes é uma ocorrência visual
    independente. Cada ocorrência de fato produzido também é independente, para
    que o diagrama represente a evolução real do blackboard e não uma árvore
    estática colapsada por ``fact_key``.
    """
    knowledge_snapshot = knowledge_snapshot or {}
    waves = [w for w in scan_report.wave_reports if w.modules_run]

    lines = [
        "%%{init:{",
        '"flowchart":{',
        '"useMaxWidth":false,',
        '"nodeSpacing":90,',
        '"rankSpacing":120,',
        '"htmlLabels":true,',
        '"diagramPadding":20',
        "}",
        "}}%%",
        "",
        "flowchart TD",
    ]

    def fact_label(fact_key: str) -> str:
        snapshot_entry = knowledge_snapshot.get(fact_key)
        if isinstance(snapshot_entry, dict) and "value" in snapshot_entry:
            return f"{fact_key}\\n= {_truncate_value(snapshot_entry.get('value'))}"
        return fact_key

    # Primeira passagem: descobre somente os fatos que já precisavam existir
    # antes da primeira produção observada. Isso evita o bug anterior onde um
    # fato produzido na onda 10 podia ser desenhado como se fosse conhecimento
    # inicial para um consumidor da onda 2.
    available: set[str] = set()
    seed_fact_keys: list[str] = []
    seen_seed: set[str] = set()
    for wave in waves:
        for _module_name, fact_keys in wave.triggered_by.items():
            for fact_key in fact_keys:
                if fact_key not in available and fact_key not in seen_seed:
                    seen_seed.add(fact_key)
                    seed_fact_keys.append(fact_key)
        for fact_key, _produced_by in wave.new_facts:
            available.add(fact_key)

    seed_fact_nodes: dict[str, str] = {}
    if seed_fact_keys:
        lines.append('    subgraph knowledge_seed ["Conhecimento inicial"]')
        lines.append("        direction TB")
        for index, fact_key in enumerate(seed_fact_keys):
            node_id = f"fact_seed_{index}_{_sanitize_node_id(fact_key)}"
            seed_fact_nodes[fact_key] = node_id
            lines.append(f'        {node_id}(("{fact_label(fact_key)}"))')
            lines.append(f"        style {node_id} fill:#30363d,stroke:#6e7681,color:#fff")
        lines.append("    end")

    module_nodes_by_wave: dict[int, dict[str, str]] = {}
    produced_fact_nodes_by_wave: dict[int, list[tuple[str, str, str]]] = {}
    all_module_nodes: list[tuple[str, str]] = []

    # Renderização: dentro de cada onda, módulos vêm antes do conhecimento
    # que eles próprios produziram. As duas camadas ficam explícitas.
    for wave in waves:
        w = wave.wave_number
        module_lookup: dict[str, str] = {}
        produced_here: list[tuple[str, str, str]] = []

        lines.append(f'    subgraph wave{w} ["Onda {w}"]')
        lines.append("        direction TB")

        lines.append(f'        subgraph wave{w}_modules ["Módulos"]')
        lines.append("            direction TB")
        occurrence_count: dict[str, int] = {}
        for module_name in wave.modules_run:
            occurrence_count[module_name] = occurrence_count.get(module_name, 0) + 1
            suffix = "" if occurrence_count[module_name] == 1 else f"_{occurrence_count[module_name]}"
            node_id = f"mod_w{w}_" + _sanitize_node_id(module_name) + suffix
            lines.append(f'            {node_id}["{module_name}"]')
            module_lookup[module_name] = node_id
            all_module_nodes.append((node_id, module_name))
        lines.append("        end")

        if wave.new_facts:
            lines.append(f'        subgraph wave{w}_knowledge ["Conhecimento produzido"]')
            lines.append("            direction TB")
            for index, (fact_key, produced_by) in enumerate(wave.new_facts):
                fact_node = f"fact_w{w}_{index}_{_sanitize_node_id(fact_key)}"
                lines.append(f'            {fact_node}(("{fact_label(fact_key)}"))')
                lines.append(f"            style {fact_node} fill:#1f3a5f,stroke:#4d7ea8,color:#fff")
                produced_here.append((fact_node, fact_key, produced_by))
            lines.append("        end")

        lines.append("    end")
        module_nodes_by_wave[w] = module_lookup
        produced_fact_nodes_by_wave[w] = produced_here

        # Cada produtor é desenhado ACIMA de todos os conhecimentos que produziu
        # naquela onda. Uma aresta distinta preserva a proveniência real.
        for fact_node, _fact_key, produced_by in produced_here:
            producer = module_lookup.get(produced_by)
            if producer:
                lines.append(f"    {producer} --> {fact_node}")

    # Segunda passagem: conecta o conhecimento disponível no momento da
    # decisão ao módulo que o consumiu. Outputs só entram no blackboard depois
    # que a onda termina.
    available_nodes: dict[str, str] = dict(seed_fact_nodes)
    for wave in waves:
        w = wave.wave_number
        module_lookup = module_nodes_by_wave[w]
        for module_name, fact_keys in wave.triggered_by.items():
            mod_node = module_lookup.get(module_name)
            if not mod_node:
                continue
            for fact_key in fact_keys:
                fact_node = available_nodes.get(fact_key)
                if fact_node:
                    lines.append(f"    {fact_node} --> {mod_node}")

        for fact_node, fact_key, _produced_by in produced_fact_nodes_by_wave[w]:
            available_nodes[fact_key] = fact_node

    for node_id, module_name in all_module_nodes:
        lines.append(f"    click {node_id} call wraithShowModuleDetails({json.dumps(module_name)})")

    lines.extend([
        "",
        "    classDef default font-size:13px",
    ])
    return "\n".join(lines)


def build_decision_graph_html(
    scan_report,
    knowledge_snapshot: dict | None = None,
    title: str = "TRACE — Cadeia de Descoberta"
) -> str:
    """
    Gera um HTML standalone com zoom, pan e scroll para visualizar grafos
    grandes sem que o Mermaid reduza tudo para caber na tela, e um painel
    lateral que abre ao clicar num módulo, mostrando seu metadado (nome
    amigável, resumo, categoria, custo estimado, fatos consumidos/produzidos)
    -- lido de ScanReport.module_metadata, resolvido em knowledge/bootstrap.py
    via ModuleSpec.describe(), com fallback automático para docstring/nome
    de classe quando o módulo não declara display_name/summary explícitos.

    Módulos sem nenhum metadado explícito (a maioria dos ~55 atuais, que não
    têm display_name/summary no decorator) ainda abrem o painel -- só com
    summary genérico ("Sem descrição disponível para este módulo ainda.")
    em vez de painel vazio ou clique sem efeito.
    """
    mermaid_src = build_mermaid_decision_graph(scan_report, knowledge_snapshot)
    module_metadata = getattr(scan_report, "module_metadata", {}) or {}
    # json.dumps com ensure_ascii=True (default) evita qualquer problema de
    # encoding ao embutir como literal JS dentro do <script> -- nomes/resumos
    # em português com acentuação saem como \uXXXX, que o JS interpreta
    # corretamente na hora de exibir.
    module_metadata_json = json.dumps(module_metadata)

    return f"""<!DOCTYPE html>
<html lang="pt-br">

<head>
<meta charset="UTF-8">
<title>{title}</title>

<script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"></script>

<style>

html, body {{
    margin:0;
    padding:0;
    width:100%;
    height:100%;
    background:#0d1117;
    color:#c9d1d9;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}}

header {{
    padding:18px 24px;
}}

h1 {{
    margin:0;
    font-size:20px;
}}

.subtitle {{
    color:#8b949e;
    margin-top:8px;
}}

#controls{{
    position:fixed;
    right:20px;
    top:20px;
    z-index:999;
}}

#controls button{{
    width:42px;
    height:42px;
    margin-left:6px;
    border:none;
    border-radius:8px;
    cursor:pointer;
    background:#21262d;
    color:white;
    font-size:20px;
}}

#controls button:hover{{
    background:#30363d;
}}

#graph-container{{
    width:100%;
    height:calc(100vh - 95px);
    overflow:auto;
    background:#161b22;
    border-top:1px solid #30363d;
}}

#graph{{
    display:inline-block;
    padding:40px;
    transform-origin:top left;
}}

.mermaid{{
    display:inline-block;
    width:max-content;
    min-width:100%;
}}

.mermaid svg{{
    max-width:none !important;
    width:auto !important;
    height:auto !important;
}}

.mermaid text{{
    font-size:15px !important;
}}

/* nós de módulo ficam clicáveis -- o cursor pointer é o único sinal visual
   nativo do Mermaid para "isso é clicável"; sem isso, nada indica ao usuário
   que existe uma interação disponível além do hover padrão do navegador. */
.mermaid .clickable {{
    cursor: pointer;
}}

#detail-panel {{
    position: fixed;
    top: 0;
    right: -380px;
    width: 360px;
    height: 100%;
    background: #161b22;
    border-left: 1px solid #30363d;
    padding: 24px 20px;
    box-sizing: border-box;
    transition: right 0.2s ease;
    overflow-y: auto;
    z-index: 1000;
}}

#detail-panel.open {{
    right: 0;
}}

#detail-panel h2 {{
    margin: 0 0 4px 0;
    font-size: 17px;
    color: #fff;
}}

#detail-panel .module-name {{
    color: #8b949e;
    font-size: 12px;
    font-family: monospace;
    margin-bottom: 16px;
}}

#detail-panel .summary {{
    font-size: 14px;
    line-height: 1.5;
    margin-bottom: 20px;
    color: #c9d1d9;
}}

#detail-panel .field-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #6e7681;
    margin-top: 16px;
    margin-bottom: 6px;
}}

#detail-panel .pill {{
    display: inline-block;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 12px;
    font-family: monospace;
    margin: 2px 4px 2px 0;
}}

#detail-panel .pill.fact-requires {{ border-color: #4d7ea8; color: #79c0ff; }}
#detail-panel .pill.fact-produces {{ border-color: #3fb950; color: #56d364; }}

#detail-panel-close {{
    position: absolute;
    top: 20px;
    right: 20px;
    background: none;
    border: none;
    color: #8b949e;
    font-size: 22px;
    cursor: pointer;
    line-height: 1;
}}

#detail-panel-close:hover {{
    color: #fff;
}}

#detail-panel-empty {{
    color: #6e7681;
    font-size: 13px;
}}

</style>

</head>

<body>

<header>

<h1>{title}</h1>

<div class="subtitle">
Alvo: {getattr(scan_report, "target", "?")}
&nbsp;&nbsp;—&nbsp;&nbsp;
{len(scan_report.wave_reports)} onda(s)
&nbsp;&nbsp;—&nbsp;&nbsp;
clique em um módulo para ver detalhes
</div>

</header>

<div id="controls">
<button onclick="zoomIn()">+</button>
<button onclick="zoomOut()">−</button>
<button onclick="resetZoom()">⟳</button>
</div>

<div id="graph-container">

<div id="graph">

<pre class="mermaid">
{mermaid_src}
</pre>

</div>

</div>

<div id="detail-panel">
<button id="detail-panel-close" onclick="wraithCloseModuleDetails()">×</button>
<div id="detail-panel-body">
<p id="detail-panel-empty">Clique em um módulo no grafo para ver sua descrição, categoria, custo estimado e os fatos que ele consome/produz.</p>
</div>
</div>

<script>

const TRACE_MODULE_METADATA = {module_metadata_json};

mermaid.initialize({{

    startOnLoad:true,

    theme:"dark",

    securityLevel:"loose",

    flowchart:{{

        useMaxWidth:false,

        htmlLabels:true,

        nodeSpacing:90,

        rankSpacing:120,

        curve:"basis"

    }}

}});

let scale = 1;

const graph = document.getElementById("graph");

function applyZoom(){{
    graph.style.transform = "scale(" + scale + ")";
}}

function zoomIn(){{
    scale *= 1.15;
    applyZoom();
}}

function zoomOut(){{
    scale /= 1.15;
    applyZoom();
}}

function resetZoom(){{
    scale = 1;
    applyZoom();
}}

document.getElementById("graph-container").addEventListener("wheel", function(e){{
    if(!e.ctrlKey)
        return;

    e.preventDefault();

    if(e.deltaY < 0)
        zoomIn();
    else
        zoomOut();

}}, {{passive:false}});

// Chamado pela diretiva `click` do Mermaid (ver build_mermaid_decision_graph,
// "click {{node_id}} call wraithShowModuleDetails(...)"). securityLevel:"loose"
// é o que permite o Mermaid invocar uma função JS arbitrária do escopo global
// a partir do diagrama -- sem isso, diretivas click são ignoradas por padrão
// (medida de segurança do próprio Mermaid contra diagramas de fontes não
// confiáveis; aqui o diagrama é gerado por nós mesmos, então é seguro relaxar).
function wraithShowModuleDetails(moduleName) {{
    const meta = TRACE_MODULE_METADATA[moduleName];
    const body = document.getElementById("detail-panel-body");

    if (!meta) {{
        // módulo rodou mas não está em module_metadata -- não deveria
        // acontecer (todo módulo registrado no engine passa por
        // describe()), mas se acontecer, o painel é honesto sobre isso em
        // vez de mostrar undefined/null.
        body.innerHTML = "<p id='detail-panel-empty'>Sem metadado disponível para <code>" + moduleName + "</code>.</p>";
        document.getElementById("detail-panel").classList.add("open");
        return;
    }}

    const requiresPills = (meta.requires || []).map(
        k => "<span class='pill fact-requires'>" + k + "</span>"
    ).join(" ") || "<span style='color:#6e7681'>nenhum (módulo raiz)</span>";

    const producesPills = (meta.produces || []).map(
        k => "<span class='pill fact-produces'>" + k + "</span>"
    ).join(" ") || "<span style='color:#6e7681'>nenhum fato declarado</span>";

    body.innerHTML = `
        <h2>${{meta.display_name}}</h2>
        <div class="module-name">${{moduleName}}</div>
        <div class="summary">${{meta.summary}}</div>
        <div class="field-label">Categoria</div>
        <span class="pill">${{meta.category}}</span>
        <div class="field-label">Custo estimado (requisições)</div>
        <span class="pill">${{meta.cost}}</span>
        <div class="field-label">Consome (requires)</div>
        ${{requiresPills}}
        <div class="field-label">Produz (produces)</div>
        ${{producesPills}}
    `;

    document.getElementById("detail-panel").classList.add("open");
}}

function wraithCloseModuleDetails() {{
    document.getElementById("detail-panel").classList.remove("open");
}}

</script>

</body>
</html>
"""