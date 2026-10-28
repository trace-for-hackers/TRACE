"""
modules/dependency_confusion_scanner.py

Busca package.json exposto publicamente na raiz do alvo, extrai
dependencia, e checa CADA NOME contra o registro PUBLICO real do npm
(registry.npmjs.org) -- se o nome NAO existe la, e candidato real a
dependency confusion: um atacante pode publicar um pacote malicioso com
esse nome exato, e se o pipeline de build do alvo algum dia resolver
esse nome pro registro publico em vez do interno (por engano de
configuracao, cache, ou fallback), o pacote malicioso e instalado.

Essa e a tecnica original de Alex Birsan (2021) que gerou bounty de
mais de US$130 mil em empresas como Apple, Microsoft, PayPal -- o
mecanismo de checagem aqui e literalmente "esse nome existe no publico
ou nao", a mesma pergunta que o pesquisador original fazia manualmente.

So cobre npm/package.json por enquanto -- composer.json (PHP/Packagist)
tem o mesmo principio, mas nao esta coberto aqui porque packagist.org
nao esta na lista de dominio permitido deste ambiente pra validar ao
vivo (ver limitacao no MODULES.md).
"""

from __future__ import annotations

import json

import requests

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}"


def parse_package_json_dependencies(raw_json: str) -> list[str]:
    """Extrai nome de pacote de dependencies + devDependencies --
    funcao pura, so parsing, sem rede. Retorna lista vazia (nao lanca
    excecao) se o JSON for invalido ou nao tiver os campos esperados."""
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        return []

    if not isinstance(data, dict):
        return []

    names = set()
    for field in ("dependencies", "devDependencies"):
        deps = data.get(field, {})
        if isinstance(deps, dict):
            names.update(deps.keys())

    return sorted(names)


def check_exists_on_public_npm(package_name: str) -> bool | None:
    """True se existe no registro publico, False se NAO existe (404 --
    candidato a confusion), None se a checagem falhou por outro motivo
    (rede, rate limit) -- None nunca deve virar achado, so "nao sei"."""
    try:
        r = requests.get(_NPM_REGISTRY_URL.format(name=package_name), timeout=8)
    except requests.exceptions.RequestException:
        return None

    if r.status_code == 200:
        return True
    if r.status_code == 404:
        return False
    return None  # rate limit ou outro erro -- nao afirma nada


@discovery_module(
    requires=(),
    produces=[],
    cost=20,  # domina o custo por causa das N chamadas ao registro npm, uma por dependencia
    category="vulnerable_components",
    display_name="Scanner de Dependency Confusion",
    summary="Busca package.json exposto e checa CADA dependência contra o registro público real do npm -- nome que não existe publicamente é candidato real a dependency confusion.",
)
class DependencyConfusionScanner:
    name = "dependency_confusion_scanner"

    def run(self, target: str):
        r = get(target.rstrip("/") + "/package.json")
        if r is None or r.status_code != 200:
            return None

        package_names = parse_package_json_dependencies(r.text)
        if not package_names:
            return None

        findings = []
        for name in package_names:
            exists = check_exists_on_public_npm(name)
            if exists is False:
                findings.append({
                    "title": f"Candidato a Dependency Confusion: '{name}' não existe no npm público",
                    "severity": "high",
                    "module": self.name,
                    "category": "dependency_confusion",
                    "endpoint": target.rstrip("/") + "/package.json",
                    "description": (
                        f"O package.json exposto declara a dependência '{name}', que NÃO existe "
                        f"no registro público do npm (checado ao vivo). Se o pipeline de build "
                        f"algum dia resolver esse nome pro registro público em vez de um "
                        f"registro interno, um atacante que publicar um pacote malicioso com "
                        f"esse nome exato teria seu código executado no processo de build/deploy."
                    ),
                    "business_impact": "Execução de código arbitrário na cadeia de build/CI, potencialmente com acesso a segredo de build e ao próprio pipeline de deploy.",
                    "remediation": "Reservar o nome no registro público (mesmo como pacote vazio), ou configurar escopo (@empresa/pacote) com o registro interno como fonte exclusiva e verificada.",
                    "evidence": {"package_name": name},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)
