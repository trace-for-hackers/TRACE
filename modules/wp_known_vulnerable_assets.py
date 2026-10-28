"""
modules/wp_known_vulnerable_assets.py

O módulo que faltava desde o início: junta os fatos tech.<slug>.version
(agora produzidos por plugin_detectors.py, ver PLUGIN_VERSION_KEYS lá) com
o feed de vulnerabilidades da Wordfence (core/vuln_db.py) e vira Finding
quando a versão instalada cai numa faixa vulnerável.

DECISÕES DE DESIGN e por que elas existem:

1. requires=[Requirement("tech.*", min_confidence=0.5)] (wildcard) --
   fica elegível assim que QUALQUER fato tech.* aparecer, não um plugin
   específico. Isso só funciona de verdade depois da correção em
   knowledge/scheduler.py._invoke_module que resolve wildcard pra uma
   LISTA de Facts via query_prefix -- antes disso, o `facts` recebido
   aqui seria {"tech.*": None} (busca de chave literal, nunca bate).

2. cost=0 -- não faz nenhuma requisição HTTP, é matching local puro contra
   o cache do feed. O "custo" real (a chamada à API da Wordfence) já
   aconteceu fora do scan, no refresh diário do cache.

3. max_reentries=15 -- este módulo precisa reavaliar toda vez que um NOVO
   fato tech.*.version aparece ao longo do scan (plugins são detectados em
   momentos diferentes, não todos de uma vez). Sem reentrância ele rodaria
   uma única vez, cedo, e perderia qualquer plugin detectado depois.
   Subiu de 8 pra 15 quando wp_assets_extractor passou a produzir fatos
   também (29/08/2026) -- agora há duas fontes de tech.*.version chegando
   em momentos diferentes do scan (detectores individuais + varredura
   ampla de assets), então a folga precisa cobrir ambas sem esgotar o
   orçamento antes da segunda rodar.

4. Dedup por atributo DE CLASSE (não de instância): o scheduler cria uma
   instância nova a cada reentrância (`rm.module_class()`), então um `set`
   de instância seria sempre vazio, e mandaria a mesma Finding pro
   relatório em cada reentrância. `_reported` é de classe -- persiste
   entre as reentrâncias dentro do mesmo processo de scan (um scan por
   processo, então isso nunca vaza entre alvos diferentes rodando em
   paralelo... porque hoje o WRAITH não roda dois scans no mesmo processo
   Python. Se isso mudar no futuro, essa dedup precisa virar por instância
   de KnowledgeStore, não de classe).
"""

from __future__ import annotations

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from core.vuln_db import load_feed, build_lookup, find_matches


@discovery_module(
    requires=[Requirement("tech.*", min_confidence=0.5)],
    produces=[],
    cost=0,
    max_reentries=15,
    category="vulnerability_matching",
    display_name="Correlação com Vulnerabilidades Conhecidas (Wordfence)",
    summary="Cruza a versão de cada plugin/tema detectado contra o feed de vulnerabilidades da Wordfence Intelligence e reporta os matches como Finding.",
)
class WPKnownVulnerableAssets:
    name = "wp_known_vulnerable_assets"

    # de classe de propósito -- ver docstring do módulo, seção 4
    _reported: set[tuple[str, str, str]] = set()   # (target, slug, vuln_id)
    _lookup_cache = None
    # BUG REAL encontrado rodando contra site real (07/09/2026): quando
    # load_feed() falhava (rate limit da Wordfence, 429), _lookup_cache
    # continuava None -- então TODA reentrância seguinte (até 16 vezes
    # num scan real, uma por onda) tentava buscar o feed de novo, batendo
    # de novo no mesmo rate limit (que dura ~30min, não segundos). Cada
    # tentativa reimprimia o mesmo aviso, poluindo o log sem chance real
    # de dar certo antes do fim do scan. Agora a FALHA também é
    # cacheada por classe -- desiste de tentar de novo pro resto desta
    # sessão de scan, em vez de reentrância virar retry automático.
    _load_error: str | None = None

    @classmethod
    def _get_lookup(cls):
        """Carrega o feed (via cache local de core/vuln_db.py, refresh só
        quando o TTL vence) e constrói o índice por slug uma única vez por
        processo -- não a cada reentrância, já que o feed não muda no meio
        de um scan."""
        if cls._load_error is not None:
            raise RuntimeError(cls._load_error)
        if cls._lookup_cache is None:
            try:
                feed = load_feed()
            except RuntimeError as e:
                cls._load_error = str(e)
                print(f"[wp_known_vulnerable_assets] indisponível: {e} "
                      f"(não vai tentar de novo nesta sessão de scan)")
                raise
            cls._lookup_cache = build_lookup(feed)
        return cls._lookup_cache

    def run(self, target, facts):
        version_facts = facts.get("tech.*", [])
        if not version_facts:
            return None

        try:
            lookup = self._get_lookup()
        except RuntimeError:
            # aviso já foi impresso em _get_lookup() na primeira falha --
            # reentrâncias seguintes saem quietas daqui, sem repetir o
            # mesmo erro sem chance real de mudar dentro do mesmo scan
            # (ver docstring de _load_error acima).
            return None

        findings = []

        for f in version_facts:
            if not str(f.key).endswith(".version"):
                continue  # só nos interessa tech.<slug>.version, não .present

            value = f.value or {}
            slug = value.get("slug")
            installed_version = value.get("version")
            if not slug or not installed_version:
                continue

            for record in find_matches(slug, installed_version, lookup):
                dedup_key = (target, slug, record.id)
                if dedup_key in self._reported:
                    continue
                self._reported.add(dedup_key)

                findings.append({
                    "title": record.title,
                    "severity": record.severity,
                    "module": self.name,
                    "category": "known_vulnerability",
                    "endpoint": f"/wp-content/plugins/{slug}/",
                    "description": (
                        f"{record.description}\n\n"
                        f"Versão instalada detectada: {installed_version}."
                    ),
                    "business_impact": (
                        f"Vulnerabilidade conhecida e catalogada (CVSS "
                        f"{record.cvss_score if record.cvss_score is not None else 'N/A'}) "
                        f"em componente de terceiros ativo no alvo."
                    ),
                    "remediation": record.remediation or (
                        f"Atualizar para uma versão corrigida: {', '.join(record.patched_versions)}"
                        if record.patched_versions else "Verificar changelog do plugin/tema."
                    ),
                    "evidence": {
                        "slug": slug,
                        "installed_version": installed_version,
                        "affected_range": f"{record.from_version} - {record.to_version}",
                        "cve": record.cve or f"Wordfence ID: {record.id}",
                        "cvss_score": record.cvss_score,
                        "references": record.references,
                    },
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)
