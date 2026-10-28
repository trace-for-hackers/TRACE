"""
core/vuln_db.py

Cliente + cache local do feed de vulnerabilidades da Wordfence Intelligence.

DECISAO DE ARQUITETURA IMPORTANTE: o feed da Wordfence nao e uma API de
consulta ("essa versao desse plugin e vulneravel?") -- e um dump completo
do banco inteiro, hoje com mais de 100MB por request. Bater nele a cada
scan seria lento, gastaria banda a toa, e arrisca rate limit desnecessario.
A abordagem certa (e a que qualquer integrador serio faz, inclusive os
proprios plugins de WP que consomem esse feed) e: baixar o feed inteiro
periodicamente (1x/dia é mais que suficiente -- vulnerabilidade nova não
aparece de hora em hora), cachear em disco, e servir os lookups a partir
do cache local durante os scans.

CONFIGURACAO NECESSARIA (variavel de ambiente, mesmo padrao do resto do
projeto -- ver core/memory.py):

    TRACE_WORDFENCE_API_KEY   sua chave da secao "Integrations" do
                               dashboard wordfence.com (API v3 -- a v2,
                               sem chave, parou de responder em 03/2026)

CONFIRMADO (29/08/2026, teste real do usuário): o endpoint responde 200 em
/api/intelligence/v3/vulnerabilities/production com
"Authorization: Bearer <chave>" -- é esquema Bearer mesmo, não chave crua
como a doc de outras integrações da Wordfence sugeria. _auth_header() já
reflete isso.

AINDA NÃO CONFIRMADO: o schema exato de cada registro do feed (nomes de
campo em `software[]`, `affected_versions`, `cvss`). build_lookup() abaixo
continua com a estrutura assumida da documentação pública -- rode
`python3 -m core.vuln_db sample` pra baixar o feed *scanner* (bem menor
que o *production*) e ver 2 registros crus antes de confiar no parsing.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
import requests

load_dotenv('~/TRACE/.env')
FEED_HOST = "https://www.wordfence.com"
# v3 e a unica versao viva hoje (v2 parou de responder em 09/03/2026).
# Path por convencao com o v2 documentado publicamente
# (GET /api/intelligence/v2/vulnerabilities/production) -- ainda nao
# confirmado ao vivo, ver aviso no docstring do modulo.
PRODUCTION_FEED_PATH = "/api/intelligence/v3/vulnerabilities/production"
SCANNER_FEED_PATH = "/api/intelligence/v3/vulnerabilities/scanner"

DEFAULT_CACHE_PATH = os.getenv(
    "TRACE_WORDFENCE_CACHE",
    # dentro do projeto, não em Path.home() -- em Windows, home costuma
    # estar redirecionado pro OneDrive, e escrita numa pasta oculta nova
    # (".wraith") ali pode esbarrar em sincronização/antivírus/permissão
    # de conta. Isso já aconteceu na prática (PermissionError em
    # C:\Users\<user>\.wraith); o diretório do projeto é mais previsível.
    str(Path(__file__).resolve().parent.parent / ".cache" / "wordfence_feed.json"),
)
DEFAULT_CACHE_TTL_HOURS = int(os.getenv("TRACE_WORDFENCE_CACHE_TTL_HOURS", "24"))


def _api_key() -> str:
    key = os.getenv("TRACE_WORDFENCE_API_KEY")
    if not key:
        raise RuntimeError(
            "TRACE_WORDFENCE_API_KEY não configurada. Gere a chave em "
            "wordfence.com > sua conta > Integrations, e exporte a variável "
            "de ambiente (ou coloque no .env, igual as credenciais do "
            "Postgres/Redis em core/memory.py)."
        )
    return key


def _auth_header(key: str) -> dict:
    """Confirmado por teste real: esquema Bearer, não chave crua."""
    return {"Authorization": f"Bearer {key}"}


def test_connection() -> None:
    """Roda com: python3 -m core.vuln_db test
    Faz UMA requisição pequena (HEAD, não baixa o feed inteiro) só pra
    confirmar que a chave e o header estão certos antes de você commitar
    pra baixar 100+MB."""
    key = _api_key()
    url = FEED_HOST + PRODUCTION_FEED_PATH
    resp = requests.head(url, headers=_auth_header(key), timeout=15)
    print(f"GET {url}")
    print(f"Status: {resp.status_code}")
    print(f"Headers relevantes: Content-Length={resp.headers.get('Content-Length')}, "
          f"Content-Type={resp.headers.get('Content-Type')}")
    if resp.status_code == 401 or resp.status_code == 403:
        print("\n[!] Não autenticado. Tente trocar _auth_header() para usar "
              "'Bearer <chave>' em vez da chave crua, e rode de novo.")
    elif resp.status_code == 200:
        print("\n[✓] Chave e endpoint parecem corretos.")
    else:
        print(f"\n[?] Status inesperado -- verifique se o path do endpoint "
              f"mudou (confira em wordfence.com > Integrations > docs).")


def bootstrap(sample_n: int = 2) -> None:
    """Roda com: python3 -m core.vuln_db bootstrap

    Faz UMA ÚNICA requisição (a Wordfence libera 1 request a cada 30min --
    confirmado na prática, então cada chamada separada de test/sample
    queima cota à toa). Esse comando:
      1. baixa o feed PRODUCTION (o que build_lookup() vai consumir de
         verdade -- não o scanner, que é só um formato mínimo à parte e
         pode ter schema diferente)
      2. salva no cache local (load_feed já não precisa buscar de novo
         por 24h)
      3. imprime `sample_n` registros crus do que acabou de baixar, sem
         request nenhuma a mais, pra você (e eu) confirmarmos o schema
         real de uma vez.
    """
    print("Baixando o feed PRODUCTION (1 request, ~24h de cache depois disso)...")
    try:
        data = load_feed(force_refresh=True)
    except RuntimeError as e:
        print(str(e))
        return

    print(f"\nOK -- {len(data)} registros no cache ({DEFAULT_CACHE_PATH}).")
    print(f"\n--- amostra de {sample_n} registro(s) ---")
    for vuln_id, entry in list(data.items())[:sample_n]:
        print(f"\nid: {vuln_id}")
        print(json.dumps(entry, indent=2, ensure_ascii=False)[:2000])


def sample_records(n: int = 2) -> None:
    """Roda com: python3 -m core.vuln_db sample
    ATENÇÃO: isso consome sozinho 1 das suas requisições liberadas a cada
    30min. Se você ainda não tem o cache populado, use `bootstrap` em vez
    disso -- ele baixa o feed que você realmente vai usar (production) E
    já mostra a amostra, no mesmo request. Use `sample` só se quiser
    inspecionar o feed SCANNER especificamente (formato mínimo, schema
    pode diferir do production)."""
    key = _api_key()
    url = FEED_HOST + SCANNER_FEED_PATH
    print(f"Baixando {url} (feed scanner, formato mínimo)...")
    try:
        resp = _request_with_rate_limit_info(url, _auth_header(key), timeout=120)
    except RuntimeError as e:
        print(str(e))
        print("Espere o tempo indicado (ou uns 5-10min se não veio Retry-After) e rode de novo.")
        return

    data = resp.json()

    print(f"\nTipo do payload: {type(data).__name__}")
    if isinstance(data, dict):
        print(f"Total de registros: {len(data)}")
        items = list(data.items())[:n]
        for vuln_id, entry in items:
            print(f"\n--- id: {vuln_id} ---")
            print(json.dumps(entry, indent=2, ensure_ascii=False)[:2000])
    elif isinstance(data, list):
        print(f"Total de registros: {len(data)}")
        for entry in data[:n]:
            print("\n---")
            print(json.dumps(entry, indent=2, ensure_ascii=False)[:2000])


@dataclass
class VulnRecord:
    id: str
    title: str
    description: str
    slug: str
    software_type: str          # "plugin" | "theme" | "core"
    from_version: str | None    # pode vir o literal "*" (sem limite inferior)
    from_inclusive: bool
    to_version: str | None
    to_inclusive: bool
    cve: str | None
    cvss_score: float | None
    severity: str                # derivado do cvss_score
    patched: bool
    patched_versions: list
    remediation: str
    references: list


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _request_with_rate_limit_info(url: str, headers: dict, timeout: int):
    """GET com tratamento explícito de 429 -- em vez de deixar
    raise_for_status() estourar um traceback cru, lê Retry-After (e
    qualquer header X-RateLimit-* que a Wordfence mandar, se mandar) e
    devolve uma mensagem que diz o que fazer, não só "deu erro". Usado
    tanto no modo de inspeção manual (sample_records) quanto, mais
    importante, no refresh diário do cache em produção (load_feed) --
    lá, estourar sem tratamento significaria o scan inteiro falhar por
    causa de uma dependência externa temporariamente indisponível.
    """
    resp = requests.get(url, headers=headers, timeout=timeout)

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        rl_remaining = resp.headers.get("X-RateLimit-Remaining")
        rl_reset = resp.headers.get("X-RateLimit-Reset")

        msg = "[!] Rate limit da Wordfence (429) -- "
        if retry_after:
            msg += f"eles pedem pra esperar {retry_after}s antes de tentar de novo. "
        else:
            msg += "sem header Retry-After na resposta; espere alguns minutos. "
        if rl_remaining is not None:
            msg += f"(X-RateLimit-Remaining={rl_remaining}"
            if rl_reset:
                msg += f", reset={rl_reset}"
            msg += ")"

        raise RuntimeError(msg)

    resp.raise_for_status()
    return resp


def _download_feed(feed_path: str) -> dict:
    key = _api_key()
    url = FEED_HOST + feed_path
    resp = _request_with_rate_limit_info(url, _auth_header(key), timeout=120)
    return resp.json()


def _is_cache_fresh(path: Path, ttl_hours: int) -> bool:
    if not path.exists():
        return False
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    return age_hours < ttl_hours


def load_feed(force_refresh: bool = False) -> dict:
    """Retorna o feed cru (dict indexado por id de vulnerabilidade). Usa
    cache em disco com TTL de 24h por padrão -- ajustável via
    TRACE_WORDFENCE_CACHE_TTL_HOURS. `force_refresh=True` ignora o cache
    (útil pra um cron job noturno dedicado a atualizar a base).

    Se o refresh esbarrar em rate limit (429) e existir cache antigo em
    disco, usa o cache velho com um aviso em vez de derrubar o scan --
    uma base de CVE de ontem ainda é infinitamente melhor que nenhuma
    base, e um scan não deveria falhar por causa de uma dependência
    externa temporariamente indisponível (mesmo princípio de
    knowledge/bootstrap.py._run_without_memory: degradar, não travar)."""
    cache_path = Path(DEFAULT_CACHE_PATH)

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise RuntimeError(
            f"Sem permissão pra criar {cache_path.parent} ({e}). "
            f"Aponte o cache pra outro lugar com "
            f"TRACE_WORDFENCE_CACHE=<caminho>\\wordfence_feed.json "
            f"antes de rodar de novo -- causas comuns no Windows: pasta "
            f"do usuário sincronizada com OneDrive, ou antivírus barrando "
            f"criação de pasta nova."
        ) from e

    if not force_refresh and _is_cache_fresh(cache_path, DEFAULT_CACHE_TTL_HOURS):
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    try:
        data = _download_feed(PRODUCTION_FEED_PATH)
    except RuntimeError as e:
        if cache_path.exists():
            print(f"{e} -- usando cache antigo de {cache_path} (pode estar desatualizado).")
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        raise

    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except PermissionError as e:
        # já baixamos os dados com sucesso -- não perde o download por causa
        # de não conseguir gravar o cache, só avisa que vai ter que baixar
        # de novo na próxima vez (e queimar outra request da cota de 30min)
        print(f"[!] Baixado com sucesso mas não consegui salvar cache em {cache_path}: {e}")

    return data


def build_lookup(feed: dict) -> dict[str, list[VulnRecord]]:
    """Indexa o feed por slug de plugin/tema -> lista de VulnRecord.

    SCHEMA CONFIRMADO em 29/08/2026 via `bootstrap` real contra o feed
    production (ver amostra de 2 registros que validamos):
      entry = {id, title, description, software: [...], cve, cvss:
               {score, rating, vector}, references: [urls...], ...}
      software[i] = {type, name, slug, affected_versions: {"<range_key>":
               {from_version, from_inclusive, to_version, to_inclusive}},
               patched, patched_versions: [...], remediation}

    Duas coisas que eu tinha assumido erradas antes de ver dado real:
      - `remediation` fica DENTRO de cada item de software[], não no
        nível do registro (faz sentido -- plugin e tema no mesmo CVE
        podem ter remediação diferente)
      - `from_version` pode vir o literal "*" (string, não null) quando
        não há limite inferior conhecido -- ex.: "*-1.37" cobre tudo até
        1.37. Isso vai importar na hora de comparar versão no módulo de
        matching: tratar "*" como "sem piso", não tentar fazer parse de
        versão nele.

    `cve` frequentemente vem `null` -- a Wordfence atribui um ID próprio
    (o `id` do registro) mesmo pra vulnerabilidades sem CVE formal ainda.
    O link em `references[0]` (threat-intel/vulnerabilities/id/<id>) serve
    de referência estável nesses casos.
    """
    lookup: dict[str, list[VulnRecord]] = {}

    for vuln_id, entry in feed.items():
        cvss = (entry.get("cvss") or {}).get("score")
        for sw in entry.get("software", []):
            slug = sw.get("slug")
            if not slug:
                continue
            for version_range in (sw.get("affected_versions") or {}).values():
                record = VulnRecord(
                    id=vuln_id,
                    title=entry.get("title", "Vulnerabilidade sem título"),
                    description=entry.get("description", ""),
                    slug=slug,
                    software_type=sw.get("type", "plugin"),
                    from_version=version_range.get("from_version"),
                    from_inclusive=bool(version_range.get("from_inclusive", True)),
                    to_version=version_range.get("to_version"),
                    to_inclusive=bool(version_range.get("to_inclusive", True)),
                    cve=entry.get("cve"),
                    cvss_score=cvss,
                    severity=_severity_from_cvss(cvss),
                    patched=bool(sw.get("patched", False)),
                    patched_versions=sw.get("patched_versions", []),
                    remediation=sw.get("remediation", ""),
                    references=entry.get("references", []),
                )
                lookup.setdefault(slug, []).append(record)

    return lookup


from packaging.version import Version, InvalidVersion


def _parse_version(v: str | None) -> Version | None:
    """Parse tolerante -- versão de plugin WP nem sempre é semver estrito
    (às vezes vem "1.2" sem patch, ou com sufixo tipo "1.2.3-beta"). Retorna
    None em vez de lançar quando o parsing falha; quem chama decide como
    tratar (normalmente: não consegue comparar -> não afirma nem nega)."""
    if v is None or v == "*":
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def is_vulnerable(installed_version: str, record: VulnRecord) -> bool | None:
    """
    Compara a versão instalada contra a faixa afetada de um VulnRecord.

    Retorna True/False quando dá pra decidir, e None quando a versão
    instalada ou os limites da faixa não são parseáveis -- IMPORTANTE:
    None não deve virar Finding. Um scanner que assume "vulnerável" toda
    vez que não consegue comparar gera falso positivo sistemático; melhor
    silenciosamente não afirmar nada do que afirmar errado num relatório
    de pentest.

    from_version == "*" significa "sem piso conhecido" (a faixa cobre
    desde a primeira versão publicada) -- tratado como sempre satisfeito
    do lado de baixo.
    """
    installed = _parse_version(installed_version)
    if installed is None:
        return None

    if record.from_version and record.from_version != "*":
        floor = _parse_version(record.from_version)
        if floor is None:
            return None
        if record.from_inclusive:
            if installed < floor:
                return False
        else:
            if installed <= floor:
                return False

    if record.to_version:
        ceiling = _parse_version(record.to_version)
        if ceiling is None:
            return None
        if record.to_inclusive:
            if installed > ceiling:
                return False
        else:
            if installed >= ceiling:
                return False

    return True


def find_matches(slug: str, installed_version: str, lookup: dict[str, list[VulnRecord]]) -> list[VulnRecord]:
    """Todos os VulnRecord do slug dado cuja faixa cobre installed_version.
    Ignora silenciosamente entradas não comparáveis (ver is_vulnerable)."""
    candidates = lookup.get(slug, [])
    return [r for r in candidates if is_vulnerable(installed_version, r) is True]


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_connection()
    elif len(sys.argv) > 1 and sys.argv[1] == "bootstrap":
        bootstrap()
    elif len(sys.argv) > 1 and sys.argv[1] == "sample":
        sample_records()
    else:
        print("Uso: python3 -m core.vuln_db test | bootstrap | sample")
        print("  test      -- HEAD, confirma chave/endpoint (consome 1 request)")
        print("  bootstrap -- baixa+cacheia o feed production e mostra amostra (1 request, recomendado)")
        print("  sample    -- baixa só o feed scanner pra inspeção (1 request)")
