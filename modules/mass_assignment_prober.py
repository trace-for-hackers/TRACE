"""
modules/mass_assignment_prober.py

Testa se um endpoint de criação aceita campo NÃO documentado no schema
(ex.: "admin": true no registro de usuário) e se esse campo é
efetivamente HONRADO pelo backend -- não só aceito sem erro.

GENERALIZAÇÃO NECESSÁRIA em relação a api_resource_provisioner.py: lá,
o pareamento "criação -> leitura" exige que o path de item seja o path
de coleção + "/{id}" (ex.: POST /books/v1 -> GET /books/v1/{book_title}).
Isso quebra pra casos reais como POST /users/v1/register -> GET
/users/v1/{username} -- prefixos diferentes, mesmo "recurso" conceitual.
Achado testando contra o VAmPI de verdade: o registro de usuário aceita
"admin": true sem estar documentado nem no schema interno nem no spec
público, e não pareia pela regra antiga.

A generalização certa: em vez de comparar PATH, compara NOME DE CAMPO --
se o {parametro} de algum GET-de-item bate (case-insensitive) com uma
propriedade do corpo esperado por algum POST em QUALQUER lugar do spec,
os dois pareiam, não importa se os paths compartilham prefixo. Essa
função vive aqui, não em api_resource_provisioner.py, de propósito --
evita mexer numa função já testada e usada em produção (idor_correlator)
só pra resolver um problema que só este módulo tem.

MÉTODO DE CONFIRMAÇÃO (não é só "aceitou sem erro 400"): cria DOIS
recursos com a MESMA identidade -- um baseline (só campos documentados)
e um "envenenado" (baseline + 1 campo de privilégio não documentado,
ex. admin=true) -- depois LÊ os dois de volta e compara se o campo
aparece marcado no envenenado mas não no baseline. Comparação A/B, não
uma observação isolada -- evita falso positivo de uma API que sempre
retorna o campo como true por outro motivo.
"""

from __future__ import annotations

from utils.requester import get_as, post_as, registered_identities
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.api_resource_provisioner import build_request_body, _dummy_value_for, _random_suffix

# campos que, se aceitos sem estarem documentados no schema, indicam
# escalação de privilégio via mass assignment -- lista curta e
# específica de propósito (baixo falso positivo), não genérica demais
_PRIVILEGE_FIELD_CANDIDATES = [
    "admin", "is_admin", "isAdmin", "is_staff", "is_superuser",
    "role", "verified", "is_verified", "email_verified",
]


def find_verifiable_post_endpoints(spec: dict) -> list[dict]:
    """
    Pareia POST (criação) com GET-de-item (leitura) casando pelo NOME DO
    CAMPO, não pelo path -- ver docstring do módulo. Um POST pode parear
    com mais de um GET-de-item se mais de um parâmetro bater (raro, mas
    tratado); cada par vira uma entrada própria.

    BUG REAL encontrado testando contra o VAmPI: sem filtro nenhum,
    /users/v1/login pareava com /users/v1/{username} (o corpo de login
    também tem 'username') -- mas login não CRIA nada, então "criar
    baseline e poisoned com id diferente" não faz sentido pra esse
    endpoint, e gerava achado sem sentido. _ACTION_VERB_DENYLIST existe
    pra excluir esse tipo de falso pareamento pela PALAVRA no path, não
    porque path é uma fonte de verdade perfeita, mas porque é o sinal
    mais barato disponível sem ter que inferir semântica do schema.
    """
    _ACTION_VERB_DENYLIST = ("login", "logout", "auth", "session", "token", "logon", "signin", "signout")

    paths = spec.get("paths", {})

    item_gets = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        if path.endswith("}") and "get" in {k.lower() for k in ops}:
            param_name = path.rsplit("/", 1)[-1].strip("{}")
            item_gets.append((param_name, path))

    results = []
    for post_path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        if any(verb in post_path.lower() for verb in _ACTION_VERB_DENYLIST):
            continue
        post_op = ops.get("post") or ops.get("POST")
        if not post_op:
            continue
        schema = (
            post_op.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        properties = schema.get("properties", {})
        if not properties:
            continue

        for param_name, item_path in item_gets:
            matching_prop = next((p for p in properties if p.lower() == param_name.lower()), None)
            if matching_prop:
                results.append({
                    "post_path": post_path,
                    "item_path": item_path,
                    "id_field": matching_prop,
                    "request_schema": schema,
                })

    return results


def undocumented_privilege_fields(schema: dict) -> list[str]:
    """Candidatos que NÃO estão documentados no schema -- injetar um
    campo que JÁ é parte legítima do schema não é mass assignment, é uso
    normal da API. A vulnerabilidade é especificamente sobre campo que
    o cliente não deveria nem saber que existe."""
    documented = {p.lower() for p in schema.get("properties", {})}
    return [f for f in _PRIVILEGE_FIELD_CANDIDATES if f.lower() not in documented]


def _extract_field_value(response_json, field_name: str):
    """Procura o campo (case-insensitive) em qualquer nível do JSON de
    resposta -- API pode devolver o objeto direto ou envolto em
    {"user": {...}} etc."""
    if isinstance(response_json, dict):
        for k, v in response_json.items():
            if k.lower() == field_name.lower():
                return v
            found = _extract_field_value(v, field_name)
            if found is not None:
                return found
    elif isinstance(response_json, list):
        for item in response_json:
            found = _extract_field_value(item, field_name)
            if found is not None:
                return found
    return None


def _is_truthy_privilege_value(value) -> bool:
    if isinstance(value, bool):
        return value is True
    if isinstance(value, str):
        return value.strip().lower() in ("true", "admin", "yes", "1")
    return False


@discovery_module(
    requires=[
        Requirement("config.identity_available", min_confidence=0.5),
        Requirement("config.openapi_spec_available", min_confidence=0.5),
    ],
    produces=[],
    cost=10,
    category="mass_assignment",
    display_name="Sondagem de Mass Assignment",
    summary="Cria um recurso baseline e um 'envenenado' (com campo de privilégio não documentado) e compara as duas leituras de volta -- só confirma se o campo injetado aparece honrado no envenenado e ausente/falso no baseline.",
)
class MassAssignmentProber:
    name = "mass_assignment_prober"

    def run(self, target: str):
        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[mass_assignment_prober] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        identities = registered_identities()
        if not identities:
            print("[mass_assignment_prober] nenhuma identidade registrada -- nada a fazer.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[mass_assignment_prober] não consegui carregar o spec: {e}")
            return None

        candidates = find_verifiable_post_endpoints(spec)
        if not candidates:
            return None

        findings = []

        for pair in candidates:
            undocumented = undocumented_privilege_fields(pair["request_schema"])
            if not undocumented:
                continue

            identity = identities[0]  # uma identidade já basta -- é sobre o PRÓPRIO recurso dela

            for priv_field in undocumented:
                baseline_id = f"surfacer_ma_base_{_random_suffix()}"
                poisoned_id = f"surfacer_ma_poison_{_random_suffix()}"

                baseline_body = build_request_body(pair["request_schema"], pair["id_field"], baseline_id)
                poisoned_body = build_request_body(pair["request_schema"], pair["id_field"], poisoned_id)
                poisoned_body[priv_field] = True

                post_url = target.rstrip("/") + pair["post_path"]
                resp_baseline = post_as(identity, post_url, json_body=baseline_body)
                resp_poisoned = post_as(identity, post_url, json_body=poisoned_body)

                if resp_baseline is None or resp_poisoned is None:
                    continue
                if resp_baseline.status_code not in (200, 201) or resp_poisoned.status_code not in (200, 201):
                    continue  # criação falhou -- não dá pra confirmar nada

                baseline_read_url = target.rstrip("/") + pair["item_path"].replace("{" + pair["id_field"] + "}", baseline_id)
                poisoned_read_url = target.rstrip("/") + pair["item_path"].replace("{" + pair["id_field"] + "}", poisoned_id)

                r_baseline = get_as(identity, baseline_read_url)
                r_poisoned = get_as(identity, poisoned_read_url)
                if r_baseline is None or r_poisoned is None:
                    continue

                try:
                    baseline_json = r_baseline.json()
                    poisoned_json = r_poisoned.json()
                except ValueError:
                    continue

                baseline_value = _extract_field_value(baseline_json, priv_field)
                poisoned_value = _extract_field_value(poisoned_json, priv_field)

                if _is_truthy_privilege_value(poisoned_value) and not _is_truthy_privilege_value(baseline_value):
                    findings.append({
                        "title": f"Mass Assignment confirmado: campo '{priv_field}' não documentado é honrado em {pair['post_path']}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "mass_assignment",
                        "endpoint": post_url,
                        "description": (
                            f"O endpoint {pair['post_path']} aceitou o campo '{priv_field}' mesmo "
                            f"não estando documentado no schema, e o valor foi efetivamente honrado: "
                            f"recurso criado com '{priv_field}={poisoned_value}' contra baseline com "
                            f"'{priv_field}={baseline_value}' no mesmo endpoint."
                        ),
                        "business_impact": (
                            "Possível escalação de privilégio via mass assignment -- cliente "
                            "consegue definir campo que deveria ser exclusivamente controlado "
                            "pelo servidor (ex.: tornar a própria conta administradora)."
                        ),
                        "remediation": (
                            "Usar allowlist explícita de campos aceitos na desserialização do "
                            "corpo da requisição, em vez de aceitar qualquer campo presente no JSON."
                        ),
                        "evidence": {
                            "endpoint": pair["post_path"], "field": priv_field,
                            "baseline_id": baseline_id, "poisoned_id": poisoned_id,
                            "baseline_value": baseline_value, "poisoned_value": poisoned_value,
                            "confirmation": "leitura de volta mostra o campo honrado",
                        },
                    })
                # BUG REAL encontrado testando contra o VAmPI (07/09/2026):
                # cheguei a existir aqui um terceiro nível "campo aceito sem
                # erro, efeito não confirmado" -- e ele disparou pra
                # PRATICAMENTE TODO campo candidato (18 achados de 9
                # candidatos x 2 endpoints), porque "não reclamar de campo
                # desconhecido" é o comportamento PADRÃO da maioria dos
                # parsers JSON (que ignoram campo extra em vez de rejeitar
                # OU honrar) -- não é sinal de vulnerabilidade nenhuma,
                # é só como JSON funciona. Removido: melhor reportar ZERO
                # quando não dá pra confirmar de verdade do que inflar um
                # sinal que não distingue API vulnerável de API normal.
                #
                # Caso real do VAmPI especificamente: o campo 'admin' É
                # honrado no banco (confirmado lendo o código-fonte), mas
                # nem a leitura via /users/v1/{username} nem o JWT expõem
                # esse campo -- só dá pra confirmar de fora tentando uma
                # AÇÃO que dependa desse privilégio depois (módulo futuro:
                # privileged_function_prober). Esse módulo, sozinho, não
                # tem como provar esse caso específico -- e está tudo bem
                # reportar isso como limitação em vez de forçar um sinal
                # fraco pra "achar alguma coisa".

        if not findings:
            return None
        return ModuleResult(findings=findings)
