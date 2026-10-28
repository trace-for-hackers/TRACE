"""
modules/api_resource_provisioner.py

Equivalente do auth_crawler.py para API JSON pura (sem <a href>, sem
<form> -- o que quebrou contra o VAmPI). Em vez de OBSERVAR navegação,
CRIA um recurso de teste como cada identidade (via um endpoint de
criação real, documentado no OpenAPI spec do próprio alvo) e já sabe de
quem é o recurso, porque foi ELE quem criou -- sem precisar adivinhar ID
nem confiar em regex de formato (o que já quebrou contra o VAmPI: o
identificador de recurso lá é um título de livro, string livre, não
número nem UUID).

Isso é metodologia real de teste de BOLA/IDOR, não um atalho: provisionar
dado de teste conhecido é como qualquer pentester testa isso na prática
(criar 2 contas, cada uma cria um registro próprio, testar acesso
cruzado) -- só que aqui automatizado a partir do spec.

COMO acha o que criar: procura no spec um par "coleção" (POST /recurso)
+ "item" (GET /recurso/{id}) -- o nome do path parameter em {id} é
comparado (case-insensitive) contra as propriedades do corpo esperado
pelo POST; se bater, esse é o campo que vira o identificador que a
gente MESMO escolhe (embutindo o nome da identidade + um sufixo
aleatório, pra nunca colidir entre identidades nem com dado real do
alvo). Os outros campos obrigatórios do schema são preenchidos com
valor mínimo plausível pro tipo declarado.

LIMITAÇÃO HONESTA: só funciona pra endpoint de criação simples (POST
retorna sucesso, dado fica imediatamente recuperável pelo mesmo ID que
foi enviado). Fluxo de criação assíncrono, ID gerado pelo servidor
(auto-increment que não podemos escolher), ou schema com dependência
entre campos (ex.: um campo só é válido dependendo do valor de outro)
não são cobertos -- nesses casos, ainda dá pra alimentar
surface.resource.*.owned_by.* manualmente, o formato do fato é o mesmo.
"""

from __future__ import annotations

import random
import string

import yaml

from utils.requester import get, post_as, registered_identities, register_test_artifact
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult


def load_spec(path_or_url: str) -> dict:
    """Aceita caminho local ou URL -- para o caso comum de o spec estar
    hospedado no próprio alvo (ex.: http://alvo/openapi_specs/openapi3.yml)."""
    if path_or_url.startswith(("http://", "https://")):
        r = get(path_or_url)
        if not r or r.status_code != 200:
            raise RuntimeError(f"não consegui buscar o spec em {path_or_url}")
        text = r.text
    else:
        with open(path_or_url, "r", encoding="utf-8") as f:
            text = f.read()
    return yaml.safe_load(text)


def find_resource_pairs(spec: dict) -> list[dict]:
    """
    Acha todo par (caminho de criação, caminho de item) no spec.

    Um "item path" é qualquer path terminando em "/{algo}" com operação
    GET. O "collection path" é esse mesmo path sem o último segmento,
    desde que exista no spec com uma operação POST. O param_name vem
    direto do nome entre chaves -- o spec já diz explicitamente qual
    segmento é variável, sem precisar de heurística de regex tipo
    "parece numérico?" (que já provou ser insuficiente contra IDs em
    formato de string livre).
    """
    paths = spec.get("paths", {})
    pairs = []

    for item_path, item_ops in paths.items():
        if not item_path.endswith("}") or "/" not in item_path:
            continue
        if "get" not in {k.lower() for k in item_ops}:
            continue

        param_name = item_path.rsplit("/", 1)[-1].strip("{}")
        collection_path = item_path.rsplit("/", 1)[0]

        collection_ops = paths.get(collection_path)
        if not collection_ops or "post" not in {k.lower() for k in collection_ops}:
            continue

        post_op = collection_ops["post"] if "post" in collection_ops else collection_ops.get("POST")
        schema = (
            post_op.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )

        pairs.append({
            "item_path": item_path,
            "collection_path": collection_path,
            "param_name": param_name,
            "request_schema": schema,
        })

    return pairs


def _dummy_value_for(prop_schema: dict, override: str | None = None) -> object:
    if override is not None:
        return override
    prop_type = prop_schema.get("type", "string")
    fmt = prop_schema.get("format", "")
    if prop_type == "string":
        if "email" in fmt or "email" in prop_schema.get("example", ""):
            return "surfacer_test@example.com"
        return prop_schema.get("example") or "surfacer_test_value"
    if prop_type in ("integer", "number"):
        return 1
    if prop_type == "boolean":
        return True
    return "surfacer_test_value"


def build_request_body(schema: dict, param_name: str, chosen_id: str) -> dict:
    """Monta um corpo de requisição válido o suficiente pro schema:
    campo que corresponde ao path param recebe o ID que A GENTE escolheu
    (chosen_id) -- não um valor aleatório que teríamos que descobrir
    depois. Outros campos obrigatórios recebem valor mínimo plausível."""
    properties = schema.get("properties", {})
    required = schema.get("required", list(properties.keys()))
    body = {}

    for prop_name, prop_schema in properties.items():
        if prop_name not in required:
            continue
        if prop_name.lower() == param_name.lower():
            body[prop_name] = chosen_id
        else:
            body[prop_name] = _dummy_value_for(prop_schema)

    return body


def _random_suffix(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# estado global de configuração -- mesmo padrão de register_identity() em
# utils/requester.py. Necessário porque o scheduler sempre instancia
# módulo com rm.module_class() (zero argumentos, ver knowledge/
# scheduler.py) -- não há como passar spec_path pelo construtor.
_spec_path: str | None = None


def configure_openapi_spec(path_or_url: str) -> None:
    """Chamado uma vez, no início do scan (ver main.py --openapi-spec),
    antes do scheduler rodar."""
    global _spec_path
    _spec_path = path_or_url


@discovery_module(
    requires=[
        Requirement("config.identity_available", min_confidence=0.5),
        Requirement("config.openapi_spec_available", min_confidence=0.5),
    ],
    produces=[Produces("surface.resource.*.owned_by.*", durable=True)],
    cost=10,
    category="discovery_bac",
    display_name="Provisionamento de Recurso via OpenAPI",
    summary="Cria um recurso de teste como cada identidade registrada, usando um par criação/item achado no spec OpenAPI do alvo -- equivalente do auth_crawler.py para API JSON pura.",
)
class ApiResourceProvisioner:
    name = "api_resource_provisioner"

    def run(self, target: str):
        if not _spec_path:
            print("[api_resource_provisioner] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        identities = registered_identities()
        if not identities:
            print("[api_resource_provisioner] nenhuma identidade registrada -- nada a fazer.")
            return None

        try:
            spec = load_spec(_spec_path)
        except Exception as e:
            print(f"[api_resource_provisioner] não consegui carregar o spec: {e}")
            return None

        pairs = find_resource_pairs(spec)
        if not pairs:
            print("[api_resource_provisioner] nenhum par criação/item encontrado no spec.")
            return None

        all_facts = []

        for identity in identities:
            for pair in pairs:
                chosen_id = f"surfacer_{identity}_{_random_suffix()}"
                body = build_request_body(pair["request_schema"], pair["param_name"], chosen_id)

                collection_url = target.rstrip("/") + pair["collection_path"]
                resp = post_as(identity, collection_url, json_body=body)

                if resp is None or resp.status_code not in (200, 201):
                    continue  # criação falhou -- endpoint pode exigir campo que não geramos direito

                concrete_url = target.rstrip("/") + pair["item_path"].replace(
                    "{" + pair["param_name"] + "}", chosen_id
                )
                url_template = target.rstrip("/") + pair["item_path"].replace(
                    "{" + pair["param_name"] + "}", "{id}"
                )

                key = f"surface.resource.{identity}_{_random_suffix(4)}.owned_by.{identity}"
                all_facts.append(fact(key, {
                    "url_template": url_template, "resource_id": chosen_id,
                    "id_location": "path", "concrete_url": concrete_url, "identity": identity,
                }, 0.9, self.name, target, identity=identity))

                print(f"[api_resource_provisioner] '{identity}' criou recurso de teste em {pair['collection_path']}.")
                register_test_artifact(f"recurso de teste ({pair['collection_path']})", concrete_url, identity=identity)

        if not all_facts:
            return None
        return ModuleResult(facts=all_facts)
