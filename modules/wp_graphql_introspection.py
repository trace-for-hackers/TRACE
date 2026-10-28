from utils.requester import post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


INTROSPECTION_QUERY = """
{
  "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"
}
"""


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.wpgraphql.present", min_confidence=0.5)],
    cost=1,
    category="wpgraphql",
    display_name="GraphQL Schema Introspection Habilitado",
    summary="Testa se o endpoint /graphql aceita uma query de introspection completa (__schema), vazando todo o schema de tipos, campos e mutations sem autenticação.",
)
class WPGraphQLIntrospection:
    """
    Testa se o endpoint /graphql aceita uma query de introspection completa
    (__schema). Em produção, isso deveria estar desabilitado -- a
    introspection revela TODOS os tipos, campos, mutations e relacionamentos
    do schema, incluindo nomes de campos sensíveis que dão pistas diretas
    sobre estrutura de dados interna (ex.: "stripeCustomerId", "internalNotes",
    mutations de admin que não deveriam ser descobertas por tentativa e erro).

    Diferente de scanners genéricos de GraphQL, este módulo só roda quando
    DetectWPGraphQL (modules/plugin_detectors.py) já confirmou que o endpoint
    /graphql existe e responde -- evita gastar a requisição de introspection
    (mais pesada, schema completo) em alvos que nem têm GraphQL.
    """
    name = "wp_graphql_introspection"

    def run(self, target):
        r = post(f"{target}/graphql", INTROSPECTION_QUERY)
        if not r or r.status_code != 200:
            return None

        try:
            data = r.json()
        except Exception:
            return None

        schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
        if not schema:
            return None

        types = schema.get("types", [])
        type_names = [t.get("name") for t in types if t.get("name")]
        mutation_type = schema.get("mutationType", {})
        has_mutations = bool(mutation_type and mutation_type.get("name"))

        f = Finding(
            module=self.name,
            title="WPGraphQL Schema Introspection Enabled",
            severity="medium",
            description=(
                "The /graphql endpoint accepts introspection queries, exposing the "
                "complete GraphQL schema (types, fields, and mutations) without "
                "authentication."
            ),
            endpoint="/graphql",
            evidence={
                "total_types": len(type_names),
                "sample_types": type_names[:25],
                "mutations_exposed": has_mutations,
            },
        )

        f.business_impact = (
            "Introspection reveals the entire data model, including field names that "
            "hint at sensitive internal data and the full list of available mutations "
            "(write operations). This significantly reduces the effort needed to find "
            "and exploit authorization flaws or sensitive data exposure in custom "
            "resolvers."
        )

        f.remediation = (
            "Disable GraphQL introspection in production (most WPGraphQL setups expose "
            "a config flag for this) or restrict /graphql access to authenticated "
            "requests/known IPs."
        )

        f.exploitability = "Easy"

        return [f.to_dict()]