"""
core/fact.py

Define a unidade atômica de conhecimento do TRACE: o Fact.

Um Fact é diferente de um Finding:
  - Finding  -> achado de segurança, para humano ler em relatório.
  - Fact     -> conhecimento estrutural sobre o alvo, para a MÁQUINA decidir.

Exemplo: o módulo de detecção de WooCommerce pode não gerar nenhum Finding
(não é uma vulnerabilidade ter WooCommerce instalado), mas DEVE gerar o Fact
`tech.woocommerce.present=True`, porque isso é o gatilho que libera 10 outros
módulos.

Um Fact é imutável após criado (frozen dataclass) — para "atualizar" um fato,
o KnowledgeStore cria uma nova versão com versionamento por timestamp,
preservando histórico para auditoria/explicabilidade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class FactSource(str, Enum):
    """De onde o fato veio — importante para auditoria e para confiar mais ou menos nele."""
    MODULE = "module"          # produzido por um módulo durante o scan atual
    MEMORY = "memory"          # recuperado da memória de longo prazo (scan anterior)
    CLASSIFIER = "classifier"  # produzido pelo SiteClassifier
    USER = "user"               # fornecido manualmente (ex.: --assume wordpress)
    INFERENCE = "inference"     # derivado por uma regra de inferência (fato sobre fatos)


@dataclass(frozen=True)
class FactKey:
    """
    Chave canônica de um fato. Usamos namespacing hierárquico com ponto,
    estilo OpenTelemetry/Prometheus, para permitir consultas por prefixo
    (ex.: "tech.woocommerce.*") sem precisar de um schema rígido central.

    Convenção de namespaces (não é enforced em código, é convenção de projeto,
    documentada para quem escreve módulos novos):

        cms.*           -> fatos sobre o CMS em si (wordpress.detected, wordpress.version)
        tech.<plugin>.* -> presença/versão de tecnologias e plugins
        surface.*       -> superfícies de ataque mapeadas (rest_api, admin_ajax, uploads)
        endpoint.*      -> endpoints específicos confirmados
        auth.*          -> fatos sobre autenticação (app_passwords, xmlrpc habilitado)
        profile.*       -> perfil do site (ecommerce, blog, lms...)
        infra.*         -> infraestrutura (waf, cdn, server headers)
    """
    namespace: str   # ex.: "tech.woocommerce.present"

    def matches_prefix(self, prefix: str) -> bool:
        return self.namespace == prefix or self.namespace.startswith(prefix + ".")

    def __str__(self) -> str:
        return self.namespace


@dataclass(frozen=True)
class Fact:
    """
    Uma unidade de conhecimento sobre o alvo.

    confidence: float em [0.0, 1.0]
        1.0  -> confirmado de forma inequívoca (ex.: JSON da REST API contém o campo)
        0.7  -> heurística forte (ex.: header específico de um plugin)
        0.4  -> heurística fraca (ex.: keyword solta no HTML)
        Módulos consumidores decidem o próprio limiar mínimo de confiança aceitável.

    identity: None para a esmagadora maioria dos fatos (TRACE inteiro, e a
        maior parte de qualquer domínio novo) -- um fato sobre o ALVO não
        pertence a ninguém. Só passa a ter valor em domínios onde a mesma
        pergunta ("esse recurso existe?") tem resposta DIFERENTE dependendo
        de QUEM pergunta -- o caso central de Broken Access Control. Nesses
        casos, o fact_key também deveria embutir a identidade como segmento
        de namespace (ex. "surface.resource.<hash>.owned_by.<identidade>"),
        porque o KnowledgeStore mantém só UMA versão "atual" por fact_key --
        sem isso, a afirmação da identidade B substituiria silenciosamente
        a de A, quando na verdade as duas precisam coexistir. Este campo é
        o companheiro ERGONÔMICO dessa convenção (não obriga quem consome o
        fato a fazer parsing de string pra saber de quem é), não uma
        mudança na forma como o Store decide qual fato é "atual".

    ttl_seconds: tempo de vida do fato antes de ser considerado "stale" (None = não expira
        dentro da sessão; fatos de memória de longo prazo têm seu próprio TTL no Postgres).
    """
    key: FactKey
    value: Any
    confidence: float
    source: FactSource
    produced_by: str                       # module.name que produziu (ou "classifier", "memory")
    target: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ttl_seconds: int | None = None
    evidence_ref: str | None = None        # id do Finding correlato, se existir
    identity: str | None = None            # ver docstring acima -- None em quase todo fato

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.ttl_seconds is None:
            return False
        now = now or datetime.utcnow()
        return (now - self.timestamp).total_seconds() > self.ttl_seconds

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": str(self.key),
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source.value,
            "produced_by": self.produced_by,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "evidence_ref": self.evidence_ref,
            "identity": self.identity,
        }


def fact(
    key: str,
    value: Any,
    confidence: float,
    produced_by: str,
    target: str,
    source: FactSource = FactSource.MODULE,
    ttl_seconds: int | None = None,
    evidence_ref: str | None = None,
    identity: str | None = None,
) -> Fact:
    """Helper de criação — assinatura curta para uso dentro de módulos."""
    return Fact(
        key=FactKey(key),
        value=value,
        confidence=confidence,
        source=source,
        produced_by=produced_by,
        target=target,
        ttl_seconds=ttl_seconds,
        evidence_ref=evidence_ref,
        identity=identity,
    )
