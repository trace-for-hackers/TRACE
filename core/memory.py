"""
core/memory.py

Persistência do WRAITH -- SQLite, sem Postgres, sem Redis.

Por que tirar os dois: a versão CLI precisa instalar via `apt` num Kali
sem exigir dois serviços externos rodando. E o Redis, olhando o código de
perto, já era vestigial na prática -- `start_session` escrevia um hash no
Redis com TTL, mas nada no fluxo real (`bootstrap.py`, `scheduler.py`)
jamais LIA esse hash de volta; toda decisão de resumo já vinha da tabela
`executed_modules` no Postgres (durável), exatamente pelo motivo que o
próprio docstring de `mark_module_done_durable` explicava: Redis expira,
Postgres não. Ou seja, tirar o Redis não perde nenhum comportamento --
só remove uma dependência que já não fazia nada.

CONSOLIDAÇÃO: esta classe também absorve tudo que `knowledge/
memory_extension.py` fazia via monkeypatch (save_fact, seed_knowledge_store,
mark_module_done_durable, get_resumable_session, etc.). A separação por
monkeypatch existia para manter o "core/memory.py original" congelado e
diffável isoladamente contra Postgres -- motivo que deixa de fazer sentido
numa reescrita que já troca o backend inteiro. `knowledge/memory_extension.py`
foi removido; `knowledge/bootstrap.py` não precisa mudar nada além de parar
de importar/instalar essa extensão, porque os nomes de método são os mesmos.

BUG REAL encontrado ao consolidar (29/08/2026): get_module_priority() fazia
JOIN contra a tabela `module_runs`, populada por `record_module_run()` --
mas `record_module_run()` nunca era chamado em lugar nenhum do fluxo real
(nem scheduler.py, nem bootstrap.py). Resultado: a "prioridade aprendida
por histórico", uma das peças centrais da arquitetura, sempre retornava
{} (vazio) em produção -- rodava, não quebrava, só nunca fazia nada.
Corrigido fazendo `mark_module_done_durable` (que O SCHEDULER REALMENTE
CHAMA a cada módulo) alimentar `module_runs` também, com um parâmetro novo
`via_cache` pra preservar a semântica original de não contar módulo
pulado por cache no denominador (ver scheduler.py).
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from knowledge.fact import Fact, FactKey, FactSource


def _get_db_path() -> str:
    return os.getenv("TRACE_DB_PATH", str(Path.home() / ".trace" / "trace.db"))


def _get_skip_days() -> int:
    return int(os.getenv("TRACE_SKIP_DAYS", "30"))


def _get_profile_ttl_days() -> int:
    return int(os.getenv("TRACE_PROFILE_TTL_DAYS", "7"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    session_id TEXT NOT NULL UNIQUE,
    site_type TEXT NOT NULL DEFAULT 'unknown',
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    target TEXT NOT NULL,
    module_name TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    category TEXT,
    evidence_json TEXT,
    found_at TEXT NOT NULL,
    is_new INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS site_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL UNIQUE,
    site_type TEXT NOT NULL,
    indicators_json TEXT,
    detected_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- populada por mark_module_done_durable quando via_cache=False -- é o
-- denominador real do hit_rate (ver get_module_priority). Antes desta
-- consolidação, nada gravava aqui (record_module_run nunca era chamado).
CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    module_name TEXT NOT NULL,
    ran_at TEXT NOT NULL
);

-- resumo de scan interrompido -- fonte de verdade durável (não Redis)
CREATE TABLE IF NOT EXISTS executed_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    session_id TEXT NOT NULL,
    module_name TEXT NOT NULL,
    errored INTEGER NOT NULL DEFAULT 0,
    executed_at TEXT NOT NULL,
    UNIQUE (session_id, module_name)
);

-- fatos duráveis (Produces.durable=True) -- é o que faz "WooCommerce
-- encontrado há 3 dias" persistir entre execuções da CLI.
CREATE TABLE IF NOT EXISTS target_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    value_json TEXT,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    produced_by TEXT NOT NULL,
    asserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    id_finding INTEGER REFERENCES findings(id),
    id_session TEXT NOT NULL,
    confidence REAL,
    has_runned INTEGER NOT NULL DEFAULT 1,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS audit_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    target TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER,
    record_count INTEGER,
    format TEXT NOT NULL,
    partitioning TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target_module ON findings(target, module_name);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_site_type ON scans(site_type);
CREATE INDEX IF NOT EXISTS idx_module_runs_scan_module ON module_runs(scan_id, module_name);
CREATE INDEX IF NOT EXISTS idx_executed_modules_session ON executed_modules(session_id);
CREATE INDEX IF NOT EXISTS idx_target_facts_lookup ON target_facts(target, fact_key);
CREATE INDEX IF NOT EXISTS idx_finding_history_finding ON finding_history(id_finding, timestamp);
CREATE INDEX IF NOT EXISTS idx_finding_history_session ON finding_history(id_session);
CREATE INDEX IF NOT EXISTS idx_audit_artifacts_session ON audit_artifacts(session_id);

"""


class MemoryManager:
    """
    Memória única (SQLite) -- curto e longo prazo não são mais backends
    diferentes, são só tabelas diferentes no mesmo arquivo. Isso é
    estritamente mais simples que Postgres+Redis para o caso de uso real:
    um scan de cada vez, sem necessidade de um servidor de cache separado.

    Variáveis de ambiente:
        TRACE_DB_PATH            Caminho do banco SQLite  (padrão: ~/.trace/trace.db)
        TRACE_SKIP_DAYS          Janela de skip por finding recente (padrão: 30)
        TRACE_PROFILE_TTL_DAYS   Validade do perfil de site em dias (padrão: 7)
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _get_db_path()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.skip_days = _get_skip_days()
        self.profile_ttl = _get_profile_ttl_days()
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            # Lightweight migrations for SQLite databases created by older TRACE versions.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
            migrations = (
                ("is_new", "ALTER TABLE findings ADD COLUMN is_new INTEGER NOT NULL DEFAULT 1"),
                ("first_seen", "ALTER TABLE findings ADD COLUMN first_seen TEXT"),
                ("last_seen", "ALTER TABLE findings ADD COLUMN last_seen TEXT"),
                ("status", "ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'new'"),
                ("fingerprint", "ALTER TABLE findings ADD COLUMN fingerprint TEXT"),
            )
            for name, ddl in migrations:
                if name not in columns:
                    conn.execute(ddl)

    # ── ciclo de vida da sessão ──────────────────────────────────────────

    def start_session(self, target: str, site_type: str = "unknown") -> str:
        session_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scans (target, session_id, site_type, started_at) VALUES (?, ?, ?, ?)",
                (target, session_id, site_type, _now_iso()),
            )
        return session_id

    def get_scan_id_for_session(self, session_id: str) -> int | None:
        with self._conn() as conn:
            row = conn.execute("SELECT id FROM scans WHERE session_id = ?", (session_id,)).fetchone()
        return row["id"] if row else None

    def get_session(self, session_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id AS scan_id, target, session_id, site_type, started_at, finished_at FROM scans WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return dict(row) if row else None

    def finish_session(self, session_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET finished_at = ? WHERE session_id = ?",
                (_now_iso(), session_id),
            )

    # ── findings ─────────────────────────────────────────────────────────

    @staticmethod
    def _finding_identity(finding: dict) -> tuple:
        evidence = finding.get("evidence")
        endpoint = evidence.get("endpoint") if isinstance(evidence, dict) else None
        endpoint = endpoint or finding.get("endpoint", "")
        return (
            finding.get("module_name") or finding.get("module", "unknown"),
            finding.get("title", ""),
            str(endpoint),
        )

    @staticmethod
    def _finding_confidence(finding: dict):
        for key in ("confidence", "combined_confidence"):
            value = finding.get(key)
            if value is not None:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    pass
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            for key in ("confidence", "combined_confidence"):
                try:
                    if evidence.get(key) is not None:
                        return float(evidence[key])
                except (TypeError, ValueError):
                    pass
        return None

    def save_finding(self, finding, target: str, session_id: str) -> None:
        """Persist one finding while preserving a stable lifecycle record.

        A finding is one logical record per target/fingerprint. Each scan that
        observes it appends an entry to finding_history and refreshes the same
        row in findings. This is what makes NEW/SEEN/CLOSED/REOPENED reliable.
        """
        if isinstance(finding, dict):
            item = dict(finding)
            module_name = item.get("module_name") or item.get("module", "unknown")
        else:
            item = finding.to_dict() if hasattr(finding, "to_dict") else vars(finding)
            module_name = getattr(finding, "module_name", None) or getattr(finding, "module", "unknown")

        title = item.get("title") or "Finding"
        severity = item.get("severity") or "info"
        category = item.get("category") or "general"
        evidence = item.get("evidence", {})
        confidence = self._finding_confidence(item)
        identity = self._finding_identity({**item, "module_name": module_name, "title": title, "evidence": evidence})
        fingerprint = "|".join(identity)
        now = _now_iso()
        endpoint = identity[2]
        metadata = {
            "identity": list(identity),
            "fingerprint": fingerprint,
            "severity": severity,
            "category": category,
            "endpoint": endpoint,
            "parameter": item.get("parameter") or (evidence.get("parameter") if isinstance(evidence, dict) else ""),
            "source_finding": item,
        }

        finding_id = None
        is_new = False
        first_seen = now
        status = "seen"
        with self._conn() as conn:
            row = conn.execute("SELECT id FROM scans WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                return
            scan_id = row["id"]

            previous = conn.execute(
                "SELECT id, is_new, first_seen, last_seen, status FROM findings "
                "WHERE target = ? AND (fingerprint = ? OR (fingerprint IS NULL AND module_name = ? AND title = ? AND COALESCE(json_extract(evidence_json, '$.endpoint'), '') = ?)) "
                "ORDER BY COALESCE(last_seen, found_at) DESC, id DESC LIMIT 1",
                (target, fingerprint, module_name, title, endpoint),
            ).fetchone()

            if previous is None:
                is_new = True
                first_seen = now
                status = "new"
                cur = conn.execute(
                    "INSERT INTO findings (scan_id, target, module_name, title, severity, category, evidence_json, found_at, is_new, first_seen, last_seen, status, fingerprint) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, target, module_name, title, severity, category, json.dumps(evidence, ensure_ascii=False, default=str),
                     now, 1, first_seen, now, status, fingerprint),
                )
                finding_id = cur.lastrowid
            else:
                finding_id = previous["id"]
                first_seen = previous["first_seen"] or now
                status = "reopened" if (previous["status"] or "").lower() == "closed" else "seen"
                conn.execute(
                    "UPDATE findings SET scan_id = ?, target = ?, module_name = ?, title = ?, severity = ?, category = ?, "
                    "evidence_json = ?, found_at = ?, is_new = 0, first_seen = ?, last_seen = ?, status = ?, fingerprint = ? WHERE id = ?",
                    (scan_id, target, module_name, title, severity, category, json.dumps(evidence, ensure_ascii=False, default=str),
                     now, first_seen, now, status, fingerprint, finding_id),
                )

            conn.execute(
                "INSERT INTO finding_history (timestamp, id_finding, id_session, confidence, has_runned, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                (now, finding_id, session_id, confidence, 1, json.dumps(metadata, ensure_ascii=False, default=str)),
            )

        lifecycle_values = {
            "id": finding_id,
            "status": status,
            "is_new": bool(is_new),
            "first_seen": first_seen,
            "last_seen": now,
            "fingerprint": fingerprint,
            "timestamp": item.get("timestamp") or now,
        }
        for key, value in lifecycle_values.items():
            try:
                if isinstance(finding, dict):
                    finding[key] = value
                else:
                    setattr(finding, key, value)
            except Exception:
                pass

    def finalize_finding_statuses(self, target: str, session_id: str) -> None:
        """Close logical findings absent from the completed current scan."""
        with self._conn() as conn:
            row = conn.execute("SELECT id FROM scans WHERE session_id = ? AND finished_at IS NULL", (session_id,)).fetchone()
            if not row:
                return
            # Current findings are the logical identities touched by this session.
            current_rows = conn.execute(
                "SELECT DISTINCT fingerprint, module_name, title, COALESCE(json_extract(evidence_json, '$.endpoint'), '') AS endpoint "
                "FROM findings WHERE scan_id = ?", (row["id"],)
            ).fetchall()
            current = set()
            for r in current_rows:
                current.add(r["fingerprint"] or "|".join((r["module_name"], r["title"] or "Finding", r["endpoint"])))

            active = conn.execute(
                "SELECT id, fingerprint, module_name, title, COALESCE(json_extract(evidence_json, '$.endpoint'), '') AS endpoint, status "
                "FROM findings WHERE target = ? AND status <> 'closed'", (target,)
            ).fetchall()
            now = _now_iso()
            for r in active:
                fingerprint = r["fingerprint"] or "|".join((r["module_name"], r["title"] or "Finding", r["endpoint"]))
                if fingerprint in current:
                    continue
                changed = conn.execute(
                    "UPDATE findings SET status = 'closed', is_new = 0 WHERE id = ? AND status <> 'closed'",
                    (r["id"],),
                ).rowcount
                if changed:
                    conn.execute(
                        "INSERT INTO finding_history (timestamp, id_finding, id_session, confidence, has_runned, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (now, r["id"], session_id, None, 0, json.dumps({
                            "status": "closed", "reason": "absent_from_current_scan", "fingerprint": fingerprint
                        }, ensure_ascii=False)),
                    )

    def save_audit_artifact(self, session_id: str, target: str, artifact: dict, artifact_type: str = "session") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_artifacts (session_id, target, artifact_type, path, sha256, size_bytes, record_count, format, partitioning, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, target, artifact_type, artifact["path"], artifact["sha256"], artifact.get("size_bytes"), artifact.get("record_count"), artifact.get("format", "parquet"), artifact.get("partitioning", "hive"), artifact.get("created_at", _now_iso())),
            )

    def finding_exists_recently(self, target: str, module_name: str, days: int | None = None) -> bool:
        days = days if days is not None else self.skip_days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM findings WHERE target = ? AND module_name = ? AND found_at > ? LIMIT 1",
                (target, module_name, cutoff),
            ).fetchone()
        return row is not None

    def get_recent_findings(self, target: str, module_name: str, days: int | None = None) -> list[dict]:
        days = days if days is not None else self.skip_days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT scan_id FROM findings WHERE target = ? AND module_name = ? AND found_at > ? "
                "ORDER BY found_at DESC LIMIT 1",
                (target, module_name, cutoff),
            ).fetchone()
            if not row:
                return []
            rows = conn.execute(
                "SELECT id, module_name, title, severity, category, evidence_json, found_at, is_new, first_seen, last_seen, status "
                "FROM findings WHERE scan_id = ? AND module_name = ? ORDER BY found_at DESC",
                (row["scan_id"], module_name),
            ).fetchall()

        return [
            {
                "module_name": r["module_name"], "module": r["module_name"],
                "title": r["title"], "severity": r["severity"], "category": r["category"],
                "evidence": json.loads(r["evidence_json"] or "null") or {},
                "cached": True, "cached_date": r["found_at"][:10],
                "is_new": bool(r["is_new"]), "first_seen": r["first_seen"],
                "last_seen": r["last_seen"], "status": r["status"], "id": r["id"],
            }
            for r in rows
        ]

    def get_scans_for_target(self, target: str, limit: int = 20) -> list[dict]:
        """Só scans finalizados (finished_at IS NOT NULL) -- scan interrompido
        não aparece no histórico, pode ter findings incompletos."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT
                    s.id AS scan_id, s.session_id, s.site_type, s.started_at, s.finished_at,
                    COUNT(f.id) AS total_findings,
                    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                WHERE s.target = ? AND s.finished_at IS NOT NULL
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
            """, (target, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_findings_for_scan_id(self, scan_id: int) -> list[dict]:
        """Versão RICA -- usada por core/scan_diff.py e core/vuln_history.py,
        e pela aba de histórico da GUI."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT id, module_name, title, severity, category, evidence_json, found_at, is_new, first_seen, last_seen, status
                FROM findings WHERE scan_id = ?
                ORDER BY
                    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                                  WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                    found_at DESC
            """, (scan_id,)).fetchall()

        results = []
        for r in rows:
            evidence = json.loads(r["evidence_json"] or "null")
            evidence_dict = evidence if isinstance(evidence, dict) else {}
            results.append({
                "id": r["id"], "module": r["module_name"], "module_name": r["module_name"],
                "title": r["title"] or "Finding", "severity": r["severity"] or "info",
                "category": r["category"] or "General",
                "evidence": evidence if evidence is not None else {},
                "description": evidence_dict.get("description", ""),
                "business_impact": evidence_dict.get("business_impact", ""),
                "remediation": evidence_dict.get("remediation", ""),
                "notes": "", "cached": True, "cached_date": r["found_at"][:10],
                "is_new": bool(r["is_new"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"], "status": r["status"],
            })
        return results

    def get_findings_for_scan(self, scan_id: int) -> list[dict]:
        """Versão MÍNIMA -- usada só por scheduler.py ao retomar um scan
        interrompido (não precisa dos campos derivados de evidence, só o
        essencial pra repopular self.findings sem re-executar o módulo)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT module_name, title, severity, category, evidence_json FROM findings WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        return [
            {
                "module": r["module_name"], "title": r["title"], "severity": r["severity"],
                "category": r["category"], "evidence": json.loads(r["evidence_json"] or "null"),
            }
            for r in rows
        ]

    # ── perfil de site ───────────────────────────────────────────────────

    def save_site_profile(self, target: str, site_type: str, indicators: dict) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO site_profiles (target, site_type, indicators_json, detected_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target) DO UPDATE SET
                    site_type = excluded.site_type,
                    indicators_json = excluded.indicators_json,
                    updated_at = excluded.updated_at
            """, (target, site_type, json.dumps(indicators, default=str), _now_iso(), _now_iso()))

    def get_site_profile(self, target: str) -> dict | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.profile_ttl)).isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT site_type, indicators_json, updated_at FROM site_profiles "
                "WHERE target = ? AND updated_at > ?",
                (target, cutoff),
            ).fetchone()
        if not row:
            return None
        return {
            "site_type": row["site_type"],
            "indicators": json.loads(row["indicators_json"] or "null"),
            "updated_at": row["updated_at"],
        }

    # ── prioridade aprendida ─────────────────────────────────────────────

    def mark_module_done_durable(self, scan_id: int, session_id: str, module_name: str,
                                  errored: bool = False, via_cache: bool = False) -> None:
        """
        Chamado pelo scheduler imediatamente após cada módulo terminar --
        sucesso, erro, OU pulo por cache (ver `via_cache`).

        `via_cache`: True quando o scheduler pulou a execução de verdade e
        só reaproveitou um achado recente (ver knowledge/scheduler.py,
        _execute_wave). Só grava em `module_runs` (denominador do hit_rate)
        quando via_cache=False -- contar um pulo como "execução" infla
        artificialmente o hit_rate de um módulo que só está sendo
        reaproveitado, não checado de novo de verdade. `executed_modules`
        (controle de retomada) grava sempre, independente disso -- pra
        retomada, um módulo pulado por cache já está tão "resolvido" quanto
        um executado de verdade.
        """
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO executed_modules (scan_id, session_id, module_name, errored, executed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id, module_name) DO UPDATE SET
                    errored = excluded.errored, executed_at = excluded.executed_at
            """, (scan_id, session_id, module_name, int(errored), _now_iso()))

            if not via_cache:
                conn.execute(
                    "INSERT INTO module_runs (scan_id, module_name, ran_at) VALUES (?, ?, ?)",
                    (scan_id, module_name, _now_iso()),
                )

    def get_module_priority(self, site_type: str) -> dict[str, float]:
        """
        {module_name: hit_rate} = scans onde o módulo achou algo ÷ scans
        onde o módulo EXECUTOU DE VERDADE (via_cache=False em module_runs).
        """
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT
                    mr.module_name,
                    CAST(COUNT(DISTINCT f.scan_id) AS REAL) / COUNT(DISTINCT mr.scan_id) AS hit_rate
                FROM module_runs mr
                JOIN scans s ON s.id = mr.scan_id
                LEFT JOIN findings f ON f.scan_id = mr.scan_id AND f.module_name = mr.module_name
                WHERE s.site_type = ? AND s.finished_at IS NOT NULL
                GROUP BY mr.module_name
                ORDER BY hit_rate DESC
            """, (site_type,)).fetchall()
        return {r["module_name"]: r["hit_rate"] for r in rows}

    def get_executed_modules(self, session_id: str) -> set[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT module_name FROM executed_modules WHERE session_id = ?", (session_id,),
            ).fetchall()
        return {r["module_name"] for r in rows}

    def get_resumable_session(self, target: str, max_age_hours: int = 24) -> dict | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
        with self._conn() as conn:
            row = conn.execute("""
                SELECT id AS scan_id, session_id, site_type, started_at
                FROM scans WHERE target = ? AND finished_at IS NULL AND started_at > ?
                ORDER BY started_at DESC LIMIT 1
            """, (target, cutoff)).fetchone()
        return dict(row) if row else None

    # ── fatos duráveis ───────────────────────────────────────────────────

    def save_fact(self, fact: Fact) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO target_facts (target, fact_key, value_json, confidence, source, produced_by, asserted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (fact.target, str(fact.key), json.dumps(fact.value, default=str),
                 fact.confidence, fact.source.value, fact.produced_by, _now_iso()),
            )

    def get_durable_facts(self, target: str, max_age_days: int = 7) -> list[Fact]:
        """Última versão (por fact_key) de cada fato durável dentro da
        janela de validade. Usa ROW_NUMBER() em vez de GROUP BY+HAVING com
        coluna solta -- essa segunda forma não garante pegar valor/confiança/
        produced_by da MESMA linha que tem o asserted_at mais recente, só
        garante que o asserted_at bate; em SQLite (mais permissivo que
        Postgres com colunas fora do GROUP BY) isso podia silenciosamente
        misturar campos de linhas diferentes do mesmo fact_key."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT fact_key, value_json, confidence, produced_by, asserted_at FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY fact_key ORDER BY asserted_at DESC
                    ) AS rn
                    FROM target_facts
                    WHERE target = ? AND asserted_at > ?
                ) WHERE rn = 1
            """, (target, cutoff)).fetchall()

        return [
            Fact(
                key=FactKey(r["fact_key"]), value=json.loads(r["value_json"] or "null"),
                confidence=r["confidence"], source=FactSource.MEMORY,
                produced_by=f"memory:{r['produced_by']}", target=target,
                timestamp=datetime.fromisoformat(r["asserted_at"]),
            )
            for r in rows
        ]

    def seed_knowledge_store(self, store, target: str, max_age_days: int = 7) -> int:
        facts = self.get_durable_facts(target, max_age_days=max_age_days)
        for f in facts:
            store.assert_fact(f, durable=False)  # já está no SQLite, não regravar
        return len(facts)
