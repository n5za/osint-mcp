"""Private, project-scoped evidence graph for ongoing investigations."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .common import guarded, utcnow

DEFAULT_DB = Path.home() / ".local" / "share" / "osint-mcp" / "cases.sqlite3"
MAX_RESULT_BYTES = 1_000_000


def _safe_excerpt(value: str, limit: int) -> str:
    text = (value or "").strip()[:limit]
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|\bAKIA[0-9A-Z]{16}\b",
                  "[redacted]", text)
    return re.sub(r"(?i)\b(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*['\"]?[^\s,'\"]+",
                  r"\1=[redacted]", text)


def _db_path() -> Path:
    return Path(os.environ.get("OSINT_CASES_DB", str(DEFAULT_DB))).expanduser()


@contextmanager
def _db():
    path = _db_path()
    existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix" and (not existed or path == DEFAULT_DB):
        os.chmod(path.parent, 0o700)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            connection.execute("PRAGMA journal_mode=WAL")  # concurrent readers + crash safety
        except sqlite3.DatabaseError:
            pass
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                url TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL, UNIQUE(case_id, url)
            );
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                kind TEXT NOT NULL, name TEXT NOT NULL COLLATE NOCASE,
                created_at TEXT NOT NULL, UNIQUE(case_id, kind, name)
            );
            CREATE TABLE IF NOT EXISTS mentions (
                case_id TEXT NOT NULL REFERENCES cases(id),
                entity_id INTEGER NOT NULL REFERENCES entities(id),
                source_id INTEGER NOT NULL REFERENCES sources(id),
                PRIMARY KEY(case_id, entity_id, source_id)
            );
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                source_id INTEGER REFERENCES sources(id),
                entity_id INTEGER REFERENCES entities(id),
                text TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                subject_id INTEGER NOT NULL REFERENCES entities(id),
                predicate TEXT NOT NULL,
                object_id INTEGER NOT NULL REFERENCES entities(id),
                source_id INTEGER REFERENCES sources(id),
                evidence TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, subject_id, predicate, object_id, source_id, evidence)
            );
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                sha256 TEXT NOT NULL, dhash TEXT NOT NULL, path TEXT NOT NULL,
                original_url TEXT, source_id INTEGER REFERENCES sources(id),
                analysis_json TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(case_id, sha256)
            );
            CREATE TABLE IF NOT EXISTS image_people (
                case_id TEXT NOT NULL REFERENCES cases(id),
                image_id INTEGER NOT NULL REFERENCES images(id),
                entity_id INTEGER NOT NULL REFERENCES entities(id),
                PRIMARY KEY(case_id, image_id, entity_id)
            );
            CREATE TABLE IF NOT EXISTS image_hits (
                case_id TEXT NOT NULL REFERENCES cases(id),
                image_id INTEGER NOT NULL REFERENCES images(id),
                source_id INTEGER NOT NULL REFERENCES sources(id),
                provider TEXT NOT NULL, score REAL,
                match_image_url TEXT,
                PRIMARY KEY(case_id, image_id, source_id, provider)
            );
            CREATE INDEX IF NOT EXISTS idx_entities_case_name ON entities(case_id, name);
            CREATE INDEX IF NOT EXISTS idx_facts_case_subject ON facts(case_id, subject_id);
            CREATE INDEX IF NOT EXISTS idx_facts_case_object ON facts(case_id, object_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_observations_unique ON observations(
                case_id, COALESCE(source_id,-1), COALESCE(entity_id,-1), text
            );
        """)
        _ensure_fts(connection)
        yield connection
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------- FTS5 full-text
def _ensure_fts(db: sqlite3.Connection) -> None:
    """Create FTS5 index + write triggers once; backfill existing databases.

    Version history: 0 = legacy (pre-2.0), 2 = FTS5 index present.
    Falls back silently when the SQLite build lacks FTS5.
    """
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version >= 2:
        return
    try:
        db.executescript("""
            CREATE VIRTUAL TABLE IF NOT EXISTS case_fts USING fts5(
                text, case_id UNINDEXED, kind UNINDEXED, ref_id UNINDEXED
            );
            CREATE TRIGGER IF NOT EXISTS trg_entities_fts AFTER INSERT ON entities BEGIN
                INSERT INTO case_fts(case_id, kind, ref_id, text)
                VALUES(new.case_id, 'entity', new.id, new.name);
            END;
            CREATE TRIGGER IF NOT EXISTS trg_observations_fts AFTER INSERT ON observations BEGIN
                INSERT INTO case_fts(case_id, kind, ref_id, text)
                VALUES(new.case_id, 'observation', new.id, new.text);
            END;
            CREATE TRIGGER IF NOT EXISTS trg_facts_fts AFTER INSERT ON facts BEGIN
                INSERT INTO case_fts(case_id, kind, ref_id, text) VALUES(
                    new.case_id, 'fact', new.id,
                    (SELECT name FROM entities WHERE id=new.subject_id) || ' ' || new.predicate
                    || ' ' || (SELECT name FROM entities WHERE id=new.object_id)
                    || ' ' || new.evidence);
            END;
        """)
        db.execute("DELETE FROM case_fts")
        db.execute("INSERT INTO case_fts(case_id, kind, ref_id, text) SELECT case_id, 'entity', id, name FROM entities")
        db.execute("INSERT INTO case_fts(case_id, kind, ref_id, text) SELECT case_id, 'observation', id, text FROM observations")
        db.execute("""INSERT INTO case_fts(case_id, kind, ref_id, text)
            SELECT f.case_id, 'fact', f.id,
                (SELECT name FROM entities WHERE id=f.subject_id) || ' ' || f.predicate
                || ' ' || (SELECT name FROM entities WHERE id=f.object_id) || ' ' || f.evidence
            FROM facts f""")
        db.execute("PRAGMA user_version=2")
    except sqlite3.OperationalError:
        # FTS5 unavailable: searches fall back to LIKE
        pass


def _fts_match_query(query: str) -> str:
    """Turn a free-text query into a safe FTS5 MATCH expression (AND of quoted terms)."""
    words = [word for word in re.findall(r"[\wÀ-ÿ]+", query) if word]
    return " AND ".join('"' + word + '"' for word in words[:8])


def _case_id(db: sqlite3.Connection, case: str) -> str:
    row = db.execute("SELECT id FROM cases WHERE id=? OR name=?", (case.strip(), case.strip())).fetchone()
    if not row:
        raise ValueError("case not found; create it with case_create")
    return row["id"]


def _required(value: str, label: str, limit: int = 300) -> str:
    value = (value or "").strip()
    if not value or len(value) > limit:
        raise ValueError(f"{label} must be 1-{limit} characters")
    return value


def _source(db: sqlite3.Connection, case_id: str, url: str, title: str = "") -> int:
    url = _required(url, "source URL", 2000)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("source URL must be HTTP or HTTPS")
    sensitive = {"token", "key", "api_key", "apikey", "secret", "password", "access_token", "auth", "code"}
    query = urlencode([(k, "[redacted]" if k.lower() in sensitive else v)
                       for k, v in parse_qsl(parsed.query, keep_blank_values=True)])
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port:
        host += f":{parsed.port}"
    url = urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    db.execute(
        "INSERT INTO sources(case_id,url,title,checked_at) VALUES(?,?,?,?) "
        "ON CONFLICT(case_id,url) DO UPDATE SET title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE sources.title END, checked_at=excluded.checked_at",
        (case_id, url, title[:300], utcnow().isoformat(timespec="seconds")),
    )
    return db.execute("SELECT id FROM sources WHERE case_id=? AND url=?", (case_id, url)).fetchone()["id"]


def _entity(db: sqlite3.Connection, case_id: str, name: str, kind: str) -> int:
    name = _required(name, "entity name")
    kind = _required(kind.lower(), "entity kind", 40)
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", kind):
        raise ValueError("entity kind must use lowercase letters, digits, underscores or hyphens")
    db.execute("INSERT OR IGNORE INTO entities(case_id,kind,name,created_at) VALUES(?,?,?,?)",
               (case_id, kind, name, utcnow().isoformat(timespec="seconds")))
    return db.execute("SELECT id FROM entities WHERE case_id=? AND kind=? AND name=?",
                      (case_id, kind, name)).fetchone()["id"]


def _row(row: sqlite3.Row) -> dict:
    return dict(row)


@guarded
async def case_create(name: str, description: str = "") -> dict:
    """Create or reopen a local investigation case. Data stays in a private SQLite file."""
    name = _required(name, "case name", 120)
    description = (description or "").strip()[:2000]
    with _db() as db:
        db.execute("INSERT OR IGNORE INTO cases(id,name,description,created_at) VALUES(?,?,?,?)",
                   (uuid.uuid4().hex[:12], name, description, utcnow().isoformat(timespec="seconds")))
        row = db.execute("SELECT * FROM cases WHERE name=?", (name,)).fetchone()
        return {"ok": True, "case": _row(row), "database": str(_db_path())}


@guarded
async def case_list() -> dict:
    """List locally saved investigation cases with entity, source and fact counts."""
    with _db() as db:
        rows = db.execute("""
            SELECT c.*, (SELECT count(*) FROM entities e WHERE e.case_id=c.id) AS entities,
            (SELECT count(*) FROM sources s WHERE s.case_id=c.id) AS sources,
            (SELECT count(*) FROM facts f WHERE f.case_id=c.id) AS facts
            FROM cases c ORDER BY c.created_at DESC
        """).fetchall()
        return {"ok": True, "cases": [_row(row) for row in rows]}


@guarded
async def case_add_fact(
    case: str, subject: str, predicate: str, object_name: str,
    subject_kind: str = "person", object_kind: str = "person",
    source_url: str = "", evidence: str = "",
) -> dict:
    """Add an explicit relationship to a case, with a source and short evidence quote.

    Without a source, it is stored as an unverified lead. Never infer causality
    or identity merely because two entities appear on the same page.
    """
    predicate = _required(predicate, "predicate", 100).lower()
    evidence = _safe_excerpt(evidence, 1000)
    with _db() as db:
        case_id = _case_id(db, case)
        subject_id = _entity(db, case_id, subject, subject_kind)
        object_id = _entity(db, case_id, object_name, object_kind)
        source_id = _source(db, case_id, source_url) if source_url else None
        status = "sourced" if source_id and evidence else "lead"
        existing = db.execute("""SELECT id FROM facts WHERE case_id=? AND subject_id=?
            AND predicate=? AND object_id=? AND source_id IS ? AND evidence=?""",
            (case_id, subject_id, predicate, object_id, source_id, evidence)).fetchone()
        if not existing:
            cursor = db.execute("""INSERT INTO facts
                (case_id,subject_id,predicate,object_id,source_id,evidence,status,created_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (case_id, subject_id, predicate, object_id, source_id, evidence, status,
                 utcnow().isoformat(timespec="seconds")))
        fact_id = existing["id"] if existing else cursor.lastrowid
        row = db.execute("""SELECT f.id, f.predicate, f.evidence, f.status,
            s.name AS subject, s.kind AS subject_kind, o.name AS object, o.kind AS object_kind,
            src.url AS source_url FROM facts f
            JOIN entities s ON s.id=f.subject_id JOIN entities o ON o.id=f.object_id
            LEFT JOIN sources src ON src.id=f.source_id
            WHERE f.id=?""", (fact_id,)).fetchone()
        return {"ok": True, "fact": _row(row)}


@guarded
async def case_note(case: str, entity: str, kind: str, observation: str,
                    source_url: str = "") -> dict:
    """Save a person, place, event, organization, or other entity with a short note.

    A source URL records where the observation came from. Notes are evidence
    excerpts or leads, not proof of a relationship to another entity.
    """
    observation = _safe_excerpt(_required(observation, "observation", 500), 500)
    with _db() as db:
        case_id = _case_id(db, case)
        entity_id = _entity(db, case_id, entity, kind)
        source_id = _source(db, case_id, source_url) if source_url else None
        if source_id:
            db.execute("INSERT OR IGNORE INTO mentions(case_id,entity_id,source_id) VALUES(?,?,?)",
                       (case_id, entity_id, source_id))
        db.execute("INSERT OR IGNORE INTO observations(case_id,source_id,entity_id,text) VALUES(?,?,?,?)",
                   (case_id, source_id, entity_id, observation))
        stored_url = db.execute("SELECT url FROM sources WHERE id=?", (source_id,)).fetchone()["url"] if source_id else None
        return {"ok": True, "entity_id": entity_id, "entity": entity, "kind": kind,
                "observation": observation, "source_url": stored_url,
                "status": "sourced" if source_id else "lead"}


def _capture_pages(db: sqlite3.Connection, case_id: str, pages: list) -> dict:
    sources_added = 0
    mentions_added = 0
    observations_added = 0
    for page in pages[:100]:
        if not isinstance(page, dict) or page.get("blocked") or page.get("error"):
            continue
        url = page.get("final_url") or page.get("url") or page.get("source_url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        source_id = _source(db, case_id, url, str(page.get("title") or ""))
        sources_added += 1
        for sentence in (page.get("key_sentences") or [])[:10]:
            if not isinstance(sentence, str) or not sentence.strip():
                continue
            cursor = db.execute("INSERT OR IGNORE INTO observations(case_id,source_id,entity_id,text) VALUES(?,?,NULL,?)",
                                (case_id, source_id, _safe_excerpt(sentence, 500)))
            observations_added += cursor.rowcount
        for item in (page.get("entities") or [])[:200]:
            if not isinstance(item, dict):
                continue
            name = item.get("value") or item.get("name")
            kind = item.get("type") or item.get("kind")
            if not isinstance(name, str) or not isinstance(kind, str):
                continue
            try:
                entity_id = _entity(db, case_id, name, kind)
            except ValueError:
                continue
            cursor = db.execute("INSERT OR IGNORE INTO mentions(case_id,entity_id,source_id) VALUES(?,?,?)",
                                (case_id, entity_id, source_id))
            mentions_added += cursor.rowcount
    return {"sources_processed": sources_added, "new_mentions": mentions_added,
            "new_observations": observations_added}


@guarded
async def case_capture(case: str, result_json: str) -> dict:
    """Save source URLs and entity mentions from a browser_crawl/deep_osint JSON result.

    Accepts an object with `pages` or a page list. Stores short key sentences,
    but not raw page text, screenshots, or inferred causal relationships.
    """
    if len(result_json.encode("utf-8")) > MAX_RESULT_BYTES:
        return {"ok": False, "error": "result exceeds 1 MB; capture a smaller page set"}
    data = json.loads(result_json)
    pages = data.get("pages", []) if isinstance(data, dict) else data
    if not isinstance(pages, list):
        return {"ok": False, "error": "expected JSON object with pages array or a page array"}
    with _db() as db:
        case_id = _case_id(db, case)
        counts = _capture_pages(db, case_id, pages)
        return {"ok": True, "case_id": case_id, **counts}


@guarded
async def case_research(case: str, query: str, max_pages: int = 6) -> dict:
    """Run deep_osint, then automatically save discovered sources and entity mentions.

    Returns the original research result plus capture counts. Facts about who did
    what or why require case_add_fact with source evidence.
    """
    from .deep_tools import deep_osint
    with _db() as db:
        case_id = _case_id(db, case)
    result = await deep_osint(query, max_pages=max_pages, screenshots=False)
    if not result.get("ok"):
        return result
    with _db() as db:
        counts = _capture_pages(db, case_id, result.get("pages") or [])
    return {"ok": True, "case_id": case_id, "capture": counts, "research": result}


def _fts_search(db: sqlite3.Connection, case_id: str, match_query: str, limit: int) -> dict | None:
    """FTS5-backed search across entities, observations, and facts."""
    try:
        hits = db.execute(
            "SELECT kind, ref_id FROM case_fts WHERE case_id=? AND case_fts MATCH ? ORDER BY rank LIMIT ?",
            (case_id, match_query, limit * 3),
        ).fetchall()
    except sqlite3.OperationalError:
        return None
    entity_ids: list[int] = []
    observation_ids: list[int] = []
    fact_ids: list[int] = []
    for hit in hits:
        target_list = {"entity": entity_ids, "observation": observation_ids, "fact": fact_ids}.get(hit["kind"])
        if target_list is not None and len(target_list) < limit:
            target_list.append(hit["ref_id"])
    result: dict = {"entities": [], "observations": [], "facts": []}
    if entity_ids:
        placeholders = ",".join("?" for _ in entity_ids)
        result["entities"] = [_row(r) for r in db.execute(
            f"SELECT id,kind,name FROM entities WHERE id IN ({placeholders})", entity_ids).fetchall()]
    if observation_ids:
        placeholders = ",".join("?" for _ in observation_ids)
        result["observations"] = [_row(r) for r in db.execute(
            f"""SELECT o.id, o.text, s.url AS source_url FROM observations o
            LEFT JOIN sources s ON s.id=o.source_id WHERE o.id IN ({placeholders})""",
            observation_ids).fetchall()]
    if fact_ids:
        placeholders = ",".join("?" for _ in fact_ids)
        result["facts"] = [_row(r) for r in db.execute(
            f"""SELECT f.id, a.name AS subject, f.predicate, b.name AS object,
            f.status, f.evidence, src.url AS source_url FROM facts f
            JOIN entities a ON a.id=f.subject_id JOIN entities b ON b.id=f.object_id
            LEFT JOIN sources src ON src.id=f.source_id WHERE f.id IN ({placeholders})""",
            fact_ids).fetchall()]
    return result


@guarded
async def case_search(case: str, query: str, limit: int = 30) -> dict:
    """Search a case's entities, sources, observations, and relationship text.

    Uses an FTS5 full-text index when available (relevance-ranked, word-based
    matching); falls back to substring LIKE matching otherwise.
    """
    query = _required(query, "query", 200)
    limit = max(1, min(int(limit), 100))
    with _db() as db:
        case_id = _case_id(db, case)
        match_query = _fts_match_query(query)
        if match_query:
            fts_result = _fts_search(db, case_id, match_query, limit)
            if fts_result is not None:
                # sources are still substring-matched (URLs/titles are not in FTS)
                needle = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                sources = db.execute(
                    "SELECT id,url,title,checked_at FROM sources WHERE case_id=? AND (url LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\') LIMIT ?",
                    (case_id, needle, needle, limit),
                ).fetchall()
                return {
                    "ok": True,
                    "mode": "fts",
                    "query": query,
                    "entities": fts_result["entities"][:limit],
                    "sources": [_row(r) for r in sources],
                    "observations": fts_result["observations"][:limit],
                    "facts": fts_result["facts"][:limit],
                }
        needle = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        entities = db.execute("SELECT id,kind,name FROM entities WHERE case_id=? AND name LIKE ? ESCAPE '\\' LIMIT ?",
                              (case_id, needle, limit)).fetchall()
        sources = db.execute("SELECT id,url,title,checked_at FROM sources WHERE case_id=? AND (url LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\') LIMIT ?",
                             (case_id, needle, needle, limit)).fetchall()
        observations = db.execute("""SELECT o.id, o.text, s.url AS source_url FROM observations o
            LEFT JOIN sources s ON s.id=o.source_id WHERE o.case_id=? AND o.text LIKE ? ESCAPE '\\'
            LIMIT ?""", (case_id, needle, limit)).fetchall()
        facts = db.execute("""SELECT f.id, a.name AS subject, f.predicate, b.name AS object,
            f.status, f.evidence, src.url AS source_url FROM facts f
            JOIN entities a ON a.id=f.subject_id JOIN entities b ON b.id=f.object_id
            LEFT JOIN sources src ON src.id=f.source_id WHERE f.case_id=? AND
            (a.name LIKE ? ESCAPE '\\' OR b.name LIKE ? ESCAPE '\\' OR f.predicate LIKE ? ESCAPE '\\')
            LIMIT ?""", (case_id, needle, needle, needle, limit)).fetchall()
        return {"ok": True, "mode": "like", "query": query, "entities": [_row(r) for r in entities],
                "sources": [_row(r) for r in sources], "observations": [_row(r) for r in observations],
                "facts": [_row(r) for r in facts]}


@guarded
async def case_graph(case: str, entity: str = "", limit: int = 100) -> dict:
    """Return case entities and evidenced edges; optionally focus on one entity.

    Mentions are separate from explicit facts. Use the returned IDs and source URLs
    to explain who is connected to whom and which claims remain leads.
    """
    limit = max(1, min(int(limit), 500))
    with _db() as db:
        case_id = _case_id(db, case)
        params = [case_id]
        filter_sql = ""
        if entity.strip():
            filter_sql = " AND (a.name=? COLLATE NOCASE OR b.name=? COLLATE NOCASE)"
            params.extend([entity.strip(), entity.strip()])
        facts = db.execute("""SELECT f.id, a.id AS subject_id, a.name AS subject, a.kind AS subject_kind,
            f.predicate, b.id AS object_id, b.name AS object, b.kind AS object_kind,
            f.status, f.evidence, src.id AS source_id, src.url AS source_url FROM facts f
            JOIN entities a ON a.id=f.subject_id JOIN entities b ON b.id=f.object_id
            LEFT JOIN sources src ON src.id=f.source_id WHERE f.case_id=?""" + filter_sql +
            " ORDER BY f.id DESC LIMIT ?", (*params, limit)).fetchall()
        mention_sql = "" if not entity.strip() else " AND e.name=? COLLATE NOCASE"
        mentions = db.execute("""SELECT e.id AS entity_id, e.name, e.kind,
            s.id AS source_id, s.url AS source_url, s.title
            FROM mentions m JOIN entities e ON e.id=m.entity_id
            JOIN sources s ON s.id=m.source_id WHERE m.case_id=?""" + mention_sql +
            " ORDER BY m.source_id DESC LIMIT ?",
            (case_id, entity.strip(), limit) if entity.strip() else (case_id, limit)).fetchall()
        observations = db.execute("""SELECT o.text, s.url AS source_url FROM observations o
            LEFT JOIN sources s ON s.id=o.source_id WHERE o.case_id=?""" +
            (" AND (o.text LIKE ? OR o.entity_id IN (SELECT id FROM entities WHERE case_id=? AND name=? COLLATE NOCASE))" if entity.strip() else "") + " ORDER BY o.id DESC LIMIT ?",
            (case_id, f"%{entity.strip()}%", case_id, entity.strip(), limit) if entity.strip() else (case_id, limit)).fetchall()
        entity_rows = db.execute("SELECT id,name,kind FROM entities WHERE case_id=?" +
                                 (" AND name=? COLLATE NOCASE" if entity.strip() else "") +
                                 " ORDER BY id DESC LIMIT ?",
                                 (case_id, entity.strip(), limit) if entity.strip() else (case_id, limit)).fetchall()
        case_row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        nodes: dict[str, dict] = {}
        edges = []
        for item in entity_rows:
            node_id = f"entity:{item['id']}"
            nodes[node_id] = {"id": node_id, "type": "entity",
                              "name": item["name"], "kind": item["kind"]}
        for fact in facts:
            for side in ("subject", "object"):
                node_id = f"entity:{fact[side + '_id']}"
                nodes[node_id] = {"id": node_id, "type": "entity",
                                  "name": fact[side], "kind": fact[side + "_kind"]}
            if fact["source_id"]:
                source_node = f"source:{fact['source_id']}"
                nodes[source_node] = {"id": source_node, "type": "source", "url": fact["source_url"]}
            edges.append({"from": f"entity:{fact['subject_id']}",
                          "to": f"entity:{fact['object_id']}", "type": "fact",
                          "label": fact["predicate"], "status": fact["status"],
                          "source": f"source:{fact['source_id']}" if fact["source_id"] else None})
        for mention in mentions:
            entity_node = f"entity:{mention['entity_id']}"
            source_node = f"source:{mention['source_id']}"
            nodes[entity_node] = {"id": entity_node, "type": "entity",
                                  "name": mention["name"], "kind": mention["kind"]}
            nodes[source_node] = {"id": source_node, "type": "source",
                                  "url": mention["source_url"], "title": mention["title"]}
            edges.append({"from": entity_node, "to": source_node, "type": "mention"})
        image_filter = (" AND p.name=? COLLATE NOCASE" if entity.strip() else "")
        image_rows = db.execute("""SELECT i.id, i.sha256, i.path, i.source_id,
            src.url AS source_url, p.id AS person_id, p.name AS person_name FROM images i
            LEFT JOIN image_people ip ON ip.image_id=i.id AND ip.case_id=i.case_id
            LEFT JOIN entities p ON p.id=ip.entity_id
            LEFT JOIN sources src ON src.id=i.source_id WHERE i.case_id=?""" + image_filter +
            " ORDER BY i.id DESC LIMIT ?",
            (case_id, entity.strip(), limit) if entity.strip() else (case_id, limit)).fetchall()
        for item in image_rows:
            image_node = f"image:{item['id']}"
            nodes[image_node] = {"id": image_node, "type": "image",
                                 "sha256": item["sha256"], "path": item["path"]}
            if item["person_id"]:
                person_node = f"entity:{item['person_id']}"
                nodes[person_node] = {"id": person_node, "type": "entity",
                                      "name": item["person_name"], "kind": "person"}
                edges.append({"from": person_node, "to": image_node,
                              "type": "image_reference", "status": "association_only"})
            if item["source_id"]:
                source_node = f"source:{item['source_id']}"
                nodes[source_node] = {"id": source_node, "type": "source", "url": item["source_url"]}
                edges.append({"from": image_node, "to": source_node, "type": "image_source"})
        image_ids = [item["id"] for item in image_rows]
        if image_ids:
            placeholders = ",".join("?" for _ in image_ids)
            hits = db.execute("""SELECT h.image_id, h.provider, h.score,
                s.id AS source_id, s.url FROM image_hits h
                JOIN sources s ON s.id=h.source_id WHERE h.case_id=? AND h.image_id IN (""" +
                placeholders + ") ORDER BY h.image_id LIMIT ?", (case_id, *image_ids, limit)).fetchall()
            for hit in hits:
                source_node = f"source:{hit['source_id']}"
                nodes[source_node] = {"id": source_node, "type": "source", "url": hit["url"]}
                edges.append({"from": f"image:{hit['image_id']}", "to": source_node,
                              "type": "image_seen_on", "provider": hit["provider"],
                              "score": hit["score"]})
        return {"ok": True, "case": _row(case_row), "facts": [_row(r) for r in facts],
                "mentions": [_row(r) for r in mentions], "observations": [_row(r) for r in observations],
                "nodes": list(nodes.values()), "edges": edges,
                "note": "Mentions are co-occurrences, not proof of a relationship."}


@guarded
async def case_export(case: str, out_path: str = "", max_items: int = 5000) -> dict:
    """Export a full case as portable JSON (entities, sources, observations, facts, image metadata).

    Without out_path the JSON is returned inline; with out_path it is written to a
    file (JSON, 0o600 on POSIX) and only the path and digest are returned. Binary
    image files are not embedded; image rows carry their stored paths and hashes.
    """
    max_items = max(100, min(int(max_items), 50000))
    with _db() as db:
        case_id = _case_id(db, case)
        case_row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        payload = {
            "schema": "osint-mcp/case-export",
            "version": 2,
            "exported_at": utcnow().isoformat(timespec="seconds"),
            "case": _row(case_row),
            "sources": [_row(r) for r in db.execute(
                "SELECT * FROM sources WHERE case_id=? LIMIT ?", (case_id, max_items)).fetchall()],
            "entities": [_row(r) for r in db.execute(
                "SELECT * FROM entities WHERE case_id=? LIMIT ?", (case_id, max_items)).fetchall()],
            "mentions": [_row(r) for r in db.execute(
                "SELECT * FROM mentions WHERE case_id=? LIMIT ?", (case_id, max_items)).fetchall()],
            "observations": [_row(r) for r in db.execute(
                "SELECT * FROM observations WHERE case_id=? LIMIT ?", (case_id, max_items)).fetchall()],
            "facts": [_row(r) for r in db.execute(
                "SELECT * FROM facts WHERE case_id=? LIMIT ?", (case_id, max_items)).fetchall()],
            "images": [_row(r) for r in db.execute(
                "SELECT id,sha256,dhash,path,original_url,source_id,created_at FROM images WHERE case_id=? LIMIT ?",
                (case_id, max_items)).fetchall()],
            "note": "Claims need sources and evidence; mentions are co-occurrences, not proof.",
        }

    if not out_path:
        return {"ok": True, "format": "inline", "case_id": case_id, "data": payload}

    path = Path(os.path.expanduser(out_path)).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    import hashlib

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"ok": True, "format": "file", "case_id": case_id, "path": str(path),
            "sha256": digest, "bytes": path.stat().st_size}
