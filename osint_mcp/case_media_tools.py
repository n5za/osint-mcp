"""Image evidence, reverse-image lookup, and person dossiers for local cases."""

from __future__ import annotations

import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from mcp.server.fastmcp import Image as MCPImage
from PIL import Image

from .case_tools import _case_id, _db, _db_path, _entity, _source
from .common import api_key, guarded, request, utcnow
from .deep_tools import image_analyze

MAX_IMAGE_BYTES = 12_000_000
MAX_PIXELS = 40_000_000


def _case_dir(case_id: str) -> Path:
    root = _private_dir(_db_path().parent / "cases")
    return _private_dir(root / case_id)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    if os.name == "posix":
        os.chmod(path, 0o600)


def _person_dir(case_id: str, entity_id: int, name: str) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "person"
    return _private_dir(_case_dir(case_id) / "people" / f"{entity_id}-{slug}")


async def _image_bytes(source: str) -> tuple[bytes, str | None]:
    value = source.strip()
    if value.startswith(("https://", "http://")):
        response = await request(value, timeout=30)
        response.raise_for_status()
        data = response.content
        original_url = value
    else:
        path = Path(value).expanduser()
        if path.stat().st_size > MAX_IMAGE_BYTES:
            raise ValueError("image larger than 12 MB")
        data = path.read_bytes()
        original_url = None
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("image larger than 12 MB")
    with Image.open(io.BytesIO(data)) as image:
        if image.width * image.height > MAX_PIXELS:
            raise ValueError("image has too many pixels")
        image.verify()
    return data, original_url


@guarded
async def case_image_add(case: str, image: str, person: str = "",
                         source_url: str = "", ocr: bool = True) -> dict:
    """Save a local/remote image in a case, analyze it, and optionally file it under a person.

    Assigning a person labels the file for organization; it does not identify the
    face or prove who appears in the image. No image is uploaded by this tool.
    """
    with _db() as db:
        case_id = _case_id(db, case)
    data, original_url = await _image_bytes(image)
    digest = hashlib.sha256(data).hexdigest()
    with Image.open(io.BytesIO(data)) as loaded:
        ext = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp", "GIF": ".gif",
               "BMP": ".bmp", "TIFF": ".tif"}.get(loaded.format, ".img")
    images_dir = _private_dir(_case_dir(case_id) / "images")
    saved = images_dir / f"{digest}{ext}"
    if not saved.exists():
        _write_private(saved, data)
    analysis = await image_analyze(str(saved), ocr=ocr, qr=True, reverse_search=False)
    if not analysis.get("ok"):
        return analysis
    # Store bounded, useful analysis rather than the entire OCR stream or raw EXIF blob.
    summary = {key: analysis.get(key) for key in
               ("format", "width", "height", "sha256", "dhash", "ahash", "gps", "qr_codes")}
    summary["exif"] = {key: value for key, value in (analysis.get("exif") or {}).items()
                       if key in {"DateTime", "DateTimeOriginal", "Make", "Model", "Software", "Artist", "Copyright"}}
    summary["ocr_text"] = (analysis.get("ocr_text") or "")[:1000]
    person_folder = None
    with _db() as db:
        source_id = _source(db, case_id, source_url or original_url) if (source_url or original_url) else None
        db.execute("""INSERT OR IGNORE INTO images
            (case_id,sha256,dhash,path,original_url,source_id,analysis_json,created_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (case_id, digest, analysis["dhash"], str(saved), original_url,
             source_id, json.dumps(summary, ensure_ascii=False), utcnow().isoformat(timespec="seconds")))
        row = db.execute("SELECT id FROM images WHERE case_id=? AND sha256=?", (case_id, digest)).fetchone()
        image_id = row["id"]
        if person.strip():
            person_id = _entity(db, case_id, person, "person")
            db.execute("INSERT OR IGNORE INTO image_people(case_id,image_id,entity_id) VALUES(?,?,?)",
                       (case_id, image_id, person_id))
            person_folder = _private_dir(_person_dir(case_id, person_id, person) / "images")
            copy_path = person_folder / saved.name
            if not copy_path.exists():
                shutil.copyfile(saved, copy_path)
                if os.name == "posix":
                    os.chmod(copy_path, 0o600)
    if person_folder:
        await person_dossier(case, person)
    return {"ok": True, "case_id": case_id, "image_id": image_id,
            "path": str(saved), "person_folder": str(person_folder.parent) if person_folder else None,
            "analysis": summary, "note": "Person label is an association, not face identification."}


@guarded
async def case_image_similar(case: str, image_id: int, max_distance: int = 10) -> dict:
    """Find visually similar images already saved in this case using dHash distance.

    Similarity is about the whole image and does not establish that two people
    are the same person. Exact copies also have the same SHA-256 digest.
    """
    max_distance = max(0, min(int(max_distance), 64))
    with _db() as db:
        case_id = _case_id(db, case)
        target = db.execute("SELECT * FROM images WHERE case_id=? AND id=?", (case_id, image_id)).fetchone()
        if not target:
            return {"ok": False, "error": "image not found in case"}
        rows = db.execute("SELECT id,path,sha256,dhash FROM images WHERE case_id=? AND id<>?",
                          (case_id, image_id)).fetchall()
    matches = []
    for row in rows:
        try:
            distance = (int(target["dhash"], 16) ^ int(row["dhash"], 16)).bit_count()
        except ValueError:
            continue
        if distance <= max_distance:
            matches.append({"image_id": row["id"], "path": row["path"],
                            "distance": distance, "same_file": row["sha256"] == target["sha256"]})
    matches.sort(key=lambda item: item["distance"])
    return {"ok": True, "image_id": image_id, "matches": matches[:100],
            "note": "Visual similarity is not proof of shared identity or origin."}


@guarded
async def case_image_view(case: str, image_id: int) -> MCPImage:
    """Return a saved image inline so a vision-capable MCP client can inspect it.

    The model may describe visible objects and text, then save useful observations
    with case_note. Visual appearance alone cannot establish a person's identity.
    """
    with _db() as db:
        case_id = _case_id(db, case)
        row = db.execute("SELECT path FROM images WHERE case_id=? AND id=?",
                         (case_id, image_id)).fetchone()
        if not row:
            raise ValueError("image not found in case")
        return MCPImage(path=row["path"])


@guarded
async def case_image_crop(case: str, image_id: int, left: int, top: int,
                          right: int, bottom: int, person: str = "") -> dict:
    """Crop a region for closer visual inspection and save it as a new case image.

    Coordinates are pixels from the top-left. An optional person label only files
    the crop in that person's folder; it does not verify identity.
    """
    with _db() as db:
        case_id = _case_id(db, case)
        row = db.execute("""SELECT i.path, s.url AS source_url FROM images i
            LEFT JOIN sources s ON s.id=i.source_id WHERE i.case_id=? AND i.id=?""",
            (case_id, image_id)).fetchone()
        if not row:
            return {"ok": False, "error": "image not found in case"}
    with Image.open(row["path"]) as original:
        box = tuple(int(value) for value in (left, top, right, bottom))
        if not (0 <= box[0] < box[2] <= original.width and
                0 <= box[1] < box[3] <= original.height):
            return {"ok": False, "error": "crop coordinates must lie inside the image"}
        crop = original.crop(box).convert("RGB")
        crop_dir = _private_dir(_case_dir(case_id) / "crops")
        crop_path = crop_dir / f"{image_id}-{box[0]}-{box[1]}-{box[2]}-{box[3]}.png"
        crop.save(crop_path)
        if os.name == "posix":
            os.chmod(crop_path, 0o600)
    added = await case_image_add(case, str(crop_path), person=person,
                                 source_url=row["source_url"] or "", ocr=True)
    if added.get("ok"):
        added["crop_of_image_id"] = image_id
        added["box"] = box
    return added


def _search_links(url: str | None) -> dict:
    if not url:
        return {"google_lens": "https://lens.google.com/", "tineye": "https://tineye.com/"}
    encoded = quote(url, safe="")
    return {"google_lens": f"https://lens.google.com/uploadbyurl?url={encoded}",
            "tineye": f"https://tineye.com/search?url={encoded}"}


def _account_candidate(url: str) -> dict | None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").removeprefix("www.").lower()
    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return None
    platform = None
    handle = None
    if host in {"x.com", "twitter.com", "flickr.com"}:
        platform = "x" if host in {"x.com", "twitter.com"} else "flickr"
        handle = parts[1] if platform == "flickr" and len(parts) > 1 and parts[0] == "photos" else parts[0] if platform == "x" else None
    elif host == "tiktok.com" and parts[0].startswith("@"):
        platform, handle = "tiktok", parts[0]
    elif host == "bsky.app" and len(parts) > 1 and parts[0] == "profile":
        platform, handle = "bluesky", parts[1]
    elif host == "youtube.com" and parts[0].startswith("@"):
        platform, handle = "youtube", parts[0]
    elif host == "reddit.com" and len(parts) > 1 and parts[0] in {"user", "u"}:
        platform, handle = "reddit", parts[1]
    elif host == "linkedin.com" and len(parts) > 1 and parts[0] in {"in", "company"}:
        platform, handle = "linkedin", parts[1]
    if not handle or not re.fullmatch(r"@?[A-Za-z0-9._-]{2,80}", handle):
        return None
    if handle.lower().lstrip("@") in {"home", "search", "explore", "images", "login", "signup"}:
        return None
    return {"platform": platform, "handle": handle,
            "status": "candidate_from_page_url_not_verified_owner"}


async def _tineye_search(image_url: str | None, path: str, key: str, limit: int) -> dict:
    headers = {"x-api-key": key}
    async with httpx.AsyncClient(timeout=60) as client:
        if image_url:
            response = await client.get("https://api.tineye.com/rest/search/", headers=headers,
                                        params={"image_url": image_url, "limit": limit,
                                                "backlink_limit": 20})
        else:
            data = Path(path).read_bytes()
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            response = await client.post("https://api.tineye.com/rest/search/", headers=headers,
                                         data={"limit": str(limit), "backlink_limit": "20"},
                                         files={"image_upload": (Path(path).name, data, mime)})
    if response.status_code != 200:
        return {"ok": False, "status": response.status_code,
                "error": "TinEye request failed; check key, quota, or image support"}
    payload = response.json()
    if payload.get("code") != 200:
        return {"ok": False, "error": "TinEye returned an API error", "messages": payload.get("messages")}
    matches = []
    for match in payload.get("results", {}).get("matches", [])[:limit]:
        backlinks = []
        for item in match.get("backlinks", [])[:20]:
            if item.get("backlink"):
                backlinks.append({"page_url": item["backlink"],
                                  "image_url": item.get("url"), "crawl_date": item.get("crawl_date"),
                                  "account_candidate": _account_candidate(item["backlink"])})
        matches.append({"domain": match.get("domain"), "score": match.get("score"),
                        "tags": match.get("tags") or [], "backlinks": backlinks})
    return {"ok": True, "stats": payload.get("stats") or payload.get("results", {}).get("stats"),
            "matches": matches}


@guarded
async def case_image_reverse(case: str, image_id: int, use_tineye: bool = True,
                             limit: int = 20) -> dict:
    """Find pages using an image through TinEye API, plus manual search links.

    TinEye needs a paid TINEYE_API_KEY. If the image is local, invoking this tool
    with a key and use_tineye=True uploads it to TinEye. With no key it returns
    manual search pages, but no claimed matches. A matching page is not proof
    that its account owns or depicts the image's labeled person.
    """
    limit = max(1, min(int(limit), 100))
    with _db() as db:
        case_id = _case_id(db, case)
        row = db.execute("SELECT * FROM images WHERE case_id=? AND id=?", (case_id, image_id)).fetchone()
        if not row:
            return {"ok": False, "error": "image not found in case"}
        image_url = row["original_url"]
        path = row["path"]
    links = _search_links(image_url)
    key = api_key("tineye")
    if not use_tineye or not key:
        return {"ok": True, "image_id": image_id, "search_links": links,
                "needs_key": bool(use_tineye and not key), "matches": [],
                "note": "Open search links manually; no search results were retrieved."}
    result = await _tineye_search(image_url, path, key, limit)
    if not result.get("ok"):
        return {"ok": False, "image_id": image_id, "search_links": links, **result}
    saved = 0
    with _db() as db:
        for match in result["matches"]:
            for backlink in match["backlinks"]:
                page_url = backlink["page_url"]
                if urlsplit(page_url).scheme not in {"http", "https"}:
                    continue
                source_id = _source(db, case_id, page_url)
                cursor = db.execute("""INSERT OR IGNORE INTO image_hits
                    (case_id,image_id,source_id,provider,score,match_image_url)
                    VALUES(?,?,?,?,?,?)""",
                    (case_id, image_id, source_id, "tineye", match.get("score"), backlink.get("image_url")))
                saved += cursor.rowcount
                candidate = backlink.get("account_candidate")
                if candidate:
                    account_id = _entity(db, case_id,
                                         f"{candidate['platform']}:{candidate['handle']}", "account")
                    db.execute("INSERT OR IGNORE INTO mentions(case_id,entity_id,source_id) VALUES(?,?,?)",
                               (case_id, account_id, source_id))
    return {"ok": True, "image_id": image_id, "search_links": links,
            "provider": "tineye", "matches": result["matches"], "stats": result["stats"],
            "new_source_links": saved,
            "note": "Backlinks identify pages where matching images appeared, not account ownership."}


@guarded
async def person_dossier(case: str, person: str) -> dict:
    """Build a private per-person profile.json with notes, facts, images and sources.

    The file is refreshed when this tool is called. It does not infer a person's
    identity from a photo or treat co-occurrence as a confirmed relationship.
    """
    with _db() as db:
        case_id = _case_id(db, case)
        row = db.execute("SELECT id,name FROM entities WHERE case_id=? AND kind='person' AND name=?",
                         (case_id, person.strip())).fetchone()
        if not row:
            return {"ok": False, "error": "person not found in case"}
        person_id = row["id"]
        notes = [dict(item) for item in db.execute("""SELECT o.text, s.url AS source_url
            FROM observations o LEFT JOIN sources s ON s.id=o.source_id
            WHERE o.case_id=? AND o.entity_id=? ORDER BY o.id DESC""", (case_id, person_id))]
        facts = [dict(item) for item in db.execute("""SELECT a.name AS subject, f.predicate,
            b.name AS object, f.status, f.evidence, s.url AS source_url FROM facts f
            JOIN entities a ON a.id=f.subject_id JOIN entities b ON b.id=f.object_id
            LEFT JOIN sources s ON s.id=f.source_id
            WHERE f.case_id=? AND (f.subject_id=? OR f.object_id=?) ORDER BY f.id DESC""",
            (case_id, person_id, person_id))]
        images = [dict(item) for item in db.execute("""SELECT i.id, i.path, i.sha256,
            i.analysis_json, s.url AS source_url FROM images i
            JOIN image_people p ON p.image_id=i.id AND p.case_id=i.case_id
            LEFT JOIN sources s ON s.id=i.source_id
            WHERE i.case_id=? AND p.entity_id=? ORDER BY i.id DESC""",
            (case_id, person_id))]
        for image in images:
            image["analysis"] = json.loads(image.pop("analysis_json"))
            image["web_matches"] = [dict(hit) for hit in db.execute("""SELECT s.url AS page_url,
                h.provider, h.score FROM image_hits h JOIN sources s ON s.id=h.source_id
                WHERE h.case_id=? AND h.image_id=? ORDER BY h.score DESC LIMIT 50""",
                (case_id, image["id"]))]
    folder = _person_dir(case_id, person_id, row["name"])
    dossier = {"case_id": case_id, "person": row["name"], "entity_id": person_id,
               "notes": notes, "facts": facts, "images": images,
               "updated_at": utcnow().isoformat(timespec="seconds"),
               "caution": "Image association and web appearance do not verify identity or account ownership."}
    profile = folder / "profile.json"
    _write_private(profile, json.dumps(dossier, ensure_ascii=False, indent=2).encode("utf-8"))
    return {"ok": True, "folder": str(folder), "profile": str(profile), **dossier}
