#!/usr/bin/env python3
"""Mailbox Hit Checker.

Paste mailbox credentials (email:password or email:apppassword) and a list of
search inputs (any text — full links, partial links, plain phrases). The app
connects to each mailbox over IMAP, scans the INBOX and the Spam/Junk folder,
and reports how many emails contain each input.

The IMAP connection logic (domain -> server auto-detect, SSL login, MIME
decoding) is adapted from the 'header + body extractore +edit' app.

Run:  python app.py --port 5010
"""

from __future__ import annotations

import argparse
import binascii
import html as html_lib
import imaplib
import json
import os
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "data.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")

# Secret admin account — never listed anywhere in the public UI.
ADMIN_EMAIL = "ayoubdraidi1@gmail.com"
ADMIN_PASSWORD = "Aemae9ea8J"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def _load_secret_key() -> str:
    """Persistent session key so logins survive a server restart."""
    if os.path.isfile(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r", encoding="utf-8") as fh:
                key = fh.read().strip()
                if key:
                    return key
        except Exception:  # noqa: BLE001
            pass
    key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, "w", encoding="utf-8") as fh:
            fh.write(key)
    except Exception:  # noqa: BLE001
        pass
    return key


app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# --------------------------------------------------------------------------- #
#  Global run state
# --------------------------------------------------------------------------- #
STATE_LOCK = threading.Lock()
STOP_FLAG = threading.Event()

STATE = {
    "running": False,
    "mode": "hybrid",
    "started_at": None,
    "finished_at": None,
    "progress": 0,          # folders processed
    "total": 0,             # folders to process
    "current": "",
    "log": [],
    "results": None,
    "counts": {"mailboxes": 0, "inputs": 0},
    "owner": None,          # email of the user who started the current run
}

MAX_LOG_LINES = 500


def log(msg: str) -> None:
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
    with STATE_LOCK:
        STATE["log"].append(line)
        if len(STATE["log"]) > MAX_LOG_LINES:
            STATE["log"] = STATE["log"][-MAX_LOG_LINES:]


def _set_progress(delta: int = 0, current: str | None = None) -> None:
    with STATE_LOCK:
        STATE["progress"] += delta
        if current is not None:
            STATE["current"] = current


# --------------------------------------------------------------------------- #
#  Accounts / auth  (users.json)
#  Each record: {email, pass_hash, role, mailboxes, tests[], created_at}
#  The admin account is seeded here and is never exposed in the public UI.
# --------------------------------------------------------------------------- #
USERS_LOCK = threading.Lock()


def _load_users() -> dict:
    if os.path.isfile(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    return data
        except Exception:  # noqa: BLE001
            log("Could not read users.json — starting empty.")
    return {}


def _save_users(users: dict) -> None:
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_FILE)


def _new_user(email: str, password: str, role: str = "user") -> dict:
    return {
        "email": email,
        "pass_hash": generate_password_hash(password),
        "role": role,
        "mailboxes": "",
        "tests": [],
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


def _ensure_admin() -> None:
    """Create the secret admin account once, if it does not exist."""
    with USERS_LOCK:
        users = _load_users()
        key = ADMIN_EMAIL.lower()
        entry = users.get(key)
        if not entry or entry.get("role") != "admin":
            entry = entry or _new_user(ADMIN_EMAIL, ADMIN_PASSWORD, role="admin")
            entry["role"] = "admin"
            entry["email"] = ADMIN_EMAIL
            entry.setdefault("mailboxes", "")
            entry.setdefault("tests", [])
            entry.setdefault("created_at", datetime.now().isoformat(timespec="seconds"))
            if not entry.get("pass_hash"):
                entry["pass_hash"] = generate_password_hash(ADMIN_PASSWORD)
            users[key] = entry
            _save_users(users)


def _public_user(entry: dict, full: bool = False) -> dict:
    data = {
        "email": entry.get("email"),
        "role": entry.get("role", "user"),
        "created_at": entry.get("created_at"),
        "test_count": len(entry.get("tests") or []),
        "mailbox_count": len([ln for ln in (entry.get("mailboxes") or "").splitlines() if ln.strip()]),
    }
    if full:
        data["mailboxes"] = entry.get("mailboxes", "")
        data["tests"] = entry.get("tests") or []
    return data


def current_user() -> dict | None:
    email = (session.get("email") or "").lower()
    if not email:
        return None
    with USERS_LOCK:
        entry = _load_users().get(email)
    return entry


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("email"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Not signed in"}), 401
            return redirect("/")
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin only"}), 403
            return redirect("/admin")
        return fn(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------- #
#  Live result streaming
#  Results are aggregated and pushed to STATE["results"] while the scan runs so
#  the UI shows hits as they are found instead of waiting for the whole run.
# --------------------------------------------------------------------------- #
LIVE_LOCK = threading.Lock()
LIVE_ORDER: list[str] = []
LIVE_MAILBOXES: dict[str, dict] = {}
LIVE_INPUTS: list[dict] = []
LIVE_CTX = {"mode": "hybrid", "started": 0.0, "last_publish": 0.0}
PUBLISH_INTERVAL = 2.0  # seconds


def _blank_mailbox_result(email_address: str, n_inputs: int) -> dict:
    return {
        "email": email_address,
        "status": "running",
        "error": None,
        "folders": {},
        "inbox": [0] * n_inputs,
        "spam": [0] * n_inputs,
        "previews": {"inbox": [[] for _ in range(n_inputs)], "spam": [[] for _ in range(n_inputs)]},
        "inbox_total": 0,
        "spam_total": 0,
    }


def _aggregate_results(partial: bool) -> dict:
    mailbox_results = [LIVE_MAILBOXES[email] for email in LIVE_ORDER if email in LIVE_MAILBOXES]
    result_inputs = []
    for idx, prep in enumerate(LIVE_INPUTS):
        per_mailbox = []
        spam_total = 0
        inbox_total = 0
        for mailbox in mailbox_results:
            ok = mailbox["status"] != "error"
            inbox_count = mailbox["inbox"][idx] if ok else 0
            spam_count = mailbox["spam"][idx] if ok else 0
            spam_total += spam_count
            inbox_total += inbox_count
            previews = []
            if ok:
                previews.extend(mailbox["previews"]["inbox"][idx])
                previews.extend(mailbox["previews"]["spam"][idx])
            per_mailbox.append(
                {
                    "email": mailbox["email"],
                    "status": mailbox["status"],
                    "error": mailbox["error"],
                    "inbox": inbox_count,
                    "spam": spam_count,
                    "previews": previews,
                }
            )
        
        # TRUNCATION: Only send a snippet of the text to the UI to keep JSON small
        # The full text is already in the user's textarea.
        text_snippet = prep["text"]
        if len(text_snippet) > 800:
            text_snippet = text_snippet[:800] + "..."

        result_inputs.append(
            {
                "text": text_snippet, 
                "full_text_len": len(prep["text"]),
                "spam": spam_total, 
                "inbox": inbox_total, 
                "mailboxes": per_mailbox
            }
        )

    mailbox_summary = [
        {
            "email": mailbox["email"],
            "status": mailbox["status"],
            "error": mailbox["error"],
            "inbox_total": mailbox.get("inbox_total", 0),
            "spam_total": mailbox.get("spam_total", 0),
            "folders": mailbox.get("folders", {}),
        }
        for mailbox in mailbox_results
    ]

    duration = round(time.time() - LIVE_CTX["started"], 1) if LIVE_CTX["started"] else 0
    return {
        "mode": LIVE_CTX["mode"],
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "duration": duration,
        "stopped": STOP_FLAG.is_set(),
        "partial": partial,
        "inputs": result_inputs,
        "mailboxes": mailbox_summary,
    }


def _publish_live(force: bool = False) -> None:
    """Re-aggregate the current progress and push it to the UI (throttled)."""
    now = time.time()
    if not force and now - LIVE_CTX["last_publish"] < PUBLISH_INTERVAL:
        return
    LIVE_CTX["last_publish"] = now
    with LIVE_LOCK:
        snapshot = _aggregate_results(partial=True)
    with STATE_LOCK:
        STATE["results"] = snapshot


# --------------------------------------------------------------------------- #
#  ISP config / server auto-detect  (reused connection method)
# --------------------------------------------------------------------------- #
DEFAULT_ISP = {
    "gmail.com": {"imap": "imap.gmail.com", "imap_port": 993},
    "googlemail.com": {"imap": "imap.gmail.com", "imap_port": 993},
    "outlook.com": {"imap": "outlook.office365.com", "imap_port": 993},
    "hotmail.com": {"imap": "outlook.office365.com", "imap_port": 993},
    "live.com": {"imap": "outlook.office365.com", "imap_port": 993},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "imap_port": 993},
    "aol.com": {"imap": "imap.aol.com", "imap_port": 993},
    "icloud.com": {"imap": "imap.mail.me.com", "imap_port": 993},
    "gmx.com": {"imap": "imap.gmx.com", "imap_port": 993},
    "zoho.com": {"imap": "imap.zoho.com", "imap_port": 993},
}


def load_isp_config() -> dict:
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            cfg = data.get("isp_configs") or {}
            if cfg:
                return cfg
        except Exception as exc:  # noqa: BLE001
            log("Could not read data.json (%s), using built-in defaults." % exc)
    return DEFAULT_ISP


def get_imap_server(domain: str, isp_configs: dict) -> tuple[str, int]:
    domain = (domain or "").lower()
    if domain in ("gmail.com", "googlemail.com"):
        return "imap.gmail.com", 993
    cfg = isp_configs.get(domain)
    if cfg and cfg.get("imap"):
        return cfg["imap"], int(cfg.get("imap_port", 993))
    return "imap.%s" % domain, 993


def decode_mime_header(header) -> str:
    if header is None:
        return ""
    parts = []
    try:
        for chunk, enc in decode_header(header):
            if isinstance(chunk, bytes):
                try:
                    parts.append(chunk.decode(enc or "utf-8", errors="replace"))
                except Exception:  # noqa: BLE001
                    parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(chunk)
    except Exception:  # noqa: BLE001
        return str(header)
    return "".join(parts)


def _friendly_error(exc: Exception) -> str:
    low = str(exc).lower()
    if "application-specific password" in low or "web login required" in low:
        return "App password required for this provider"
    if "authenticationfailed" in low or "invalid credentials" in low or "login failed" in low:
        return "Login failed — wrong password (app password may be required)"
    if "timed out" in low or "timeout" in low:
        return "Connection timed out"
    if "getaddrinfo" in low or "name or service" in low or "nodename" in low:
        return "Unknown IMAP server for this domain"
    if "certificate" in low or "ssl" in low:
        return "SSL / certificate error"
    if "too many" in low or "rate" in low:
        return "Provider rate limit / too many connections"
    return str(exc)[:200]


# --------------------------------------------------------------------------- #
#  Folders
# --------------------------------------------------------------------------- #
SPAM_KEYWORDS = ("spam", "junk", "bulk", "indésirable", "indesirable", "corbeille")


def list_folders(mail: imaplib.IMAP4_SSL) -> list[dict]:
    folders: list[dict] = []
    try:
        status, raw_list = mail.list()
    except Exception:  # noqa: BLE001
        return folders
    if status != "OK" or not raw_list:
        return folders
    for raw in raw_list:
        line = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
        match = re.match(r'\((?P<flags>[^)]*)\)\s+(?:"(?P<delim>[^"]*)"|NIL)\s+(?P<name>.+)$', line)
        if not match:
            continue
        name = match.group("name").strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1]
        folders.append({"name": name, "flags": match.group("flags")})
    return folders


def find_folders(mail: imaplib.IMAP4_SSL) -> tuple[str, str | None, list[dict]]:
    folders = list_folders(mail)
    inbox = "INBOX"
    for folder in folders:
        if folder["name"].upper() == "INBOX":
            inbox = folder["name"]
            break
    else:
        for folder in folders:
            if folder["name"].lower().endswith("inbox"):
                inbox = folder["name"]
                break

    spam = None
    for folder in folders:
        if "\\Junk" in folder["flags"] or "\\Spam" in folder["flags"]:
            spam = folder["name"]
            break
    if spam is None:
        for keyword in SPAM_KEYWORDS:
            for folder in folders:
                if keyword in folder["name"].lower() and folder["name"].lower() != inbox.lower():
                    spam = folder["name"]
                    break
            if spam:
                break
    return inbox, spam, folders


# --------------------------------------------------------------------------- #
#  Text handling / matching
# --------------------------------------------------------------------------- #
def prepare_input(text: str) -> dict:
    clean = text.strip()
    low = clean.lower()
    return {"text": clean, "low": low, "nospace": re.sub(r"\s+", "", low)}


def build_haystack(msg) -> str:
    """Return a single decoded searchable string for the message."""
    html_parts: list[str] = []
    plain_parts: list[str] = []
    try:
        parts = list(msg.walk())
    except Exception:  # noqa: BLE001
        return ""
    for part in parts:
        try:
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/html", "text/plain"):
                continue
            payload = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001
            continue
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="ignore")
        except Exception:  # noqa: BLE001
            text = payload.decode("utf-8", errors="ignore")
        if ctype == "text/html":
            html_parts.append(text)
        else:
            plain_parts.append(text)
    if html_parts:
        return "\n".join(html_parts)
    return "\n".join(plain_parts)


def _nospace(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _clean_snippet(text: str, width: int = 400) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = " ".join(text.split())
    return text[:width]


def iter_view_texts(hay: str):
    """Yield searchable lowercase views of the decoded message, cheapest first.

    Each view is only built when the previous one left inputs unmatched, so a hit
    is classified as early as possible and no extra work is done afterwards:
      - raw lower       : plain text / URL exactly as stored
      - entity decoded  : &amp; -> & so a real pasted link matches
      - tag stripped    : a URL split by inline tags becomes contiguous
      - flattened       : whitespace/tag-split removed (single flatten pass)
    Yields (text, is_flat) tuples.
    """
    raw_low = hay.lower()
    yield raw_low, False
    if "<" not in raw_low and "&" not in raw_low:
        return  # plain email — nothing to decode or strip
    unescaped = html_lib.unescape(hay).lower()
    if unescaped != raw_low:
        yield unescaped, False
    stripped = re.sub(r"<[^>]+>", " ", unescaped)
    if stripped != raw_low and stripped != unescaped:
        yield stripped, False
    flat = _nospace(stripped)
    if flat and flat != stripped:
        yield flat, True


def make_snippet(hay: str, prep: dict, window: int = 110) -> str:
    candidates = [re.sub(r"<[^>]+>", " ", hay), hay]
    needle = prep["text"].lower()
    for text in candidates:
        text_low = text.lower()
        idx = text_low.find(needle)
        if idx >= 0:
            start = max(0, idx - window)
            end = min(len(text), idx + len(needle) + window)
            return _clean_snippet(text[start:end])
    flat = _nospace(hay).lower()
    needle_flat = prep["nospace"]
    if needle_flat:
        idx = flat.find(needle_flat)
        if idx >= 0:
            start = max(0, idx - window)
            end = min(len(flat), idx + len(needle_flat) + window)
            return _clean_snippet(flat[start:end])
    return _clean_snippet(hay[: window * 2])


def make_preview(msg, hay: str, prep: dict, folder_kind: str) -> dict:
    return {
        "folder": folder_kind,
        "from": decode_mime_header(msg.get("From")),
        "subject": decode_mime_header(msg.get("Subject")),
        "date": decode_mime_header(msg.get("Date")),
        "snippet": make_snippet(hay, prep),
    }


# --------------------------------------------------------------------------- #
#  IMAP helpers
# --------------------------------------------------------------------------- #
def _uid_chunks(uids: list[bytes], size: int):
    for idx in range(0, len(uids), size):
        yield uids[idx : idx + size]


def _limit_uids(uids: list[bytes], cfg: dict) -> list[bytes]:
    """Apply the per-folder email caps.

    first_emails -> keep only the FIRST N uids (oldest messages).
    max_emails   -> keep only the LAST N uids (newest messages).
    0 means "no limit" for either.
    """
    first = cfg.get("first_emails", 0) or 0
    if first > 0:
        uids = uids[:first]
    last = cfg.get("max_emails", 0) or 0
    if last > 0:
        uids = uids[-last:]
    return uids


def _iter_fetch(data):
    for item in data:
        if isinstance(item, tuple) and len(item) == 2:
            yield item


def _uid_from_meta(meta: bytes) -> bytes | None:
    match = re.search(rb"UID (\d+)", meta or b"")
    return match.group(1) if match else None


def _imap_quote(value: str) -> str:
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


# --------------------------------------------------------------------------- #
#  BODYSTRUCTURE parsing (skeleton fetch)
#  The server returns the MIME skeleton of every message. We use it to learn
#  which parts are text and how big each one is, so we can fetch ONLY the text
#  and skip attachments entirely (this is what makes Super Turbo fast).
# --------------------------------------------------------------------------- #
def _tokenize_sexpr(data: bytes) -> list[str]:
    """Split an IMAP parenthesised list into tokens (quoted strings unescaped)."""
    tokens: list[str] = []
    i, n = 0, len(data)
    while i < n:
        ch = data[i:i + 1]
        if ch == b"(" or ch == b")":
            tokens.append(ch.decode())
            i += 1
        elif ch in (b" ", b"\r", b"\n", b"\t"):
            i += 1
        elif ch == b'"':
            j, buf = i + 1, bytearray()
            while j < n:
                cur = data[j:j + 1]
                if cur == b"\\":
                    buf += data[j + 1:j + 2]
                    j += 2
                elif cur == b'"':
                    break
                else:
                    buf += cur
                    j += 1
            tokens.append(buf.decode("utf-8", errors="replace"))
            i = j + 1
        else:
            j = i
            while j < n and data[j:j + 1] not in (b" ", b"(", b")", b"\r", b"\n", b"\t"):
                j += 1
            tokens.append(data[i:j].decode("utf-8", errors="replace"))
            i = j
    return tokens


def _build_sexpr(tokens: list[str]) -> list:
    stack: list[list] = [[]]
    for token in tokens:
        if token == "(":
            node: list = []
            stack[-1].append(node)
            stack.append(node)
        elif token == ")":
            if len(stack) > 1:
                stack.pop()
        else:
            stack[-1].append(token)
    return stack[0][0] if stack[0] else []


def _balanced_after(data: bytes, key: bytes) -> bytes | None:
    """Return the balanced (...) group that follows the given keyword."""
    upper = data.upper()
    idx = upper.find(key.upper())
    if idx < 0:
        return None
    start = data.find(b"(", idx)
    if start < 0:
        return None
    depth, i, n, in_str = 0, start, len(data), False
    while i < n:
        ch = data[i:i + 1]
        if in_str:
            if ch == b"\\":
                i += 2
                continue
            if ch == b'"':
                in_str = False
        elif ch == b'"':
            in_str = True
        elif ch == b"(":
            depth += 1
        elif ch == b")":
            depth -= 1
            if depth == 0:
                return data[start:i + 1]
        i += 1
    return None


def _text_parts_from_structure(node) -> list[tuple[str, str, str, str, int]]:
    """Flatten a BODYSTRUCTURE tree into leaf parts.

    Returns a list of (part_number, content_type, charset, encoding, size) for
    every leaf. Part numbers use IMAP notation ("1", "1.2", ...).
    """
    parts: list[tuple[str, str, str, str, int]] = []

    def walk(current, prefix: str) -> None:
        if not isinstance(current, list) or not current:
            return
        # A multipart body starts with a nested list; its children are the parts
        # until the subtype string ("ALTERNATIVE", "MIXED", ...) is reached.
        if isinstance(current[0], list):
            index = 1
            for child in current:
                if isinstance(child, list):
                    walk(child, (prefix + "." if prefix else "") + str(index))
                    index += 1
                else:
                    break
            return
        if len(current) < 2:
            return
        ctype = "%s/%s" % (str(current[0]).lower(), str(current[1]).lower())
        params = current[2] if len(current) > 2 and isinstance(current[2], list) else []
        encoding = str(current[5]) if len(current) > 5 else "7BIT"
        raw_size = str(current[6]) if len(current) > 6 else "0"
        charset = ""
        for k in range(0, len(params) - 1, 2):
            if str(params[k]).lower() == "charset":
                charset = str(params[k + 1])
        parts.append((prefix or "1", ctype, charset, encoding, int(raw_size) if raw_size.isdigit() else 0))

    walk(node, "")
    return parts


def _decode_part_text(raw: bytes, charset: str, encoding: str) -> str:
    """Decode a raw MIME part body using its transfer encoding + charset.

    Uses the C-accelerated binascii helpers so multi-megabyte parts stay fast.
    """
    enc = (encoding or "7bit").strip().lower()
    if enc == "base64":
        try:
            data = binascii.a2b_base64(raw)
        except Exception:  # noqa: BLE001
            data = raw
    elif enc == "quoted-printable":
        try:
            data = binascii.a2b_qp(raw)
        except Exception:  # noqa: BLE001
            data = raw
    else:
        data = raw
    try:
        return data.decode(charset or "utf-8", errors="ignore")
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="ignore")


def _collect_structures(data) -> dict[bytes, list[tuple]]:
    """Map UID -> parsed text parts from a (BODYSTRUCTURE) FETCH response."""
    out: dict[bytes, list[tuple]] = {}
    for item in data:
        resp = item[0] if isinstance(item, tuple) else item
        if not isinstance(resp, (bytes, bytearray)):
            continue
        uid = _uid_from_meta(resp)
        if not uid:
            continue
        blob = _balanced_after(bytes(resp), b"BODYSTRUCTURE")
        if blob is None:
            continue
        try:
            out[uid] = _text_parts_from_structure(_build_sexpr(_tokenize_sexpr(blob)))
        except Exception:  # noqa: BLE001
            out[uid] = []
    return out


def _uid_and_part_from_meta(meta: bytes) -> tuple[bytes | None, str | None]:
    """Extract (uid, part_number) from a BODY[...] FETCH response line."""
    uid = _uid_from_meta(meta or b"")
    match = re.search(rb"BODY\[([^\]]*)\]", meta or b"")
    part = None
    if match:
        try:
            part = match.group(1).decode("ascii", errors="ignore")
        except Exception:  # noqa: BLE001
            part = None
    return uid, part


def _search_variants(text: str) -> list[str]:
    variants = [text]
    escaped = html_lib.escape(text, quote=False)  # & -> &amp; etc.
    if escaped != text:
        variants.append(escaped)
    return variants


def _select_folder(mail: imaplib.IMAP4_SSL, folder: str) -> bool:
    for readonly in (True, False):
        try:
            status, _ = mail.select(folder, readonly=readonly)
            if status == "OK":
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _folder_total(mail: imaplib.IMAP4_SSL, folder: str, cfg: dict) -> int:
    try:
        if not _select_folder(mail, folder):
            return 0
        status, data = mail.uid("search", None, "ALL")
        if status == "OK" and data and data[0]:
            return len(_limit_uids(data[0].split(), cfg))
    except Exception:  # noqa: BLE001
        pass
    return 0


def _folder_target_uids(mail: imaplib.IMAP4_SSL, cfg: dict) -> set[bytes] | None:
    """UIDs allowed by the per-folder caps, or None when no cap is set.

    The caller must have selected the folder already.
    """
    if not (cfg.get("first_emails") or cfg.get("max_emails")):
        return None
    try:
        status, data = mail.uid("search", None, "ALL")
        if status == "OK" and data and data[0]:
            return set(_limit_uids(data[0].split(), cfg))
    except Exception:  # noqa: BLE001
        pass
    return None


# --------------------------------------------------------------------------- #
#  Scan engines
# --------------------------------------------------------------------------- #
def scan_accurate(mail, folder, prepared, cfg, on_tick=None) -> tuple[list[int], list[list[dict]], int]:
    """Fetch each email once, then match every input in a single early-exit pass.

    An input is counted and classified the moment it is found in any view of the
    message; remaining views are skipped for that input and, once every input is
    matched, the rest of the message is not processed at all.
    """
    counts = [0] * len(prepared)
    previews: list[list[dict]] = [[] for _ in prepared]
    if not _select_folder(mail, folder):
        return counts, previews, 0
    try:
        status, data = mail.uid("search", None, "ALL")
    except Exception:  # noqa: BLE001
        return counts, previews, 0
    if status != "OK" or not data or not data[0]:
        return counts, previews, 0

    uids = _limit_uids(data[0].split(), cfg)
    total = len(uids)
    if on_tick:
        on_tick(counts, previews, 0, total)

    processed = 0
    last_tick = time.time()
    for uid in uids:
        if STOP_FLAG.is_set():
            break
        
        try:
            status, data = mail.uid("FETCH", uid, "(BODY.PEEK[])")
        except Exception:  # noqa: BLE001
            continue
        if status != "OK":
            continue
        
        content = None
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                content = item[1]
                break
        
        if not content:
            continue
            
        processed += 1
        
        if STOP_FLAG.is_set():
            break
            
        try:
            msg = message_from_bytes(content)
        except Exception:  # noqa: BLE001
            continue
        
        hay = build_haystack(msg)
        if not hay:
            continue

        if STOP_FLAG.is_set():
            break
            
        pending = set(range(len(prepared)))
        for text, is_flat in iter_view_texts(hay):
            if not pending:
                break
            for idx in list(pending):
                prep = prepared[idx]
                needle = prep["low"]
                hit = False
                if needle and needle in text:
                    hit = True
                elif is_flat:
                    hit = bool(prep["nospace"]) and prep["nospace"] in text
                
                if hit:
                    counts[idx] += 1
                    if len(previews[idx]) < cfg["previews"]:
                        previews[idx].append(make_preview(msg, hay, prep, folder))
                    pending.discard(idx)
        
        now = time.time()
        if on_tick and now - last_tick >= PUBLISH_INTERVAL:
            last_tick = now
            on_tick(counts, previews, processed, total)
    if on_tick:
        on_tick(counts, previews, processed, total)
    return counts, previews, total


def scan_fast(mail, folder, prepared, cfg):
    """Server-side IMAP text search only — no body download.

    Returns (counts, candidate_uids) or (None, None) when the server cannot
    answer the search reliably (then the caller falls back to a full scan).
    """
    if not _select_folder(mail, folder):
        return None, None
    allowed = _folder_target_uids(mail, cfg)
    counts = [0] * len(prepared)
    candidates: list[set[bytes]] = [set() for _ in prepared]
    for idx, prep in enumerate(prepared):
        if len(prep["text"]) > cfg["max_fast_len"]:
            return None, None  # too long for an IMAP SEARCH command -> full scan
        found: set[bytes] = set()
        answered = False
        for variant in _search_variants(prep["text"]):
            if not variant.isascii():
                continue  # non-ASCII needs a charset; not supported -> fall back
            try:
                status, data = mail.uid("search", None, "TEXT", _imap_quote(variant))
            except Exception:  # noqa: BLE001
                return None, None
            if status != "OK":
                return None, None
            answered = True
            if data and data[0]:
                found.update(data[0].split())
        if not answered:
            return None, None
        if allowed is not None:
            found &= allowed
        candidates[idx] = found
        counts[idx] = len(found)
    return counts, candidates


def _fast_previews(mail, candidates, prepared, cfg, folder) -> list[list[dict]]:
    previews: list[list[dict]] = [[] for _ in prepared]
    needed: set[bytes] = set()
    for idx in range(len(prepared)):
        for uid in list(candidates[idx])[: cfg["previews"]]:
            needed.add(uid)
    if not needed:
        return previews
    fetched: dict[bytes, bytes] = {}
    uids_sorted = sorted(needed, key=lambda value: int(value))
    for chunk in _uid_chunks(uids_sorted, cfg["batch"]):
        if STOP_FLAG.is_set():
            break
        try:
            status, data = mail.uid("FETCH", "%s:%s" % (chunk[0].decode(), chunk[-1].decode()), "(BODY.PEEK[])")
        except Exception:  # noqa: BLE001
            break
        if status != "OK":
            continue
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                uid = _uid_from_meta(item[0])
                if uid:
                    fetched[uid] = item[1]
    for idx, prep in enumerate(prepared):
        for uid in list(candidates[idx])[: cfg["previews"]]:
            content = fetched.get(uid)
            if not content:
                continue
            try:
                msg = message_from_bytes(content)
            except Exception:  # noqa: BLE001
                continue
            hay = build_haystack(msg)
            previews[idx].append(make_preview(msg, hay, prep, folder))
    return previews


def _part_sort_key(part: str):
    return tuple(int(bit) if bit.isdigit() else 0 for bit in part.split("."))


def _match_haystack(hay: str, prepared, counts) -> list[int]:
    """Match every input against one decoded message; record hits in place.

    Returns the indices that matched (needed for lazy preview building).
    """
    matched: list[int] = []
    pending = set(range(len(prepared)))
    for text, is_flat in iter_view_texts(hay):
        if not pending:
            break
        for idx in list(pending):
            prep = prepared[idx]
            needle = prep["low"]
            hit = False
            if needle and needle in text:
                hit = True
            elif is_flat:
                hit = bool(prep["nospace"]) and prep["nospace"] in text
            if hit:
                counts[idx] += 1
                matched.append(idx)
                pending.discard(idx)
    return matched


def _build_turbo_previews(mail, folder, hits, prepared, cfg, previews) -> None:
    """Build previews for messages that hit, fetching only their headers.

    `hits` is a list of (uid, haystack, matched_input_indices). Headers are
    downloaded in small batches — cheap compared to the body parts we already
    fetched — and only for messages that actually matched something.
    """
    limit = cfg["previews"]
    need: dict[int, list[int]] = {}  # input idx -> positions into `hits`
    for pos, (_uid, _hay, matched) in enumerate(hits):
        for idx in matched:
            bucket = need.setdefault(idx, [])
            if len(bucket) < limit:
                bucket.append(pos)
    if not need:
        return

    positions = sorted({p for bucket in need.values() for p in bucket})
    uids_needed = [hits[p][0] for p in positions]
    headers: dict[bytes, bytes] = {}
    for start in range(0, len(uids_needed), 40):
        sub = uids_needed[start:start + 40]
        try:
            status, data = mail.uid("FETCH", ",".join(u.decode() for u in sub), "(BODY.PEEK[HEADER])")
        except Exception as exc:  # noqa: BLE001
            log("✗ turbo header fetch failed: %s" % exc)
            break
        if status != "OK" or not data:
            continue
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                uid = _uid_from_meta(item[0])
                if uid:
                    headers[uid] = item[1]

    for idx, bucket in need.items():
        prep = prepared[idx]
        for pos in bucket:
            uid, hay, _matched = hits[pos]
            raw_headers = headers.get(uid)
            if not raw_headers:
                continue
            try:
                msg = message_from_bytes(raw_headers)
            except Exception:  # noqa: BLE001
                continue
            previews[idx].append(make_preview(msg, hay, prep, folder))


def _turbo_scan_chunk(mail, folder, chunk, prepared, cfg, counts, previews) -> int:
    """Process one batch of UIDs on a single IMAP connection.

    Skeleton fetch -> download only the text parts -> match in memory.
    Returns the number of emails processed.
    """
    if not chunk:
        return 0

    # 1) Skeleton: learn which parts are text (and their sizes) without bodies.
    range_str = ",".join(u.decode() for u in chunk)
    try:
        status, data = mail.uid("FETCH", range_str, "(BODYSTRUCTURE)")
    except Exception as exc:  # noqa: BLE001
        log("✗ turbo skeleton fetch failed: %s" % exc)
        return len(chunk)
    if status != "OK" or not data:
        return len(chunk)

    structures = _collect_structures(data)
    if not structures:
        return len(chunk)

    max_part = cfg.get("max_part_bytes", 0)
    part_meta: dict[bytes, list[tuple]] = {}
    for uid, parts in structures.items():
        text_parts = [
            p for p in parts
            if p[1] in ("text/plain", "text/html") and (max_part <= 0 or p[4] <= max_part)
        ]
        if text_parts:
            part_meta[uid] = text_parts
    if not part_meta:
        return len(chunk)

    # 2) Fetch ONLY the text parts. Group messages by their part-number
    #    signature so a part number that is text in one message never drags an
    #    attachment out of another (attachments are never requested at all).
    groups: dict[tuple, list[bytes]] = {}
    for uid, parts in part_meta.items():
        sig = tuple(sorted({p[0] for p in parts}, key=_part_sort_key))
        groups.setdefault(sig, []).append(uid)

    bodies: dict[bytes, dict[str, bytes]] = {}
    for sig, uids in groups.items():
        if STOP_FLAG.is_set():
            break
        spec = " ".join("BODY.PEEK[%s]" % part for part in sig)
        try:
            status, data = mail.uid("FETCH", ",".join(u.decode() for u in uids), "(%s)" % spec)
        except Exception as exc:  # noqa: BLE001
            log("✗ turbo body fetch failed: %s" % exc)
            continue
        if status != "OK" or not data:
            continue
        for item in data:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            uid, part = _uid_and_part_from_meta(item[0])
            if not uid or part is None:
                continue
            bodies.setdefault(uid, {})[part] = item[1]

    # 3) Decode + match entirely in memory, remembering which inputs matched
    #    which message so previews can be built lazily (headers only on hits).
    hits: list[tuple[bytes, str, list[int]]] = []
    for uid in chunk:
        if STOP_FLAG.is_set():
            break
        parts = part_meta.get(uid)
        blobs = bodies.get(uid)
        if not parts or not blobs:
            continue
        texts = []
        for part_no, _ctype, charset, encoding, _size in parts:
            raw = blobs.get(part_no)
            if raw:
                texts.append(_decode_part_text(raw, charset, encoding))
        if not texts:
            continue
        hay = "\n".join(texts)
        if not hay:
            continue
        matched = _match_haystack(hay, prepared, counts)
        if matched:
            hits.append((uid, hay, matched))

    # 4) Preview headers are only needed for messages that actually hit (rare).
    if hits and cfg["previews"] > 0:
        _build_turbo_previews(mail, folder, hits, prepared, cfg, previews)

    return len(chunk)


def scan_turbo(mail, folder, prepared, cfg, on_tick=None, conn_factory=None):
    """Super Turbo Scan — skeleton fetch, parallel connections, no attachments.

    1. Ask the server for the MIME skeleton (BODYSTRUCTURE) of each batch.
    2. Download ONLY the text/plain + text/html parts (attachments are skipped).
    3. Match every input in memory, in parallel across several IMAP connections.
    """
    counts = [0] * len(prepared)
    previews: list[list[dict]] = [[] for _ in prepared]
    if not _select_folder(mail, folder):
        return counts, previews, 0

    try:
        status, data = mail.uid("search", None, "ALL")
    except Exception as exc:  # noqa: BLE001
        log("✗ Turbo search failed: %s" % exc)
        return counts, previews, 0
    if status != "OK" or not data or not data[0]:
        return counts, previews, 0

    uids = _limit_uids(data[0].split(), cfg)
    total = len(uids)
    if on_tick:
        on_tick(counts, previews, 0, total)
    if not uids:
        return counts, previews, 0

    n_inputs = len(prepared)
    acc_lock = threading.Lock()
    acc = {"counts": counts, "previews": previews, "processed": 0}

    def report(local_counts, local_previews, done):
        with acc_lock:
            for i in range(n_inputs):
                acc["counts"][i] += local_counts[i]
                room = cfg["previews"] - len(acc["previews"][i])
                if room > 0 and local_previews[i]:
                    acc["previews"][i].extend(local_previews[i][:room])
            acc["processed"] += done
            snapshot_counts = list(acc["counts"])
            snapshot_previews = [list(p) for p in acc["previews"]]
            snapshot_done = acc["processed"]
        if on_tick:
            on_tick(snapshot_counts, snapshot_previews, snapshot_done, total)

    conns = 1
    if conn_factory is not None:
        conns = max(1, min(int(cfg.get("turbo_conns", 8)), len(uids)))
    batch = max(1, int(cfg.get("turbo_batch", 8)))

    if conns <= 1:
        # Single connection: reuse the caller's socket.
        for idx in range(0, len(uids), batch):
            if STOP_FLAG.is_set():
                break
            chunk = uids[idx:idx + batch]
            local_counts = [0] * n_inputs
            local_previews: list[list[dict]] = [[] for _ in range(n_inputs)]
            done = _turbo_scan_chunk(mail, folder, chunk, prepared, cfg, local_counts, local_previews)
            report(local_counts, local_previews, done)
        return acc["counts"], acc["previews"], total

    groups = [uids[i::conns] for i in range(conns)]

    def worker(group):
        if STOP_FLAG.is_set() or not group:
            return
        conn = None
        try:
            conn = conn_factory()
            if not _select_folder(conn, folder):
                return
            for idx in range(0, len(group), batch):
                if STOP_FLAG.is_set():
                    break
                chunk = group[idx:idx + batch]
                local_counts = [0] * n_inputs
                local_previews: list[list[dict]] = [[] for _ in range(n_inputs)]
                done = _turbo_scan_chunk(conn, folder, chunk, prepared, cfg, local_counts, local_previews)
                report(local_counts, local_previews, done)
        except Exception as exc:  # noqa: BLE001
            log("✗ turbo worker error: %s" % exc)
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:  # noqa: BLE001
                    pass

    workers = max(1, min(len([g for g in groups if g]), conns))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(worker, groups))

    return acc["counts"], acc["previews"], total


def scan_folder(mail, folder, prepared, cfg, on_tick=None, conn_factory=None):
    """Dispatch to the selected engine, with safety fallback in hybrid mode."""
    mode = cfg["mode"]
    if mode == "turbo":
        return scan_turbo(mail, folder, prepared, cfg, on_tick, conn_factory)
    if mode in ("fast", "hybrid"):
        counts, candidates = scan_fast(mail, folder, prepared, cfg)
        if counts is not None and (mode == "fast" or sum(counts) > 0):
            previews = _fast_previews(mail, candidates, prepared, cfg, folder)
            if on_tick:
                on_tick(counts, previews, 0, 0)
            return counts, previews, _folder_total(mail, folder, cfg)
        # fast search unsupported, or hybrid found nothing -> verify with a full scan
    counts, previews, total = scan_accurate(mail, folder, prepared, cfg, on_tick)
    return counts, previews, total


# --------------------------------------------------------------------------- #
#  Per-mailbox worker
# --------------------------------------------------------------------------- #
def process_mailbox(cred, prepared, cfg) -> dict:
    email_address, password = cred
    with LIVE_LOCK:
        result = LIVE_MAILBOXES.get(email_address)
        if result is None:
            result = _blank_mailbox_result(email_address, len(prepared))
            LIVE_MAILBOXES[email_address] = result
        result["status"] = "running"
        result["error"] = None

    try:
        domain = email_address.split("@", 1)[-1].lower() if "@" in email_address else ""
        host, port = get_imap_server(domain, cfg["isp"])
        socket.setdefaulttimeout(cfg["timeout"])
        mail = imaplib.IMAP4_SSL(host, port)
        mail.login(email_address, password)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = _friendly_error(exc)
        result["error_raw"] = str(exc)[:300]
        log("✗ %s — %s" % (email_address, result["error"]))
        _set_progress(2)
        _publish_live(force=True)
        return result

    def make_conn():
        """Open a fresh, independent IMAP connection (used by turbo workers)."""
        socket.setdefaulttimeout(cfg["timeout"])
        conn = imaplib.IMAP4_SSL(host, port)
        conn.login(email_address, password)
        return conn

    try:
        inbox, spam, folders = find_folders(mail)
        result["folders"] = {"inbox": inbox, "spam": spam, "all": [f["name"] for f in folders]}
        log("→ %s connected (%d folders, spam=%s)" % (email_address, len(folders), spam or "not found"))
        targets = [("inbox", inbox)]
        if spam and spam.lower() != inbox.lower():
            targets.append(("spam", spam))

        for kind, folder in targets:
            if STOP_FLAG.is_set():
                break
            log("… %s — scanning %s" % (email_address, folder))

            def on_tick(counts, previews, processed, total, _kind=kind, _folder=folder):
                result[_kind] = counts
                result["previews"][_kind] = previews
                if total:
                    result[_kind + "_total"] = total
                _set_progress(0, "%s — %s: %d/%d emails" % (email_address, _folder, processed, total or processed))
                _publish_live()

            counts, previews, total = scan_folder(mail, folder, prepared, cfg, on_tick, make_conn)
            result[kind] = counts
            result["previews"][kind] = previews
            result[kind + "_total"] = total
            hits = sum(counts)
            log("✓ %s — %s (%s): %d emails, %d inputs hit" % (email_address, kind, folder, total, hits))
            _set_progress(1)
            _publish_live(force=True)

        # If spam was skipped, still increment progress to keep the bar accurate
        if len(targets) < 2:
            _set_progress(1)

        result["status"] = "ok"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = _friendly_error(exc)
        result["error_raw"] = str(exc)[:300]
        log("✗ %s — %s" % (email_address, result["error"]))
    finally:
        try:
            mail.logout()
        except Exception:  # noqa: BLE001
            pass
        _publish_live(force=True)
    return result


# --------------------------------------------------------------------------- #
#  Aggregation + run loop
# --------------------------------------------------------------------------- #
def run_check(payload: dict) -> None:
    started = time.time()
    inputs = [line for line in (payload.get("inputs") or "").splitlines() if line.strip()]
    prepared = [prepare_input(line) for line in inputs]

    creds = []
    seen_emails = set()
    for line in (payload.get("mailboxes") or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        email_address, password = line.split(":", 1)
        email_address = email_address.strip()
        password = password.strip()
        if email_address and password and email_address.lower() not in seen_emails:
            seen_emails.add(email_address.lower())
            creds.append((email_address, password))

    mode = payload.get("mode", "hybrid")
    if mode not in ("hybrid", "accurate", "fast", "turbo"):
        mode = "hybrid"

    cfg = {
        "mode": mode,
        "isp": load_isp_config(),
        "max_emails": int(payload.get("max_emails") or 0),
        "first_emails": int(payload.get("first_emails") or 0),
        "previews": int(payload.get("previews") or 5),
        "batch": 3,
        "timeout": 90,
        "max_fast_len": 512,
        "threads": max(1, min(int(payload.get("threads") or 5), 50)),
        # Super Turbo: several parallel IMAP connections (Gmail caps a single
        # connection at ~0.85 MB/s, so parallelism is what makes it fast) and a
        # batch of UIDs per FETCH. max_part_bytes=0 means no text part is skipped.
        "turbo_conns": max(1, min(int(payload.get("turbo_conns") or 8), 12)),
        "turbo_batch": max(1, min(int(payload.get("turbo_batch") or 8), 50)),
        "max_part_bytes": int(payload.get("max_part_bytes") or 0),
    }

    with LIVE_LOCK:
        LIVE_ORDER[:] = [cred[0] for cred in creds]
        LIVE_INPUTS[:] = prepared
        LIVE_MAILBOXES.clear()
        for email_address, _password in creds:
            LIVE_MAILBOXES[email_address] = _blank_mailbox_result(email_address, len(prepared))
    LIVE_CTX.update({"mode": mode, "started": started, "last_publish": 0.0})

    with STATE_LOCK:
        STATE.update(
            {
                "running": True,
                "mode": mode,
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "finished_at": None,
                "progress": 0,
                "total": len(creds) * 2,
                "current": "starting…",
                "log": [],
                "results": None,
                "counts": {"mailboxes": len(creds), "inputs": len(prepared)},
            }
        )

    log("Started — %d mailbox(es), %d input(s), mode=%s" % (len(creds), len(prepared), mode))

    if not creds:
        log("No valid mailbox lines (expected email:password).")
    if not prepared:
        log("No search inputs provided.")

    _publish_live(force=True)  # show the table immediately, then fill it in live

    try:
        if creds and prepared:
            with ThreadPoolExecutor(max_workers=cfg["threads"]) as executor:
                futures = [executor.submit(process_mailbox, cred, prepared, cfg) for cred in creds]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001
                        log("✗ worker crashed — %s" % exc)
    finally:
        with LIVE_LOCK:
            for mailbox in LIVE_MAILBOXES.values():
                if mailbox["status"] == "running":
                    mailbox["status"] = "ok" if mailbox.get("folders") else "error"
                    if mailbox["status"] == "error" and not mailbox.get("error"):
                        mailbox["error"] = "scan did not complete"

        with LIVE_LOCK:
            final = _aggregate_results(partial=False)
        duration = final["duration"]
        stopped = STOP_FLAG.is_set()
        with STATE_LOCK:
            STATE["results"] = final
            STATE["running"] = False
            STATE["finished_at"] = datetime.now().isoformat(timespec="seconds")
            STATE["current"] = "stopped" if stopped else "done"
        log("Finished in %ss (%s)" % (duration, "stopped" if stopped else "complete"))


# --------------------------------------------------------------------------- #
#  Routes — pages
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
def admin_page():
    """Hidden entry point for the secret admin account (not linked anywhere)."""
    return render_template("admin.html")


# --------------------------------------------------------------------------- #
#  Routes — auth / accounts
# --------------------------------------------------------------------------- #
def _valid_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value or ""))


@app.route("/api/me")
def api_me():
    entry = current_user()
    if not entry:
        return jsonify({"authenticated": False, "role": None, "email": None})
    payload = _public_user(entry, full=True)
    payload["authenticated"] = True
    return jsonify(payload)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    with USERS_LOCK:
        entry = _load_users().get(email)
    
    if not entry or not check_password_hash(entry.get("pass_hash", ""), password):
        return jsonify({"error": "Invalid email or password"}), 401
    
    session.clear()
    session["email"] = email
    session["role"] = entry.get("role", "user")
    return jsonify({"status": "ok", "email": entry["email"], "role": session["role"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "ok"})


@app.route("/api/save_mailboxes", methods=["POST"])
@login_required
def api_save_mailboxes():
    data = request.get_json(silent=True) or {}
    mailboxes = data.get("mailboxes") or ""
    email = session["email"]
    with USERS_LOCK:
        users = _load_users()
        entry = users.get(email)
        if not entry:
            return jsonify({"error": "Account not found"}), 404
        entry["mailboxes"] = mailboxes
        users[email] = entry
        _save_users(users)
    count = len([ln for ln in mailboxes.splitlines() if ln.strip()])
    return jsonify({"status": "saved", "mailbox_count": count,
                    "saved_at": datetime.now().isoformat(timespec="seconds")})


@app.route("/api/tests", methods=["GET"])
@login_required
def api_tests_list():
    with USERS_LOCK:
        entry = _load_users().get(session["email"]) or {}
    return jsonify({"tests": entry.get("tests") or []})


@app.route("/api/tests", methods=["POST"])
@login_required
def api_tests_save():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    inputs = data.get("inputs") or ""
    if not name:
        return jsonify({"error": "Test name required"}), 400
    email = session["email"]
    with USERS_LOCK:
        users = _load_users()
        entry = users.get(email)
        if not entry:
            return jsonify({"error": "Account not found"}), 404
        tests = [t for t in (entry.get("tests") or []) if t.get("name") != name]
        tests.append({"name": name, "inputs": inputs,
                      "saved_at": datetime.now().isoformat(timespec="seconds")})
        entry["tests"] = tests
        users[email] = entry
        _save_users(users)
    return jsonify({"status": "saved", "tests": entry["tests"]})


@app.route("/api/tests/delete", methods=["POST"])
@login_required
def api_tests_delete():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = session["email"]
    with USERS_LOCK:
        users = _load_users()
        entry = users.get(email)
        if not entry:
            return jsonify({"error": "Account not found"}), 404
        entry["tests"] = [t for t in (entry.get("tests") or []) if t.get("name") != name]
        users[email] = entry
        _save_users(users)
    return jsonify({"status": "deleted", "tests": entry["tests"]})


# --------------------------------------------------------------------------- #
#  Routes — admin (secret)
# --------------------------------------------------------------------------- #
@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    with USERS_LOCK:
        entry = _load_users().get(email)
    if not entry or entry.get("role") != "admin" or not check_password_hash(entry.get("pass_hash", ""), password):
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["email"] = email
    session["role"] = "admin"
    return jsonify({"status": "ok", "email": entry["email"], "role": "admin"})


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def api_admin_users():
    with USERS_LOCK:
        users = _load_users()
    # The admin account itself is never listed.
    public = [_public_user(u) for u in users.values() if u.get("role") != "admin"]
    public.sort(key=lambda u: (u.get("created_at") or "", u.get("email") or ""))
    return jsonify({"users": public})


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def api_admin_create_user():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not _valid_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    key = email.lower()
    with USERS_LOCK:
        users = _load_users()
        if key in users:
            return jsonify({"error": "An account with this email already exists"}), 400
        users[key] = _new_user(email, password, role="user")
        _save_users(users)
    return jsonify({"status": "created", "email": email})


@app.route("/api/admin/users/delete", methods=["POST"])
@admin_required
def api_admin_delete_user():
    data = request.get_json(silent=True) or {}
    key = (data.get("email") or "").strip().lower()
    with USERS_LOCK:
        users = _load_users()
        entry = users.get(key)
        if not entry:
            return jsonify({"error": "User not found"}), 404
        if entry.get("role") == "admin":
            return jsonify({"error": "Cannot delete the admin account"}), 400
        del users[key]
        _save_users(users)
    return jsonify({"status": "deleted", "email": key})


@app.route("/api/admin/users/reset", methods=["POST"])
@admin_required
def api_admin_reset_user():
    data = request.get_json(silent=True) or {}
    key = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    with USERS_LOCK:
        users = _load_users()
        entry = users.get(key)
        if not entry:
            return jsonify({"error": "User not found"}), 404
        if entry.get("role") == "admin":
            return jsonify({"error": "Cannot reset the admin password here"}), 400
        entry["pass_hash"] = generate_password_hash(password)
        users[key] = entry
        _save_users(users)
    return jsonify({"status": "reset", "email": key})


# --------------------------------------------------------------------------- #
#  Routes — scan engine
# --------------------------------------------------------------------------- #
@app.route("/api/status")
@login_required
def api_status():
    with STATE_LOCK:
        owner = STATE.get("owner")
        # A user only ever sees the run they started themselves.
        mine = bool(owner) and owner == session.get("email")
        return jsonify(
            {
                "running": STATE["running"],
                "mode": STATE["mode"],
                "started_at": STATE["started_at"],
                "finished_at": STATE["finished_at"],
                "progress": STATE["progress"],
                "total": STATE["total"],
                "current": STATE["current"],
                "log": STATE["log"][-120:],
                "counts": STATE["counts"],
                "results": STATE["results"] if mine else None,
                "owner": owner if mine else None,
            }
        )


@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    email = session.get("email")
    print(f"DEBUG: /api/start called by {email}")
    
    with STATE_LOCK:
        if STATE["running"]:
            print(f"DEBUG: Scan already running by {STATE['owner']}")
            return jsonify({"error": f"A scan is already being run by {STATE['owner']}. Please wait or ask them to Stop it."}), 400

    payload = request.get_json(silent=True) or {}
    mailboxes_raw = (payload.get("mailboxes") or "").strip()
    inputs_raw = (payload.get("inputs") or "").strip()
    
    if not mailboxes_raw:
        return jsonify({"error": "No mailboxes provided"}), 400
    if not inputs_raw:
        return jsonify({"error": "No search inputs provided"}), 400

    # Reset EVERYTHING for a fresh start
    STOP_FLAG.clear()
    with LIVE_LOCK:
        LIVE_MAILBOXES.clear()
        LIVE_ORDER.clear()
        LIVE_INPUTS.clear()
        LIVE_CTX["last_publish"] = 0.0

    with STATE_LOCK:
        STATE.update(
            {
                "running": True,
                "mode": payload.get("mode", "hybrid"),
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "finished_at": None,
                "progress": 0,
                "total": 0,
                "current": "initializing…",
                "log": [],
                "results": None,
                "counts": {"mailboxes": 0, "inputs": 0},
                "owner": email,
            }
        )

    print(f"DEBUG: Launching run_check for {email}")
    thread = threading.Thread(target=run_check, args=(payload,), daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
@login_required
def api_stop():
    STOP_FLAG.set()
    log("Stop requested…")
    return jsonify({"status": "stopping"})


@app.route("/api/reset", methods=["POST"])
@login_required
def api_reset():
    with STATE_LOCK:
        STATE["running"] = False
        STATE["current"] = "reset"
        STATE["results"] = None
        STATE["owner"] = None
    STOP_FLAG.set()
    log("System state reset by user.")
    return jsonify({"status": "reset"})


_ensure_admin()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mailbox Hit Checker")
    parser.add_argument("--port", type=int, default=5010, help="Port (default 5010)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
