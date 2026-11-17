#!/usr/bin/env python3
"""
Santa's Sleigh Desk - a tiny local web app.

  * Organisers manage the event + roster, but never see who got whom.
  * The draw happens on this machine; each Santa gets their giftee by email.
  * Pairings are kept only in a sealed vault (data/vault.sealed) so lost emails
    can be re-sent and the big reveal can happen on exchange day.

Run:  python server.py      (no pip installs needed - Python 3.9+ stdlib only)
"""
import base64
import csv
import hashlib
import hmac
import html
import imaplib
import io
import json
import os
import re
import secrets
import smtplib
import ssl
import sys
import threading
import time
import traceback
import webbrowser
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
STATE_FILE = os.path.join(DATA, "state.json")
VAULT_FILE = os.path.join(DATA, "vault.sealed")
KEY_FILE = os.path.join(DATA, "vault.key")
HOST = "127.0.0.1"
PORT = int(os.environ.get("SANTA_PORT", "8765"))

LOCK = threading.RLock()
SECRETS_IN_MEMORY = {"smtp_password": ""}  # never written to disk
JOB = {"active": False, "kind": "", "done": 0, "total": 0, "message": "", "ok": True}

EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


class ApiError(Exception):
    pass


# --------------------------------------------------------------------------- state

def default_state():
    return {
        "event": {
            "title": "Arista BLR Secret Santa 2026",
            "budget": "Around Rs. 750 (flexible - it's the thought that counts!)",
            "dates": "Dec 14 - Dec 18, 2026 (final day decided by vote)",
            "location": "Arista BLR Office",
            "organisers": "The Elf Committee",
            "note": "",
        },
        "participants": [],
        "smtp": {
            "preset": "gmail",
            "host": "smtp.gmail.com",
            "port": 587,
            "security": "starttls",
            "user": "",
            "from_name": "Santa's Robot Elf",
            "from_email": "",
            "shred": True,
            "imap_host": "imap.gmail.com",
        },
        "draw": {"status": "none", "drawn_at": None, "fingerprint": None, "key_burned": False, "late_batches": []},
        "sends": {},
    }


def load_state():
    if not os.path.exists(STATE_FILE):
        return default_state()
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        st = json.load(f)
    base = default_state()
    for k, v in base.items():  # forward-compatible merge
        if k not in st:
            st[k] = v
        elif isinstance(v, dict):
            for kk, vv in v.items():
                st[k].setdefault(kk, vv)
    return st


def save_state(st):
    os.makedirs(DATA, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------- sealed vault
# Stdlib-only authenticated encryption (SHA-256 counter keystream + HMAC-SHA256).
# Goal: nobody "accidentally" sees pairings. Whoever runs the machine could still
# dig the key out - so we offer "Burn the key" once emails are confirmed delivered.

def _subkeys(key):
    return hashlib.sha256(b"enc" + key).digest(), hashlib.sha256(b"mac" + key).digest()


def _xor_stream(key, nonce, data):
    out = bytearray(len(data))
    for block in range(0, len(data), 32):
        ks = hashlib.sha256(key + nonce + block.to_bytes(8, "big")).digest()
        for i, b in enumerate(data[block:block + 32]):
            out[block + i] = b ^ ks[i]
    return bytes(out)


def seal(key, plaintext):
    ek, mk = _subkeys(key)
    nonce = secrets.token_bytes(16)
    ct = _xor_stream(ek, nonce, plaintext)
    tag = hmac.new(mk, nonce + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def unseal(key, blob):
    ek, mk = _subkeys(key)
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    if not hmac.compare_digest(tag, hmac.new(mk, nonce + ct, hashlib.sha256).digest()):
        raise ApiError("The vault looks tampered with or the key doesn't match.")
    return _xor_stream(ek, nonce, ct)


def write_vault(payload):
    os.makedirs(DATA, exist_ok=True)
    key = secrets.token_bytes(32)
    blob = seal(key, json.dumps(payload).encode("utf-8"))
    with open(VAULT_FILE, "wb") as f:
        f.write(blob)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return hashlib.sha256(blob).hexdigest()[:12].upper()


def read_vault():
    if not os.path.exists(VAULT_FILE):
        raise ApiError("No draw has happened yet.")
    if not os.path.exists(KEY_FILE):
        raise ApiError("The vault key has been burned - pairings can no longer be read by anyone.")
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    with open(VAULT_FILE, "rb") as f:
        blob = f.read()
    return json.loads(unseal(key, blob).decode("utf-8"))


# --------------------------------------------------------------------------- backups & history
# A snapshot is everything needed to carry on: the roster/state plus the sealed vault and its key.
# Automatic history lives next to the vault (same protection as the vault itself).
# Downloaded backup files are locked with a passphrase the organiser chooses.

HISTORY_KEEP = 80
BACKUP_APP = "santas-sleigh-desk-backup"


def history_dir():
    return os.path.join(DATA, "history")


def _read_bytes(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def take_snapshot():
    b64 = lambda b: base64.b64encode(b).decode("ascii") if b is not None else None
    return {"state": load_state(), "vault": b64(_read_bytes(VAULT_FILE)), "key": b64(_read_bytes(KEY_FILE))}


def apply_snapshot(snap):
    st = snap.get("state")
    if not isinstance(st, dict) or not isinstance(st.get("participants"), list) or not isinstance(st.get("draw"), dict):
        raise ApiError("That backup doesn't look like a Sleigh Desk backup.")
    os.makedirs(DATA, exist_ok=True)
    for path, val in ((VAULT_FILE, snap.get("vault")), (KEY_FILE, snap.get("key"))):
        if val:
            with open(path, "wb") as f:
                f.write(base64.b64decode(val))
        elif os.path.exists(path):
            os.remove(path)
    if not snap.get("key") and st["draw"].get("status") != "none":
        st["draw"]["key_burned"] = True
    save_state(st)


def summary_of(st):
    P = st["participants"]
    if st["draw"].get("status") == "none":
        return f"{len(P)} Santas - not drawn yet"
    sent = sum(1 for x in st["sends"].values() if x.get("status") == "sent")
    drawn = [p for p in P if not is_waiting(p)]
    parts = [f"{len(P)} Santas", f"{sent} of {len(drawn)} letters sent"]
    loops = len(st["draw"].get("late_batches") or [])
    if loops:
        parts.append(f"{loops} late loop{'s' if loops > 1 else ''}")
    waiting = len(P) - len(drawn)
    if waiting:
        parts.append(f"{waiting} late joiner{'s' if waiting > 1 else ''} not drawn yet")
    if st["draw"].get("key_burned"):
        parts.append("key burned")
    return " - ".join(parts)


def save_history(reason):
    """Keeps an automatic restore point. Never lets a failure here break the real action."""
    try:
        with LOCK:
            snap = take_snapshot()
            os.makedirs(history_dir(), exist_ok=True)
            now = datetime.now()
            hid = now.strftime("%Y%m%d-%H%M%S-%f")
            rec = {"id": hid, "at": now.isoformat(timespec="seconds"), "reason": reason,
                   "summary": summary_of(snap["state"]), "snapshot": snap}
            with open(os.path.join(history_dir(), hid + ".json"), "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False)
            files = sorted(n for n in os.listdir(history_dir()) if n.endswith(".json"))
            for old in files[:-HISTORY_KEEP]:
                os.remove(os.path.join(history_dir(), old))
    except Exception:
        traceback.print_exc()


def _history_files():
    d = history_dir()
    if not os.path.isdir(d):
        return []
    return sorted((n for n in os.listdir(d) if n.endswith(".json")), reverse=True)


def list_history():
    out = []
    for n in _history_files():
        try:
            with open(os.path.join(history_dir(), n), "r", encoding="utf-8") as f:
                r = json.load(f)
            out.append({"id": r["id"], "at": r["at"], "reason": r["reason"], "summary": r["summary"]})
        except Exception:
            continue
    return out


def load_history(hid):
    if not re.fullmatch(r"[0-9-]+", hid or ""):
        raise ApiError("Unknown restore point.")
    path = os.path.join(history_dir(), hid + ".json")
    if not os.path.exists(path):
        raise ApiError("That restore point no longer exists.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def strip_history_keys():
    """Burning the key must also burn every copy of it in the automatic history."""
    for n in _history_files():
        path = os.path.join(history_dir(), n)
        try:
            with open(path, "r", encoding="utf-8") as f:
                r = json.load(f)
            if r["snapshot"].get("key"):
                r["snapshot"]["key"] = None
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(r, f, ensure_ascii=False)
        except Exception:
            traceback.print_exc()


def _pass_key(passphrase, salt):
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 300_000)


def export_backup(passphrase):
    if len(passphrase or "") < 6:
        raise ApiError("Pick a passphrase of at least 6 characters - you'll need it to restore.")
    snap = take_snapshot()
    salt = secrets.token_bytes(16)
    blob = seal(_pass_key(passphrase, salt), json.dumps(snap).encode("utf-8"))
    created = datetime.now().isoformat(timespec="seconds")
    return {"app": BACKUP_APP, "version": 1, "created": created,
            "summary": summary_of(snap["state"]),   # readable label only - no names, no pairings
            "salt": base64.b64encode(salt).decode("ascii"), "data": base64.b64encode(blob).decode("ascii")}


def open_backup(text, passphrase):
    try:
        f = json.loads(text)
        if f.get("app") != BACKUP_APP:
            raise ValueError
        salt, blob = base64.b64decode(f["salt"]), base64.b64decode(f["data"])
    except Exception:
        raise ApiError("That file isn't a Sleigh Desk backup (.json downloaded from the Backups tab).")
    try:
        return json.loads(unseal(_pass_key(passphrase or "", salt), blob).decode("utf-8"))
    except ApiError:
        raise ApiError("Wrong passphrase for this backup (or the file was changed).")


# --------------------------------------------------------------------------- roster

def _split_tokens(s):
    return [t.strip().lower() for t in re.split(r"[,;\n/|]+", s or "") if t.strip()]


def name_from_email(email):
    local = re.sub(r"\d+", "", email.split("@")[0])
    parts = [w for w in re.split(r"[._\-+]+", local) if w]
    return " ".join(w.capitalize() for w in parts) or email.split("@")[0]


def parse_roster(text):
    text = (text or "").strip("﻿").strip()
    if not text:
        raise ApiError("Paste some rows first.")
    first = text.splitlines()[0]
    delim = "\t" if "\t" in first else ","
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
    header = [c.strip().lower() for c in rows[0]]

    def find(pred):
        for i, h in enumerate(header):
            if pred(h):
                return i
        return None

    # Matches the sign-up form: "Your name", "E-mail", "Gifts I do not want (optional):",
    # "Do you want your Santa identity to remain anonymous even after the final day?".
    # Other questions (daily fun tasks, in office on exchange day) aren't needed for the draw.
    i_email = find(lambda h: "e-mail" in h or "email" in h or h == "mail")
    has_header = i_email is not None and not any("@" in c for c in rows[0])
    if has_header:
        i_code = find(is_codename_header)
        i_name = find(lambda h: re.search(r"\bname\b", h) and "email" not in h and "user" not in h
                      and not is_codename_header(h))
        i_nogift = find(lambda h: "gift" in h and ("not want" in h or "don't want" in h or "dont want" in h
                                                    or "do not" in h or "avoid" in h))
        i_hint = find(lambda h: any(w in h for w in ("wish", "hint", "interest"))) if i_nogift is None else None
        i_anon = find(lambda h: "anonym" in h)
        body = rows[1:]
    else:
        i_name, i_email, i_nogift, i_hint, i_anon, i_code = 0, 1, 2, None, None, None
        body = rows

    people, warnings, seen = [], [], {}
    for n, r in enumerate(body, start=2 if has_header else 1):
        cell = lambda i: (r[i].strip() if i is not None and i < len(r) else "")
        name, email = cell(i_name), cell(i_email).lower()
        if not name and not email:
            continue
        if not EMAIL_RE.match(email):
            warnings.append(f"Row {n}: skipped '{name or '?'}' - invalid email '{email}'.")
            continue
        p = {"id": secrets.token_hex(6), "name": name or name_from_email(email),
             "email": email, "hints": cell(i_nogift) or cell(i_hint), "avoid": "",
             "anonymous": cell(i_anon).lower().startswith("y"), "codename": clean_codename(cell(i_code))}
        if email in seen:
            warnings.append(f"Row {n}: '{email}' appeared again - kept the latest response.")
            people[seen[email]] = p
        else:
            seen[email] = len(people)
            people.append(p)
    # Duplicate secret names would confuse Exchange Day. Report the row only, never the name itself.
    taken = set()
    for p in people:
        key = p["codename"].lower()
        if key and key in taken:
            warnings.append(f"{p['name']} picked a secret name someone else already chose - "
                            "they'll get a number added to theirs.")
        taken.add(key)
    return people, warnings


def is_codename_header(h):
    return (any(w in h for w in ("codename", "code name", "alias", "nickname", "secret name", "santa name"))
            or (bool(re.search(r"\bname\b", h)) and ("secret" in h or "santa" in h)))


# Answers that mean "I didn't pick one" - these get an auto-assigned codename instead.
NO_CODENAME = {"na", "nil", "none", "no", "nope", "nothing", "null", "nan", "x", "0", "idk", "skip", "notapplicable",
               "nopreference", "noname", "nonamechosen", "auto", "random", "any", "anything", "pickforme", "chooseforme",
               "youpick", "youchoose", "surpriseme", "yourchoice", "notneeded", "notrequired", "blank", "empty", "tbd"}


def clean_codename(s):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    key = re.sub(r"[^a-z0-9]", "", s.lower())
    if not key or key in NO_CODENAME:   # blank, "-", "N/A", "n.a.", "None", "--", "?" ...
        return ""
    return s[:60]


def clean_participants(items):
    out, seen = [], set()
    for p in items:
        name = str(p.get("name", "")).strip()
        email = str(p.get("email", "")).strip().lower()
        if not name or not EMAIL_RE.match(email):
            raise ApiError(f"Each Santa needs a name and a valid email (problem with '{name or email}').")
        if email in seen:
            raise ApiError(f"Duplicate email: {email}")
        seen.add(email)
        out.append({"id": p.get("id") or secrets.token_hex(6), "name": name, "email": email,
                    "hints": str(p.get("hints", "")).strip(), "avoid": str(p.get("avoid", "")).strip(),
                    "anonymous": bool(p.get("anonymous")), "codename": clean_codename(p.get("codename"))})
    return out


# --------------------------------------------------------------------------- the draw

ADJ = ["Frosty", "Jolly", "Twinkly", "Sneaky", "Sparkly", "Cosy", "Merry", "Snowy", "Velvet", "Ginger",
       "Peppermint", "Tinsel", "Midnight", "Silent", "Starlit", "Cinnamon", "Fuzzy", "Glittery", "Crimson",
       "Evergreen", "Sugarplum", "Whistling", "Moonlit", "Toasty", "Jingly", "Mistletoe", "Nutmeg", "Woolly"]
NOUN = ["Reindeer", "Snowflake", "Elf", "Penguin", "Nutcracker", "Gingerbread", "Polar Bear", "Snowman",
        "Candy Cane", "Owl", "Sleigh", "Mitten", "Pinecone", "Lantern", "Comet", "Yeti", "Cocoa", "Bauble",
        "Marshmallow", "Stocking", "Walrus", "Chimney", "Robin", "Fox", "Narwhal", "Plum Pudding"]


def blocked_pairs(people):
    lookup = {}
    for p in people:
        lookup[p["email"].lower()] = p["id"]
        lookup[p["name"].lower()] = p["id"]
    blocked = set()
    for p in people:
        for tok in _split_tokens(p.get("avoid")):
            other = lookup.get(tok)
            if other and other != p["id"]:
                blocked.add((p["id"], other))
                blocked.add((other, p["id"]))
    return blocked


def make_circle(people, rng, min_size=3):
    """One loop: A -> B -> C -> ... -> A. No self-gifting. With min_size=2 a two-person swap is allowed
    (used for late joiners - their letters never say they're in a separate loop)."""
    n = len(people)
    if n < min_size:
        raise ApiError(f"You need at least {min_size} Santas for a proper secret draw.")
    blocked = blocked_pairs(people)
    ids = [p["id"] for p in people]
    for _ in range(100000):
        rng.shuffle(ids)
        if all((ids[i], ids[(i + 1) % n]) not in blocked for i in range(n)):
            return list(ids)
    raise ApiError("Couldn't find a valid draw with these 'avoid' rules. Try loosening a few.")


def do_draw(people):
    """The main draw: one big loop through the whole office."""
    rng = secrets.SystemRandom()
    ids = make_circle(people, rng)
    return {"chain": ids, "codenames": assign_codenames(people, set(), rng),
            "drawn_at": datetime.now().isoformat(timespec="seconds")}


def circles_of(vault):
    """The main loop plus any late-joiner loops. Each loop is closed on its own."""
    return [vault["chain"]] + [c["chain"] for c in vault.get("late", [])]


def receiver_map(vault):
    return {g: c[(i + 1) % len(c)] for c in circles_of(vault) for i, g in enumerate(c)}


def assign_codenames(people, used, rng):
    """Santas who chose their own secret name keep it; everyone else gets an auto-assigned one.
    `used` holds names (lower-case) already taken by earlier draws."""
    codenames, used = {}, set(used)
    for p in people:
        own = clean_codename(p.get("codename"))
        if own:
            name, k = own, 2
            while name.lower() in used:
                name, k = f"{own} #{k}", k + 1
            codenames[p["id"]] = name
            used.add(name.lower())
    combos = [c for c in (f"Agent {a} {b}" for a in ADJ for b in NOUN) if c.lower() not in used]
    rng.shuffle(combos)
    for p in people:
        if p["id"] not in codenames:
            name = combos.pop() if combos else f"Agent {rng.choice(ADJ)} {rng.choice(NOUN)} #{len(used) + 1}"
            codenames[p["id"]] = name
            used.add(name.lower())
    return codenames


def full_mapping_text(st, vault):
    """Everything the organiser needs to run Exchange Day by hand if the app can't start:
    every pairing (main loop + late loops), each Santa's codename, and who must stay anonymous."""
    people = {p["id"]: p for p in st["participants"]}
    cn = vault["codenames"]
    when = lambda s: (s or "").replace("T", " ")[:16]
    loops = [("MAIN DRAW", vault["chain"], vault.get("drawn_at"))]
    loops += [(f"LATE JOINERS - LOOP {i + 1}", c["chain"], c.get("drawn_at")) for i, c in enumerate(vault.get("late", []))]
    total = sum(len(c) for _, c, _ in loops)
    w = max((len(people[g]["name"]) for _, c, _ in loops for g in c if g in people), default=10)
    rule = "=" * 78
    out = [f"{st['event'].get('title', 'Secret Santa')} - FULL MAPPING (CONFIDENTIAL)",
           f"Downloaded {datetime.now().strftime('%Y-%m-%d %H:%M')} - draw fingerprint {st['draw'].get('fingerprint')}",
           f"{total} Santas in {len(loops)} loop{'s' if len(loops) > 1 else ''}"
           + (" (main draw + late joiners)" if len(loops) > 1 else ""),
           "",
           "Keep this file private. It's the backup plan if the app can't run on Exchange Day.",
           "[ANON] = this Santa asked to stay anonymous. Don't unmask them at the reveal.",
           ""]
    for title, chain, at in loops:
        out += [rule, f"{title}  ({len(chain)} Santas, drawn {when(at)})", rule]
        for i, g in enumerate(chain):
            r = chain[(i + 1) % len(chain)]
            if g not in people or r not in people:
                continue
            anon = "  [ANON]" if people[g].get("anonymous") else ""
            out.append(f"{i + 1:>3}) {people[g]['name']:<{w}}  gifts  {people[r]['name']}"
                       f"    (signs as: {cn.get(g, '?')}){anon}")
        out.append("")
    # Reveal order: by giftee, so on the day you can read out "X, your Santa was ..."
    rows = sorted(((people[r]["name"], people[g]) for _, c, _ in loops for i, g in enumerate(c)
                   for r in [c[(i + 1) % len(c)]] if g in people and r in people), key=lambda x: x[0].lower())
    out += [rule, "FOR THE REVEAL - sorted by who received the gift", rule]
    for recv, g in rows:
        who = "stays anonymous - don't unmask" if g.get("anonymous") else g["name"]
        out.append(f"  {recv:<{w}}  got a gift from  {cn.get(g['id'], '?')}  =  {who}")
    return "\r\n".join(out) + "\r\n"


def mapping_filename():
    return f"secret-santa-full-mapping-{datetime.now().strftime('%Y%m%d-%H%M')}.txt"


# --------------------------------------------------------------------------- emails

def _e(s):
    return html.escape(str(s or ""))


def _first(name):
    return (name or "").split()[0] if name else "Santa"


def render_email(event, giver, receiver, codename, kind="assignment", note=""):
    """Returns (subject, text, html)."""
    gf, rf = _first(giver["name"]), _first(receiver["name"])
    if kind == "reminder":
        subject = f"\U0001F384 Psst, {gf} - a little nudge from the North Pole"
        headline = "Just a friendly nudge from the North Pole!"
        lead = "In case the elves' first letter got buried under snow, here's your mission again:"
    else:
        subject = f"\U0001F385 {gf}, your Secret Santa mission has arrived!"
        headline = f"Ho, ho, ho, {_e(gf)}!"
        lead = "The robot elves have drawn the names, and your top-secret mission is to bring joy to:"
    hints = receiver.get("hints", "").strip()
    hints_html = (_e(hints).replace("\n", "<br>") if hints else
                  f"No gift no-gos from {_e(rf)} - anything thoughtful will do! \U0001F381")
    if giver.get("anonymous"):
        unmask_html = ("You asked to stay anonymous, so your codename will <b>not</b> be unmasked on the final day "
                       "- your secret stays safe forever \U0001F92B")
        unmask_text = "You asked to stay anonymous, so your codename will NOT be unmasked on the final day."
    else:
        unmask_html = "On the final day we'll unmask the codenames - until then, stay in character!"
        unmask_text = "On the final day we'll unmask the codenames - until then, stay in character!"
    note_html = (f'<tr><td style="padding:0 32px 8px"><div style="background:#fff7e0;border-left:4px solid #e0a526;'
                 f'padding:12px 16px;border-radius:8px;color:#5b4a1d;font-size:14px">'
                 f'<b>Note from the organisers:</b><br>{_e(note).replace(chr(10), "<br>")}</div></td></tr>'
                 if note.strip() else "")
    ev_note = (f'<tr><td style="padding:4px 0;color:#7a6b5d">Also</td><td style="padding:4px 0">{_e(event.get("note"))}</td></tr>'
               if event.get("note", "").strip() else "")

    body = f"""<!doctype html><html><body style="margin:0;background:#0f2a22;font-family:Segoe UI,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0f2a22;padding:28px 12px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#fffaf2;border-radius:18px;overflow:hidden">
 <tr><td style="background:#b3202a;background-image:linear-gradient(135deg,#c8283a,#8e1420);padding:28px 32px;color:#fff;text-align:center">
   <div style="font-size:44px;line-height:1">\U0001F385\U0001F381\U0001F384</div>
   <div style="font-size:13px;letter-spacing:3px;text-transform:uppercase;opacity:.85;margin-top:10px">Top secret &middot; for your eyes only</div>
   <div style="font-size:22px;font-weight:700;margin-top:4px">{_e(event.get("title"))}</div>
 </td></tr>
 <tr><td style="padding:28px 32px 8px;color:#2b2420;font-size:16px;line-height:1.55">
   <div style="font-size:22px;font-weight:700;color:#8e1420;margin-bottom:8px">{headline}</div>
   {lead}
 </td></tr>
 <tr><td style="padding:8px 32px 8px">
   <div style="border:2px dashed #c8283a;border-radius:14px;padding:22px;text-align:center;background:#fff">
     <div style="font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#7a6b5d">Your giftee</div>
     <div style="font-size:30px;font-weight:800;color:#155d43;margin-top:6px">{_e(receiver["name"])}</div>
   </div>
 </td></tr>
 <tr><td style="padding:12px 32px 8px;color:#2b2420;font-size:15px;line-height:1.55">
   <div style="font-weight:700;color:#155d43;margin-bottom:4px">\U0001F6AB Gifts {_e(rf)} would rather not get</div>
   <div style="background:#eef6f1;border-radius:10px;padding:12px 16px">{hints_html}</div>
 </td></tr>
 <tr><td style="padding:12px 32px 8px;color:#2b2420;font-size:15px;line-height:1.55">
   <div style="font-weight:700;color:#155d43;margin-bottom:4px">\U0001F575️ Your Santa codename</div>
   <div style="background:#1b3a30;color:#ffe9a8;border-radius:10px;padding:14px 16px;font-size:18px;font-weight:700;text-align:center">{_e(codename)}</div>
   <div style="font-size:13px;color:#7a6b5d;margin-top:8px">Sign your gift tag as
     <b>&ldquo;To {_e(receiver["name"])} &middot; From {_e(codename)}&rdquo;</b>.
     {unmask_html}</div>
 </td></tr>
 {note_html}
 <tr><td style="padding:12px 32px 4px">
   <table role="presentation" width="100%" style="font-size:14px;color:#2b2420;border-top:1px solid #eadfcd;padding-top:10px">
     <tr><td style="padding:4px 0;color:#7a6b5d;width:120px">Exchange</td><td style="padding:4px 0">{_e(event.get("dates"))}</td></tr>
     {ev_note}
   </table>
 </td></tr>
 <tr><td style="padding:16px 32px 28px">
   <div style="background:#f3ece0;border-radius:10px;padding:12px 16px;font-size:13px;color:#5d5045">
   \U0001F92B <b>Not even the organisers know who you got.</b> This letter was sent by a robot elf straight from the draw.
   Please don't reply or forward it - just keep the secret and happy sneaky shopping! \U0001F6CD️</div>
   <div style="text-align:center;font-size:12px;color:#a2968a;margin-top:14px">With love from {_e(event.get("organisers"))} &#10052;</div>
 </td></tr>
</table></td></tr></table></body></html>"""

    plain_head = html.unescape(headline)
    text = (f"{plain_head}\n\n{lead}\n\n    >>> {receiver['name']} <<<\n\n"
            f"Gifts {rf} would rather not get:\n{hints or '(none - anything thoughtful will do!)'}\n\n"
            f"Your Santa codename: {codename}\nSign the gift tag: \"To {receiver['name']} - From {codename}\"\n"
            f"{unmask_text}\n\n"
            + (f"Note from the organisers:\n{note}\n\n" if note.strip() else "")
            + f"Exchange: {event.get('dates')}\n"
            + (f"Also:     {event.get('note')}\n" if event.get("note", "").strip() else "")
            + "\nNot even the organisers know who you got. Please keep the secret!\n")
    return subject, text, body


def build_message(cfg, to_name, to_email, subject, text, body):
    msg = EmailMessage()
    from_email = cfg.get("from_email") or cfg.get("user")
    msg["From"] = formataddr((cfg.get("from_name") or "Secret Santa", from_email))
    msg["To"] = formataddr((to_name, to_email))
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain="santa-workshop.local")
    msg.set_content(text)
    msg.add_alternative(body, subtype="html")
    return msg


def smtp_connect(cfg):
    host, port = cfg.get("host"), int(cfg.get("port") or 587)
    if not host:
        raise ApiError("Set up the mailbox first (Mailbox tab).")
    ctx = ssl.create_default_context()
    if cfg.get("security") == "ssl":
        s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
        s.ehlo()
        if cfg.get("security", "starttls") == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
    if cfg.get("user"):
        if not SECRETS_IN_MEMORY["smtp_password"]:
            s.close()
            raise ApiError("Enter the mailbox password again (it is kept in memory only, never saved).")
        s.login(cfg["user"], SECRETS_IN_MEMORY["smtp_password"])
    return s


# ---- shredding the robot's "Sent" copies so the organiser's mailbox doesn't leak pairings

def _imap_folders(M):
    typ, data = M.list()
    out = []
    for raw in data or []:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        m = re.match(r'\((?P<flags>[^)]*)\)\s+(?:"[^"]*"|NIL)\s+(?P<name>.+)$', line)
        if m:
            out.append((m["flags"].lower(), m["name"].strip()))
    return out


def _quote(folder):
    return folder if folder.startswith('"') else '"' + folder + '"'


def _find_ids(M, msgids):
    nums = []
    for mid in msgids:
        typ, data = M.search(None, f'(HEADER Message-ID "{mid}")')
        if typ == "OK" and data and data[0]:
            nums += data[0].split()
    return nums


def shred_sent_copies(cfg, msgids):
    if not msgids:
        return "nothing to shred"
    host = cfg.get("imap_host")
    if not host:
        return "no IMAP host configured - delete the robot's Sent copies by hand (without reading them!)"
    M = imaplib.IMAP4_SSL(host, 993, ssl_context=ssl.create_default_context())
    try:
        M.login(cfg["user"], SECRETS_IN_MEMORY["smtp_password"])
        folders = _imap_folders(M)
        sent = next((n for f, n in folders if "\\sent" in f), None)
        trash = next((n for f, n in folders if "\\trash" in f), None)
        if not sent:
            for cand in ("Sent", "Sent Items", "Sent Messages", "INBOX.Sent"):
                if any(n.strip('"').lower() == cand.lower() for _, n in folders):
                    sent = cand
                    break
        is_gmail = "gmail" in host.lower() or "googlemail" in host.lower()
        removed = 0
        if sent:
            time.sleep(2)  # give the server a moment to file the copies
            if M.select(_quote(sent))[0] == "OK":
                for num in _find_ids(M, msgids):
                    if is_gmail:
                        M.store(num, "+X-GM-LABELS", "\\Trash")  # Gmail: plain delete just archives
                    else:
                        M.store(num, "+FLAGS", "\\Deleted")
                    removed += 1
                M.expunge()
        if trash:
            time.sleep(2)
            if M.select(_quote(trash))[0] == "OK":
                for num in _find_ids(M, msgids):
                    M.store(num, "+FLAGS", "\\Deleted")
                M.expunge()
        return f"shredded {removed} sent cop{'y' if removed == 1 else 'ies'} from the robot's mailbox"
    finally:
        try:
            M.logout()
        except Exception:
            pass


# ---- background send jobs

def start_job(kind, fn):
    with LOCK:
        if JOB["active"]:
            raise ApiError("The elves are still busy with the previous batch - hang on.")
        JOB.update(active=True, kind=kind, done=0, total=0, message="Warming up the sleigh...", ok=True)

    def runner():
        try:
            msg = fn()
            with LOCK:
                JOB.update(message=msg, ok=True)
        except ApiError as e:
            with LOCK:
                JOB.update(message=str(e), ok=False)
        except Exception as e:  # network / auth problems
            traceback.print_exc()
            with LOCK:
                JOB.update(message=f"{type(e).__name__}: {e}", ok=False)
        finally:
            with LOCK:
                JOB["active"] = False

    threading.Thread(target=runner, daemon=True).start()


def send_batch(target_ids, kind, note=""):
    with LOCK:
        st = load_state()
    vault = read_vault()
    people = {p["id"]: p for p in st["participants"]}
    receiver_of = receiver_map(vault)
    target_ids = [pid for pid in target_ids if pid in receiver_of]
    cfg = st["smtp"]
    JOB["total"] = len(target_ids)
    sent_ids, failed, msgids = 0, 0, []
    s = None
    try:
        for pid in target_ids:
            giver = people[pid]
            receiver = people[receiver_of[pid]]
            subject, text, body = render_email(st["event"], giver, receiver, vault["codenames"][pid], kind, note)
            msg = build_message(cfg, giver["name"], giver["email"], subject, text, body)
            err = None
            for attempt in range(2):
                try:
                    if s is None:
                        s = smtp_connect(cfg)
                    s.send_message(msg)
                    err = None
                    break
                except ApiError:
                    raise
                except Exception as e:
                    err = f"{type(e).__name__}: {e}"
                    try:
                        s and s.close()
                    except Exception:
                        pass
                    s = None
            with LOCK:
                st2 = load_state()
                rec = st2["sends"].setdefault(pid, {})
                if err:
                    failed += 1
                    if kind == "assignment":
                        rec.update(status="failed", error=err)
                    rec["last_error"] = err
                else:
                    sent_ids += 1
                    msgids.append(msg["Message-ID"])
                    stamp = datetime.now().isoformat(timespec="seconds")
                    if kind == "assignment":
                        rec.update(status="sent", at=stamp, error=None)
                    else:
                        rec["reminded_at"] = stamp
                save_state(st2)
                JOB["done"] += 1
                JOB["message"] = f"Delivered {sent_ids} of {len(target_ids)}..."
            time.sleep(0.5)  # be gentle with the mail server
    finally:
        if s is not None:
            try:
                s.quit()
            except Exception:
                pass
    label = "mission letters" if kind == "assignment" else "reminders"
    summary = f"Sent {sent_ids} {label}" + (f", {failed} failed (see the table)" if failed else "") + "."
    if cfg.get("shred") and cfg.get("user") and msgids:
        JOB["message"] = summary + " Shredding sent copies..."
        try:
            summary += " Also " + shred_sent_copies(cfg, msgids) + "."
        except Exception as e:
            summary += f" Couldn't shred sent copies automatically ({type(e).__name__}: {e}) - " \
                       "empty the robot mailbox's Sent folder without opening it."
    save_history(f"After sending {label}")
    if failed:
        raise ApiError(summary)
    return summary


# --------------------------------------------------------------------------- API

def public_state():
    st = load_state()
    # Organisers only learn *whether* someone chose a secret name, never the name itself.
    st["participants"] = [{**{k: v for k, v in p.items() if k != "codename"}, "has_codename": bool(p.get("codename"))}
                          for p in st["participants"]]
    st["smtp"]["password_set"] = bool(SECRETS_IN_MEMORY["smtp_password"])
    st["vault"] = {"exists": os.path.exists(VAULT_FILE), "key": os.path.exists(KEY_FILE)}
    with LOCK:
        st["job"] = dict(JOB)
    st["history"] = list_history()
    return st


def require_no_draw(st):
    if st["draw"]["status"] != "none":
        raise ApiError("Names are already drawn - the roster is locked so nobody can redirect a letter. "
                       "Add newcomers with the 'Late joiners' box instead.")


def is_waiting(p):
    """A late joiner who hasn't been drawn yet."""
    return bool(p.get("late")) and not p.get("batch")


def drawn_ids(st):
    return [p["id"] for p in st["participants"] if not is_waiting(p)]


def require_drawn(st):
    if st["draw"]["status"] == "none":
        raise ApiError("Late joiners are for after the main draw. Before the draw, just add people normally.")


def add_late(st, people):
    """Adds only people whose email isn't on the list yet. Never touches anyone already there."""
    have = {p["email"] for p in st["participants"]}
    added, skipped = [], 0
    for p in people:
        if p["email"] in have:
            skipped += 1
            continue
        have.add(p["email"])
        p.update(late=True, batch=None)
        added.append(p)
    st["participants"] += added
    return added, skipped


def api(path, body):
    with LOCK:
        st = load_state()

        if path == "/api/event":
            for k in st["event"]:
                if k in body:
                    st["event"][k] = str(body[k]).strip()
            save_state(st)
            return {"ok": True}

        if path == "/api/participants/import":
            require_no_draw(st)
            people, warnings = parse_roster(body.get("text", ""))
            if body.get("mode") == "append":
                by_email = {p["email"]: p for p in st["participants"]}
                for p in people:
                    old = by_email.get(p["email"])
                    if old:  # merge: only overwrite fields the new paste actually has
                        if p["name"] == name_from_email(p["email"]):
                            p["name"] = old["name"]
                        for k in ("hints", "avoid"):
                            p[k] = p[k] or old.get(k, "")
                        p["id"] = old["id"]
                    by_email[p["email"]] = p
                people = list(by_email.values())
            st["participants"] = people
            save_state(st)
            save_history(f"Imported {len(people)} Santas")
            return {"ok": True, "count": len(people), "warnings": warnings}

        if path == "/api/participants":
            require_no_draw(st)
            incoming = body.get("participants", [])
            old = {p["id"]: p for p in st["participants"]}
            for p in incoming:  # the page never sees secret names, so carry them over
                if "codename" not in p and p.get("id") in old:
                    p["codename"] = old[p["id"]].get("codename", "")
            st["participants"] = clean_participants(incoming)
            save_state(st)
            return {"ok": True}

        if path == "/api/smtp":
            for k in ("preset", "host", "security", "user", "from_name", "from_email", "imap_host"):
                if k in body:
                    st["smtp"][k] = str(body[k]).strip()
            if "port" in body:
                st["smtp"]["port"] = int(body["port"] or 587)
            if "shred" in body:
                st["smtp"]["shred"] = bool(body["shred"])
            if body.get("password"):
                SECRETS_IN_MEMORY["smtp_password"] = body["password"]
            save_state(st)
            return {"ok": True}

        if path == "/api/smtp/test":
            to = str(body.get("to", "")).strip()
            if not EMAIL_RE.match(to):
                raise ApiError("Enter a valid address to send the test to.")
            cfg = st["smtp"]
            dummy_g = {"name": "Test Santa", "email": to}
            dummy_r = {"name": "Jingle Bells", "hints": "This is a TEST letter - no real names inside.\nMugs, scented candles"}
            subject, text, body_html = render_email(st["event"], dummy_g, dummy_r, "Agent Twinkly Penguin")
            msg = build_message(cfg, "Test Santa", to, "[TEST] " + subject, text, body_html)
            s = smtp_connect(cfg)
            try:
                s.send_message(msg)
            finally:
                s.quit()
            return {"ok": True}

        if path == "/api/draw":
            require_no_draw(st)
            people = st["participants"]
            vault = do_draw(people)
            fp = write_vault(vault)
            st["draw"] = {"status": "drawn", "drawn_at": vault["drawn_at"], "fingerprint": fp, "key_burned": False}
            st["sends"] = {p["id"]: {"status": "pending"} for p in people}
            save_state(st)
            save_history("Main draw done")
            return {"ok": True, "fingerprint": fp, "list": full_mapping_text(st, vault), "filename": mapping_filename()}

        if path == "/api/mapping":
            if st["draw"]["status"] == "none":
                raise ApiError("Draw the names first.")
            return {"ok": True, "list": full_mapping_text(st, read_vault()), "filename": mapping_filename()}

        # ---- late joiners: they get their own separate loop, so nobody already drawn is touched
        if path == "/api/late/import":
            require_drawn(st)
            people, warnings = parse_roster(body.get("text", ""))
            added, skipped = add_late(st, people)
            save_state(st)
            if added:
                save_history(f"Added {len(added)} late joiner{'s' if len(added) > 1 else ''}")
            return {"ok": True, "added": len(added), "skipped": skipped, "warnings": warnings}

        if path == "/api/late/add":
            require_drawn(st)
            p = clean_participants([{k: body.get(k) for k in ("name", "email", "hints", "anonymous")}])[0]
            added, _ = add_late(st, [p])
            if not added:
                raise ApiError(f"{p['email']} is already on the list.")
            save_state(st)
            save_history(f"Added late joiner {p['name']}")
            return {"ok": True}

        if path == "/api/late/remove":
            pid = body.get("id")
            if not any(p["id"] == pid and is_waiting(p) for p in st["participants"]):
                raise ApiError("Only late joiners who haven't been drawn yet can be removed.")
            st["participants"] = [p for p in st["participants"] if p["id"] != pid]
            save_state(st)
            return {"ok": True}

        if path == "/api/late/draw":
            require_drawn(st)
            if JOB["active"]:
                raise ApiError("Wait for the current batch to finish.")
            waiting = [p for p in st["participants"] if is_waiting(p)]
            if len(waiting) < 2:
                raise ApiError("Only 1 late joiner waiting - they need at least one more person to swap with.")
            vault = read_vault()
            rng = secrets.SystemRandom()
            chain = make_circle(waiting, rng, min_size=2)
            used = {c.lower() for c in vault["codenames"].values()}
            codenames = assign_codenames(waiting, used, rng)
            batch_no = len(vault.get("late", [])) + 1
            stamp = datetime.now().isoformat(timespec="seconds")
            vault.setdefault("late", []).append({"chain": chain, "drawn_at": stamp})
            vault["codenames"].update(codenames)
            fp = write_vault(vault)
            for p in waiting:
                p["batch"] = batch_no
                st["sends"][p["id"]] = {"status": "pending"}
            st["draw"]["fingerprint"] = fp
            st["draw"].setdefault("late_batches", []).append({"batch": batch_no, "at": stamp, "count": len(waiting)})
            save_state(st)
            save_history(f"Late joiners drawn (loop {batch_no})")
            return {"ok": True, "fingerprint": fp, "batch": batch_no, "ids": chain,
                    "list": full_mapping_text(st, vault), "filename": mapping_filename()}

        if path == "/api/send":
            if st["draw"]["status"] == "none":
                raise ApiError("Draw the names first.")
            which = body.get("which", "pending")
            drawn = drawn_ids(st)
            if isinstance(body.get("ids"), list):
                ids = [i for i in body["ids"] if i in drawn]
            elif which == "all":
                ids = drawn
            elif which == "pending":
                ids = [i for i in drawn if st["sends"].get(i, {}).get("status") != "sent"]
            else:
                ids = [which] if which in drawn else []
            if not ids:
                raise ApiError("Everyone already has their letter.")
            read_vault()  # fail fast if key burned
            start_job("assignment", lambda: send_batch(ids, "assignment"))
            return {"ok": True}

        if path == "/api/remind":
            if st["draw"]["status"] == "none":
                raise ApiError("Draw the names first.")
            read_vault()
            ids = drawn_ids(st)
            note = str(body.get("note", ""))
            start_job("reminder", lambda: send_batch(ids, "reminder", note))
            return {"ok": True}

        if path == "/api/reveal":
            if body.get("confirm") != "REVEAL":
                raise ApiError("Type REVEAL to unmask the Santas.")
            vault = read_vault()
            people = {p["id"]: p for p in st["participants"]}
            out = []
            # Main loop and late-joiner loops all go into one list, so late joiners are part of the show.
            for g, r in receiver_map(vault).items():
                if g not in people or r not in people:
                    continue
                anon = bool(people[g].get("anonymous"))
                out.append({"giver": None if anon else people[g]["name"], "receiver": people[r]["name"],
                            "codename": vault["codenames"][g], "anonymous": anon})
            secrets.SystemRandom().shuffle(out)  # random reveal order, so the gift loop isn't visible
            return {"ok": True, "chain": out}

        if path == "/api/burn":
            if os.path.exists(KEY_FILE):
                os.remove(KEY_FILE)
            st["draw"]["key_burned"] = True
            save_state(st)
            strip_history_keys()
            return {"ok": True}

        # ---- backups: download a passphrase-locked file, or go back to any automatic restore point
        if path == "/api/backup/export":
            return {"ok": True, "file": export_backup(str(body.get("passphrase", "")))}

        if path in ("/api/backup/import", "/api/history/restore"):
            if body.get("confirm") != "RESTORE":
                raise ApiError("Type RESTORE to confirm.")
            if JOB["active"]:
                raise ApiError("Wait for the current batch to finish.")
            if path == "/api/backup/import":
                snap = open_backup(str(body.get("text", "")), str(body.get("passphrase", "")))
            else:
                snap = load_history(body.get("id"))["snapshot"]
            save_history("Just before a restore (undo point)")
            apply_snapshot(snap)
            save_history("Restored" + (" from a backup file" if path == "/api/backup/import" else " a restore point"))
            return {"ok": True, "summary": summary_of(load_state())}

        if path == "/api/reset":
            if body.get("confirm") != "START OVER":
                raise ApiError("Type START OVER to confirm.")
            if JOB["active"]:
                raise ApiError("Wait for the current batch to finish.")
            save_history("Just before 'Start over' (undo point)")
            for f in (VAULT_FILE, KEY_FILE):
                if os.path.exists(f):
                    os.remove(f)
            st["draw"] = default_state()["draw"]
            st["sends"] = {}
            for p in st["participants"]:  # after a full redraw, late joiners are just regular Santas
                p.pop("late", None)
                p.pop("batch", None)
            save_state(st)
            return {"ok": True}

    raise ApiError("Unknown endpoint")


def preview_html():
    st = load_state()
    g = {"name": "Your Name", "email": "you@example.com"}
    r = {"name": "Jingle Bells", "hints": "Mugs, scented candles, anything with chocolate"}
    return render_email(st["event"], g, r, "Agent Frosty Reindeer")[2]


class Handler(BaseHTTPRequestHandler):
    server_version = "SantaWorkshop/1.0"

    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")  # blocks DNS-rebinding tricks

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden", "text/plain")
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(BASE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path in ("/reveal", "/reveal.html"):
            with open(os.path.join(BASE, "reveal.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._send(200, json.dumps(public_state()))
        if path == "/api/preview":
            return self._send(200, preview_html(), "text/html; charset=utf-8")
        self._send(404, '{"error":"not found"}')

    def do_POST(self):
        # The custom header forces a CORS preflight, so random websites can't poke this API.
        if not self._host_ok() or self.headers.get("X-Santa") != "1":
            return self._send(403, '{"error":"forbidden"}')
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            self._send(200, json.dumps(api(self.path.split("?")[0], body)))
        except ApiError as e:
            self._send(400, json.dumps({"error": str(e)}))
        except smtplib.SMTPAuthenticationError as e:
            self._send(400, json.dumps({"error": "The mail server rejected the login. For Gmail use an App Password "
                                                 f"(not your normal password). Details: {e}"}))
        except Exception as e:
            traceback.print_exc()
            self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.makedirs(DATA, exist_ok=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}/"
    print(f"\n  \U0001F385  Santa's Sleigh Desk is open at {url}\n      (Ctrl+C to close the desk)\n")
    if not os.environ.get("SANTA_NO_BROWSER"):
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Sleigh Desk closed. Merry Christmas!")


if __name__ == "__main__":
    main()
