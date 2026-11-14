#!/usr/bin/env python3
"""SWS405 Group 3 analysis helper. Every report fits an 80x40 terminal.

  hash-add <file> <ID> <note>         hash an exhibit into logs/hash_log.csv
  verify                              re-hash all exhibits + compare device vs host hashes
  ab2tar <file.ab> <outdir>           unpack an adb backup (no Java needed)
  sqlite-check <db>                   one-line "SQLite, N tables" check
  storage <FS_ID> <SIG_DEC_ID>        where each app keeps its data + timestamp check
  score <ADB_ID> <FS_ID> <WA_DEC_ID> <SIG_DEC_ID>
                                      recovered items vs activity script, per acquisition
  disappear <FS_BEFORE> <FS_AFTER> <SIG_BEFORE> <SIG_AFTER>
                                      where deleted / disappearing messages survive

Databases are only ever opened through temporary copies, so nothing in work/
or evidence/ is changed by an analysis run.
"""
import csv
import getpass
import hashlib
import os
import re
import shutil
import socket
import sqlite3
import sys
import tarfile
import tempfile
import textwrap
import zlib
from datetime import datetime, timedelta, timezone

BT = timezone(timedelta(hours=6))          # Asia/Thimphu, no daylight saving
HASH_LOG = os.path.join("logs", "hash_log.csv")
ACT_LOG = os.path.join("logs", "activity_log.csv")
FIELDS = ["evidence_id", "path", "size_bytes", "sha256", "time_utc+06:00", "host", "user", "event", "note"]
PKG = {"W": "com.whatsapp", "T": "org.telegram.messenger", "S": "org.thoughtcrime.securesms"}
APP = {"W": "WhatsApp", "T": "Telegram", "S": "Signal"}
TOKEN_RE = re.compile(rb"G3-(CONTACT|[WTS]\d{1,2}(?= ))")
TOKEN16_RE = re.compile("G3-(CONTACT|[WTS]\\d{1,2}(?= ))")


# ----------------------------------------------------------------- utilities
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def now_bt():
    return datetime.now(BT).strftime("%Y-%m-%d %H:%M:%S")


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def append_log(row):
    os.makedirs("logs", exist_ok=True)
    new = not os.path.exists(HASH_LOG)
    with open(HASH_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


class DbCopy:
    """Open a SQLite database through a temporary copy (with its -wal/-shm)."""

    def __init__(self, path):
        self.path = path
        self.tmp = None
        self.con = None

    def __enter__(self):
        if not self.path or not os.path.isfile(self.path):
            return None
        self.tmp = tempfile.mkdtemp(prefix="g3db_")
        base = os.path.join(self.tmp, "db")
        for suf in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suf):
                shutil.copy2(self.path + suf, base + suf)
        try:
            self.con = sqlite3.connect(base)
            self.con.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.DatabaseError:
            self.con = None
        return self.con

    def __exit__(self, *a):
        if self.con:
            self.con.close()
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


def tables(con):
    return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def has_table(con, t):
    return t in tables(con)


def q1(con, sql, args=()):
    try:
        r = con.execute(sql, args).fetchone()
        return r[0] if r else None
    except sqlite3.DatabaseError:
        return None


def is_sqlite(path):
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def rows_with(con, token):
    """Tables whose live rows contain token (any column, text or blob)."""
    needle = token.encode()
    hits = []
    for t in tables(con):
        try:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
        except sqlite3.DatabaseError:
            continue
        for c in cols:
            n = q1(con, f'SELECT count(*) FROM "{t}" WHERE instr(CAST("{c}" AS BLOB), ?) > 0', (needle,))
            if n:
                hits.append(t)
                break
    return hits


# ------------------------------------------------------- raw token scanning
def scan_file(path):
    """Set of token ids (W1, T10, CONTACT ...) present in the raw bytes of a file."""
    found = set()
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return found
    if b"G3-" in data:
        found.update(m.group(1).decode() for m in TOKEN_RE.finditer(data))
    if b"G\x003\x00-\x00" in data:
        for off in (0, 1):
            txt = data[off:].decode("utf-16-le", errors="ignore")
            found.update(m.group(1) for m in TOKEN16_RE.finditer(txt))
    return found


def classify(rel):
    """Return (owner, kind) for a path inside an acquisition folder."""
    r = rel.replace("\\", "/")
    for p, pkg in PKG.items():
        for pre in (f"data/data/{pkg}/", f"data/media/0/Android/media/{pkg}/",
                    f"data/media/0/Android/data/{pkg}/", f"apps/{pkg}/"):
            if r.startswith(pre):
                return p, "app"
    if "notification_history" in r:
        return None, "notif"
    return None, "other"


_SCAN = {}


def scan_tree(root):
    """{token: [(owner, kind, relpath), ...]} for every file under root (cached per run)."""
    if root in _SCAN:
        return _SCAN[root]
    idx = _SCAN[root] = {}
    if not root or not os.path.isdir(root):
        return idx
    for d, _, files in os.walk(root):
        for name in files:
            full = os.path.join(d, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            toks = scan_file(full)
            if toks:
                owner, kind = classify(rel)
                for t in toks:
                    idx.setdefault(t, []).append((owner, kind, rel))
    return idx


def scan_single(path, owner):
    return {t: [(owner, "app", os.path.basename(path))] for t in scan_file(path)} if path and os.path.isfile(path) else {}


# ---------------------------------------------------------------- locations
def wa_db(root):
    return os.path.join(root, "data/data/com.whatsapp/databases/msgstore.db")


def tg_db(root):
    p = os.path.join(root, "data/data/org.telegram.messenger/files/cache4.db")
    if os.path.isfile(p):
        return p
    for d, _, files in os.walk(os.path.join(root, "data/data/org.telegram.messenger/files")):
        if "cache4.db" in files:
            return os.path.join(d, "cache4.db")
    return p


def sig_dec(sid):
    return os.path.join("work", sid, "database.sqlite") if sid and sid != "-" else None


def find_named(root, name):
    for d, _, files in os.walk(root or "."):
        if name in files:
            return os.path.join(d, name)
    return None


# ------------------------------------------------------------------ commands
def cmd_hash_add(path, eid, note):
    row = {"evidence_id": eid, "path": path.replace("\\", "/"), "size_bytes": os.path.getsize(path),
           "sha256": sha256(path), "time_utc+06:00": now_bt(), "host": socket.gethostname(),
           "user": getpass.getuser(), "event": "acquired", "note": note}
    append_log(row)
    print(f"{eid:<4} {os.path.basename(path):<30} {human(row['size_bytes']):>9}  sha256 {row['sha256'][:16]}...")


def cmd_verify():
    if not os.path.exists(HASH_LOG):
        sys.exit("no logs/hash_log.csv yet")
    with open(HASH_LOG, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["event"] == "acquired"]
    print(f"Integrity check on {socket.gethostname()} by {getpass.getuser()} at {now_bt()} (UTC+06:00)")
    print("\nExhibits: hash now vs hash at acquisition")
    ok = 0
    for r in rows:
        if os.path.exists(r["path"]):
            h = sha256(r["path"])
            st = "MATCH" if h == r["sha256"] else "MISMATCH"
        else:
            h, st = "", "MISSING"
        ok += st == "MATCH"
        print(f"  {st:<8} {r['evidence_id']:<4} {os.path.basename(r['path']):<30} {r['sha256'][:16]}...")
        append_log({**r, "sha256": h or r["sha256"], "time_utc+06:00": now_bt(), "host": socket.gethostname(),
                    "user": getpass.getuser(), "event": f"verify:{st}", "note": ""})
    print("\nDevice vs host: hash on the emulator vs hash of the pulled copy")
    dok = dn = 0
    for hf in sorted(f for f in os.listdir("evidence") if f.endswith("_device_hashes.txt")):
        eid = hf.split("_")[0]
        with open(os.path.join("evidence", hf), encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) != 3:
                    continue
                dh, dpath, host = parts
                dn += 1
                hh = sha256(host) if os.path.isfile(host) else ""
                st = "MATCH" if hh == dh else ("MISSING" if not hh else "MISMATCH")
                dok += st == "MATCH"
                print(f"  {st:<8} {eid:<4} {dpath[-58:]}")
    print(f"\n{ok}/{len(rows)} exhibits unchanged since acquisition; {dok}/{dn} device hashes match host copies.")
    sys.exit(0 if ok == len(rows) and dok == dn else 1)


def cmd_ab2tar(ab, out):
    with open(ab, "rb") as f:
        head = [f.readline().strip() for _ in range(4)]
        if head[0] != b"ANDROID BACKUP":
            sys.exit("  not an Android backup file")
        if head[3] != b"none":
            sys.exit("  backup is password-encrypted; redo it with an empty password")
        tar_path = os.path.splitext(ab)[0] + ".tar"
        dec = zlib.decompressobj() if head[2] == b"1" else None
        with open(os.path.join("work", os.path.basename(tar_path)), "wb") as t:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                t.write(dec.decompress(chunk) if dec else chunk)
    tpath = os.path.join("work", os.path.basename(tar_path))
    os.makedirs(out, exist_ok=True)
    counts = {"W": 0, "T": 0, "S": 0, None: 0}
    try:
        with tarfile.open(tpath) as tf:
            for m in tf:
                owner, _ = classify(m.name)
                if m.isfile():
                    counts[owner] += 1
                try:
                    tf.extract(m, out, filter="data") if hasattr(tarfile, "data_filter") else tf.extract(m, out)
                except Exception:
                    pass
    except tarfile.ReadError:
        pass
    os.remove(tpath)
    print(f"  adb backup contents: WhatsApp {counts['W']} files, Telegram {counts['T']}, "
          f"Signal {counts['S']}, other {counts[None]}")


def cmd_sqlite_check(db):
    with DbCopy(db) as con:
        print(f"SQLite, {len(tables(con))} tables" if con else "not a readable SQLite database")


def cmd_storage(fs, sdec):
    root = os.path.join("work", fs)
    print(f"Where each app keeps its data (acquisition {fs}, extracted copy)")
    print(f"{'app':<9}{'item':<35}{'size':>10}  format")

    def fmt(path):
        if not os.path.exists(path):
            return "-", "not found"
        if os.path.isdir(path):
            n = s = 0
            for d, _, files in os.walk(path):
                for x in files:
                    n += 1
                    s += os.path.getsize(os.path.join(d, x))
            return human(s), f"folder, {n} files"
        size = human(os.path.getsize(path))
        with open(path, "rb") as f:
            head = f.read(16)
        if head == b"SQLite format 3\x00":
            with DbCopy(path) as con:
                return size, f"SQLite 3, {len(tables(con)) if con else '?'} tables"
        if head.startswith(b"<?xml"):
            return size, "XML (plain text)"
        return size, "encrypted, not SQLite" if path.endswith(".db") else "binary"

    W, T, S = (f"data/data/{PKG[k]}" for k in "WTS")
    items = [
        ("WhatsApp", f"{W}/databases/msgstore.db", "databases/msgstore.db"),
        ("WhatsApp", f"{W}/databases/wa.db", "databases/wa.db"),
        ("WhatsApp", f"{W}/files/key", "files/key (backup key)"),
        ("WhatsApp", "data/media/0/Android/media/com.whatsapp/WhatsApp/Media", "shared storage: WhatsApp/Media"),
        ("WhatsApp", "data/media/0/Android/media/com.whatsapp/WhatsApp/Databases", "shared storage: WhatsApp/Databases"),
        ("Telegram", os.path.relpath(tg_db(root), root), "files/cache4.db"),
        ("Telegram", f"{T}/shared_prefs", "shared_prefs/"),
        ("Telegram", "data/media/0/Android/data/org.telegram.messenger/files/Telegram", "shared storage: Telegram/"),
        ("Signal", f"{S}/databases/signal.db", "databases/signal.db"),
        ("Signal", f"{S}/shared_prefs/org.thoughtcrime.securesms_preferences.xml", "shared_prefs/..._preferences.xml"),
        ("Signal", f"{S}/app_parts", "app_parts/ (attachments)"),
        ("Android", "data/system_ce/0/notification_history", "notification_history/"),
        ("Android", "data/data/com.android.providers.contacts/databases/contacts2.db", "contacts2.db (phone contacts)"),
    ]
    for app, rel, label in items:
        size, f = fmt(os.path.join(root, rel))
        print(f"{app:<9}{label:<35}{size:>10}  {f}")

    # ---- timestamps
    logged = {}
    if os.path.exists(ACT_LOG):
        with open(ACT_LOG, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                logged[r["id"]] = r["host_time_utc+06:00"]
    print("\nTimestamps: first message of each app vs the time we logged it")
    print(f"{'id':<4}{'raw value':<15}{'unit':<5}{'UTC':<10}{'UTC+06:00':<11}{'logged':<10}{'diff':>9}")
    probes = [
        ("W1", wa_db(root), "ms", ["SELECT timestamp FROM message WHERE text_data LIKE 'G3-W1 %'",
                                   "SELECT timestamp FROM messages WHERE data LIKE 'G3-W1 %'"]),
        ("T1", tg_db(root), "s", ["SELECT date FROM messages_v2 WHERE instr(data, CAST('G3-T1 ' AS BLOB)) > 0"]),
        ("S1", sig_dec(sdec), "ms", ["SELECT date_sent FROM message WHERE body LIKE 'G3-S1 %'",
                                     "SELECT date_sent FROM sms WHERE body LIKE 'G3-S1 %'"]),
    ]
    day = None
    for tid, db, unit, sqls in probes:
        raw = None
        with DbCopy(db) as con:
            if con:
                for s in sqls:
                    raw = q1(con, s)
                    if raw:
                        break
        if not raw:
            print(f"{tid:<4}not found")
            continue
        dt = datetime.fromtimestamp(raw / (1000 if unit == "ms" else 1), timezone.utc)
        loc = dt.astimezone(BT)
        day = loc.strftime("%Y-%m-%d")
        lg = logged.get(tid, "")
        diff = ""
        if lg:
            lgdt = datetime.strptime(lg, "%Y-%m-%d %H:%M:%S").replace(tzinfo=BT)
            diff = f"{(loc - lgdt).total_seconds():+.0f} s"
        print(f"{tid:<4}{raw:<15}{unit:<5}{dt:%H:%M:%S}  {loc:%H:%M:%S}   {lg[11:] or '-':<10}{diff:>9}")
    if day:
        print(f"date {day}. WhatsApp, Signal: ms since 1970 UTC; Telegram: s since 1970 UTC")
        print("diff = stored time minus the time we logged it (we logged just after sending)")


def calls(kind, db):
    with DbCopy(db) as con:
        if not con:
            return None
        if kind == "W":
            return q1(con, "SELECT count(*) FROM call_log") if has_table(con, "call_log") else 0
        if kind == "T":   # messageActionPhoneCall#80e11a7f, little-endian in the TL blob
            return q1(con, "SELECT count(*) FROM messages_v2 WHERE instr(data, X'7f1ae180') > 0") \
                if has_table(con, "messages_v2") else 0
        if kind == "S":
            if has_table(con, "call"):
                return q1(con, "SELECT count(*) FROM call")
            return q1(con, "SELECT count(*) FROM message WHERE (type & 31) IN (1,2,3,10,11)") or 0


def cmd_score(a, b, wa, sig):
    roots = {"A": os.path.join("work", a), "B": os.path.join("work", b)}
    idx = {"A": scan_tree(roots["A"]), "B": scan_tree(roots["B"])}
    cdb = {"W": os.path.join("work", wa, "msgstore.db"), "S": sig_dec(sig)}
    idx_c = {k: scan_single(v, k) for k, v in cdb.items()}

    def cell(col, p, tok):
        hits = idx[col].get(tok, []) if col in idx else idx_c.get(p, {}).get(tok, [])
        if any(o == p and k == "app" for o, k, _ in hits):
            return "Y"
        return "n" if hits else "N"

    def call_cell(col, p):
        if col == "C":
            db = cdb.get(p)
        elif col == "A":
            name = {"W": "msgstore.db", "T": "cache4.db", "S": "signal.db"}[p]
            db = find_named(os.path.join(roots["A"], "apps", PKG[p]), name) if os.path.isdir(roots["A"]) else None
        else:
            db = {"W": wa_db, "T": tg_db}.get(p, lambda r: None)(roots["B"])
        n = calls(p, db) if db else None
        return (str(n) if n else "N"), bool(n)

    print(f"Recovered vs activity script  A={a} adb backup  B={b} file system  C=app backup")
    print("Y = in the app's data   n = only outside it (e.g. notification history)   N = no")
    print(f"{'id':<9}{'item':<30}{'A':>7}{'B':>7}{'C':>7}")
    tot = {"A": 0, "B": 0, "C": 0}
    cmax = 0
    for p in "WTS":
        cdir = {"W": wa, "T": None, "S": sig}[p]
        cols = ["A", "B"] + (["C"] if cdir and cdir != "-" else [])
        cmax += 10 if "C" in cols else 0
        print(f"-- {APP[p]}" + ("   (C = " + cdir + ")" if "C" in cols else "   (C: no local backup)"))
        rows = []
        texts = []
        for c in ("A", "B", "C"):
            if c in cols:
                k = sum(cell(c, p, f"{p}{i}") == "Y" for i in range(1, 5))
                texts.append(f"{k}/4")
                tot[c] += k
            else:
                texts.append("-")
        rows.append((f"{p}1-{p}4", "text messages", texts))
        for i, label in ((5, "image sent (caption)"), (6, "image received (caption)"),
                         (7, "voice call (call records)"), (8, "contact G3-CONTACT"),
                         (9, "deleted for everyone"), (10, "disappearing message")):
            vals = []
            for c in ("A", "B", "C"):
                if c not in cols:
                    vals.append("-")
                    continue
                if i == 7:
                    v, good = call_cell(c, p)
                else:
                    v = cell(c, p, "CONTACT" if i == 8 else f"{p}{i}")
                    good = v == "Y"
                tot[c] += good
                vals.append(v)
            rows.append((f"{p}{i}", label, vals))
        for rid, label, vals in rows:
            print(f"{rid:<9}{label:<30}{vals[0]:>7}{vals[1]:>7}{vals[2]:>7}")
    print(f"{'total':<39}{tot['A']:>4}/30{tot['B']:>4}/30{tot['C']:>4}/{cmax}")


def locations(token, owner, fs_root, sig_db):
    """Short labels for where a token survives."""
    labels = []
    idx = scan_tree(fs_root)
    for o, kind, rel in idx.get(token, []):
        if kind == "notif":
            labels.append("notif-history")
        elif kind == "app" and o == owner:
            if rel.endswith("-wal"):
                labels.append("wal")
            elif is_sqlite(os.path.join(fs_root, rel)):
                with DbCopy(os.path.join(fs_root, rel)) as con:
                    t = rows_with(con, token + " ") if con else []
                labels.append("row:" + "+".join(t) if t else "free-page")
            elif rel.endswith(".db"):
                labels.append("enc-db")
            else:
                labels.append(os.path.basename(rel)[:18])
        elif kind == "app":
            labels.append(f"other-app:{os.path.basename(rel)[:12]}")
        else:
            labels.append(os.path.basename(rel)[:18])
    if sig_db:
        with DbCopy(sig_db) as con:
            t = rows_with(con, token + " ") if con else []
        labels.append("backup-row:" + "+".join(t) if t else "backup:none")
    seen = []
    for x in labels:
        if x not in seen:
            seen.append(x)
    return ", ".join(seen) or "none"


def cmd_disappear(before, after, sb, sa):
    rb, ra = os.path.join("work", before), os.path.join("work", after)
    print(f"Deleted and disappearing messages: where each one survives")
    print(f"before = {before} (+{sb} Signal backup)   after = {after} (+{sa} Signal backup)")
    print("row:<table> = live row  free-page = bytes left in db file  wal = write-ahead log")
    for tok in ("W9", "W10", "T9", "T10", "S9", "S10"):
        p = tok[0]
        b = locations(tok, p, rb, sig_dec(sb) if p == "S" else None)
        a = locations(tok, p, ra, sig_dec(sa) if p == "S" else None)
        kind = "deleted" if tok.endswith("9") else "disappearing"
        print(f"\n{tok:<4}{APP[p]} {kind}")
        for label, text in (("before", b), ("after ", a)):
            print(textwrap.fill(text, 80, initial_indent=f"   {label}: ", subsequent_indent=" " * 11))


def main():
    a = sys.argv[1:]
    cmds = {"hash-add": (cmd_hash_add, 3), "verify": (cmd_verify, 0), "ab2tar": (cmd_ab2tar, 2),
            "sqlite-check": (cmd_sqlite_check, 1), "storage": (cmd_storage, 2), "score": (cmd_score, 4),
            "disappear": (cmd_disappear, 4)}
    if not a or a[0] not in cmds or len(a) - 1 != cmds[a[0]][1]:
        sys.exit(__doc__)
    cmds[a[0]][0](*a[1:])


if __name__ == "__main__":
    main()
