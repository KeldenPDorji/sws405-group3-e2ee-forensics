#!/usr/bin/env python3
"""SWS405 Group 3 analysis helper (Signal). Every report fits an 80x40 terminal.

  hash-add <file> <ID> <note>          hash an exhibit into logs/hash_log.csv
  verify                               re-hash all exhibits + compare device vs host hashes
  ab2tar <file.ab> <outdir>            unpack an adb backup (no Java needed)
  sqlite-check <db>                    one-line "SQLite, N tables" check
  storage <FS_ID> <BACKUP_ID>          where Signal keeps its data + timestamp check
  score <ADB_ID> <FS_ID> <BACKUP_ID>   recovered items vs activity script, per acquisition
  disappear <FS_BEFORE> <FS_AFTER> <BACKUP_BEFORE> <BACKUP_AFTER>
                                       where deleted / disappearing / edited messages survive

Databases are only opened through temporary copies, so nothing in work/ or
evidence/ is changed by an analysis run.
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
PKG = "org.thoughtcrime.securesms"
TOKEN_RE = re.compile(rb"G3-(CONTACT|S\d{1,2}(?= ))")
TOKEN16_RE = re.compile("G3-(CONTACT|S\\d{1,2}(?= ))")


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
        self.path, self.tmp, self.con = path, None, None

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


def rows_with(con, needle_text):
    """Tables whose live rows contain the text (any column, text or blob)."""
    needle = needle_text.encode()
    hits = []
    for t in tables(con):
        try:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
        except sqlite3.DatabaseError:
            continue
        for c in cols:
            if q1(con, f'SELECT count(*) FROM "{t}" WHERE instr(CAST("{c}" AS BLOB), ?) > 0', (needle,)):
                hits.append(t)
                break
    return hits


# ------------------------------------------- Android notification history
def pb_fields(buf):
    """Minimal protobuf walker: yields (field, wiretype, value). Raises on bad data."""
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            v, i = int.from_bytes(buf[i:i + 8], "little"), i + 8
        elif wt == 2:
            ln, i = _varint(buf, i)
            v, i = buf[i:i + ln], i + ln
        elif wt == 5:
            v, i = int.from_bytes(buf[i:i + 4], "little"), i + 4
        else:
            raise ValueError("bad wiretype")
        if i > n or f == 0:
            raise ValueError("truncated")
        yield f, wt, v


def _varint(buf, i):
    r = shift = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise ValueError("bad varint")
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return r, i


def notif_times(fs_root):
    """{token: posted_time_ms} from Android notification_history protobuf files."""
    out = {}
    base = os.path.join(fs_root or "", "data/system_ce/0/notification_history")
    for d, _, files in os.walk(base):
        for name in files:
            with open(os.path.join(d, name), "rb") as f:
                data = f.read()
            try:
                top = list(pb_fields(data))
            except ValueError:
                continue
            for _, wt, v in top:
                if wt != 2 or b"G3-" not in v:
                    continue
                try:
                    sub = list(pb_fields(v))
                except ValueError:
                    continue
                ms = [x for _, w, x in sub if w == 0 and 1_600_000_000_000 < x < 2_100_000_000_000]
                toks = {m.group(1).decode() for _, w, x in sub if w == 2 for m in TOKEN_RE.finditer(x)}
                for t in toks:
                    if ms and t not in out:
                        out[t] = ms[0]
    return out


# ------------------------------------------------------- raw token scanning
def scan_file(path):
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
            found.update(m.group(1) for m in TOKEN16_RE.finditer(data[off:].decode("utf-16-le", errors="ignore")))
    return found


def classify(rel):
    r = rel.replace("\\", "/")
    if r.startswith(f"data/data/{PKG}/") or r.startswith(f"apps/{PKG}/"):
        return "app"
    if "notification_history" in r:
        return "notif"
    if "com.android.providers.contacts" in r:
        return "contacts"
    return "other"


_SCAN = {}


def scan_tree(root):
    """{token: [(kind, relpath), ...]} for every file under root (cached)."""
    if root in _SCAN:
        return _SCAN[root]
    idx = _SCAN[root] = {}
    if not root or not os.path.isdir(root):
        return idx
    for d, _, files in os.walk(root):
        for name in files:
            full = os.path.join(d, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            for t in scan_file(full):
                idx.setdefault(t, []).append((classify(rel), rel))
    return idx


def bdb(bid):
    return os.path.join("work", bid, "database.sqlite") if bid and bid != "-" else None


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
                short = dpath.replace(f"/data/data/{PKG}/", "/data/data/<signal>/")
                if "/signal-backup-" in dpath:
                    short = "<backup folder>/" + "/".join(dpath.split("/")[-2:])
                print(f"  {st:<8} {eid:<4} {short[-60:]}")
    print(f"\n{ok}/{len(rows)} exhibits unchanged since acquisition; {dok}/{dn} device hashes match host copies.")
    sys.exit(0 if ok == len(rows) and dok == dn else 1)


def cmd_ab2tar(ab, out):
    with open(ab, "rb") as f:
        head = [f.readline().strip() for _ in range(4)]
        if head[0] != b"ANDROID BACKUP":
            sys.exit("  not an Android backup file")
        if head[3] != b"none":
            sys.exit("  backup is password-encrypted; redo it with an empty password")
        tpath = os.path.join("work", os.path.basename(os.path.splitext(ab)[0]) + ".tar")
        dec = zlib.decompressobj() if head[2] == b"1" else None
        with open(tpath, "wb") as t:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                t.write(dec.decompress(chunk) if dec else chunk)
    os.makedirs(out, exist_ok=True)
    sig = other = 0
    try:
        with tarfile.open(tpath) as tf:
            for m in tf:
                if m.isfile():
                    if classify(m.name) == "app":
                        sig += 1
                    else:
                        other += 1
                try:
                    tf.extract(m, out, filter="data") if hasattr(tarfile, "data_filter") else tf.extract(m, out)
                except Exception:
                    pass
    except tarfile.ReadError:
        pass
    os.remove(tpath)
    print(f"  adb backup contents: Signal {sig} files, other apps {other} files")


def cmd_sqlite_check(db):
    with DbCopy(db) as con:
        if not con:
            print("not a readable SQLite database")
            return
        n = q1(con, "SELECT count(*) FROM message") if "message" in tables(con) else None
        print(f"SQLite, {len(tables(con))} tables" + (f", {n} messages" if n is not None else ""))


def cmd_storage(fs, bk):
    root = os.path.join("work", fs)
    print(f"Where Signal keeps its data (acquisition {fs}, extracted copy)")
    print(f"{'item':<44}{'size':>10}  format")

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
        return size, "encrypted, not SQLite" if ".db" in path else "binary"

    S = f"data/data/{PKG}"
    items = [
        (f"{S}/databases/signal.db", "Signal databases/signal.db"),
        (f"{S}/databases/signal.db-wal", "Signal databases/signal.db-wal"),
        (f"{S}/shared_prefs/{PKG}_preferences.xml", "Signal shared_prefs/..._preferences.xml"),
        (f"{S}/app_parts", "Signal app_parts/ (attachments)"),
        (f"{S}/app_avatars", "Signal app_avatars/"),
        ("data/media/0/Download", "shared storage: Download/ (backups)"),
        ("data/media/0/DCIM", "shared storage: DCIM/ (camera photos)"),
        ("data/system_ce/0/notification_history", "Android notification_history/"),
        ("data/data/com.android.providers.contacts/databases/contacts2.db", "Android contacts2.db (phone contacts)"),
        ("data/misc/keystore/persistent.sqlite", "Android keystore persistent.sqlite"),
    ]
    for rel, label in items:
        size, f = fmt(os.path.join(root, rel))
        print(f"{label:<44}{size:>10}  {f}")
    db = bdb(bk)
    with DbCopy(db) as con:
        n = q1(con, "SELECT count(*) FROM message") if con else None
    print(f"{'decrypted backup ' + bk + ': database.sqlite':<44}"
          f"{human(os.path.getsize(db)) if db and os.path.isfile(db) else '-':>10}  "
          f"{'SQLite 3, ' + str(n) + ' messages' if n is not None else 'not readable'}")

    # ---- timestamps
    logged = {}
    if os.path.exists(ACT_LOG):
        with open(ACT_LOG, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                logged[r["id"]] = r["host_time_utc+06:00"]
    def row(tid, col, raw):
        dt = datetime.fromtimestamp(raw / 1000, timezone.utc)
        loc = dt.astimezone(BT)
        lg = logged.get(tid, "")
        diff = ""
        if lg:
            diff = f"{(loc - datetime.strptime(lg, '%Y-%m-%d %H:%M:%S').replace(tzinfo=BT)).total_seconds():+.0f} s"
        print(f"{tid:<5}{col:<14}{raw:<16}{dt:%H:%M:%S}  {loc:%H:%M:%S}   {lg[11:] or '-':<10}{diff:>8}")
        return loc.strftime("%Y-%m-%d")

    hdr = f"{'id':<5}{'column':<14}{'raw value (ms)':<16}{'UTC':<10}{'UTC+06:00':<11}{'logged':<10}{'diff':>8}"
    day = None
    with DbCopy(db) as con:
        if con:
            print(f"\nTimestamps in backup {bk} vs the time we logged each action")
            print(hdr)
            for tid in ("S1", "S2", "S14", "S15"):
                for col in ("date_sent", "date_received"):
                    raw = q1(con, f"SELECT {col} FROM message WHERE body LIKE ?", (f"G3-{tid} %",))
                    if raw and raw > 0:
                        day = row(tid, col, raw)
    if day is None:
        nt = notif_times(root)
        print(f"\nBackup {bk} not readable, so timestamps come from Android notification")
        print(f"history in {fs} (posted_time_ms of each Signal notification)")
        print(hdr)
        for tid in sorted((t for t in nt if t.startswith("S")), key=lambda t: (len(t), t)):
            day = row(tid, "posted_time", nt[tid])
        if not nt:
            print("  no G3 tokens in notification history")
    if day:
        print(f"date {day}. Stored as ms since 1970 UTC. Bhutan = UTC+06:00, no DST")
        print("logged = time we ran 'mark'.  diff = stored minus logged")

def cmd_score(a, b, c):
    roots = {"A": os.path.join("work", a), "B": os.path.join("work", b)}
    idx = {"A": scan_tree(roots["A"]), "B": scan_tree(roots["B"])}
    cdb = bdb(c)
    idx["C"] = {t: [("app", "database.sqlite")] for t in scan_file(cdb)} if cdb and os.path.isfile(cdb) else {}

    def cell(col, tok):
        hits = idx[col].get(tok, [])
        if any(k == "app" for k, _ in hits):
            return "Y"
        return "n" if hits else "N"

    def calls(col):
        if col == "C":
            db = cdb
        elif col == "A":
            db = find_named(os.path.join(roots["A"], "apps", PKG), "signal.db") if os.path.isdir(roots["A"]) else None
        else:
            db = os.path.join(roots["B"], f"data/data/{PKG}/databases/signal.db")
        with DbCopy(db) as con:
            if not con:
                return "N"
            n = q1(con, "SELECT count(*) FROM call") if "call" in tables(con) else 0
            return str(n) if n else "N"

    print(f"Signal: recovered vs activity script, per acquisition")
    cl = "decrypted" if idx["C"] else "NOT decryptable"
    print(f"A = {a} adb backup  B = {b} file system (root)  C = {c} Signal backup, {cl}")
    print("Y = in Signal's data  n = only outside Signal (e.g. notification history) N = no")
    print(f"{'id':<8}{'scripted action':<36}{'A':>6}{'B':>6}{'C':>6}")
    tot = {"A": 0, "B": 0, "C": 0}
    rows = []
    vals = []
    for col in "ABC":
        k = sum(cell(col, f"S{i}") == "Y" for i in range(1, 5))
        tot[col] += k
        vals.append(f"{k}/4")
    rows.append(("S1-S4", "text messages (2 sent, 2 received)", vals))
    for i, label in ((5, "image sent (caption)"), (6, "image received (caption)"), (7, "voice call (call records)"),
                     (8, "contact G3-CONTACT"), (9, "deleted for everyone"), (10, "sent before timer (control)"),
                     (11, "deleted for me only"), (12, "edited: original text"), (13, "edited: new text"),
                     (14, "disappearing message (1 h)")):
        vals = []
        for col in "ABC":
            v = calls(col) if i == 7 else cell(col, "CONTACT" if i == 8 else f"S{i}")
            tot[col] += v not in ("N", "n")
            vals.append(v)
        rows.append((f"S{i}", label, vals))
    for rid, label, v in rows:
        print(f"{rid:<8}{label:<36}{v[0]:>6}{v[1]:>6}{v[2]:>6}")
    print(f"{'recovered (of 14)':<44}{tot['A']:>6}{tot['B']:>6}{tot['C']:>6}")
    notif = sorted({t for t, h in idx["B"].items() if any(k == "notif" for k, _ in h)},
                   key=lambda t: (len(t), t))
    print(f"\nTokens readable in Android notification history ({b}): {', '.join(notif) or 'none'}")


def locations(token, fs_root, backup_db):
    labels = []
    for kind, rel in scan_tree(fs_root).get(token, []):
        if kind == "notif":
            labels.append("notif-history")
        elif kind == "app":
            path = os.path.join(fs_root, rel)
            if rel.endswith("-wal"):
                labels.append("signal-wal")
            elif is_sqlite(path):
                with DbCopy(path) as con:
                    t = rows_with(con, f"G3-{token} ") if con else []
                labels.append("row:" + "+".join(t) if t else "free-page")
            else:
                labels.append("signal:" + os.path.basename(rel)[:16])
        else:
            labels.append(os.path.basename(rel)[:18])
    with DbCopy(backup_db) as con:
        t = rows_with(con, f"G3-{token} ") if con else []
    labels.append("backup-row:" + "+".join(t) if t else "backup:none")
    seen = []
    for x in labels:
        if x not in seen:
            seen.append(x)
    return ", ".join(seen)


def cmd_disappear(fb, fa, bb, ba):
    rb, ra = os.path.join("work", fb), os.path.join("work", fa)
    print("Deleted, disappearing and edited Signal messages: where each one survives")
    print(f"before = {fb} file system + {bb} backup    after = {fa} file system + {ba} backup")
    print("backup-row:<table> = live row in decrypted backup   notif-history = Android")
    print("notification history   backup:none = not in the backup")
    for tok, label in (("S9", "deleted for everyone"), ("S10", "control: sent before timer"),
                       ("S14", "disappearing, 1 hour"),
                       ("S11", "deleted for me only"), ("S12", "edited: original text"),
                       ("S13", "edited: new text")):
        print(f"\n{tok:<4}{label}")
        for when, root, db in (("before", rb, bdb(bb)), ("after ", ra, bdb(ba))):
            print(textwrap.fill(locations(tok, root, db), 80, initial_indent=f"   {when}: ", subsequent_indent=" " * 11))
    flags = []
    for bid in (bb, ba):
        with DbCopy(bdb(bid)) as con:
            n = q1(con, "SELECT count(*) FROM message WHERE remote_deleted = 1") if con else None
        flags.append(f"{bid}: {n if n is not None else '-'}")
    print(f"\nRows flagged remote_deleted (text wiped, row kept): {'   '.join(flags)}")


def main():
    a = sys.argv[1:]
    cmds = {"hash-add": (cmd_hash_add, 3), "verify": (cmd_verify, 0), "ab2tar": (cmd_ab2tar, 2),
            "sqlite-check": (cmd_sqlite_check, 1), "storage": (cmd_storage, 2), "score": (cmd_score, 3),
            "disappear": (cmd_disappear, 4)}
    if not a or a[0] not in cmds or len(a) - 1 != cmds[a[0]][1]:
        sys.exit(__doc__)
    cmds[a[0]][0](*a[1:])


if __name__ == "__main__":
    main()
