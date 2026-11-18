#!/usr/bin/env python3
"""
wa_merge.py - merge an old phone's WhatsApp history into your current phone's WhatsApp backup,
so you keep both. Runs on the phone itself (Termux on Android), or on a computer.

How it works: it unlocks the old and the current phone's end-to-end encrypted local backups
(msgstore.db.crypt15, each with its own 64-digit key), copies the old history into the current
one, and locks the result again with the current phone's key. You then restore that file with
the official WhatsApp app. Your original backup files are never changed.

Built on wakit 0.3.0 by Mena Maged (https://github.com/menaxmaged/wakit): wakit does the
decryption details and its merge logic is adapted here, with these changes:
  * backups are decrypted / encrypted in small pieces, so it fits in a phone's memory
  * tables are read row by row; only what is needed later is kept in memory
  * progress lines throughout, and it can pick up where it stopped
  * a temporary index speeds up the per-chat step (removed again before saving)
  * the old database is opened read-only in place instead of being copied
  * also copies message details wakit 0.3.0 leaves out (contact cards, locations, call bubbles,
    read info, group invites, ...), each table only when every link in it is understood, and
    each checked on its own; disappearing-message timers, reminders and unsent work are left out
  * completes and rebuilds WhatsApp's search index, so every message can be found by search

Not affiliated with WhatsApp or Meta. Unofficial: keep untouched copies of your backups.

Setup (Termux):  termux-setup-storage
                 pkg install python python-cryptography
                 pip install wakit==0.3.0
Run:             python wa_merge.py                 (walks you through every step)
Options:         --old FILE       the old phone's msgstore.db.crypt15
                                  (default: <storage>/WA old backup/msgstore.db.crypt15)
                 --current FILE   the current phone's msgstore.db.crypt15
                                  (default: read from WhatsApp's own Databases folder)
                 --out DIR        where to write the results (default: <storage>/WA work)
                 --work DIR       where the unlocked copies are kept (default: ~/wa, private to Termux)
                 --redo-merge     merge again from a new current-phone backup (keeps the unlocked old one)
                 --wakit-only     copy only what wakit 0.3.0 copies (skip the extra details)
                 --fix-search     no merge: rebuild the search index of the current backup (for merges
                                  made before this was fixed, where older messages weren't searchable)
Keys are typed in when asked; they are never saved or printed.

MIT License

Copyright (c) 2026 the wa_merge.py contributors
Portions adapted from wakit, Copyright (c) 2026 Mena Maged

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import argparse, getpass, hashlib, os, re, secrets, shutil, sqlite3, subprocess, sys, time, urllib.parse, zlib

WAKIT_VERSION = "0.3.0"
SHARED = "/storage/emulated/0"                 # the phone's Internal storage, as Termux sees it
OLD_BACKUP = os.path.join(SHARED, "WA old backup", "msgstore.db.crypt15")
CUR_BACKUP = None                              # None: read it from WhatsApp's Databases folder
WA_DATABASES = os.path.join(SHARED, "Android", "media", "com.whatsapp", "WhatsApp", "Databases")
OUT_DIR = os.path.join(SHARED, "WA work")
WORK = os.path.expanduser("~/wa")             # private to Termux: no other app can read the unlocked chats
WAKIT_ONLY = False


def set_work(work):
    global WORK, OLD_DB, NEW_DB, OLD_READY, MERGED_OK
    WORK = work
    OLD_DB, NEW_DB = os.path.join(WORK, "old.db"), os.path.join(WORK, "new.db")
    OLD_READY, MERGED_OK = os.path.join(WORK, "old.ready"), os.path.join(WORK, "merged.ok")


set_work(WORK)
CHUNK = 8 << 20
T0 = time.time()


# --------------------------------------------------------------------------------------------- small helpers

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}  +{(time.time() - T0) / 60:5.1f} min]  {msg}", flush=True)


def stop(msg):
    print(f"\nSTOPPED: {msg}\nNothing in WhatsApp or in your backup files was changed.", flush=True)
    sys.exit(1)


def ask_yes(question):
    while True:
        a = input(f"\n{question} [yes/no]: ").strip().lower()
        if a in ("y", "yes"):
            return True
        if a in ("n", "no"):
            return False


def gb(n):
    return f"{n / 1e9:.2f} GB"


def free_bytes(path):
    return shutil.disk_usage(path).free


def mem_available():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def ask_key(label):
    from wakit import crypt
    while True:
        k = getpass.getpass(f"\nPaste the {label} (64 characters; it stays hidden) and press Enter: ")
        if crypt.root_key(k):
            print(f"  key accepted (ends in ...{k.strip()[-4:]})")
            return k
        print("  That isn't a 64-character key (only 0-9 and a-f, spaces allowed). Try again.")


# --------------------------------------------------------------------------------------------- crypt15, streamed

class WrongKey(Exception):
    pass


def _cipher():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher, algorithms, modes


def _decrypt_pass(src, size, head, key, with_md5, out, sha, label):
    """One pass over the file. Returns True if the trailer layout guess was right."""
    Cipher, algorithms, modes = _cipher()
    with open(src, "rb") as f:
        if with_md5:
            f.seek(size - 32)
            tag, stored = f.read(16), f.read(16)
            ct_end, md5_end = size - 32, size - 16
        else:
            f.seek(size - 16)
            tag, stored = f.read(16), None
            ct_end, md5_end = size - 16, 0
        f.seek(0)
        dec = Cipher(algorithms.AES(key), modes.GCM(head["iv"], tag)).decryptor()
        md5 = hashlib.md5()
        z = None
        raw = None  # True: not compressed
        pos, last_pct = 0, -1
        while pos < max(ct_end, md5_end):
            want = min(CHUNK, max(ct_end, md5_end) - pos)
            buf = f.read(want)
            if not buf:
                break
            if pos < md5_end:
                md5.update(buf[:max(0, md5_end - pos)])
            a, b = max(head["start"], pos), min(ct_end, pos + len(buf))
            if a < b:
                plain = dec.update(buf[a - pos:b - pos])
                if raw is None:
                    if plain[:4] == b"PK\x03\x04":
                        raise RuntimeError("this backup is a ZIP-packed file - not a chat database")
                    if plain[:16] == b"SQLite format 3\x00":
                        raw = True
                    elif len(plain) >= 2 and plain[0] == 0x78 and (plain[0] * 256 + plain[1]) % 31 == 0:
                        raw, z = False, zlib.decompressobj()
                    else:
                        raise WrongKey()
                data = plain if raw else z.decompress(plain)
                if sha is not None:
                    sha.update(data)
                if out is not None:
                    out.write(data)
            pos += len(buf)
            pct = int(pos * 100 / size)
            if label and pct // 10 != last_pct // 10:
                last_pct = pct
                log(f"{label}: {pct}%")
        if with_md5 and md5.digest() != stored:
            return False
        try:
            dec.finalize()
        except Exception:
            raise WrongKey()
        if z is not None:
            tail = z.flush()
            if sha is not None:
                sha.update(tail)
            if out is not None:
                out.write(tail)
            if not z.eof:
                raise RuntimeError("the backup file ends too early (incomplete copy?)")
    return True


def decrypt_file(src, key_text, dst=None, label=None):
    """Decrypt a .crypt15 to dst (or just hash it when dst is None). Returns the SHA-256 of the database."""
    return _decrypt(src, key_text, dst, label)[0]


def _decrypt(src, key_text, dst, label):
    """Streams through the file, so it needs little memory. -> (SHA-256 of the database, has an MD5 trailer)"""
    from wakit import crypt
    size = os.path.getsize(src)
    with open(src, "rb") as f:
        head = crypt.parse(f.read(min(size, 1 << 16)))
    key = crypt.load_key(key_text, head["kind"])
    for with_md5 in (True, False):
        sha = hashlib.sha256()
        out = open(dst + ".part", "wb") if dst else None
        try:
            ok = _decrypt_pass(src, size, head, key, with_md5, out, sha, label)
        except BaseException:
            if out:
                out.close()
                os.remove(dst + ".part")
            raise
        if out:
            out.close()
        if ok:
            if dst:
                os.replace(dst + ".part", dst)
            return sha.hexdigest(), with_md5
        if out:
            os.remove(dst + ".part")
    raise WrongKey()


def encrypt_file(db_path, key_text, template_path, dst):
    """Encrypt db_path into a .crypt15 packed like template_path (same key), checked by decrypting it again."""
    from wakit import crypt
    Cipher, algorithms, modes = _cipher()
    # Read the original backup in pieces (never all at once: a large backup doesn't fit in a phone's memory)
    with open(template_path, "rb") as f:
        first = f.read(1 << 16)
    head = crypt.parse(first)
    key = crypt.load_key(key_text, head["kind"])
    _, with_md5 = _decrypt(template_path, key_text, None, "reading the original backup's layout")
    packing = {"md5": with_md5, "zip": None}
    if head["start"] > len(first) or head["iv_at"] + 16 > head["start"]:
        raise RuntimeError("unexpected backup header")
    iv = secrets.token_bytes(16)
    header = bytearray(first[:head["start"]])
    header[head["iv_at"]:head["iv_at"] + 16] = iv
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    comp = zlib.compressobj()
    md5, sha = hashlib.md5(), hashlib.sha256()
    size = os.path.getsize(db_path)
    part = dst + ".part"
    try:
        _encrypt_body(db_path, part, header, enc, comp, md5, sha, packing, size)
        log("checking the new backup file by decrypting it again...")
        if decrypt_file(part, key_text, None, "checking") != sha.hexdigest():
            raise RuntimeError("self-check failed - the new backup file was deleted")
    except BaseException:
        if os.path.exists(part):
            os.remove(part)
        raise
    os.replace(part, dst)


def _encrypt_body(db_path, part, header, enc, comp, md5, sha, packing, size):
    done, last = 0, -1
    with open(db_path, "rb") as src, open(part, "wb") as out:
        out.write(header)
        md5.update(header)
        while True:
            buf = src.read(CHUNK)
            if not buf:
                break
            sha.update(buf)
            e = enc.update(comp.compress(buf))
            out.write(e)
            md5.update(e)
            done += len(buf)
            pct = int(done * 100 / size)
            if pct // 10 != last // 10:
                last = pct
                log(f"encrypting: {pct}%")
        e = enc.update(comp.flush()) + enc.finalize() + enc.tag
        out.write(e)
        md5.update(e)
        if packing["md5"]:
            out.write(md5.digest())


# --------------------------------------------------------------------------------------------- merge (from wakit)

def _stream(cur, sql, params=()):
    rd = cur.connection.cursor()
    rd.execute(sql, params)
    while True:
        rows = rd.fetchmany(2000)
        if not rows:
            break
        for r in rows:
            yield r
    rd.close()


def copy_rows(cur, table, spec, maps, jids, or_ignore=False):
    """wakit's copy_rows, reading the old table row by row."""
    from wakit import db_merge as W
    if not cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
        return 0
    old_cols = W.cols(cur, table, "o")
    if not old_cols:
        return 0
    new_cols = set(W.cols(cur, table))
    common = [c for c in old_cols if c in new_cols]
    own = next((c for c, k in spec.items() if k in ("pk", "A*", "P*", "L*")), None)
    out_cols = [c for c in common if c != own]
    sql = f'INSERT {"OR IGNORE " if or_ignore else ""}INTO "{table}"({",".join(out_cols)}) VALUES({",".join("?" * len(out_cols))})'
    n = seen = 0
    for row in _stream(cur, f'SELECT {",".join(common)} FROM o."{table}"'):
        seen += 1
        if seen % 200000 == 0:
            log(f"  {table}: {seen:,} rows read, {n:,} copied")
        r = dict(zip(common, row))
        ok = True
        for c, kind in spec.items():
            if c not in r or c == own:
                continue
            v = r[c]
            if kind in ("M", "C", "A", "P"):
                if v is None or v <= 0:
                    if kind in ("M", "A"):
                        ok = False
                    continue
                if v not in maps[kind]:
                    ok = False
                    break
                r[c] = maps[kind][v]
            elif kind in ("J", "R"):
                r[c] = jids.get(v, canon=kind == "J")
        if not ok:
            continue
        if table == "message_ephemeral_setting" and r.get("user_jid_row_id_csv"):
            r["user_jid_row_id_csv"] = ",".join(str(jids.get(int(x))) for x in r["user_jid_row_id_csv"].split(",") if x.strip())
        res = cur.execute(sql, [r[c] for c in out_cols])
        if not res.rowcount:
            continue
        if own and spec[own] != "pk":
            maps[spec[own][0]][r[own]] = res.lastrowid
        n += 1
    return n


# ---- extra message details wakit 0.3.0 leaves out (contact cards, locations, read receipts, group invites, ...)
# A table is copied only when every link in it is understood; each one is copied inside its own savepoint and
# checked on its own, so a table that doesn't fit is put back exactly as it was and listed as skipped.
EXTRA_LEAVE_OUT = ("ephemeral", "pending", "retry", "send", "queue", "job", "expir", "orphan", "upload", "fts",
                   "tmp", "reminder")  # timers / unsent work: copying these could make WhatsApp delete or re-send things
EXTRA_DONE = {"message", "chat", "jid", "jid_map", "lid_display_name", "call_log"}


def _tinfo(cur, table, schema):
    return cur.execute(f'PRAGMA {schema}.table_info("{table}")').fetchall()


def plan_extra(cur, table, candidates, copied):
    """-> (spec, reason). spec: column -> how to treat it; reason: why the table can't be copied (or None).
    A reason starting with 'link:' may go away once the table it points to has been copied."""
    if any(w in table for w in EXTRA_LEAVE_OUT):
        return None, "left out on purpose"
    for (tsql,) in cur.execute("SELECT sql FROM main.sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)):
        if re.search(r"\bINSERT\s+ON\b", (tsql or "").upper().split("BEGIN")[0]):
            return None, "has triggers"  # inserting would make the app's database do something else as well
    new_cols = {r[1] for r in _tinfo(cur, table, "main")}
    old = [r for r in _tinfo(cur, table, "o") if r[1] in new_cols]
    names = [r[1] for r in old]
    anchor = "message_row_id" if "message_row_id" in names else "message_add_on_row_id"
    pks = [r for r in old if r[5]]
    spec = {}
    for cid, c, typ, notnull, dflt, pk in old:
        lc = c.lower()
        if lc == anchor:
            spec[c] = "M!" if anchor == "message_row_id" else "A!"
        elif pk and len(pks) == 1 and "INT" in (typ or "").upper():
            spec[c] = "pk"
        elif lc == "message_add_on_row_id":
            spec[c] = "A"
        elif lc.endswith("message_row_id"):
            spec[c] = "M"
        elif lc.endswith("chat_row_id"):
            spec[c] = "C"
        elif lc.endswith("jid_row_id"):
            spec[c] = "R" if ("device" in lc or lc.startswith(("old_", "new_"))) else "J"  # keep exact ids there
        elif lc.endswith("lid_row_id"):
            spec[c] = "R"  # an @lid contact id: copied exactly
        elif lc == "call_log_row_id":
            spec[c] = "L"
        elif lc.endswith("_row_id"):
            base = lc[:-7]
            hits = [t for t in candidates if t == "message_" + base] or [t for t in candidates if t.endswith(base)]
            if len(hits) != 1:
                return None, f"unknown link {c}"
            if hits[0] not in copied:
                return None, f"link:{hits[0]}"
            spec[c] = ("T", hits[0])
        elif "row_id" in lc or lc.endswith("_csv") or (lc.endswith("_id") and "INT" in (typ or "").upper()):
            return None, f"unknown link {c}"
        else:
            spec[c] = "="
    return spec, None


def copy_extra(cur, table, spec, maps, jids, pkmaps, keep_pk):
    cols = list(spec)
    own = next((c for c, k in spec.items() if k == "pk"), None)
    out = [c for c in cols if c != own]
    sql = f'INSERT OR IGNORE INTO main."{table}"({",".join(out)}) VALUES({",".join("?" * len(out))})'
    rec = pkmaps.setdefault(table, {}) if (own and keep_pk) else None
    n = seen = 0
    for row in _stream(cur, f'SELECT {",".join(cols)} FROM o."{table}"'):
        seen += 1
        if seen % 500000 == 0:
            log(f"    {table}: {seen:,} rows read, {n:,} copied")
        r = dict(zip(cols, row))
        ok = True
        for c, k in spec.items():
            v = r[c]
            if k in ("=", "pk"):
                continue
            if k in ("M!", "A!"):
                v = maps[k[0]].get(v)
                if v is None:
                    ok = False
                    break
                r[c] = v
                continue
            if not isinstance(v, int) or v <= 0:
                continue  # empty link: keep as it is
            if k in ("M", "C", "A", "L"):
                v = maps[k].get(v)
            elif k in ("J", "R"):
                v = jids.get(v, canon=k == "J") if v in jids.old else None
            else:
                v = pkmaps.get(k[1], {}).get(v)
            if v is None:  # points at something that wasn't copied: leave the row out rather than point wrongly
                ok = False
                break
            r[c] = v
        if not ok:
            continue
        res = cur.execute(sql, [r[c] for c in out])
        if res.rowcount:
            n += 1
            if rec is not None:
                rec[r[own]] = res.lastrowid
    return n


def copy_extras(cur, maps, jids, report):
    from wakit import db_merge as W
    done = EXTRA_DONE | {t for t, _ in W.CHILDREN}
    old_tables = [r[0] for r in cur.execute("SELECT name FROM o.sqlite_master WHERE type='table' ORDER BY name")]
    new_tables = {r[0] for r in cur.execute("SELECT name FROM main.sqlite_master WHERE type='table'")}
    candidates = []
    for t in old_tables:
        if t in done or t not in new_tables or t.startswith("sqlite_"):
            continue
        names = {r[1] for r in _tinfo(cur, t, "o")} & {r[1] for r in _tinfo(cur, t, "main")}
        if "message_row_id" in names or "message_add_on_row_id" in names:
            candidates.append(t)
    # which tables other tables point at (their old->new row numbers are kept)
    parents = set()
    for t in candidates:
        for r in _tinfo(cur, t, "o"):
            lc = r[1].lower()
            if lc.endswith("_row_id") and not lc.endswith(("message_row_id", "chat_row_id", "jid_row_id", "lid_row_id")) \
                    and lc not in ("message_add_on_row_id", "call_log_row_id"):
                base = lc[:-7]
                hits = [x for x in candidates if x == "message_" + base] or [x for x in candidates if x.endswith(base)]
                parents.update(hits[:1] if len(hits) == 1 else [])
    pkmaps, copied, skipped = {}, set(), {}
    todo = list(candidates)
    for _ in range(3):  # tables that point at another table wait until that one is copied
        later = []
        for t in todo:
            spec, why = plan_extra(cur, t, candidates, copied)
            if why:
                (later if why.startswith("link:") else []).append(t)
                skipped[t] = why
                continue
            skipped.pop(t, None)
            saved = (dict(jids.new_by_raw), jids.added, set(jids.mapped))
            cur.execute("SAVEPOINT extra")
            try:
                n = copy_extra(cur, t, spec, maps, jids, pkmaps, t in parents)
                bad = cur.execute(f'PRAGMA main.foreign_key_check("{t}")').fetchall()
                if bad:
                    raise ValueError("links don't check out")
                cur.execute("RELEASE extra")
            except (sqlite3.Error, ValueError) as e:
                cur.execute("ROLLBACK TO extra")
                cur.execute("RELEASE extra")
                jids.new_by_raw, jids.added, jids.mapped = saved
                pkmaps.pop(t, None)
                skipped[t] = str(e)[:60]
                continue
            copied.add(t)
            if n:
                report["rows"][t] = n
                log(f"  {t}: {n:,}")
        todo = later
        if not todo:
            break
    for t in todo:
        skipped[t] = "points at a table that wasn't copied"
    report["extras_skipped"] = skipped
    del pkmaps


def merge(cur, report):
    """wakit 0.3.0 db_merge.merge (fuzzy option left out), streamed and with progress."""
    from wakit import db_merge as W
    from wakit.export_import import has_fts
    jids = W.Jids(cur)
    maps = {"M": {}, "C": {}, "A": {}, "P": {}, "L": {}}

    log("step 1/7: chats")
    chat_cols_new = set(W.cols(cur, "chat"))
    chat_cols = [c for c in W.cols(cur, "chat", "o") if c in chat_cols_new and c != "_id"]
    created, merged, hidden_new = set(), {}, {}
    direct_defaults, group_defaults = W.chat_defaults(cur)
    old_chats = cur.execute(f"""SELECT c._id, {",".join("c." + x for x in chat_cols)} FROM o.chat c
                                JOIN o.jid j ON j._id=c.jid_row_id
                                WHERE EXISTS(SELECT 1 FROM o.message m WHERE m.chat_row_id=c._id)
                                ORDER BY c._id""").fetchall()
    for row in old_chats:
        oid, r = row[0], dict(zip(chat_cols, row[1:]))
        old_jid = jids.old[r["jid_row_id"]]
        if old_jid[2] in W.SKIP_SERVERS:
            report["skipped chats"] = report.get("skipped chats", 0) + 1
            continue
        njid = jids.get(r["jid_row_id"])
        hit = cur.execute("SELECT _id, hidden FROM chat WHERE jid_row_id=?", (njid,)).fetchone()
        if hit:
            maps["C"][oid] = hit[0]
            if hit[0] not in created:
                merged[hit[0]] = old_jid[6]
                if hit[1] and not r["hidden"]:
                    hidden_new[hit[0]] = True
            continue
        r.update(W.CHAT_RESET)
        r.update({c: None for c in W.CHAT_MSG_COLS + W.CHAT_SORT_COLS if c in r})
        r["jid_row_id"] = njid
        if "account_jid_row_id" in r:
            r["account_jid_row_id"] = njid
        for c, v in (group_defaults if old_jid[2] == "g.us" else direct_defaults).items():
            if r.get(c) is None:
                r[c] = v
        out = [c for c in r if c in chat_cols_new]
        values = [r[c] for c in out]
        extra = ", account_jid_row_id" if "account_jid_row_id" not in out else ""
        nid = cur.execute(f'INSERT INTO chat({",".join(out)}{extra}) VALUES({",".join("?" * len(out))}{", ?" if extra else ""})',
                          values + ([njid] if extra else [])).lastrowid
        maps["C"][oid] = nid
        created.add(nid)
    del old_chats
    log(f"  {len(maps['C']):,} old chats matched or created")

    log("step 2/7: messages")
    msg_cols = [c for c in W.cols(cur, "message", "o") if c in set(W.cols(cur, "message")) and c != "_id"]
    i_chat, i_from, i_key = msg_cols.index("chat_row_id"), msg_cols.index("from_me"), msg_cols.index("key_id")
    i_sender, i_sort, i_ts = msg_cols.index("sender_jid_row_id"), msg_cols.index("sort_id"), msg_cols.index("timestamp")
    old_min, old_max = cur.execute("SELECT coalesce(min(sort_id), 0), coalesce(max(sort_id), 0) FROM o.message").fetchone()
    new_min = cur.execute("SELECT coalesce(min(sort_id), 0) FROM message").fetchone()[0]
    total_old = cur.execute("SELECT count(*) FROM o.message").fetchone()[0]
    offset, shifted = 1 - old_min, False
    existing = {}
    for nid, chat, from_me, key in cur.execute("SELECT _id, chat_row_id, from_me, key_id FROM message"):
        existing[(chat, from_me, key)] = nid
    had_messages = {chat for chat, _, _ in existing}
    sql = f'INSERT INTO message({",".join(msg_cols)}) VALUES({",".join("?" * len(msg_cols))})'
    inserted = {}  # new message id -> (chat_row_id, from_me, sender_jid_row_id, timestamp)
    dupes = seen = 0
    for row in _stream(cur, f'SELECT _id, {",".join(msg_cols)} FROM o.message ORDER BY sort_id'):
        seen += 1
        if seen % 100000 == 0:
            log(f"  messages: {seen:,} of {total_old:,} checked, {len(inserted):,} copied")
        oid, r = row[0], list(row[1:])
        if r[i_chat] not in maps["C"]:
            continue
        r[i_chat] = maps["C"][r[i_chat]]
        k = (r[i_chat], r[i_from], r[i_key])
        if k in existing:
            dupes += 1
            continue
        r[i_sender] = jids.get(r[i_sender])
        if not shifted:
            W.shift_sort_ids(cur, old_max + offset + 1 - new_min)
            shifted = True
        r[i_sort] = r[i_sort] + offset
        nid = cur.execute(sql, r).lastrowid
        existing[k] = maps["M"][oid] = nid
        inserted[nid] = (r[i_chat], r[i_from], r[i_sender], r[i_ts])
    del existing
    log(f"  messages: {seen:,} checked, {len(inserted):,} copied, {dupes:,} already there")

    log("step 3/7: media records, replies, reactions and other details")
    for table, spec in W.CHILDREN:
        n = copy_rows(cur, table, spec, maps, jids)
        if n:
            report["rows"][table] = n
            log(f"  {table}: {n:,}")

    log("step 4/7: search index")
    chat_jid = dict(cur.execute("SELECT _id, jid_row_id FROM chat"))
    fts = 0
    if has_fts(cur) and has_fts(cur, "o"):
        for docid, content, ns in _stream(cur, "SELECT docid, content, fts_namespace FROM o.message_ftsv2"):
            nid = maps["M"].get(docid)
            info = inserted.get(nid)
            if info is None:
                continue
            chat, from_me, sender, _ = info
            s = "1" if from_me else (W.b36(sender + 10) if (sender or 0) > 0 else "0")
            cur.execute("INSERT INTO message_ftsv2(docid, content, fts_jid, fts_namespace) VALUES(?,?,?,?)",
                        (nid, content, f"{s} {W.b36(chat_jid[chat] + 10)}", ns or ""))
            fts += 1
            if fts % 200000 == 0:
                log(f"  search index: {fts:,}")
    report["rows"]["message_ftsv2"] = fts
    log("  completing the search index (a few minutes, no output - normal)")
    added = complete_search_index(cur)
    if added:
        report["rows"]["search entries filled in"] = added

    n = copy_rows(cur, "call_log", {"_id": "L*", "jid_row_id": "J", "group_jid_row_id": "J",
                                     "call_creator_device_jid_row_id": "R"}, maps, jids, or_ignore=True)
    if n:
        report["rows"]["call_log"] = n
    if not WAKIT_ONLY:
        log("  extra details (contact cards, locations, call bubbles, read info, ...)")
        copy_extras(cur, maps, jids, report)

    log("step 5/7: pointing each chat at its newest message")
    cur.execute("CREATE INDEX IF NOT EXISTS main.wa_merge_tmp_chat_ts ON message(chat_row_id, timestamp)")
    touched = {v[0] for v in inserted.values()}
    for i, cid in enumerate(touched, 1):
        if i % 2000 == 0:
            log(f"  chats: {i:,} of {len(touched):,}")
        first_ts = cur.execute("SELECT min(timestamp) FROM message WHERE chat_row_id=? AND timestamp>0", (cid,)).fetchone()[0]
        if cid in created or cid not in had_messages:
            last_id, last_sort, last_ts = cur.execute(
                "SELECT _id, sort_id, timestamp FROM message WHERE chat_row_id=? ORDER BY sort_id DESC LIMIT 1", (cid,)).fetchone()
            sets = {c: last_id for c in W.CHAT_MSG_COLS} | {c: last_sort for c in W.CHAT_SORT_COLS}
            sets["sort_timestamp"] = last_ts
            sets = {c: v for c, v in sets.items() if c in chat_cols_new}
            cur.execute(f'UPDATE chat SET {",".join(c + "=?" for c in sets)} WHERE _id=?', [*sets.values(), cid])
        if first_ts:
            cur.execute("UPDATE chat SET created_timestamp=min(coalesce(nullif(created_timestamp,0), ?), ?) WHERE _id=?",
                        (first_ts, first_ts, cid))
        if hidden_new.get(cid):
            cur.execute("UPDATE chat SET hidden=0 WHERE _id=?", (cid,))

    ts = [v[3] for v in inserted.values() if (v[3] or 0) > 0]
    first_ts, last_ts, n_inserted = (min(ts) if ts else None), (max(ts) if ts else None), len(inserted)
    del ts, inserted, maps
    log("step 6/7: putting all messages in time order (a few minutes, no output - normal)")
    if n_inserted:
        W.renumber_sort_ids(cur)
    for cid in created - touched:
        cur.execute("DELETE FROM chat WHERE _id=?", (cid,))
    cur.execute("DROP INDEX IF EXISTS main.wa_merge_tmp_chat_ts")
    jm, names = jids.finish()
    report.update(created=len(created & touched), merged={c: merged[c] for c in merged if c in touched},
                  unhidden=sum(1 for c in hidden_new if c in touched), messages=n_inserted, dupes=dupes,
                  jids_added=jids.added, jid_map_added=jm, names_added=names, pn_to_lid=len(jids.mapped),
                  first_ts=first_ts, last_ts=last_ts)


def complete_search_index(cur, commit_every=None):
    """Make WhatsApp's search index cover every text message.

    Backups leave out most of the search index and the app rebuilds it after a restore. Adding the old
    phone's entries made WhatsApp treat the index as complete, so messages that were already on the current
    phone could not be found by search. This adds an entry (in the format wakit uses) for every text message
    that has none, then rebuilds the index only if it is inconsistent. Works in slices of message ids, with
    progress; with commit_every it also saves after each slice, so a large backup never needs much memory."""
    from wakit import db_merge as W
    from wakit.export_import import has_fts
    if not has_fts(cur):
        return 0
    chat_jid = dict(cur.execute("SELECT _id, jid_row_id FROM main.chat"))
    sample = cur.execute("SELECT f.content, m.text_data FROM main.message_ftsv2 f JOIN main.message m ON m._id = f.docid "
                         "WHERE m.text_data != '' LIMIT 2000").fetchall()
    if sample:
        same = sum(a == b for a, b in sample) / len(sample)
        log(f"  WhatsApp's own search entries match the message text exactly: {same:.0%} of {len(sample):,} checked")
        if same < 0.9:
            log("  note: this phone's WhatsApp stores search text differently; filled-in entries use the plain text")
    lo, hi = cur.execute("SELECT coalesce(min(_id), 0), coalesce(max(_id), 0) FROM main.message").fetchone()
    has_ts = "timestamp" in [r[1] for r in cur.execute("PRAGMA main.table_info(message)")]
    months = {}
    added, step, last_log = 0, 50000, time.time()
    for a in range(lo, hi + 1, step):
        rows = cur.execute(
            "SELECT m._id, m.chat_row_id, m.from_me, m.sender_jid_row_id, m.text_data, "
            + ("m.timestamp" if has_ts else "0") + " FROM main.message m "
            "WHERE m._id >= ? AND m._id < ? AND m.text_data IS NOT NULL AND m.text_data != '' "
            "AND NOT EXISTS (SELECT 1 FROM main.message_ftsv2 f WHERE f.docid = m._id)", (a, a + step)).fetchall()
        for mid, chat, from_me, sender, text, ts in rows:
            if chat_jid.get(chat) is None:
                continue
            if ts:
                try:
                    mon = time.strftime("%Y-%m", time.gmtime(ts / 1000))
                    months[mon] = months.get(mon, 0) + 1
                except (OverflowError, OSError, ValueError):
                    pass
            s = "1" if from_me else (W.b36(sender + 10) if (sender or 0) > 0 else "0")
            cur.execute("INSERT INTO main.message_ftsv2(docid, content, fts_jid, fts_namespace) VALUES(?,?,?,'')",
                        (mid, text, f"{s} {W.b36(chat_jid[chat] + 10)}"))
            added += 1
        if commit_every:
            commit_every()
        if time.time() - last_log > 20:
            log(f"    search entries: {min(100, 100 * (a + step - lo) // max(1, hi - lo + 1))}% through, {added:,} added")
            last_log = time.time()
    if months:
        top = sorted(months.items(), key=lambda kv: -kv[1])[:6]
        log("    filled in, by month: " + ", ".join(f"{m} {n:,}" for m, n in sorted(top)))
    log(f"    search entries: {added:,} added; checking the index (a few minutes, no output - normal)")
    try:
        cur.execute("INSERT INTO main.message_ftsv2(message_ftsv2) VALUES('integrity-check')")
    except sqlite3.DatabaseError:           # inconsistent (or an older SQLite without the check): rebuild
        log("    the index needs rebuilding (a few minutes, no output - normal)")
        cur.execute("INSERT INTO main.message_ftsv2(message_ftsv2) VALUES('rebuild')")
        if commit_every:
            commit_every()
    return added


def run_merge(old_path, new_path):
    from wakit import doctor
    for path, label in ((old_path, "the old phone's database"), (new_path, "the current phone's database")):
        c = sqlite3.connect(path)
        doctor.require(c, "android", label)
        c.close()
    con = sqlite3.connect("file:" + urllib.parse.quote(new_path) + "?mode=rw", uri=True, isolation_level=None)
    con.execute("PRAGMA cache_size=-262144")
    con.execute("ATTACH ? AS o", ("file:" + urllib.parse.quote(old_path) + "?mode=ro",))
    cur = con.cursor()
    report = {"rows": {}}
    cur.execute("BEGIN")
    try:
        merge(cur, report)
        log("step 7/7: final integrity check of the merged database (often 10-30 minutes, no output - normal)")
        ok = cur.execute("PRAGMA main.integrity_check").fetchone()[0]
        if ok != "ok":
            raise RuntimeError(f"integrity check failed: {ok}")
        fk = cur.execute("PRAGMA main.foreign_key_check").fetchall()
        if fk:
            raise RuntimeError(f"foreign key check failed: {fk[:5]}")
        log("saving...")
        con.commit()
    except BaseException:
        con.rollback()
        con.close()
        raise
    con.execute("DETACH o")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    return report


def print_report(r):
    fmt = lambda ms: time.strftime("%Y-%m-%d", time.localtime(ms / 1000)) if ms else "?"
    print("\n================ MERGE REPORT ================")
    print(f"messages: {r['messages']:,} copied from the old phone ({fmt(r['first_ts'])} -> {fmt(r['last_ts'])}), "
          f"{r['dupes']:,} were already on the current phone")
    print(f"chats:    {r['created']:,} added, {len(r['merged']):,} combined with the same chat on the current phone, "
          f"{r.get('skipped chats', 0):,} skipped (statuses/channels/broadcast lists)")
    if r["unhidden"]:
        print(f"          {r['unhidden']} hidden chats were un-hidden because old history was added")
    print(f"contacts: {r['pn_to_lid']:,} phone numbers moved to their new WhatsApp id, {r['jids_added']:,} contacts added")
    print("details:  " + ", ".join(f"{t} {n:,}" for t, n in r["rows"].items()))
    if r.get("extras_skipped"):
        print("not copied: " + ", ".join(f"{t} ({why})" for t, why in r["extras_skipped"].items()))
    print("==============================================")


# --------------------------------------------------------------------------------------------- the guided run

def checks(need_old=True):
    if need_old:
        print("wa_merge - merge your old WhatsApp history into your current phone's backup\n")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        stop("the cryptography package is missing. In Termux run:  pkg install python-cryptography\n"
             "(on a computer:  pip install cryptography)")
    try:
        from importlib.metadata import version
        v = version("wakit")
    except Exception:
        stop(f"wakit is missing. Run:  pip install wakit=={WAKIT_VERSION}")
    if v != WAKIT_VERSION:
        stop(f"this script was made for wakit {WAKIT_VERSION} but {v} is installed. Run:  pip install wakit=={WAKIT_VERSION}")
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE t USING fts4(x)")
    except sqlite3.Error:
        stop("this Python's SQLite has no FTS4 search-index support")
    uses_shared = any(p.startswith(SHARED) for p in (OLD_BACKUP, OUT_DIR, CUR_BACKUP or WA_DATABASES))
    if uses_shared and not os.access(SHARED, os.R_OK):
        stop("no access to the phone's storage. Run:  termux-setup-storage   and tap Allow, then try again")
    if need_old and not os.path.exists(OLD_READY) and not os.path.isfile(OLD_BACKUP):
        stop(f"can't find the old phone's backup at:\n  {OLD_BACKUP}\n"
             "Put it there, or give its location with  --old \"<path to msgstore.db.crypt15>\"")
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    free = free_bytes(WORK)
    log(f"free space: {gb(free)}" + (f", free memory: {gb(mem_available())}" if mem_available() else ""))
    if need_old and not os.path.exists(OLD_READY):
        need = 4.5 * os.path.getsize(OLD_BACKUP) + 2e9
        if free < need:
            stop(f"not enough free space: {gb(free)} free, about {gb(need)} needed. Free some space and run again.")
    if shutil.which("termux-wake-lock"):
        subprocess.run(["termux-wake-lock"], check=False)
        log("wake lock on: the phone won't put Termux to sleep while this runs")


def find_current_backup():
    copy = os.path.join(OUT_DIR, "current-original.crypt15")
    if CUR_BACKUP:
        if not os.path.isfile(CUR_BACKUP):
            stop(f"can't find the current phone's backup at:\n  {CUR_BACKUP}")
        return CUR_BACKUP, copy
    src = os.path.join(WA_DATABASES, "msgstore.db.crypt15")
    if os.path.isfile(src) and os.access(src, os.R_OK):
        return src, copy
    manual = os.path.join(OUT_DIR, "current.crypt15")
    if os.path.isfile(manual):
        return manual, copy
    stop("can't read the current phone's WhatsApp backup directly. With a file manager, copy\n"
         "  Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15\n"
         f"to  {manual}  (rename the copy to current.crypt15) and run this again,\n"
         "or give its location with  --current \"<path>\"")


def fix_search():
    """--fix-search: no merge; make every message in the current backup findable by WhatsApp search."""
    checks(need_old=False)
    src, original = find_current_backup()
    mtime = os.path.getmtime(src)
    print(f"\nThe current phone's backup: made {time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime))} "
          f"({(time.time() - mtime) / 60:.0f} minutes ago), {gb(os.path.getsize(src))}")
    print("Anything sent or received AFTER that backup will not be in the fixed backup. Make a fresh backup in")
    print("airplane mode (Wi-Fi off) and keep the phone offline until the restore is done.")
    if not ask_yes("Is this backup fresh and is the phone offline?"):
        stop("turn on airplane mode, make a fresh backup (WhatsApp > Settings > Chats > Chat backup > Back up), "
             "and run this again")
    db = os.path.join(WORK, "fix.db")
    for f in (db, db + "-journal", db + "-wal"):     # leftovers from a run that was closed partway
        if os.path.exists(f):
            os.remove(f)
    if free_bytes(WORK) < 3.5 * os.path.getsize(src) + 2e9:
        stop("not enough free space for this backup")
    shutil.copy2(src, original + ".part")
    os.replace(original + ".part", original)
    log(f"kept an untouched copy of the current phone's backup: {original}")
    while True:
        key = ask_key("CURRENT phone's 64-digit key")
        try:
            decrypt_file(original, key, db, "decrypting the backup")
            break
        except WrongKey:
            print("  That key doesn't open this backup. Check you're using this phone's key.")
    from wakit import doctor
    c = sqlite3.connect(db)
    doctor.require(c, "android", "the backup")
    c.close()
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("PRAGMA cache_size=-65536")
    cur = con.cursor()
    texts = cur.execute("SELECT count(*) FROM message WHERE text_data IS NOT NULL AND text_data != ''").fetchone()[0]

    def save():
        cur.execute("COMMIT")
        cur.execute("BEGIN")

    cur.execute("BEGIN")
    try:
        log(f"completing the search index for {texts:,} text messages (progress every 20 seconds)")
        added = complete_search_index(cur, commit_every=save)
        cur.execute("COMMIT")
        log("checking the database (a few minutes, no output - normal)")
        ok = cur.execute("PRAGMA quick_check").fetchone()[0]
        if ok != "ok":
            raise RuntimeError(f"database check failed: {ok}")
    except BaseException:
        if con.in_transaction:
            con.rollback()
        con.close()
        raise
    con.close()
    log(f"search index: {texts:,} text messages, {added:,} entries filled in, index checked")
    out = os.path.join(OUT_DIR, "msgstore.db.crypt15")
    encrypt_file(db, key, original, out)
    del key
    log(f"done: {out} ({gb(os.path.getsize(out))})")
    if ask_yes("Delete the unlocked (readable) copy of your chats now?"):
        os.remove(db)
        log("deleted")
    print(f"""
ALL DONE. In {OUT_DIR} you now have:
  msgstore.db.crypt15        your backup with a complete search index   <- the one to restore
  current-original.crypt15   the untouched backup                       <- keep it: it's your undo

Next: follow the "Restore on Android" steps in the guide (skip the old-media step).""")
    if shutil.which("termux-wake-unlock"):
        subprocess.run(["termux-wake-unlock"], check=False)


TYPE_NAMES = {0: "text", 1: "photo", 2: "voice/audio", 3: "video", 4: "contact", 5: "location", 7: "system",
              9: "document", 13: "GIF", 15: "deleted", 20: "sticker", 42: "view-once photo", 43: "view-once video"}


def check_search(words):
    """--check-search: read-only look at why WhatsApp search can't find some words. Prints no message text."""
    import difflib
    import random
    import unicodedata
    checks(need_old=False)
    src, _ = find_current_backup()
    if not words:
        print("\nPaste a few words from a message that search can't find (long-press it in WhatsApp > Copy),")
        words = input("then press Enter: ").strip()
    if not words:
        stop("no words given")
    db = os.path.join(WORK, "check.db")
    for f in (db, db + "-journal", db + "-wal"):
        if os.path.exists(f):
            os.remove(f)
    if free_bytes(WORK) < 3.5 * os.path.getsize(src) + 1e9:
        stop("not enough free space")
    while True:
        key = ask_key("CURRENT phone's 64-digit key")
        try:
            decrypt_file(src, key, db, "decrypting the backup")
            break
        except WrongKey:
            print("  That key doesn't open this backup. Check you're using this phone's key.")
    del key
    c = sqlite3.connect(db)   # a throwaway copy (deleted at the end); writable only because the index check needs it
    c.execute("PRAGMA cache_size=-65536")
    q = lambda sql, *a: c.execute(sql, a).fetchall()
    one = lambda sql, *a: c.execute(sql, a).fetchone()
    try:
        print("\n== 1. search tables ==")
        for name, sql in q("SELECT name, sql FROM sqlite_master WHERE sql LIKE '%VIRTUAL%'"):
            sql = re.sub(r"\s+", " ", sql)
            print(f"  {name}: {sql[:110]}")
        for t in ("content", "segments", "segdir", "docsize", "stat"):
            try:
                print(f"  message_ftsv2_{t}: {one(f'SELECT count(*) FROM message_ftsv2_{t}')[0]:,} rows")
            except sqlite3.Error:
                print(f"  message_ftsv2_{t}: (none)")
        try:
            for k, v in q("SELECT key, value FROM props WHERE key LIKE '%fts%' OR key LIKE '%search%' "
                          "OR key LIKE '%index%' ORDER BY key"):
                print(f"  setting {k} = {str(v)[:30]}")
        except sqlite3.Error:
            pass
        t0 = time.time()
        try:
            c.execute("INSERT INTO message_ftsv2(message_ftsv2) VALUES('integrity-check')")
            res = "ok"
        except sqlite3.Error as e:
            res = f"FAILED ({e})"
        print(f"  index check: {res} ({time.time() - t0:.0f}s)")
        lo, hi = one("SELECT coalesce(min(_id), 0), coalesce(max(_id), 0) FROM message")
        slo, shi = one("SELECT coalesce(min(sort_id), 0), coalesce(max(sort_id), 0) FROM message")
        print(f"  message ids {lo:,}-{hi:,}, sort ids {slo:,}-{shi:,}")
        try:
            bad = one("SELECT count(*), sum(m._id IS NULL) FROM message_ftsv2_content f LEFT JOIN message m ON m._id = f.docid "
                      "WHERE m._id IS NULL OR coalesce(m.text_data, '') = ''")
            print(f"  entries pointing at a message with no text: {bad[0]:,} (at no message at all: {bad[1] or 0:,})")
        except sqlite3.Error:
            pass

        def label(chat):
            r = one("SELECT c.subject, j.user, j.server FROM chat c JOIN jid j ON j._id = c.jid_row_id WHERE c._id = ?", chat)
            if not r:
                return f"chat #{chat} (missing)"
            return f'group "{r[0]}"' if r[0] else f"1:1 ...{str(r[1])[-4:]}@{r[2]}"

        def when(ts):
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts / 1000)) if ts else "?"

        def expected_jid(chat, from_me, sender):
            from wakit import db_merge as W
            cj = one("SELECT jid_row_id FROM chat WHERE _id = ?", chat)
            if not cj:
                return None
            s = "1" if from_me else (W.b36(sender + 10) if (sender or 0) > 0 else "0")
            return f"{s} {W.b36(cj[0] + 10)}"

        print("\n== 2. your words ==")
        hits = q("SELECT _id, sort_id, chat_row_id, timestamp, message_type, from_me, sender_jid_row_id, text_data "
                 "FROM message WHERE instr(text_data, ?) > 0 ORDER BY _id LIMIT 8", words)
        print(f"  messages containing them: {len(hits)}{' (first 8)' if len(hits) == 8 else ''}")
        tokens = [w.replace('"', "") for w in words.split() if w.replace('"', "")]
        match = " ".join(f'"{w}"' for w in tokens)
        for mid, sid, chat, ts, mtype, from_me, sender, text in hits:
            e = one("SELECT content, fts_jid, fts_namespace FROM message_ftsv2 WHERE docid = ?", mid)
            print(f"  message {mid:,} (sort {sid:,}), {when(ts)}, {label(chat)}, {'sent' if from_me else 'received'}")
            if not e:
                print("    search entry: NONE")
                continue
            found = one("SELECT count(*) FROM message_ftsv2 WHERE message_ftsv2 MATCH ? AND docid = ?", match, mid)[0]
            print(f"    search entry: yes; same text: {'yes' if e[0] == text else 'no'}; "
                  f"contact/chat tag ok: {'yes' if e[1] == expected_jid(chat, from_me, sender) else 'NO'} "
                  f"({re.sub(r'[0-9a-z]', 'x', str(e[1]))}); namespace {e[2]!r}; found by search: {'yes' if found else 'NO'}")
        docs = [r[0] for r in q("SELECT docid FROM message_ftsv2 WHERE message_ftsv2 MATCH ? LIMIT 8", match)]
        print(f"  the search index finds: {len(docs)} entr{'y' if len(docs) == 1 else 'ies'}")
        for d in docs:
            m = one("SELECT _id, chat_row_id, timestamp, message_type, text_data FROM message WHERE _id = ?", d)
            if not m:
                print(f"  entry {d:,} -> NO message with that id")
                continue
            ok = words in (m[4] or "")
            print(f"  entry {d:,} -> message {m[0]:,}: {when(m[2])}, {label(m[1])}, {TYPE_NAMES.get(m[3], f'type {m[3]}')}, "
                  f"has your words: {'yes' if ok else 'NO'}")
            if not ok:
                m2 = one("SELECT _id, chat_row_id, timestamp FROM message WHERE sort_id = ? AND instr(text_data, ?) > 0", d, words)
                if m2:
                    print(f"    (the message with sort id {d:,} has your words: message {m2[0]:,}, {when(m2[2])})")

        print("\n== 3. by month: text messages / no entry / of 25 entries checked: same text, similar, UNRELATED ==")
        rnd = random.Random(1)
        stats, samples = {}, {}
        step = 50000
        for a in range(lo, hi + 1, step):
            for mid, ts, has in q("SELECT m._id, m.timestamp, EXISTS(SELECT 1 FROM message_ftsv2 f WHERE f.docid = m._id) "
                                  "FROM message m WHERE m._id >= ? AND m._id < ? AND coalesce(m.text_data, '') != ''",
                                  a, a + step):
                mon = time.strftime("%Y-%m", time.localtime(ts / 1000)) if ts and ts > 0 else "no date"
                st = stats.setdefault(mon, [0, 0])
                st[0] += 1
                st[1] += not has
                if has:
                    sm = samples.setdefault(mon, [])
                    k = st[0] - st[1]
                    if len(sm) < 25:
                        sm.append(mid)
                    elif rnd.random() < 25 / k:
                        sm[rnd.randrange(25)] = mid
        similar_pairs, unrelated = [], []
        fine = 0
        for mon in sorted(stats):
            n, missing = stats[mon]
            same = sim = unrel = 0
            for mid in samples.get(mon, []):
                text, content = one("SELECT m.text_data, f.content FROM message m JOIN message_ftsv2 f ON f.docid = m._id "
                                    "WHERE m._id = ?", mid)
                text, content = text or "", content or ""
                if text == content:
                    same += 1
                elif difflib.SequenceMatcher(None, text.lower()[:300], content.lower()[:300], autojunk=False).ratio() >= 0.6:
                    sim += 1
                    if len(similar_pairs) < 1500:
                        similar_pairs.append((text, content))
                else:
                    unrel += 1
                    if len(unrelated) < 3 and content.strip():
                        unrelated.append((mid, content))
            if missing > max(2, n // 100) or unrel:
                print(f"  {mon}: {n:>8,} / {missing:>6,} / {same} same, {sim} similar, {unrel} UNRELATED")
            else:
                fine += 1
        print(f"  ({fine} months fine and not shown)")
        if unrelated:
            print("  where the text of some unrelated entries really belongs (one pass over all messages):")
            want = {content: mid for mid, content in unrelated}
            owners = {}
            for a in range(lo, hi + 1, step):
                for oid, osort, text in q("SELECT _id, sort_id, text_data FROM message WHERE _id >= ? AND _id < ? "
                                          "AND coalesce(text_data, '') != ''", a, a + step):
                    if text in want and text not in owners:
                        owners[text] = (oid, osort)
            for content, mid in want.items():
                m = one("SELECT sort_id FROM message WHERE _id = ?", mid)
                if content in owners:
                    oid, osort = owners[content]
                    print(f"    entry {mid:,} (sort {m[0]:,}) has the text of message {oid:,} (sort {osort:,}): "
                          f"id difference {oid - mid:+,}")
                else:
                    print(f"    entry {mid:,} (sort {m[0]:,}): no message has exactly its text")

        print("\n== 4. how the entries' text differs from the messages (character changes, most common first) ==")
        changes = {}
        for text, content in similar_pairs:
            sm = difflib.SequenceMatcher(None, text or "", content or "", autojunk=False)
            for op, a1, a2, b1, b2 in sm.get_opcodes():
                if op == "equal":
                    continue
                key = (text[a1:a2][:3], (content or "")[b1:b2][:3])
                changes[key] = changes.get(key, 0) + 1

        def show(x):
            if not x:
                return "(nothing)"
            return " ".join(f"U+{ord(ch):04X}" + (f"({ch})" if unicodedata.category(ch)[0] in "LN" else "") for ch in x)
        for (a, b), n in sorted(changes.items(), key=lambda kv: -kv[1])[:12]:
            print(f"  {n:>5}x  {show(a)}  ->  {show(b)}")
        print("\nDone. Nothing was changed. Send a screenshot of everything above.")
    finally:
        c.close()
        for f in (db, db + "-journal", db + "-wal"):
            if os.path.exists(f):
                os.remove(f)
        if shutil.which("termux-wake-unlock"):
            subprocess.run(["termux-wake-unlock"], check=False)


def parse_args(argv):
    global OLD_BACKUP, CUR_BACKUP, OUT_DIR, WAKIT_ONLY
    p = argparse.ArgumentParser(description="Merge an old phone's WhatsApp backup into the current phone's backup.")
    p.add_argument("--old", help="the old phone's msgstore.db.crypt15")
    p.add_argument("--current", help="the current phone's msgstore.db.crypt15")
    p.add_argument("--out", help="where to write the results")
    p.add_argument("--work", help="where the unlocked copies are kept")
    p.add_argument("--redo-merge", action="store_true", help="merge again from a new current-phone backup")
    p.add_argument("--wakit-only", action="store_true", help="copy only what wakit 0.3.0 copies")
    p.add_argument("--fix-search", action="store_true",
                   help="no merge: make every message in the current backup findable by WhatsApp search")
    p.add_argument("--check-search", nargs="?", const="", metavar="WORDS",
                   help="no changes: show why WhatsApp search can't find some words (prints no message text)")
    a = p.parse_args(argv)
    if a.old:
        OLD_BACKUP = os.path.abspath(os.path.expanduser(a.old))
    if a.current:
        CUR_BACKUP = os.path.abspath(os.path.expanduser(a.current))
    if a.out:
        OUT_DIR = os.path.abspath(os.path.expanduser(a.out))
    if a.work:
        set_work(os.path.abspath(os.path.expanduser(a.work)))
    WAKIT_ONLY = a.wakit_only
    return a


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    if a.check_search is not None:
        print("wa_merge --check-search: why can't WhatsApp search find a message? (changes nothing)\n")
        return check_search(a.check_search)
    if a.fix_search:
        print("wa_merge --fix-search: make every message findable by WhatsApp search\n")
        return fix_search()
    if a.redo_merge:
        for f in (MERGED_OK, NEW_DB, NEW_DB + "-journal", NEW_DB + "-wal"):
            if os.path.exists(f):
                os.remove(f)
        print("Starting the merge again from a fresh current-phone backup.")
    checks()

    # ---- the old phone's database: decrypt once, repair its search index, check it
    if not os.path.exists(OLD_READY):
        print(f"\nSTEP A - unlock the old phone's backup ({gb(os.path.getsize(OLD_BACKUP))})")
        for f in (OLD_DB, OLD_DB + "-journal", OLD_DB + "-wal"):
            if os.path.exists(f):
                os.remove(f)
        while True:
            k = ask_key("OLD phone's 64-digit key")
            try:
                decrypt_file(OLD_BACKUP, k, OLD_DB, "decrypting the old backup")
                break
            except WrongKey:
                print("  That key doesn't open this backup. Check you're using the OLD phone's key, not the current one's.")
        del k
        log("repairing the search index (a few minutes, no output - normal)")
        c = sqlite3.connect(OLD_DB)
        c.execute("INSERT INTO message_ftsv2(message_ftsv2) VALUES('rebuild')")
        c.commit()
        log("checking the old database (a few minutes)")
        ok = c.execute("PRAGMA quick_check").fetchone()[0]
        n = c.execute("SELECT count(*) FROM message").fetchone()[0]
        c.close()
        if ok != "ok":
            stop(f"the old database reports a problem: {ok}\nCopy this message if you ask for help.")
        open(OLD_READY, "w").write("ok")
        log(f"old database ready: {n:,} messages")
    else:
        log("old database already unlocked and checked (from an earlier run)")

    # ---- the current phone's database
    if not os.path.exists(MERGED_OK):
        src, original = find_current_backup()
        mtime = os.path.getmtime(src)
        age_min = (time.time() - mtime) / 60
        print(f"\nSTEP B - the current phone's backup: made {time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime))} "
              f"({age_min:.0f} minutes ago), {gb(os.path.getsize(src))}")
        print("Anything sent or received on WhatsApp AFTER that backup will not be in the merged result.")
        print("Best: turn on AIRPLANE MODE (Wi-Fi off), make a fresh backup in WhatsApp, and keep the phone")
        print("offline until the restore is done.")
        if not ask_yes("Is this backup fresh and is the phone offline?"):
            stop("turn on airplane mode, make a fresh backup (WhatsApp > Settings > Chats > Chat backup > Back up), "
                 "and run this again")
        shutil.copy2(src, original + ".part")
        os.replace(original + ".part", original)
        log(f"kept an untouched copy of the current phone's backup: {original}")
        for f in (NEW_DB, NEW_DB + "-journal", NEW_DB + "-wal"):
            if os.path.exists(f):
                os.remove(f)
        while True:
            cur_key = ask_key("CURRENT phone's 64-digit key")
            try:
                decrypt_file(original, cur_key, NEW_DB, "decrypting the current backup")
                break
            except WrongKey:
                print("  That key doesn't open the current phone's backup. Check you're using the CURRENT phone's key.")

        print("\nSTEP C - merge. The original backup files are not touched; this works on unlocked copies.")
        report = run_merge(OLD_DB, NEW_DB)
        open(MERGED_OK, "w").write("ok")
        print_report(report)
        if not ask_yes("Does this look right? Continue to make the restorable backup file?"):
            print("\nStopped here. Run the script again later to continue from this point.")
            return
    else:
        log("merge already done (from an earlier run)")
        original = os.path.join(OUT_DIR, "current-original.crypt15")
        if not os.path.isfile(original):
            stop(f"the untouched copy of the current backup is missing ({original}). Run again with --redo-merge.")
        cur_key = None

    # ---- encrypt for restore
    print("\nSTEP D - lock the merged database as a WhatsApp backup (with the current phone's key)")
    for f in (NEW_DB + "-wal", NEW_DB + "-journal"):
        if os.path.exists(f) and os.path.getsize(f) > 0:
            stop(f"unexpected leftover file {f}. Run again with --redo-merge.")
    out = os.path.join(OUT_DIR, "msgstore.db.crypt15")
    while True:
        if not cur_key:
            cur_key = ask_key("CURRENT phone's 64-digit key")
        try:
            encrypt_file(NEW_DB, cur_key, original, out)
            break
        except WrongKey:
            print("  That key doesn't match the current phone's backup.")
            cur_key = None
    del cur_key
    log(f"done: {out} ({gb(os.path.getsize(out))})")

    if ask_yes("Delete the unlocked (readable) copies of your chats now? (say no if you may need a second try)"):
        for f in os.listdir(WORK):
            p = os.path.join(WORK, f)
            if os.path.isfile(p):
                os.remove(p)
        log("deleted")

    print(f"""
ALL DONE. In {OUT_DIR} you now have:
  msgstore.db.crypt15        the merged backup (old + current chats)  <- the one to restore
  current-original.crypt15   your untouched current-phone backup      <- keep it: it's your undo

Next: follow the "Restore on Android" steps in the guide. Keep the phone offline until you reinstall WhatsApp.
The unlocked copies in {WORK} are readable chats: delete them when you're done (or uninstall Termux).""")
    if shutil.which("termux-wake-unlock"):
        subprocess.run(["termux-wake-unlock"], check=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped (Ctrl+C). Nothing was saved halfway; run the script again to continue.")
        sys.exit(1)
    except WrongKey:
        stop("wrong key")
