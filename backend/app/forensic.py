"""Forensic helpers: hashing, signature identification, safe metadata analysis, log parsing.
Uploaded files are NEVER executed; archives are only listed, never extracted."""
import hashlib, io, json, re, sys, zipfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

TOOL = "dfis-analyzer 1.0"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# ---------- timestamps ----------
_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def parse_ts(val):
    """Return (naive_utc_datetime | None, note). Never invents a missing time."""
    if val is None or str(val).strip() == "":
        return None, "missing timestamp"
    try:
        if isinstance(val, (int, float)) or re.fullmatch(r"\d{9,13}(\.\d+)?", str(val).strip()):
            x = float(val)
            x = x / 1000 if x > 1e11 else x
            return datetime.fromtimestamp(x, timezone.utc).replace(tzinfo=None), "epoch seconds interpreted as UTC"
        s = str(val).strip().replace(",", ".")
        m = re.fullmatch(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)", s)
        if m and m.group(1) in _MON:
            d = datetime(datetime.now(timezone.utc).year, _MON[m.group(1)], int(m.group(2)),
                         int(m.group(3)), int(m.group(4)), int(m.group(5)))
            return d, "syslog time has no year/timezone: assumed current year and UTC (ambiguous)"
        m = re.fullmatch(r"(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)", s)  # EXIF
        if m:
            return datetime(*map(int, m.groups())), "EXIF time has no timezone: assumed UTC (ambiguous)"
        m = re.match(r"D:(\d{4})(\d\d)(\d\d)(\d\d)?(\d\d)?(\d\d)?", s)  # PDF date
        if m:
            p = [int(x) if x else 0 for x in m.groups()]
            return datetime(p[0], p[1] or 1, p[2] or 1, p[3], p[4], p[5]), "PDF date; timezone offset ignored, assumed UTC"
        s2 = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s.replace("Z", "+00:00").replace(" ", "T", 1))
        d = datetime.fromisoformat(s2)
        if d.tzinfo is None:
            return d, "no timezone in source: assumed UTC"
        return d.astimezone(timezone.utc).replace(tzinfo=None), "timezone-aware ISO-8601 normalized to UTC"
    except (ValueError, OverflowError, OSError):
        return None, "unparseable timestamp"


# ---------- identification ----------
SIGS = [(b"%PDF-", "application/pdf", "PDF document"), (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image"),
        (b"\xff\xd8\xff", "image/jpeg", "JPEG image"), (b"GIF87a", "image/gif", "GIF image"),
        (b"GIF89a", "image/gif", "GIF image"), (b"PK\x03\x04", "application/zip", "ZIP container (may be DOCX/XLSX)"),
        (b"\x1f\x8b", "application/gzip", "GZIP data"), (b"MZ", "application/x-dosexec", "Windows executable (PE)"),
        (b"\x7fELF", "application/x-elf", "ELF executable"), (b"Rar!\x1a\x07", "application/vnd.rar", "RAR archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "OLE2 legacy Office document")]
EXT_MIME = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".zip": "application/zip", ".docx": "application/zip", ".xlsx": "application/zip"}


def identify(path):
    with open(path, "rb") as f:
        head = f.read(4096)
    for sig, mime, desc in SIGS:
        if head.startswith(sig):
            return {"mime": mime, "description": desc, "method": "file signature"}
    if head[:2] == b"BM" and head[6:10] == b"\0\0\0\0":
        return {"mime": "image/bmp", "description": "BMP image", "method": "file signature"}
    if b"\0" not in head:
        try:
            head.decode("utf-8")
            return {"mime": "text/plain", "description": "Text (UTF-8 compatible)", "method": "content heuristic"}
        except UnicodeDecodeError:
            pass
    return {"mime": "application/octet-stream", "description": "Unknown binary", "method": "no signature matched"}


def _lib_versions():
    v = {"python": sys.version.split()[0], "analyzer": TOOL}
    for mod in ("PIL", "pypdf", "defusedxml", "magic"):
        try:
            m = __import__(mod)
            v[mod] = getattr(m, "__version__", "available")
        except Exception:
            v[mod] = "not installed"
    return v


def _short(x, n=200):
    return str(x)[:n]


def analyze_file(path, name):
    """Returns dict: observations (facts), interpretations (analyst-style notes), timestamps, warnings, tools."""
    p = Path(path)
    ident = identify(p)
    obs = {"size_bytes": p.stat().st_size, "sha256": sha256_file(p), "detected_mime": ident["mime"],
           "detected_type": ident["description"], "identification_method": ident["method"]}
    interp, warns, stamps, ext = [], [], [], Path(name).suffix.lower()
    try:
        import magic  # optional
        obs["libmagic"] = magic.from_file(str(p))
    except Exception:
        pass
    exp = EXT_MIME.get(ext)
    if exp and exp != ident["mime"]:
        interp.append(f"Extension '{ext}' normally implies {exp} but the signature indicates {ident['mime']}. "
                      "This mismatch warrants review; it does not by itself prove concealment.")
    if ident["mime"] in ("application/x-dosexec", "application/x-elf"):
        interp.append("Executable signature detected. The file was NOT executed.")
    mime = ident["mime"]
    try:
        if mime.startswith("image/"):
            _image(p, obs, stamps, warns)
        elif mime == "application/pdf":
            _pdf(p, obs, stamps, warns, interp)
        elif mime == "application/zip":
            _zip(p, ext, obs, stamps, warns, interp)
        elif mime == "text/plain":
            t = p.read_bytes()[:2_000_000].decode("utf-8", "replace")
            obs["line_count_first_2MB"] = t.count("\n") + 1
            obs["text_preview"] = t[:3000]
    except Exception as e:  # parser failure on corrupted/malformed files
        warns.append(f"Parser failed ({type(e).__name__}): file may be corrupted or malformed.")
    return {"observations": obs, "interpretations": interp, "timestamps": stamps, "warnings": warns,
            "tools": _lib_versions(),
            "note": "Observations are measured properties; interpretations are tentative and require expert review."}


def _image(p, obs, stamps, warns):
    from PIL import Image, ExifTags
    with Image.open(p) as im:
        obs.update(image_format=im.format, image_size=list(im.size), image_mode=im.mode)
        ex = im.getexif()
        tags = {}
        for k, v in list(ex.items())[:60]:
            tags[ExifTags.TAGS.get(k, str(k))] = _short(v)
        try:
            for k, v in ex.get_ifd(0x8769).items():
                tags[ExifTags.TAGS.get(k, str(k))] = _short(v)
        except Exception:
            pass
        if tags:
            obs["exif"] = tags
        for label in ("DateTimeOriginal", "DateTime", "DateTimeDigitized"):
            if label in tags:
                stamps.append({"label": "EXIF " + label, "value": tags[label]})
    with Image.open(p) as im2:
        im2.verify()


def _pdf(p, obs, stamps, warns, interp):
    from pypdf import PdfReader
    raw = p.read_bytes()[:10_000_000]
    flags = [k.decode() for k in (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile") if k in raw]
    if flags:
        obs["pdf_active_content_keywords"] = flags
        interp.append("PDF contains keywords associated with active/embedded content; nothing was executed.")
    r = PdfReader(str(p))
    obs["pdf_pages"], obs["pdf_encrypted"] = len(r.pages), bool(r.is_encrypted)
    if not r.is_encrypted:
        md = {str(k): _short(v) for k, v in (r.metadata or {}).items()}
        obs["pdf_metadata"] = md
        for k in ("/CreationDate", "/ModDate"):
            if k in md:
                stamps.append({"label": "PDF " + k.strip("/"), "value": md[k]})
        obs["text_preview"] = "\n".join((pg.extract_text() or "") for pg in r.pages[:5])[:3000]


def _zip(p, ext, obs, stamps, warns, interp):
    with zipfile.ZipFile(p) as z:
        infos = z.infolist()
        total = sum(i.file_size for i in infos)
        obs["zip_entries"], obs["zip_uncompressed_bytes"] = len(infos), total
        obs["zip_listing"] = [{"name": _short(i.filename, 120), "size": i.file_size} for i in infos[:200]]
        bad = [i.filename for i in infos if ".." in i.filename.split("/") or i.filename.startswith("/")]
        if bad:
            interp.append("Archive has entries with path-traversal style names; archive was NOT extracted.")
        if total > 500 * p.stat().st_size + 10_000_000:
            interp.append("Very high compression ratio (possible archive bomb); contents were not expanded.")
            return
        names = {i.filename for i in infos}
        if any(n.endswith("vbaProject.bin") for n in names):
            obs["office_macros_present"] = True
            interp.append("Office document contains a VBA project (macros). Macros were not run.")
        from defusedxml import ElementTree as ET
        if "docProps/core.xml" in names and z.getinfo("docProps/core.xml").file_size < 1_000_000:
            root = ET.fromstring(z.read("docProps/core.xml"))
            core = {el.tag.split("}")[1]: _short(el.text) for el in root if el.text}
            obs["office_core_properties"] = core
            for k in ("created", "modified"):
                if k in core:
                    stamps.append({"label": "Office " + k, "value": core[k]})
        if ext == ".docx" and "word/document.xml" in names and z.getinfo("word/document.xml").file_size < 20_000_000:
            root = ET.fromstring(z.read("word/document.xml"))
            txt = " ".join(t.text for t in root.iter() if t.tag.endswith("}t") and t.text)
            obs["text_preview"] = txt[:3000]


# ---------- log parsing ----------
DEFAULT_RULES = {"auth_failure_threshold": 5, "window_minutes": 10,
                 "privilege_keywords": ["sudo", "su:", "privilege", "escalat", "added to group", "setuid"],
                 "custom_keywords": []}
_CLASS = [("auth_failure", r"failed password|authentication fail|invalid user|login failed|failed login|incorrect password|access denied"),
          ("auth_success", r"accepted (password|publickey)|login succe|successful login|session opened"),
          ("privilege", r"sudo|\bsu:|privilege|escalat|added to group|setuid|administrator")]
_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(?P<rest>.+)$")
_SYS = re.compile(r"^(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
_USER1 = re.compile(r"user(?:name)?[=: ]+([\w.@-]{1,64})", re.I)
_USER2 = re.compile(r"\bfor (?:invalid user )?([\w.@-]{1,64})", re.I)


def classify(msg):
    for name, rx in _CLASS:
        if re.search(rx, msg, re.I):
            return name
    return "general"


def _user(msg):
    m = _USER1.search(msg) or _USER2.search(msg)
    return m.group(1) if m else None


def parse_log(path, max_lines=200_000):
    """Parse JSON Lines or timestamped text logs. Returns (events, stats, errors)."""
    events, errors, total, fmt = [], [], 0, {"jsonl": 0, "text": 0}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if n > max_lines:
                errors.append({"line": n, "error": "line limit reached; remaining lines not parsed"})
                break
            line = line.rstrip("\n")
            if not line.strip():
                continue
            total += 1
            line = line[:5000]
            if line.lstrip().startswith("{"):
                try:
                    o = json.loads(line)
                    assert isinstance(o, dict)
                except Exception:
                    errors.append({"line": n, "error": "malformed JSON line"}); continue
                g = lambda *ks: next((o[k] for k in ks if k in o and o[k] not in (None, "")), None)
                msg = str(g("message", "msg", "event", "text") or "")
                ts_raw = g("timestamp", "time", "ts", "@timestamp", "datetime")
                ts, note = parse_ts(ts_raw)
                events.append(dict(line_no=n, ts_utc=ts, ts_original=None if ts_raw is None else str(ts_raw)[:80], ts_note=note,
                                   event_type=str(g("event_type", "type", "category") or classify(msg))[:30],
                                   source=(lambda s: None if s is None else str(s)[:120])(g("source", "host", "hostname", "service")),
                                   username=(lambda s: None if s is None else str(s)[:80])(g("user", "username", "account") or _user(msg)),
                                   message=msg[:2000]))
                fmt["jsonl"] += 1
                continue
            m = _TS.match(line)
            if not m:
                errors.append({"line": n, "error": "no recognizable timestamp (unsupported or malformed line)"}); continue
            ts, note = parse_ts(m.group("ts"))
            rest, src = m.group("rest"), None
            s = _SYS.match(rest)
            if s:
                src, rest = f"{s.group('host')}/{s.group('proc')}", s.group("msg")
            events.append(dict(line_no=n, ts_utc=ts, ts_original=m.group("ts")[:80], ts_note=note, event_type=classify(rest),
                               source=src, username=_user(rest), message=rest[:2000]))
            fmt["text"] += 1
    stats = {"non_empty_lines": total, "parsed": len(events), "malformed": len(errors), "formats_seen": fmt}
    return events, stats, errors[:50]


def detect_indicators(events, rules):
    """Configurable heuristics. Output = indicators requiring human review, NOT proof of wrongdoing."""
    r = {**DEFAULT_RULES, **(rules or {})}
    alerts, fails = [], defaultdict(list)
    for e in events:
        if e["event_type"] == "auth_failure" and e["ts_utc"]:
            fails[e["username"] or e["source"] or "unknown"].append(e["ts_utc"])
    win = timedelta(minutes=int(r["window_minutes"]))
    for key, ts in fails.items():
        ts.sort()
        i = 0
        for j in range(len(ts)):
            while ts[j] - ts[i] > win:
                i += 1
            if j - i + 1 >= int(r["auth_failure_threshold"]):
                alerts.append({"rule": "repeated_authentication_failures", "subject": key, "count": j - i + 1,
                               "first": ts[i].isoformat() + "Z", "last": ts[j].isoformat() + "Z",
                               "text": f"{j - i + 1} failures within {r['window_minutes']} min for '{key}'"})
                break
    kws = [k.lower() for k in r["privilege_keywords"]]
    for e in events:
        if any(k in e["message"].lower() for k in kws):
            alerts.append({"rule": "privilege_related_event", "subject": e["username"] or e["source"], "line": e["line_no"],
                           "text": e["message"][:200]})
        for k in r.get("custom_keywords", []):
            if k and k.lower() in e["message"].lower():
                alerts.append({"rule": "custom_keyword", "subject": k, "line": e["line_no"], "text": e["message"][:200]})
    return [{**a, "disclaimer": "Indicator requiring review; not proof of malicious or criminal activity."} for a in alerts[:200]]


def group_events(events):
    g = defaultdict(int)
    for e in events:
        g[(e["event_type"], e["source"] or "-")] += 1
    return [{"event_type": k[0], "source": k[1], "count": v} for k, v in sorted(g.items(), key=lambda x: -x[1])[:25]]
