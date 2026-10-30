"""Evidence ingestion, chain of custody and integrity verification."""
import csv, io, os, re, shutil
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_
from . import config
from .db import *  # noqa
from .db import now, iso
from .security import require, get_case, get_evidence, case_filter, audit, current_user
from .forensic import sha256_file, identify, parse_ts
from .api_core import paginate

evidence_r = APIRouter(prefix="/evidence", tags=["evidence"])
integrity_r = APIRouter(prefix="/integrity", tags=["integrity"])
custody_r = APIRouter(prefix="/chain-of-custody", tags=["chain-of-custody"])


def safe_name(name):
    n = os.path.basename((name or "").replace("\\", "/"))
    n = re.sub(r"[\x00-\x1f]", "", n)
    n = re.sub(r"[^A-Za-z0-9._ -]", "_", n)[:150].strip()
    if not n or n.startswith("."):
        raise HTTPException(400, "Invalid filename")
    return n


def orig_path(e):
    p = (config.ORIGINALS / e.storage_name).resolve()
    if config.ORIGINALS.resolve() not in p.parents:
        raise HTTPException(500, "Storage error")
    return p


def uname(db, uid_):
    x = db.get(User, uid_) if uid_ else None
    return x.full_name if x else None


def ev_out(db, e):
    c = db.get(Case, e.case_id)
    return {"id": e.id, "ref": e.ref, "case_id": e.case_id, "case_ref": c.ref, "evidence_type": e.evidence_type,
            "original_filename": e.original_filename, "description": e.description, "source": e.source,
            "acquisition_method": e.acquisition_method, "acquisition_date": e.acquisition_raw,
            "acquisition_utc": iso(e.acquisition_utc), "submitted_by": e.submitted_by, "received_by": e.received_by,
            "mime": e.mime, "size": e.size, "sha256": e.sha256, "hashed_at": iso(e.hashed_at), "status": e.status,
            "custodian": uname(db, e.custodian_id), "uploaded_by": uname(db, e.uploaded_by), "created_at": iso(e.created_at)}


def cust(db, **kw):
    ev = CustodyEvent(**kw)
    db.add(ev)
    return ev


@evidence_r.post("", status_code=201)
def upload(case_id: str = Form(...), evidence_type: str = Form(...), source: str = Form(..., max_length=200),
           acquisition_method: str = Form(..., max_length=200), acquisition_date: str = Form(""),
           submitted_by: str = Form(..., max_length=100), received_by: str = Form(..., max_length=100),
           description: str = Form("", max_length=2000), file: UploadFile = File(...),
           u=Depends(require("evidence:upload")), db=Depends(get_db)):
    case = get_case(db, u, case_id)
    if case.status in ("closed", "archived"):
        raise HTTPException(409, "Evidence cannot be added to a closed or archived case")
    if evidence_type not in config.EVIDENCE_TYPES:
        raise HTTPException(422, f"evidence_type must be one of {config.EVIDENCE_TYPES}")
    name = safe_name(file.filename)
    if Path(name).suffix.lower() not in config.ALLOWED_EXT:
        audit(db, u, "evidence_rejected", "case", case.id, "failure", reason="file type not allowed", filename=name)
        raise HTTPException(415, "File type not allowed")
    sname = uid()
    tmp = config.TMP / sname
    size = 0
    try:
        with open(tmp, "wb") as out:  # controlled ingestion: stream, size-limit and hash in one pass
            while chunk := file.file.read(1 << 20):
                size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File exceeds the {config.MAX_UPLOAD_BYTES // 1048576} MB limit")
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "Empty file")
        digest = sha256_file(tmp)
        final = config.ORIGINALS / sname
        shutil.move(str(tmp), final)
        os.chmod(final, 0o444)  # immutable reference copy (read-only at filesystem level)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    ts = parse_ts(acquisition_date) if acquisition_date.strip() else (None, None)
    n = db.scalar(select(func.count(Evidence.id))) + 1
    e = Evidence(ref=f"EVD-{now().year}-{n:05d}", case_id=case.id, evidence_type=evidence_type, original_filename=name,
                 description=description, source=source, acquisition_method=acquisition_method,
                 acquisition_raw=acquisition_date.strip() or None, acquisition_utc=ts[0], acquisition_note=ts[1],
                 submitted_by=submitted_by, received_by=received_by, mime=identify(final)["mime"], size=size,
                 sha256=digest, hashed_at=now(), storage_name=sname, custodian_id=u.id, uploaded_by=u.id)
    db.add(e); db.flush()
    cust(db, evidence_id=e.id, case_id=case.id, action="INGESTED", to_user_id=u.id, by_user_id=u.id,
         reason="Initial ingestion", notes=f"SHA-256 {digest}")
    db.commit()
    audit(db, u, "evidence_registered", "evidence", e.id, ref=e.ref, size=size)
    audit(db, u, "hash_calculated", "evidence", e.id, algorithm="SHA-256", sha256=digest)
    return ev_out(db, e)


def _filtered(u, case_id="", q="", etype=""):
    st = select(Evidence).join(Case, Case.id == Evidence.case_id).where(case_filter(u)).order_by(Evidence.created_at.desc())
    if case_id:
        st = st.where(Evidence.case_id == case_id)
    if etype:
        st = st.where(Evidence.evidence_type == etype)
    if q:
        st = st.where(or_(Evidence.ref.ilike(f"%{q}%"), Evidence.original_filename.ilike(f"%{q}%"), Evidence.sha256.ilike(f"{q}%")))
    return st


@evidence_r.get("")
def list_evidence(u=Depends(require("evidence:read")), db=Depends(get_db), case_id: str = "", q: str = "",
                  evidence_type: str = "", page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=200)):
    rows, total = paginate(db, _filtered(u, case_id, q, evidence_type), page, size)
    return {"items": [ev_out(db, e) for e in rows], "total": total, "page": page, "size": size}


@evidence_r.get("/export")
def export(u=Depends(require("evidence:read")), db=Depends(get_db), case_id: str = ""):
    from .forensic import TOOL  # noqa
    from .util import csv_safe
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["ref", "case_ref", "evidence_type", "original_filename", "mime", "size", "sha256", "hashed_at", "source",
            "acquisition_method", "acquisition_date", "submitted_by", "received_by", "custodian", "status"]
    w.writerow(cols)
    for e in db.scalars(_filtered(u, case_id)):
        d = ev_out(db, e)
        w.writerow([csv_safe(d[c]) for c in cols])
    audit(db, u, "evidence_inventory_exported", "case", case_id or None)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=evidence_inventory.csv"})


@evidence_r.get("/{eid}")
def get_one(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    return ev_out(db, get_evidence(db, u, eid))


@evidence_r.get("/{eid}/download")
def download(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    p = orig_path(e)
    if not p.exists():
        raise HTTPException(404, "Stored file is missing")
    audit(db, u, "evidence_downloaded", "evidence", e.id, ref=e.ref)
    return FileResponse(p, media_type="application/octet-stream", filename=e.original_filename,
                        headers={"X-Content-Type-Options": "nosniff"})


# ---------------- custody ----------------
def cust_out(db, c, acked):
    return {"id": c.id, "action": c.action, "from_user": uname(db, c.from_user_id), "to_user": uname(db, c.to_user_id),
            "to_user_id": c.to_user_id, "by_user": uname(db, c.by_user_id), "reason": c.reason, "notes": c.notes,
            "case_ref": db.get(Case, c.case_id).ref, "ref_event_id": c.ref_event_id, "created_at": iso(c.created_at),
            "ack_status": ("acknowledged" if c.id in acked else "pending") if c.action == "TRANSFER" else None}


@custody_r.get("/{eid}")
def custody_history(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    rows = db.scalars(select(CustodyEvent).where(CustodyEvent.evidence_id == e.id).order_by(CustodyEvent.created_at)).all()
    acked = {r.ref_event_id for r in rows if r.action == "ACKNOWLEDGED"}
    audit(db, u, "custody_record_viewed", "evidence", e.id)
    return {"evidence": ev_out(db, e), "events": [cust_out(db, c, acked) for c in rows]}


class Transfer(BaseModel):
    to_user_id: str
    reason: str = Field(min_length=3, max_length=1000)
    notes: str = Field(default="", max_length=2000)


@custody_r.post("/{eid}/transfer")
def transfer(eid: str, b: Transfer, u=Depends(require("custody:transfer")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    if e.status == "transfer_pending":
        raise HTTPException(409, "A transfer is already awaiting acknowledgment")
    if u.role not in ("admin", "lead") and e.custodian_id != u.id:
        raise HTTPException(403, "Only the current custodian (or a lead/admin) can transfer this evidence")
    to = db.get(User, b.to_user_id)
    if not to or not to.is_active:
        raise HTTPException(404, "Recipient not found")
    try:
        get_case(db, to, e.case_id)
    except HTTPException:
        raise HTTPException(400, "Recipient is not assigned to this case")
    c = cust(db, evidence_id=e.id, case_id=e.case_id, action="TRANSFER", from_user_id=e.custodian_id, to_user_id=to.id,
             by_user_id=u.id, reason=b.reason, notes=b.notes)
    e.status = "transfer_pending"
    db.commit()
    audit(db, u, "custody_transfer", "evidence", e.id, to=to.username)
    return {"ok": True, "event_id": c.id}


@custody_r.post("/{eid}/acknowledge/{event_id}")
def acknowledge(eid: str, event_id: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    t = db.get(CustodyEvent, event_id)
    if not t or t.evidence_id != e.id or t.action != "TRANSFER":
        raise HTTPException(404, "Transfer not found")
    if t.to_user_id != u.id:
        raise HTTPException(403, "Only the receiving custodian can acknowledge this transfer")
    if db.scalar(select(CustodyEvent.id).where(CustodyEvent.ref_event_id == t.id, CustodyEvent.action == "ACKNOWLEDGED")):
        raise HTTPException(409, "Already acknowledged")
    cust(db, evidence_id=e.id, case_id=e.case_id, action="ACKNOWLEDGED", from_user_id=t.from_user_id, to_user_id=u.id,
         by_user_id=u.id, reason="Receipt acknowledged", ref_event_id=t.id)
    e.custodian_id, e.status = u.id, "in_custody"
    db.commit()
    audit(db, u, "custody_acknowledged", "evidence", e.id)
    return {"ok": True}


class Correction(BaseModel):
    ref_event_id: str
    notes: str = Field(min_length=5, max_length=2000)


@custody_r.post("/{eid}/correction")
def correction(eid: str, b: Correction, u=Depends(require("users:manage")), db=Depends(get_db)):
    """History is never edited; admins can only append an explicit correction note referencing an event."""
    e = get_evidence(db, u, eid)
    cust(db, evidence_id=e.id, case_id=e.case_id, action="CORRECTION_NOTE", by_user_id=u.id, ref_event_id=b.ref_event_id,
         reason="Administrative correction note", notes=b.notes)
    db.commit()
    audit(db, u, "custody_correction_note", "evidence", e.id, ref_event_id=b.ref_event_id)
    return {"ok": True}


# ---------------- integrity ----------------
MSG = {"MATCH": "Recalculated SHA-256 matches the recorded reference value. This supports integrity relative to that "
                "reference only; it does not prove authenticity or lawful acquisition.",
       "MISMATCH": "Recalculated SHA-256 does NOT match the recorded reference value. The stored file differs from what was ingested. Investigate and document.",
       "ERROR": "Integrity verification could not be completed (file missing or unreadable)."}


@integrity_r.post("/{eid}/verify")
def verify(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    calc = None
    try:
        calc = sha256_file(orig_path(e))
        res = "MATCH" if calc == e.sha256 else "MISMATCH"
    except Exception:
        res = "ERROR"
    ic = IntegrityCheck(evidence_id=e.id, result=res, calculated=calc, reference=e.sha256, by_user_id=u.id)
    db.add(ic); db.commit()
    audit(db, u, "integrity_check", "evidence", e.id, "success" if res != "ERROR" else "failure", result=res)
    return {"id": ic.id, "result": res, "calculated": calc, "reference": e.sha256, "at": iso(ic.created_at), "message": MSG[res]}


@integrity_r.get("/{eid}")
def integrity_history(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    rows = db.scalars(select(IntegrityCheck).where(IntegrityCheck.evidence_id == e.id).order_by(IntegrityCheck.created_at.desc()).limit(50))
    return [{"id": r.id, "result": r.result, "calculated": r.calculated, "reference": r.reference,
             "by_user": uname(db, r.by_user_id), "at": iso(r.created_at), "message": MSG[r.result]} for r in rows]
