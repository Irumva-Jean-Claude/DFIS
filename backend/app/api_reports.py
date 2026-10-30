"""PDF forensic report generation (ReportLab)."""
from xml.sax.saxutils import escape
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from . import config
from .db import *  # noqa
from .db import now, iso
from .security import require, get_case, audit, case_filter
from .api_evidence import uname
from .forensic import TOOL, _lib_versions

reports_r = APIRouter(prefix="/reports", tags=["reports"])


class ReportIn(BaseModel):
    case_id: str
    conclusions: str = Field(default="", max_length=8000)
    limitations: str = Field(default="", max_length=8000)
    notes: str = Field(default="", max_length=8000)


def collect(db, case):
    inv = [r for r, in db.execute(select(User.full_name).join(CaseAssignment, CaseAssignment.user_id == User.id).where(CaseAssignment.case_id == case.id))]
    evs = db.scalars(select(Evidence).where(Evidence.case_id == case.id).order_by(Evidence.created_at)).all()
    out = []
    for e in evs:
        ic = db.scalar(select(IntegrityCheck).where(IntegrityCheck.evidence_id == e.id).order_by(IntegrityCheck.created_at.desc()))
        fa = db.scalar(select(AnalysisResult).where(AnalysisResult.evidence_id == e.id, AnalysisResult.kind == "file", AnalysisResult.status == "completed").order_by(AnalysisResult.created_at.desc()))
        la = db.scalar(select(AnalysisResult).where(AnalysisResult.evidence_id == e.id, AnalysisResult.kind == "log", AnalysisResult.status == "completed").order_by(AnalysisResult.created_at.desc()))
        cu = db.scalars(select(CustodyEvent).where(CustodyEvent.evidence_id == e.id).order_by(CustodyEvent.created_at)).all()
        out.append({"e": e, "ic": ic, "fa": fa, "la": la, "cu": cu})
    tl = db.scalars(select(TimelineEvent).where(TimelineEvent.case_id == case.id, TimelineEvent.utc.is_not(None)).order_by(TimelineEvent.utc).limit(60)).all()
    return inv, out, tl


@reports_r.post("/preview")
def preview(b: ReportIn, u=Depends(require("report:create")), db=Depends(get_db)):
    c = get_case(db, u, b.case_id)
    inv, ev, tl = collect(db, c)
    return {"case": {"ref": c.ref, "title": c.title, "status": c.status, "description": c.description}, "investigators": inv,
            "evidence": [{"ref": x["e"].ref, "file": x["e"].original_filename, "sha256": x["e"].sha256,
                          "last_integrity": x["ic"].result if x["ic"] else "not verified",
                          "file_analysis": "yes" if x["fa"] else "no", "log_analysis": "yes" if x["la"] else "no",
                          "custody_events": len(x["cu"])} for x in ev],
            "timeline_events": len(tl), "next_version": (db.scalar(select(func.count(Report.id)).where(Report.case_id == c.id)) or 0) + 1}


def P(s):
    return escape(str(s if s is not None else ""))


def build_pdf(path, db, case, b, author, ref, version, rid):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    ss = getSampleStyleSheet()
    N, H1, H2, S = ss["BodyText"], ss["Heading1"], ss["Heading2"], ss["BodyText"].clone("s", fontSize=7.5, leading=9)
    inv, evs, tl = collect(db, case)
    st = []
    para = lambda t, s=N: st.append(Paragraph(P(t).replace("\n", "<br/>"), s))

    def table(rows, widths):
        t = Table([[Paragraph(P(c), S) for c in r] for r in rows], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe6ee")), ("GRID", (0, 0), (-1, -1), .4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        st.extend([t, Spacer(1, 8)])

    para(config.ORG_NAME, H2); para("Digital Forensic Investigation Report", H1)
    table([["Report ID", rid], ["Reference / Version", f"{ref} / v{version}"], ["Case", f"{case.ref} - {case.title}"],
           ["Created (UTC)", iso(now())], ["Author", author.full_name], ["Investigators", ", ".join(inv)]], [110, 380])
    para("1. Case summary", H2); para(case.description or "(no description)")
    para("2. Evidence inventory", H2)
    table([["Ref", "File", "Type", "Size", "SHA-256 (reference)"]] + [[x["e"].ref, x["e"].original_filename, x["e"].mime, x["e"].size, x["e"].sha256] for x in evs] if evs else [["No evidence registered"]], [55, 100, 70, 40, 230] if evs else [490])
    para("3. Acquisition and chain of custody", H2)
    rows = [["Evidence", "Time (UTC)", "Action", "From", "To", "Reason"]]
    for x in evs:
        for c in x["cu"]:
            rows.append([x["e"].ref, iso(c.created_at), c.action, uname(db, c.from_user_id) or "-", uname(db, c.to_user_id) or "-", c.reason])
    table(rows, [50, 85, 75, 70, 70, 140])
    para("4. SHA-256 integrity verification", H2)
    table([["Evidence", "Latest result", "Time (UTC)"]] + [[x["e"].ref, x["ic"].result if x["ic"] else "NOT VERIFIED", iso(x["ic"].created_at) if x["ic"] else "-"] for x in evs], [120, 150, 150])
    para("A matching hash supports integrity relative to the recorded reference value only. It does not prove authenticity or lawful acquisition.", S)
    para("5. File and metadata analysis (observations)", H2)
    for x in evs:
        if x["fa"] and x["fa"].result:
            o = x["fa"].result["observations"]
            para(f"{x['e'].ref}: type={o.get('detected_type')}, mime={o.get('detected_mime')}, size={o.get('size_bytes')}", S)
            for i in x["fa"].result.get("interpretations", []):
                para("Interpretation (tentative): " + i, S)
    para("6. Log analysis (indicators requiring review - not proof of wrongdoing)", H2)
    for x in evs:
        if x["la"] and x["la"].result:
            r = x["la"].result
            para(f"{x['e'].ref}: parsed={r['stats']['parsed']}, malformed={r['stats']['malformed']}, indicators={len(r['alerts'])}", S)
            for a in r["alerts"][:10]:
                para(f"- {a['rule']}: {a['text']}", S)
    para("7. Timeline (UTC-normalized, first 60 dated events)", H2)
    table([["UTC", "Category", "Event", "Original / note"]] + [[iso(t.utc), t.kind, t.title, f"{t.original_ts or ''} / {t.note or ''}"] for t in tl] if tl else [["No timeline events"]], [90, 50, 170, 180] if tl else [490])
    para("8. Methods and tool versions", H2); para(f"{TOOL}; " + ", ".join(f"{k} {v}" for k, v in _lib_versions().items()))
    para("9. Limitations and unresolved questions", H2); para(b.limitations or "None recorded by the author.")
    para("10. Investigator notes and conclusions (author's interpretation)", H2); para(b.notes or "(none)"); para(b.conclusions or "(no conclusions recorded)")
    para("Disclaimer: Prototype output for academic use. It is not forensically certified or legally validated. Observations are separated from interpretations; incomplete evidence may limit conclusions.", S)

    def footer(cv, doc):
        cv.setFont("Helvetica", 7); cv.drawString(40, 25, f"{rid}  |  {ref} v{version}  |  page {doc.page}")
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=45).build(st, onFirstPage=footer, onLaterPages=footer)


@reports_r.post("", status_code=201)
def generate(b: ReportIn, u=Depends(require("report:create")), db=Depends(get_db)):
    c = get_case(db, u, b.case_id)
    version = (db.scalar(select(func.count(Report.id)).where(Report.case_id == c.id)) or 0) + 1
    n = (db.scalar(select(func.count(Report.id))) or 0) + 1
    r = Report(ref=f"RPT-{now().year}-{n:04d}", case_id=c.id, version=version, filename=uid() + ".pdf", by_user_id=u.id)
    db.add(r); db.flush()
    try:
        build_pdf(config.REPORTS / r.filename, db, c, b, u, r.ref, version, r.id)
    except Exception as ex:
        db.rollback()
        audit(db, u, "report_generation", "case", c.id, "failure", error=type(ex).__name__)
        raise HTTPException(500, "Report generation failed")
    db.commit()
    audit(db, u, "report_generated", "report", r.id, ref=r.ref, version=version)
    return {"id": r.id, "ref": r.ref, "version": version}


@reports_r.get("")
def list_reports(u=Depends(require("report:read")), db=Depends(get_db), case_id: str = ""):
    st = select(Report, Case.ref).join(Case, Case.id == Report.case_id).where(case_filter(u)).order_by(Report.created_at.desc()).limit(200)
    if case_id:
        st = st.where(Report.case_id == case_id)
    return [{"id": r.id, "ref": r.ref, "case_ref": cr, "version": r.version, "by_user": uname(db, r.by_user_id), "created_at": iso(r.created_at)} for r, cr in db.execute(st)]


@reports_r.get("/{rid}/download")
def download(rid: str, u=Depends(require("report:read")), db=Depends(get_db)):
    r = db.scalar(select(Report).join(Case, Case.id == Report.case_id).where(Report.id == rid, case_filter(u)))
    if not r:
        raise HTTPException(404, "Report not found")
    audit(db, u, "report_downloaded", "report", r.id)
    return FileResponse(config.REPORTS / r.filename, media_type="application/pdf", filename=f"{r.ref}_v{r.version}.pdf")
