"""File, metadata, log analysis, and timeline endpoints.

Analyses run against working copies. The original evidence file is never modified.
"""
import csv
import io
import shutil
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from . import config
from .db import *  # noqa: F403
from .db import iso, now
from .security import require, get_case, get_evidence, audit
from .forensic import (
    analyze_file,
    parse_log,
    detect_indicators,
    group_events,
    parse_ts,
    DEFAULT_RULES,
    TOOL,
)
from .api_core import paginate
from .api_evidence import orig_path, uname
from .util import csv_safe


file_r = APIRouter(prefix="/file-analysis", tags=["file-analysis"])
log_r = APIRouter(prefix="/log-analysis", tags=["log-analysis"])
timeline_r = APIRouter(prefix="/timeline", tags=["timeline"])

MAX_STORED_LOG_EVENTS = 100_000
MAX_TIMELINE_UNDATED = 100


# -------------------------------------------------------------------
# Shared helpers
# -------------------------------------------------------------------

def working_copy(e):
    """Create a temporary working copy of an evidence file."""
    src = orig_path(e)

    if not src.exists():
        raise FileNotFoundError("Original evidence file is missing")

    config.WORKING.mkdir(parents=True, exist_ok=True)

    dst = config.WORKING / f"{e.storage_name}.{uid()}"
    shutil.copyfile(src, dst)

    try:
        dst.chmod(0o600)
    except OSError:
        try:
            dst.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return dst


def run_job(db, u, e, kind, fn):
    """Run an analysis and persist its success or failure status."""
    job = AnalysisResult(
        evidence_id=e.id,
        kind=kind,
        status="running",
        by_user_id=u.id,
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    wc = None

    try:
        wc = working_copy(e)

        # fn may write derived records to the database.
        # Those writes are committed only when the analysis succeeds.
        result = fn(wc, job)

        job.result = result
        job.status = "completed"
        job.error = None
        job.finished_at = now()

        db.commit()
        db.refresh(job)

    except Exception as ex:
        # Roll back database changes made by a failed analysis.
        db.rollback()

        # The job was committed before analysis started.
        # Reload it so the failed status can be saved separately.
        db.refresh(job)

        job.status = "failed"
        job.result = None
        job.error = (
            f"{type(ex).__name__}: analysis could not be completed"
        )
        job.finished_at = now()

        db.commit()
        db.refresh(job)

    finally:
        if wc is not None:
            try:
                wc.unlink(missing_ok=True)
            except OSError:
                # Cleanup failure must not overwrite the analysis result.
                pass

    audit(
        db,
        u,
        f"{kind}_analysis",
        "evidence",
        e.id,
        "success" if job.status == "completed" else "failure",
        job_id=job.id,
    )

    return job


def job_out(db, j):
    """Serialize an analysis job for API responses."""
    return {
        "id": j.id,
        "kind": j.kind,
        "status": j.status,
        "error": j.error,
        "result": j.result,
        "by_user": uname(db, j.by_user_id),
        "created_at": iso(j.created_at),
        "finished_at": iso(j.finished_at),
    }


def parse_filter_timestamp(value: str, field_name: str):
    """Parse an optional timestamp query parameter or return HTTP 422."""
    if not value:
        return None

    parsed, _note = parse_ts(value)

    if parsed is None:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid {field_name} timestamp. Use ISO-8601.",
        )

    return parsed


def validate_time_range(start: str, end: str):
    """Validate and return an optional timestamp range."""
    start_dt = parse_filter_timestamp(start, "start")
    end_dt = parse_filter_timestamp(end, "end")

    if start_dt is not None and end_dt is not None and start_dt > end_dt:
        raise HTTPException(
            status_code=422,
            detail="Start timestamp must be earlier than or equal to end timestamp.",
        )

    return start_dt, end_dt


# -------------------------------------------------------------------
# File and metadata analysis
# -------------------------------------------------------------------

@file_r.post("/{eid}")
def run_file(
    eid: str,
    u=Depends(require("analysis:run")),
    db=Depends(get_db),
):
    e = get_evidence(db, u, eid)

    def fn(path, job):
        result = analyze_file(path, e.original_filename)

        observations = result.get("observations", {})
        observations["reference_hash_matches_working_copy"] = (
            observations.get("sha256") == e.sha256
        )
        result["observations"] = observations

        # Replace only metadata timeline entries generated for this evidence.
        db.execute(
            delete(TimelineEvent).where(
                TimelineEvent.evidence_id == e.id,
                TimelineEvent.kind == "metadata",
            )
        )

        for timestamp in result.get("timestamps", []):
            raw_value = str(timestamp.get("value", ""))
            parsed, note = parse_ts(raw_value)

            db.add(
                TimelineEvent(
                    case_id=e.case_id,
                    evidence_id=e.id,
                    kind="metadata",
                    title=(
                        f"{timestamp.get('label', 'Timestamp')} "
                        f"({e.ref})"
                    ),
                    details=(
                        "Timestamp embedded in file metadata. "
                        "Its meaning depends on the source file and tool."
                    ),
                    original_ts=raw_value[:80],
                    utc=parsed,
                    note=note,
                    created_by=u.id,
                )
            )

        return result

    job = run_job(db, u, e, "file", fn)
    return job_out(db, job)


@file_r.get("/{eid}")
def file_history(
    eid: str,
    u=Depends(require("evidence:read")),
    db=Depends(get_db),
):
    e = get_evidence(db, u, eid)

    rows = db.scalars(
        select(AnalysisResult)
        .where(
            AnalysisResult.evidence_id == e.id,
            AnalysisResult.kind == "file",
        )
        .order_by(AnalysisResult.created_at.desc())
        .limit(10)
    )

    return [job_out(db, job) for job in rows]


# -------------------------------------------------------------------
# Log analysis
# -------------------------------------------------------------------

@log_r.post("/{eid}")
def run_log(
    eid: str,
    u=Depends(require("analysis:run")),
    db=Depends(get_db),
):
    e = get_evidence(db, u, eid)
    cfg = db.get(SystemConfig, "log_rules")

    def fn(path, job):
        events, stats, errors = parse_log(path)

        if not events:
            raise ValueError(
                "No parseable log lines. The format may be unsupported."
            )

        # Replace previously derived log events only after successful parsing.
        db.execute(
            delete(LogEvent).where(LogEvent.evidence_id == e.id)
        )

        stored_events = events[:MAX_STORED_LOG_EVENTS]

        for event in stored_events:
            db.add(LogEvent(evidence_id=e.id, **event))

        stats["stored_events"] = len(stored_events)
        stats["total_parsed_events"] = len(events)
        stats["storage_limit_reached"] = (
            len(events) > MAX_STORED_LOG_EVENTS
        )

        configured_rules = cfg.value if cfg and cfg.value else {}
        rules_used = {**DEFAULT_RULES, **configured_rules}

        return {
            "stats": stats,
            "errors": errors,
            "alerts": detect_indicators(events, configured_rules),
            "groups": group_events(events),
            "rules_used": rules_used,
            "tools": {"analyzer": TOOL},
            "note": (
                "Alerts are indicators requiring human review, "
                "not proof of wrongdoing."
            ),
        }

    job = run_job(db, u, e, "log", fn)

    if job.status == "failed":
        job.error = (
            (job.error or "")
            + " Check the input format, such as JSON Lines "
            "or supported timestamped text."
        )
        db.commit()
        db.refresh(job)

    return job_out(db, job)


@log_r.get("/{eid}/summary")
def log_summary(
    eid: str,
    u=Depends(require("evidence:read")),
    db=Depends(get_db),
):
    e = get_evidence(db, u, eid)

    rows = db.scalars(
        select(AnalysisResult)
        .where(
            AnalysisResult.evidence_id == e.id,
            AnalysisResult.kind == "log",
        )
        .order_by(AnalysisResult.created_at.desc())
        .limit(5)
    )

    return [job_out(db, job) for job in rows]


def _lf(eid, event_type, source, q, start, end):
    """Build the filtered log-event query for listing and exporting."""
    start_dt, end_dt = validate_time_range(start, end)

    statement = select(LogEvent).where(
        LogEvent.evidence_id == eid
    )

    if event_type:
        statement = statement.where(
            LogEvent.event_type == event_type
        )

    if source:
        statement = statement.where(
            LogEvent.source.ilike(f"%{source}%")
        )

    if q:
        statement = statement.where(
            LogEvent.message.ilike(f"%{q}%")
        )

    if start_dt is not None:
        statement = statement.where(LogEvent.ts_utc >= start_dt)

    if end_dt is not None:
        statement = statement.where(LogEvent.ts_utc <= end_dt)

    return statement.order_by(
        LogEvent.ts_utc.asc(),
        LogEvent.line_no.asc(),
    )


def _le(row):
    """Serialize a normalized log event."""
    return {
        "id": row.id,
        "line_no": row.line_no,
        "ts_utc": iso(row.ts_utc),
        "ts_original": row.ts_original,
        "ts_note": row.ts_note,
        "event_type": row.event_type,
        "source": row.source,
        "username": row.username,
        "message": row.message,
    }


@log_r.get("/{eid}/events")
def log_events(
    eid: str,
    u=Depends(require("evidence:read")),
    db=Depends(get_db),
    event_type: str = "",
    source: str = "",
    q: str = "",
    start: str = "",
    end: str = "",
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
):
    e = get_evidence(db, u, eid)

    statement = _lf(
        e.id,
        event_type,
        source,
        q,
        start,
        end,
    )

    rows, total = paginate(db, statement, page, size)

    return {
        "items": [_le(row) for row in rows],
        "total": total,
        "page": page,
        "size": size,
    }


@log_r.get("/{eid}/export")
def log_export(
    eid: str,
    u=Depends(require("evidence:read")),
    db=Depends(get_db),
    event_type: str = "",
    source: str = "",
    q: str = "",
    start: str = "",
    end: str = "",
):
    e = get_evidence(db, u, eid)

    statement = _lf(
        e.id,
        event_type,
        source,
        q,
        start,
        end,
    ).limit(MAX_STORED_LOG_EVENTS)

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)

    columns = [
        "line_no",
        "ts_utc",
        "ts_original",
        "ts_note",
        "event_type",
        "source",
        "username",
        "message",
    ]

    writer.writerow(columns)

    for row in db.scalars(statement):
        data = _le(row)
        writer.writerow([csv_safe(data[column]) for column in columns])

    audit(db, u, "log_export", "evidence", e.id)

    filename = f"normalized_log_{e.ref}.csv"

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


# -------------------------------------------------------------------
# Timeline
# -------------------------------------------------------------------

class AnalystEvent(BaseModel):
    case_id: str
    evidence_id: Optional[str] = None
    title: str = Field(min_length=3, max_length=200)
    details: str = Field(default="", max_length=3000)
    original_ts: str = Field(min_length=4, max_length=80)
    tz_offset_minutes: int = Field(default=0, ge=-840, le=840)


@timeline_r.post("", status_code=201)
def add_event(
    body: AnalystEvent,
    u=Depends(require("timeline:write")),
    db=Depends(get_db),
):
    case = get_case(db, u, body.case_id)

    evidence = None

    if body.evidence_id:
        evidence = get_evidence(db, u, body.evidence_id)

        if evidence.case_id != case.id:
            raise HTTPException(
                status_code=400,
                detail="Evidence does not belong to this case.",
            )

    timestamp, note = parse_ts(body.original_ts)

    if timestamp is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Timestamp could not be interpreted. "
                "The event was not created."
            ),
        )

    # Apply the analyst-provided offset only when the parser assumed UTC
    # for a timestamp without explicit timezone information.
    if "assumed UTC" in (note or "") and body.tz_offset_minutes:
        timestamp = timestamp - timedelta(
            minutes=body.tz_offset_minutes
        )
        note = (
            "Naive timestamp interpreted using analyst-supplied "
            f"UTC offset {body.tz_offset_minutes:+d} minutes."
        )

    event = TimelineEvent(
        case_id=case.id,
        evidence_id=evidence.id if evidence else None,
        kind="analyst",
        title=body.title,
        details=body.details,
        original_ts=body.original_ts,
        utc=timestamp,
        note=note,
        created_by=u.id,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    audit(
        db,
        u,
        "timeline_event_created",
        "case",
        case.id,
        event_id=event.id,
    )

    return {"id": event.id}


@timeline_r.get("")
def timeline(
    case_id: str,
    u=Depends(require("case:read")),
    db=Depends(get_db),
    evidence_id: str = "",
    category: str = "",
    start: str = "",
    end: str = "",
    order: str = "asc",
    limit: int = Query(500, ge=1, le=2000),
):
    case = get_case(db, u, case_id)

    if order not in {"asc", "desc"}:
        raise HTTPException(
            status_code=422,
            detail="order must be 'asc' or 'desc'.",
        )

    start_dt, end_dt = validate_time_range(start, end)

    allowed_categories = {
        "analyst",
        "metadata",
        "acquisition",
        "custody",
        "log",
    }

    if category and category not in allowed_categories:
        raise HTTPException(
            status_code=422,
            detail="Unsupported timeline category.",
        )

    evidence_rows = list(
        db.scalars(
            select(Evidence).where(Evidence.case_id == case.id)
        )
    )

    evidence_by_id = {item.id: item for item in evidence_rows}
    evidence_refs = {
        item.id: item.ref for item in evidence_rows
    }

    if evidence_id and evidence_id not in evidence_by_id:
        # Do not allow timeline queries to cross case boundaries.
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case.",
        )

    items = []

    # Analyst-created events and file metadata events.
    timeline_rows = db.scalars(
        select(TimelineEvent).where(
            TimelineEvent.case_id == case.id
        )
    )

    for event in timeline_rows:
        items.append(
            {
                "id": event.id,
                "category": (
                    "analyst"
                    if event.kind == "analyst"
                    else "metadata"
                ),
                "title": event.title,
                "details": event.details,
                "original": event.original_ts,
                "utc": event.utc,
                "note": event.note,
                "evidence_id": event.evidence_id,
            }
        )

    # Evidence acquisition events.
    for evidence in evidence_rows:
        items.append(
            {
                "id": f"acq-{evidence.id}",
                "category": "acquisition",
                "title": f"Evidence acquired: {evidence.ref}",
                "details": (
                    f"{evidence.original_filename} via "
                    f"{evidence.acquisition_method}"
                ),
                "original": evidence.acquisition_raw,
                "utc": evidence.acquisition_utc,
                "note": (
                    evidence.acquisition_note
                    or "No acquisition time recorded."
                ),
                "evidence_id": evidence.id,
            }
        )

    # Chain-of-custody events.
    custody_rows = db.scalars(
        select(CustodyEvent).where(
            CustodyEvent.case_id == case.id
        )
    )

    for custody in custody_rows:
        items.append(
            {
                "id": f"cus-{custody.id}",
                "category": "custody",
                "title": f"Custody: {custody.action}",
                "details": custody.reason,
                "original": None,
                "utc": custody.created_at,
                "note": "System-recorded timestamp.",
                "evidence_id": custody.evidence_id,
            }
        )

    # Log events belonging only to evidence in this case.
    evidence_ids = list(evidence_by_id)

    if evidence_ids:
        log_statement = (
            select(LogEvent)
            .where(LogEvent.evidence_id.in_(evidence_ids))
            .order_by(
                LogEvent.ts_utc.asc(),
                LogEvent.line_no.asc(),
            )
            .limit(limit * 2 + 1)
        )

        log_rows = list(db.scalars(log_statement))
        log_candidates_truncated = len(log_rows) > limit * 2
        log_rows = log_rows[:limit * 2]
    else:
        log_rows = []
        log_candidates_truncated = False

    for log in log_rows:
        items.append(
            {
                "id": f"log-{log.id}",
                "category": "log",
                "title": f"[{log.event_type}] {log.source or ''}".strip(),
                "details": log.message,
                "original": log.ts_original,
                "utc": log.ts_utc,
                "note": log.ts_note,
                "evidence_id": log.evidence_id,
            }
        )

    # Add evidence references to all events.
    for item in items:
        item["evidence_ref"] = evidence_refs.get(
            item["evidence_id"]
        )

    if evidence_id:
        items = [
            item for item in items
            if item["evidence_id"] == evidence_id
        ]

    if category:
        items = [
            item for item in items
            if item["category"] == category
        ]

    dated = []
    undated = []

    for item in items:
        timestamp = item["utc"]

        if timestamp is None:
            undated.append(item)
            continue

        if start_dt is not None and timestamp < start_dt:
            continue

        if end_dt is not None and timestamp > end_dt:
            continue

        dated.append(item)

    dated.sort(
        key=lambda item: item["utc"],
        reverse=(order == "desc"),
    )

    truncated = (
        len(dated) > limit
        or log_candidates_truncated
    )

    def serialize(item):
        return {
            **item,
            "utc": iso(item["utc"]),
        }

    return {
        "items": [
            serialize(item) for item in dated[:limit]
        ],
        "undated": [
            serialize(item)
            for item in undated[:MAX_TIMELINE_UNDATED]
        ],
        "truncated": truncated,
        "note": (
            "Times are normalized to UTC where possible. "
            "Original timestamp values and interpretation notes "
            "are included when available."
        ),
    }