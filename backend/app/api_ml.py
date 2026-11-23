"""ML-based network intrusion detection endpoints."""
import csv
from collections import Counter
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select
from .security import require, get_evidence
from .db import get_db, AnalysisResult
from .api_analysis import run_job, job_out

MAX_ML_ROWS = 100_000
MAX_STORED_RESULTS = 500
# NSL-KDD column order: 41 features, then optional label and difficulty.
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

ml_r = APIRouter(prefix="/ml", tags=["ml"])

_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"
_model = _le_p = _le_s = _le_f = _feats = None


def _load():
    global _model, _le_p, _le_s, _le_f, _feats
    if _model is not None:
        return True
    try:
        import joblib
        _model = joblib.load(_DIR / "intrusion_model.pkl")
        _le_p  = joblib.load(_DIR / "le_protocol.pkl")
        _le_s  = joblib.load(_DIR / "le_service.pkl")
        _le_f  = joblib.load(_DIR / "le_flag.pkl")
        _feats = joblib.load(_DIR / "features.pkl")
        return True
    except Exception:
        return False


def _enc(val, le):
    try:
        return int(le.transform([val])[0])
    except Exception:
        return 0


# Realistic demo network connections (normal + known attack types from NSL-KDD)
_DEMO = [
    {"description": "Normal HTTP browsing",
     "protocol_type": "tcp", "service": "http", "flag": "SF",
     "duration": 0, "src_bytes": 215, "dst_bytes": 45076,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 2, "srv_count": 2,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 255,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Normal FTP file transfer",
     "protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
     "duration": 2, "src_bytes": 1162, "dst_bytes": 2456,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 1, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 55, "dst_host_srv_count": 55,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.02, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Normal SMTP email session",
     "protocol_type": "tcp", "service": "smtp", "flag": "SF",
     "duration": 0, "src_bytes": 1227, "dst_bytes": 1234,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 1, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 13, "dst_host_srv_count": 10,
     "dst_host_same_srv_rate": 0.77, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Normal DNS query (UDP)",
     "protocol_type": "udp", "service": "domain_u", "flag": "SF",
     "duration": 0, "src_bytes": 25, "dst_bytes": 37,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 1, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 1.0,
     "dst_host_count": 6, "dst_host_srv_count": 6,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.17, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Normal HTTPS connection",
     "protocol_type": "tcp", "service": "http_443", "flag": "SF",
     "duration": 0, "src_bytes": 289, "dst_bytes": 5456,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 2, "srv_count": 2,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 255,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Neptune SYN flood (DoS attack)",
     "protocol_type": "tcp", "service": "private", "flag": "S0",
     "duration": 0, "src_bytes": 0, "dst_bytes": 0,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 511, "srv_count": 511,
     "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 255,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Smurf ICMP amplification (DoS attack)",
     "protocol_type": "icmp", "service": "ecr_i", "flag": "SF",
     "duration": 0, "src_bytes": 1032, "dst_bytes": 0,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 511, "srv_count": 511,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 1,
     "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.6,
     "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "PortSweep reconnaissance scan",
     "protocol_type": "tcp", "service": "private", "flag": "REJ",
     "duration": 0, "src_bytes": 0, "dst_bytes": 0,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 2, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 1.0, "srv_rerror_rate": 1.0,
     "same_srv_rate": 0.5, "diff_srv_rate": 0.5, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 2,
     "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.07,
     "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.76, "dst_host_srv_rerror_rate": 0.76},

    {"description": "IPSweep host discovery scan",
     "protocol_type": "tcp", "service": "http", "flag": "SF",
     "duration": 0, "src_bytes": 5, "dst_bytes": 6,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 1, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 1.0,
     "dst_host_count": 40, "dst_host_srv_count": 40,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 0.03, "dst_host_srv_diff_host_rate": 0.63,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Teardrop IP fragmentation attack",
     "protocol_type": "udp", "service": "private", "flag": "SF",
     "duration": 0, "src_bytes": 28, "dst_bytes": 0,
     "land": 0, "wrong_fragment": 3, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 255, "srv_count": 255,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 255, "dst_host_srv_count": 255,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},

    {"description": "Warezclient unauthorised FTP download",
     "protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
     "duration": 0, "src_bytes": 352874, "dst_bytes": 0,
     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
     "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
     "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
     "is_host_login": 0, "is_guest_login": 0,
     "count": 1, "srv_count": 1,
     "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
     "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
     "dst_host_count": 1, "dst_host_srv_count": 1,
     "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
     "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
     "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0},
]


def _model_info():
    import json
    try:
        return json.loads((_DIR / "model_info.json").read_text())
    except Exception:
        return {}


@ml_r.get("/status")
def ml_status():
    loaded = _load()
    info = _model_info()
    try:
        import sklearn
        runtime = sklearn.__version__
    except Exception:
        runtime = None
    return {
        "model_loaded": loaded,
        "model_type": "Random Forest (100 trees, NSL-KDD)" if loaded else None,
        "info": info,
        "sklearn_runtime": runtime,
        "version_mismatch": bool(info.get("sklearn_version") and runtime and info["sklearn_version"] != runtime),
    }


@ml_r.post("/intrusion-detect")
def intrusion_detect(u=Depends(require("analysis:run"))):
    if not _load():
        raise HTTPException(503, "ML model not loaded. Run ml/train_model.py first.")

    import numpy as np

    rows = []
    for conn in _DEMO:
        row = []
        for feat in _feats:
            if feat == "protocol_type":
                row.append(_enc(conn["protocol_type"], _le_p))
            elif feat == "service":
                row.append(_enc(conn["service"], _le_s))
            elif feat == "flag":
                row.append(_enc(conn["flag"], _le_f))
            else:
                row.append(float(conn.get(feat, 0)))
        rows.append(row)

    X = np.array(rows)
    preds = _model.predict(X)
    probs = _model.predict_proba(X)

    results = []
    for i, (conn, pred, prob) in enumerate(zip(_DEMO, preds, probs)):
        label = "Normal" if pred == 0 else "Attack"
        confidence = round(float(prob[pred]) * 100, 1)
        results.append({
            "id": i + 1,
            "description": conn["description"],
            "protocol": conn["protocol_type"],
            "service": conn["service"],
            "prediction": label,
            "confidence": confidence,
        })

    attacks = sum(1 for r in results if r["prediction"] == "Attack")
    return {
        "model_type": "Random Forest (100 trees, trained on NSL-KDD dataset)",
        "total_connections": len(results),
        "attacks_detected": attacks,
        "normal_detected": len(results) - attacks,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Scan real evidence (CSV of network connections in NSL-KDD format)
# ---------------------------------------------------------------------------

def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _read_connections(path):
    """Read an NSL-KDD style CSV (with or without header).

    Returns (records, skipped, has_label). Each record is a dict of column->raw value.
    """
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        if first is None:
            raise ValueError("Empty file")
        first = [c.strip() for c in first]
        if "protocol_type" in first or "duration" in first:
            header, pending = first, []
        else:
            header, pending = NSL_KDD_COLUMNS[:len(first)], [first]

        missing = [c for c in NSL_KDD_COLUMNS[:41] if c not in header]
        if missing:
            raise ValueError(f"Not an NSL-KDD connection file; missing columns: {missing[:5]}")

        records, skipped = [], 0
        for n, row in enumerate([*pending, *reader], 1):
            if len(records) >= MAX_ML_ROWS:
                break
            if len(row) < 41:
                skipped += 1
                continue
            rec = dict(zip(header, (c.strip() for c in row)))
            rec["_row"] = n
            records.append(rec)
    if not records:
        raise ValueError("No valid connection rows found")
    return records, skipped, "label" in header


def _scan(path):
    import numpy as np

    records, skipped, has_label = _read_connections(path)
    maps = {
        "protocol_type": {v: i for i, v in enumerate(_le_p.classes_)},
        "service": {v: i for i, v in enumerate(_le_s.classes_)},
        "flag": {v: i for i, v in enumerate(_le_f.classes_)},
    }
    unknown = Counter()
    X = np.zeros((len(records), len(_feats)))
    for i, rec in enumerate(records):
        for j, feat in enumerate(_feats):
            if feat in maps:
                code = maps[feat].get(rec.get(feat))
                if code is None:
                    unknown[feat] += 1
                    code = 0
                X[i, j] = code
            else:
                X[i, j] = _num(rec.get(feat))

    preds = _model.predict(X)
    probs = _model.predict_proba(X)

    results, svc_attacks, proto_attacks = [], Counter(), Counter()
    tp = tn = fp = fn = 0
    for rec, pred, prob in zip(records, preds, probs):
        pred = int(pred)
        is_attack = pred == 1
        if is_attack:
            svc_attacks[rec.get("service", "?")] += 1
            proto_attacks[rec.get("protocol_type", "?")] += 1
        item = {
            "row": rec["_row"],
            "protocol": rec.get("protocol_type"),
            "service": rec.get("service"),
            "flag": rec.get("flag"),
            "src_bytes": int(_num(rec.get("src_bytes"))),
            "dst_bytes": int(_num(rec.get("dst_bytes"))),
            "prediction": "Attack" if is_attack else "Normal",
            "confidence": round(float(prob[pred]) * 100, 1),
        }
        if has_label:
            actual = rec.get("label", "")
            item["actual"] = actual
            actual_attack = actual.lower() != "normal"
            tp += is_attack and actual_attack
            tn += (not is_attack) and (not actual_attack)
            fp += is_attack and not actual_attack
            fn += (not is_attack) and actual_attack
        results.append(item)

    attacks = sum(1 for r in results if r["prediction"] == "Attack")
    # Store attacks first (highest confidence first), then a sample of normal traffic.
    results.sort(key=lambda r: (r["prediction"] != "Attack", -r["confidence"]))

    out = {
        "source": "evidence",
        "model_type": "Random Forest (100 trees, trained on NSL-KDD dataset)",
        "total_connections": len(results),
        "attacks_detected": attacks,
        "normal_detected": len(results) - attacks,
        "skipped_rows": skipped,
        "row_limit_reached": len(records) >= MAX_ML_ROWS,
        "unknown_categories": dict(unknown),
        "attacks_by_service": [{"label": k, "value": v} for k, v in svc_attacks.most_common(8)],
        "attacks_by_protocol": [{"label": k, "value": v} for k, v in proto_attacks.most_common(8)],
        "results": results[:MAX_STORED_RESULTS],
        "results_truncated": len(results) > MAX_STORED_RESULTS,
        "note": "Model predictions are indicators requiring human review, not proof of an attack.",
    }
    if has_label:
        total = tp + tn + fp + fn
        out["evaluation"] = {
            "accuracy": round((tp + tn) / total * 100, 2) if total else None,
            "true_positive": tp, "true_negative": tn,
            "false_positive": fp, "false_negative": fn,
        }
    return out


@ml_r.post("/intrusion-detect/{eid}")
def intrusion_detect_evidence(eid: str, u=Depends(require("analysis:run")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    if not _load():
        raise HTTPException(503, "ML model not loaded. Run ml/train_model.py first.")

    job = run_job(db, u, e, "intrusion", lambda path, job: _scan(path))
    if job.status == "failed":
        job.error = (job.error or "") + (
            " The file must be a CSV of network connections in NSL-KDD format "
            "(41 feature columns, optional header and label)."
        )
        db.commit()
        db.refresh(job)
    return job_out(db, job)


@ml_r.get("/intrusion-detect/{eid}/latest")
def intrusion_latest(eid: str, u=Depends(require("evidence:read")), db=Depends(get_db)):
    e = get_evidence(db, u, eid)
    job = db.scalar(
        select(AnalysisResult)
        .where(AnalysisResult.evidence_id == e.id, AnalysisResult.kind == "intrusion")
        .order_by(AnalysisResult.created_at.desc())
    )
    return job_out(db, job) if job else None
