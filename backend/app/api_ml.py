"""ML-based network intrusion detection endpoint."""
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from .security import require

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


@ml_r.get("/status")
def ml_status():
    loaded = _load()
    return {"model_loaded": loaded, "model_type": "Random Forest (100 trees, NSL-KDD)" if loaded else None}


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
