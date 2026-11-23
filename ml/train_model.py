"""
DFIS - Network Intrusion Detection Model Training
Dataset: NSL-KDD

Usage:
    python ml/train_model.py [TRAIN_CSV] [TEST_CSV]

Dataset paths default to ml/data/KDDTrain.csv and ml/data/KDDTest.csv
(or the DFIS_KDD_TRAIN / DFIS_KDD_TEST environment variables).
Train with the same scikit-learn version the server runs
(see backend/requirements.txt), otherwise the saved model may not load correctly.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

ML_DIR = Path(__file__).resolve().parent
MODEL_DIR = ML_DIR / "models"

# ─── Step 1: Load the data ───────────────────────────────────────────────────
print("=" * 60)
print("DFIS - ML Model Training Started")
print("=" * 60)

# Column names for the NSL-KDD dataset
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Load training data
train_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DFIS_KDD_TRAIN", str(ML_DIR / "data" / "KDDTrain.csv"))
test_path  = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("DFIS_KDD_TEST",  str(ML_DIR / "data" / "KDDTest.csv"))
for p in (train_path, test_path):
    if not Path(p).exists():
        sys.exit(f"Dataset not found: {p}\nDownload NSL-KDD (KDDTrain+/KDDTest+) and pass the paths as arguments.")

print(f"\n[1/6] Loading training data from: {train_path}")
train = pd.read_csv(train_path, header=None, names=COLUMNS, low_memory=False)
if str(train.iloc[0]['duration']).strip() == 'duration':
    train = train.iloc[1:].reset_index(drop=True)
print(f"      Training rows: {len(train):,}")

print(f"[1/6] Loading test data from: {test_path}")
test = pd.read_csv(test_path, header=None, names=COLUMNS, low_memory=False)
if str(test.iloc[0]['duration']).strip() == 'duration':
    test = test.iloc[1:].reset_index(drop=True)
print(f"      Test rows: {len(test):,}")

# ─── Step 2: Understand the data ─────────────────────────────────────────────
print(f"\n[2/6] Understanding the data...")
print(f"      Attack types found: {train['label'].unique()[:10]}")
print(f"      Normal traffic: {len(train[train['label'] == 'normal']):,} records")
print(f"      Attack traffic: {len(train[train['label'] != 'normal']):,} records")

# ─── Step 3: Prepare the data ────────────────────────────────────────────────
print(f"\n[3/6] Preparing data for training...")

# Convert labels: normal = 0, any attack = 1
train['label_binary'] = train['label'].apply(lambda x: 0 if x == 'normal' else 1)
test['label_binary']  = test['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Encode text columns (protocol_type, service, flag) into numbers
le_protocol = LabelEncoder()
le_service  = LabelEncoder()
le_flag     = LabelEncoder()

# Fit on combined data so both train and test have same encoding
all_protocols = pd.concat([train['protocol_type'], test['protocol_type']])
all_services  = pd.concat([train['service'], test['service']])
all_flags     = pd.concat([train['flag'], test['flag']])

le_protocol.fit(all_protocols)
le_service.fit(all_services)
le_flag.fit(all_flags)

train['protocol_type'] = le_protocol.transform(train['protocol_type'])
train['service']       = le_service.transform(train['service'])
train['flag']          = le_flag.transform(train['flag'])

test['protocol_type']  = le_protocol.transform(test['protocol_type'])
test['service']        = le_service.transform(test['service'])
test['flag']           = le_flag.transform(test['flag'])

# Convert all numeric feature columns to float (fixes mixed-type issue)
numeric_cols = [c for c in COLUMNS if c not in ['label', 'difficulty', 'protocol_type', 'service', 'flag']]
for col in numeric_cols:
    train[col] = pd.to_numeric(train[col], errors='coerce').fillna(0)
    test[col]  = pd.to_numeric(test[col],  errors='coerce').fillna(0)

# Select features (remove label columns)
FEATURES = [c for c in COLUMNS if c not in ['label', 'difficulty']]

X_train = train[FEATURES]
y_train = train['label_binary']
X_test  = test[FEATURES]
y_test  = test['label_binary']

print(f"      Features used: {len(FEATURES)}")
print(f"      Training samples: {len(X_train):,}")
print(f"      Test samples: {len(X_test):,}")

# ─── Step 4: Train the model ─────────────────────────────────────────────────
print(f"\n[4/6] Training Random Forest model... (this may take 1-2 minutes)")

model = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees
    max_depth=20,       # max depth of each tree
    random_state=42,    # for reproducibility
    n_jobs=-1           # use all CPU cores
)

model.fit(X_train, y_train)
print(f"      Model trained successfully!")

# ─── Step 5: Test accuracy ───────────────────────────────────────────────────
print(f"\n[5/6] Testing model accuracy...")

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\n{'=' * 60}")
print(f"  MODEL ACCURACY: {accuracy * 100:.2f}%")
print(f"{'=' * 60}")
print(f"\nDetailed Report:")
print(classification_report(y_test, predictions, target_names=['Normal', 'Attack']))

# ─── Step 6: Save the model ──────────────────────────────────────────────────
print(f"\n[6/6] Saving model...")

MODEL_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(model,       MODEL_DIR / "intrusion_model.pkl", compress=3)
joblib.dump(le_protocol, MODEL_DIR / "le_protocol.pkl")
joblib.dump(le_service,  MODEL_DIR / "le_service.pkl")
joblib.dump(le_flag,     MODEL_DIR / "le_flag.pkl")
joblib.dump(FEATURES,    MODEL_DIR / "features.pkl")

# Record how the model was built so the server can report it and detect version mismatches.
(MODEL_DIR / "model_info.json").write_text(json.dumps({
    "algorithm": "RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)",
    "dataset": "NSL-KDD",
    "train_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "test_accuracy": round(float(accuracy), 4),
    "sklearn_version": sklearn.__version__,
    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
}, indent=2))

print(f"      Model saved to: {MODEL_DIR / 'intrusion_model.pkl'}")
print(f"\nDone! The model is ready to use in DFIS.")
print("=" * 60)
