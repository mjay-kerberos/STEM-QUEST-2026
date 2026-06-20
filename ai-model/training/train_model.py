#!/usr/bin/env python3
"""
train_model.py
──────────────
Trains a Random Forest classifier on the combined
DVWA dataset produced by generate_dataset.py.

Why Random Forest for this workshop?
  - No GPU needed — trains in < 10 seconds on any laptop
  - Fully interpretable — feature importances show WHY it fires
  - Generalises well on tabular security log data
  - Probability output (0.0–1.0) maps cleanly to a risk score
  - Resistant to class imbalance (which real alert data has)

Architecture:
  RandomForestClassifier (100 trees, max_depth=12)
  → predict_proba() → risk_score (0–100)
  → fed into Ollama/Mistral prompt → plain-English brief

Run:
    python training/train_model.py

Output:
    model/rf_classifier.pkl    — trained model (joblib)
    model/feature_names.json   — ordered feature list for inference
    model/label_encoder.json   — attack_type → integer mapping
    model/training_report.txt  — full eval metrics
"""

import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)
from sklearn.preprocessing import LabelEncoder

# ── Paths ─────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
DATA_PATH   = BASE_DIR / "data" / "training_dataset.csv"
MODEL_DIR   = BASE_DIR / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH  = MODEL_DIR / "rf_classifier.pkl"
FEAT_PATH   = MODEL_DIR / "feature_names.json"
LABEL_PATH  = MODEL_DIR / "label_encoder.json"
REPORT_PATH = MODEL_DIR / "training_report.txt"

# ── Feature columns (MUST match generate_dataset.py) ─────
FEATURE_COLS = [
    "rule_id",
    "rule_level",
    "http_method_post",
    "status_code",
    "url_length",
    "bytes_sent",
    "has_sqli_token",
    "has_xss_token",
    "has_cmd_token",
    "has_traversal",
    "has_encoded_chars",
    "source_is_external",
    "requests_per_min",
    "failed_logins",
    "hour_of_day",
    "is_off_hours",
]
TARGET_COL  = "label"
ATTACK_COL  = "attack_type"


def print_section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main():
    print("=" * 60)
    print("AI Threat Detection Workshop — Model Training")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # ── 1. Load dataset ───────────────────────────────────
    print_section("Step 1: Load dataset")

    if not DATA_PATH.exists():
        print(f"ERROR: Dataset not found at {DATA_PATH}")
        print("Run: python training/generate_dataset.py first")
        raise SystemExit(1)

    df = pd.read_csv(DATA_PATH)
    print(f"  Rows loaded    : {len(df):,}")
    print(f"  Columns        : {len(df.columns)}")
    print(f"  Benign (0)     : {(df[TARGET_COL] == 0).sum():,}")
    print(f"  Attack (1)     : {(df[TARGET_COL] == 1).sum():,}")
    print(f"\n  Attack breakdown:")
    for atype, count in df[ATTACK_COL].value_counts().items():
        print(f"    {atype:<22} {count:>5}")

    # ── 2. Feature matrix ─────────────────────────────────
    print_section("Step 2: Prepare features")

    X = df[FEATURE_COLS].values
    y = df[TARGET_COL].values

    # Encode attack_type for multi-class reporting (not used by binary model)
    le = LabelEncoder()
    df["attack_type_enc"] = le.fit_transform(df[ATTACK_COL])
    label_map = {int(v): k for k, v in
                 zip(le.classes_, le.transform(le.classes_))}

    print(f"  Feature matrix : {X.shape[0]} samples × {X.shape[1]} features")
    print(f"  Features       : {', '.join(FEATURE_COLS)}")

    # ── 3. Train / test split ─────────────────────────────
    print_section("Step 3: Train / test split (80 / 20, stratified)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )
    print(f"  Train set : {len(X_train):,} samples")
    print(f"  Test set  : {len(X_test):,}  samples")

    # ── 4. Train model ────────────────────────────────────
    print_section("Step 4: Train Random Forest (100 trees)")
    print("  Training... ", end="", flush=True)

    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",   # handles class imbalance
        n_jobs=-1,                 # use all CPU cores
        random_state=42,
    )
    model.fit(X_train, y_train)
    elapsed = time.time() - t0

    print(f"done in {elapsed:.1f}s")

    # ── 5. Evaluate ───────────────────────────────────────
    print_section("Step 5: Evaluate on held-out test set")

    y_pred      = model.predict(X_test)
    y_proba     = model.predict_proba(X_test)[:, 1]
    accuracy    = accuracy_score(y_test, y_pred)
    roc_auc     = roc_auc_score(y_test, y_proba)
    class_rep   = classification_report(y_test, y_pred,
                                        target_names=["benign", "attack"])
    conf_mat    = confusion_matrix(y_test, y_pred)

    print(f"\n  Accuracy       : {accuracy * 100:.2f}%")
    print(f"  ROC-AUC        : {roc_auc:.4f}")
    print(f"\n  Classification Report:")
    for line in class_rep.split("\n"):
        print(f"    {line}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={conf_mat[0,0]:4d}  FP={conf_mat[0,1]:4d}")
    print(f"    FN={conf_mat[1,0]:4d}  TP={conf_mat[1,1]:4d}")

    # ── 6. Cross-validation ───────────────────────────────
    print_section("Step 6: 5-fold stratified cross-validation")
    print("  Running... ", end="", flush=True)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="roc_auc", n_jobs=-1)

    print("done")
    print(f"  CV ROC-AUC     : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  Per-fold       : {[f'{s:.3f}' for s in cv_scores]}")

    # ── 7. Feature importance ─────────────────────────────
    print_section("Step 7: Feature importances (top 10)")

    importances = model.feature_importances_
    feat_imp = sorted(zip(FEATURE_COLS, importances),
                      key=lambda x: x[1], reverse=True)
    for rank, (feat, imp) in enumerate(feat_imp[:10], 1):
        bar = "█" * int(imp * 60)
        print(f"  {rank:2d}. {feat:<22} {imp:.4f}  {bar}")

    # ── 8. Save model and metadata ────────────────────────
    print_section("Step 8: Save model artifacts")

    joblib.dump(model, MODEL_PATH)
    print(f"  Classifier     → {MODEL_PATH}")

    with open(FEAT_PATH, "w") as f:
        json.dump(FEATURE_COLS, f, indent=2)
    print(f"  Feature names  → {FEAT_PATH}")

    with open(LABEL_PATH, "w") as f:
        json.dump(label_map, f, indent=2)
    print(f"  Label map      → {LABEL_PATH}")

    # ── 9. Write training report ──────────────────────────
    report_lines = [
        "AI Threat Detection Workshop — Training Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        f"Dataset       : {DATA_PATH}",
        f"Total samples : {len(df):,}",
        f"Train / Test  : {len(X_train):,} / {len(X_test):,}",
        "",
        f"Model         : RandomForestClassifier",
        f"n_estimators  : 100",
        f"max_depth     : 12",
        f"Training time : {elapsed:.1f}s",
        "",
        f"Accuracy      : {accuracy * 100:.2f}%",
        f"ROC-AUC       : {roc_auc:.4f}",
        f"CV ROC-AUC    : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}",
        "",
        "Classification Report:",
        class_rep,
        "",
        "Confusion Matrix:",
        f"  TN={conf_mat[0,0]}  FP={conf_mat[0,1]}",
        f"  FN={conf_mat[1,0]}  TP={conf_mat[1,1]}",
        "",
        "Feature Importances:",
    ]
    for feat, imp in feat_imp:
        report_lines.append(f"  {feat:<22} {imp:.4f}")

    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(report_lines))
    print(f"  Training report→ {REPORT_PATH}")

    # ── Done ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Model training complete!")
    print(f"  Accuracy: {accuracy * 100:.1f}%  |  ROC-AUC: {roc_auc:.3f}")
    print(f"\n  Model ready at: {MODEL_PATH}")
    print("  Start the server: uvicorn server.main:app --reload")
    print("=" * 60)


if __name__ == "__main__":
    main()
