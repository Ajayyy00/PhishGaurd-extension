"""
PhishGuard LightGBM Training Pipeline
Production-grade training script for malicious URL binary classification.

Dataset: dataset/malicious_phish.csv (651K URLs, 4 classes → binary)
Model:   LightGBM (native .txt export for <1ms inference)
Target:  >95% Accuracy, >0.98 AUC, <2ms inference
"""

import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from feature_engine import extract_features_batch, FEATURE_NAMES


# ============================================================================
# Configuration
# ============================================================================

DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "dataset", "malicious_phish.csv"
)
MODEL_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "saved")
MODEL_FILENAME = "lgbm_url_model.txt"
TEST_SIZE = 0.20
RANDOM_STATE = 42


# LightGBM hyperparameters — tuned for speed + accuracy + anti-overfitting
LGBM_PARAMS = {
    "objective": "binary",
    "metric": "auc",
    "boosting_type": "gbdt",
    "n_estimators": 300,
    "max_depth": 8,
    "num_leaves": 63,           # < 2^max_depth to prevent overfitting
    "learning_rate": 0.05,
    "min_child_samples": 50,    # Conservative to prevent overfitting
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "reg_alpha": 0.1,           # L1 regularization
    "reg_lambda": 1.0,          # L2 regularization
    "random_state": RANDOM_STATE,
    "n_jobs": -1,               # Use all CPU cores
    "verbose": -1,              # Suppress LightGBM logs during training
    "is_unbalance": True,       # Handle class imbalance natively
}


# ============================================================================
# Main Training Pipeline
# ============================================================================

def main() -> None:
    print("=" * 70)
    print("  PhishGuard LightGBM Training Pipeline")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Step 1: Load Dataset
    # ------------------------------------------------------------------
    print("\n[1/5] Loading dataset...")
    t0 = time.perf_counter()

    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"      Loaded {len(df):,} rows in {time.perf_counter() - t0:.2f}s")
    print(f"      Columns: {df.columns.tolist()}")
    print(f"      Class distribution (raw):")
    for label, count in df["type"].value_counts().items():
        print(f"        {label:>12s}: {count:>7,}")

    # ------------------------------------------------------------------
    # Step 2: Label Encoding (binary: benign=0, everything else=1)
    # ------------------------------------------------------------------
    print("\n[2/5] Encoding labels (benign=0, malicious=1)...")
    df["label"] = (df["type"] != "benign").astype(np.int8)
    print(f"      Benign:    {(df['label'] == 0).sum():>7,}")
    print(f"      Malicious: {(df['label'] == 1).sum():>7,}")

    # Drop rows with missing URLs
    df = df.dropna(subset=["url"]).reset_index(drop=True)

    # ------------------------------------------------------------------
    # Step 3: Feature Extraction (vectorised)
    # ------------------------------------------------------------------
    print("\n[3/5] Extracting features (22 features per URL)...")
    t0 = time.perf_counter()

    X = extract_features_batch(df["url"])
    y = df["label"].values

    elapsed = time.perf_counter() - t0
    print(f"      Extracted {X.shape[0]:,} × {X.shape[1]} features in {elapsed:.2f}s")
    print(f"      Throughput: {X.shape[0] / elapsed:,.0f} URLs/sec")

    # Handle any NaN/Inf from malformed URLs
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # ------------------------------------------------------------------
    # Step 4: Train/Test Split + LightGBM Training
    # ------------------------------------------------------------------
    print("\n[4/5] Training LightGBM model...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"      Train: {X_train.shape[0]:,}  |  Test: {X_test.shape[0]:,}")

    # Create LightGBM datasets for early stopping
    train_data = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES, free_raw_data=False)
    test_data = lgb.Dataset(X_test, label=y_test, feature_name=FEATURE_NAMES, reference=train_data, free_raw_data=False)

    # Train with early stopping
    t0 = time.perf_counter()
    callbacks = [
        lgb.early_stopping(stopping_rounds=30, verbose=True),
        lgb.log_evaluation(period=50),
    ]

    model = lgb.train(
        params={
            "objective": LGBM_PARAMS["objective"],
            "metric": LGBM_PARAMS["metric"],
            "boosting_type": LGBM_PARAMS["boosting_type"],
            "max_depth": LGBM_PARAMS["max_depth"],
            "num_leaves": LGBM_PARAMS["num_leaves"],
            "learning_rate": LGBM_PARAMS["learning_rate"],
            "min_child_samples": LGBM_PARAMS["min_child_samples"],
            "subsample": LGBM_PARAMS["subsample"],
            "colsample_bytree": LGBM_PARAMS["colsample_bytree"],
            "reg_alpha": LGBM_PARAMS["reg_alpha"],
            "reg_lambda": LGBM_PARAMS["reg_lambda"],
            "random_state": LGBM_PARAMS["random_state"],
            "n_jobs": LGBM_PARAMS["n_jobs"],
            "verbose": LGBM_PARAMS["verbose"],
            "is_unbalance": LGBM_PARAMS["is_unbalance"],
        },
        train_set=train_data,
        valid_sets=[test_data],
        valid_names=["validation"],
        num_boost_round=LGBM_PARAMS["n_estimators"],
        callbacks=callbacks,
    )

    train_time = time.perf_counter() - t0
    print(f"\n      Training completed in {train_time:.2f}s")
    print(f"      Best iteration: {model.best_iteration}")

    # ------------------------------------------------------------------
    # Step 5: Evaluation Metrics
    # ------------------------------------------------------------------
    print("\n[5/5] Evaluating model...")

    y_proba = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred = (y_proba >= 0.5).astype(int)

    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="binary")
    auc = roc_auc_score(y_test, y_proba)

    print("\n" + "=" * 70)
    print("  TRAINING RESULTS")
    print("=" * 70)
    print(f"  Accuracy : {accuracy:.4f}  ({accuracy * 100:.2f}%)")
    print(f"  F1-Score : {f1:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print("=" * 70)

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0][0]:>6,}  FP={cm[0][1]:>6,}")
    print(f"    FN={cm[1][0]:>6,}  TP={cm[1][1]:>6,}")

    # Feature importance
    print("\n  Top 10 Feature Importances:")
    importance = model.feature_importance(importance_type="gain")
    feat_imp = sorted(zip(FEATURE_NAMES, importance), key=lambda x: x[1], reverse=True)
    for i, (name, imp) in enumerate(feat_imp[:10], 1):
        print(f"    {i:>2}. {name:<22s}  {imp:>10.1f}")

    # ------------------------------------------------------------------
    # Step 6: Export Model (native .txt for ultra-fast loading)
    # ------------------------------------------------------------------
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_OUTPUT_DIR, MODEL_FILENAME)
    model.save_model(model_path, num_iteration=model.best_iteration)

    model_size_kb = os.path.getsize(model_path) / 1024
    print(f"\n  Model saved to: {model_path}")
    print(f"  Model size:     {model_size_kb:.1f} KB")

    # ------------------------------------------------------------------
    # Inference speed benchmark
    # ------------------------------------------------------------------
    print("\n  Inference Speed Benchmark (1000 predictions)...")
    sample_features = X_test[:1]
    t0 = time.perf_counter()
    for _ in range(1000):
        model.predict(sample_features, num_iteration=model.best_iteration)
    elapsed = (time.perf_counter() - t0) / 1000 * 1000  # ms per prediction
    print(f"  Average inference time: {elapsed:.3f} ms/prediction")

    print("\n" + "=" * 70)
    print("  Pipeline Complete ✓")
    print("=" * 70)


if __name__ == "__main__":
    main()
