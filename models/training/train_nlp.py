"""
PhishGuard NLP Training Pipeline
Fine-tune all-MiniLM-L6-v2 for phishing text binary classification.

Dataset: ealvaradob/phishing-dataset (combined_reduced.json)
Model:   sentence-transformers/all-MiniLM-L6-v2 → binary classifier
Target:  >95% Accuracy, >0.95 F1
"""

import os
import time
import numpy as np
import pandas as pd

import torch
from huggingface_hub import hf_hub_download
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, classification_report
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
    DataCollatorWithPadding,
)


# ============================================================================
# Configuration
# ============================================================================

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DATASET_REPO = "ealvaradob/phishing-dataset"
DATASET_FILE = "combined_reduced.json"

# Use absolute paths for Windows compatibility
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "saved"))
OUTPUT_DIR = os.path.join(BASE_DIR, "nlp_phish_model")
LOGGING_DIR = os.path.join(BASE_DIR, "nlp_logs")

MAX_LENGTH = 256
MAX_SAMPLES = 80_000       # Use 80K samples (40K per class) to keep RAM/time sane
TEST_SIZE = 0.15
RANDOM_STATE = 42


# ============================================================================
# Lazy Tokenized Dataset — tokenizes on-the-fly to avoid OOM
# ============================================================================

class LazyPhishingDataset(torch.utils.data.Dataset):
    """Tokenizes text on-the-fly instead of pre-tokenizing everything."""

    def __init__(self, texts, labels, tokenizer, max_length=256):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.texts[idx],
            truncation=True,
            max_length=self.max_length,
            padding=False,            # Let DataCollator handle padding per-batch
            return_tensors=None,
        )
        encoding["labels"] = self.labels[idx]
        return encoding


# ============================================================================
# Helpers
# ============================================================================

def compute_metrics(eval_pred):
    """Compute accuracy, F1, and AUC for the Trainer."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    probs = torch.softmax(torch.tensor(logits, dtype=torch.float32), dim=-1)[:, 1].numpy()
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="binary"),
        "auc": roc_auc_score(labels, probs),
    }


# ============================================================================
# Main Training Pipeline
# ============================================================================

def main() -> None:
    print("=" * 70)
    print("  PhishGuard NLP Training Pipeline")
    print("  Model: all-MiniLM-L6-v2  ->  Binary Phishing Classifier")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Step 1: Download & Load Dataset
    # ------------------------------------------------------------------
    print("\n[1/5] Downloading dataset from HuggingFace...")
    t0 = time.perf_counter()

    json_path = hf_hub_download(
        repo_id=DATASET_REPO,
        filename=DATASET_FILE,
        repo_type="dataset",
    )
    print(f"      Downloaded to: {json_path}")

    print("      Loading JSON into pandas...")
    df = pd.read_json(json_path)

    print(f"      Loaded {len(df):,} rows in {time.perf_counter() - t0:.1f}s")
    print(f"      Columns: {df.columns.tolist()}")
    print(f"      Label distribution (raw):")
    for label, count in df["label"].value_counts().items():
        lbl = "Phishing" if label == 1 else "Benign"
        print(f"        {lbl:>10s}: {count:>7,}")

    # Clean up
    df = df.dropna(subset=["text"]).reset_index(drop=True)
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    # Stratified sample to keep training manageable
    if len(df) > MAX_SAMPLES:
        print(f"\n      Sampling {MAX_SAMPLES:,} rows (stratified)...")
        df = df.groupby("label", group_keys=False).apply(
            lambda x: x.sample(n=min(len(x), MAX_SAMPLES // 2), random_state=RANDOM_STATE)
        ).reset_index(drop=True)
        print(f"      Sampled {len(df):,} rows")

    # ------------------------------------------------------------------
    # Step 2: Train/Test Split
    # ------------------------------------------------------------------
    print("\n[2/5] Splitting dataset...")
    train_df, test_df = train_test_split(
        df, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=df["label"]
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    print(f"      Train: {len(train_df):,}  |  Test: {len(test_df):,}")

    # ------------------------------------------------------------------
    # Step 3: Create lazy datasets + tokenizer
    # ------------------------------------------------------------------
    print("\n[3/5] Preparing tokenizer and datasets (lazy)...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    train_dataset = LazyPhishingDataset(
        train_df["text"].tolist(), train_df["label"].tolist(), tokenizer, MAX_LENGTH
    )
    test_dataset = LazyPhishingDataset(
        test_df["text"].tolist(), test_df["label"].tolist(), tokenizer, MAX_LENGTH
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    print("      Done (tokenization happens on-the-fly per batch)")

    # ------------------------------------------------------------------
    # Step 4: Fine-Tune Model
    # ------------------------------------------------------------------
    print("\n[4/5] Fine-tuning all-MiniLM-L6-v2...")

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"      Device: {device}")
    model.to(device)

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        logging_dir=LOGGING_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=32,
        per_device_eval_batch_size=64,
        learning_rate=2e-5,
        weight_decay=0.01,
        warmup_ratio=0.1,
        evaluation_strategy="steps",
        eval_steps=500,
        save_strategy="no",  # Disabled entirely to avoid Windows IO errors during training
        load_best_model_at_end=False,  # Disabled to prevent Windows locked-file errors
        logging_steps=100,
        fp16=torch.cuda.is_available(),
        dataloader_num_workers=0,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        # Early stopping removed since load_best_model_at_end is False
    )

    t0 = time.perf_counter()
    trainer.train()
    train_time = time.perf_counter() - t0
    print(f"\n      Training completed in {train_time:.1f}s")

    # ------------------------------------------------------------------
    # Step 5: Evaluate + Save
    # ------------------------------------------------------------------
    print("\n[5/5] Evaluating model...")

    results = trainer.evaluate()
    print("\n" + "=" * 70)
    print("  TRAINING RESULTS")
    print("=" * 70)
    print(f"  Accuracy : {results['eval_accuracy']:.4f}  ({results['eval_accuracy']*100:.2f}%)")
    print(f"  F1-Score : {results['eval_f1']:.4f}")
    print(f"  AUC-ROC  : {results['eval_auc']:.4f}")
    print("=" * 70)

    # Classification report
    print("\n  Generating classification report...")
    test_preds = trainer.predict(test_dataset)
    y_pred = np.argmax(test_preds.predictions, axis=-1)
    y_true = test_df["label"].values
    print(classification_report(y_true, y_pred, target_names=["Benign", "Phishing"]))

    # Save model + tokenizer
    print("  Saving model and tokenizer...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    model_size_mb = sum(
        os.path.getsize(os.path.join(OUTPUT_DIR, f))
        for f in os.listdir(OUTPUT_DIR)
        if os.path.isfile(os.path.join(OUTPUT_DIR, f))
    ) / (1024 * 1024)
    print(f"  Model saved to: {OUTPUT_DIR}")
    print(f"  Model size:     {model_size_mb:.1f} MB")

    print("\n" + "=" * 70)
    print("  Pipeline Complete ✓")
    print("=" * 70)


if __name__ == "__main__":
    main()
