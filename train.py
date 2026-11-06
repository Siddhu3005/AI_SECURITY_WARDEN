import pandas as pd
import os
import glob
import torch
import numpy as np
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
)
from torch.utils.data import Dataset
from torch import nn
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
)
import shutil

# ==========================================
# CONFIG
# ==========================================
MAX_LENGTH = 256          # Longer context catches multi-sentence injections
MALICIOUS_WEIGHT = 3.0   # Up-weight malicious class to handle imbalance
EPOCHS = 4
BATCH_SIZE = 16           # Smaller batch = more gradient updates per epoch
OUTPUT_DIR = "./distilbert_injection_detector"


# ==========================================
# 1. LOAD DATASETS
# ==========================================
print("Loading datasets...")

# --- MALICIOUS (label 1) ---

# deepset prompt injections (gold standard ~600 samples)
ds_deepset = load_dataset("deepset/prompt-injections")
df_deepset = pd.DataFrame(ds_deepset["train"])
df_deepset = df_deepset[["text", "label"]]

# JasperLS prompt injection (diverse attack taxonomy)
ds_jasper = load_dataset("JasperLS/gelectra-base-injection")
df_jasper = pd.DataFrame(ds_jasper["train"])
if "prompt" in df_jasper.columns:
    df_jasper.rename(columns={"prompt": "text"}, inplace=True)
df_jasper = df_jasper[["text", "label"]]

# Rubend18 ChatGPT jailbreaks (~80 high-quality jailbreaks)
ds_jailbreak = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts")
df_jailbreak = pd.DataFrame(ds_jailbreak["train"])
if "Prompt" in df_jailbreak.columns:
    df_jailbreak.rename(columns={"Prompt": "text"}, inplace=True)
df_jailbreak["label"] = 1
df_jailbreak = df_jailbreak[["text", "label"]]

# Any Kaggle CSVs the user has uploaded to /content/
kaggle_dfs = []
for file in glob.glob("/content/*.csv"):
    try:
        temp = pd.read_csv(file)
        col = next((c for c in temp.columns if c.lower() in ["prompt", "text"]), None)
        if col:
            temp.rename(columns={col: "text"}, inplace=True)
            temp["label"] = 1
            kaggle_dfs.append(temp[["text", "label"]])
    except Exception as e:
        print(f"Skipping {file}: {e}")

# Combine malicious
malicious_parts = [df_deepset[df_deepset["label"] == 1], df_jasper[df_jasper["label"] == 1], df_jailbreak]
if kaggle_dfs:
    malicious_parts += kaggle_dfs
df_malicious = pd.concat(malicious_parts, ignore_index=True)
df_malicious["label"] = 1
df_malicious.dropna(subset=["text"], inplace=True)
df_malicious.drop_duplicates(subset=["text"], inplace=True)
print(f"Malicious samples: {len(df_malicious)}")


# --- BENIGN (label 0) ---

# General instructions (diverse everyday queries)
alpaca = load_dataset("yahma/alpaca-cleaned", split="train")
df_alpaca = pd.DataFrame(alpaca)[["instruction"]].rename(columns={"instruction": "text"})

# Technical/coding instructions (reduces false positives on code requests)
code = load_dataset("sahil2801/CodeAlpaca-20k", split="train")
df_code = pd.DataFrame(code)[["instruction"]].rename(columns={"instruction": "text"})

# OpenAssistant — real human conversational turns (very important for casual FP reduction)
oa = load_dataset("OpenAssistant/oasst1", split="train")
df_oa = pd.DataFrame(oa)
df_oa = df_oa[df_oa["role"] == "prompter"][["text"]]

# Dolly — diverse categories: classification, QA, creative writing, summarization
dolly = load_dataset("databricks/databricks-dolly-15k", split="train")
df_dolly = pd.DataFrame(dolly)[["instruction"]].rename(columns={"instruction": "text"})

# Stack Overflow questions — reduces FP on security/networking technical questions
# (model must learn "how do SQL injection attacks work?" ≠ attack)
try:
    so = load_dataset("pacovaldez/stackoverflow-questions", split="train[:20000]")
    df_so = pd.DataFrame(so)
    if "title" in df_so.columns:
        df_so = df_so[["title"]].rename(columns={"title": "text"})
    else:
        df_so = pd.DataFrame(columns=["text"])
except Exception:
    print("Stack Overflow dataset unavailable, skipping.")
    df_so = pd.DataFrame(columns=["text"])

# Also keep the benign subset from deepset (label 0 rows)
df_deepset_benign = df_deepset[df_deepset["label"] == 0][["text"]]

df_benign = pd.concat(
    [df_alpaca, df_code, df_oa, df_dolly, df_so, df_deepset_benign],
    ignore_index=True,
)
df_benign["label"] = 0
df_benign.dropna(subset=["text"], inplace=True)
df_benign.drop_duplicates(subset=["text"], inplace=True)

# Balance: sample benign to ~10x malicious (enough diversity, avoids extreme imbalance)
# We still rely on class_weight to up-weight malicious during training.
target_benign = min(len(df_benign), len(df_malicious) * 10)
df_benign = df_benign.sample(n=target_benign, random_state=42).reset_index(drop=True)
print(f"Benign samples: {len(df_benign)}")


# ==========================================
# 2. COMBINE AND SPLIT
# ==========================================
df_final = pd.concat([df_benign, df_malicious], ignore_index=True)
df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

# Remove very short texts (< 5 chars) — noise
df_final = df_final[df_final["text"].str.len() >= 5]

texts = df_final["text"].tolist()
labels = df_final["label"].tolist()

train_texts, test_texts, train_labels, test_labels = train_test_split(
    texts, labels, test_size=0.15, random_state=42, stratify=labels
)
print(f"Train: {len(train_texts)}  |  Test: {len(test_texts)}")
print(f"Train malicious rate: {sum(train_labels)/len(train_labels):.3f}")


# ==========================================
# 3. TOKENISATION
# ==========================================
print("Tokenising...")
tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

train_enc = tokenizer(train_texts, truncation=True, padding=True, max_length=MAX_LENGTH)
test_enc  = tokenizer(test_texts,  truncation=True, padding=True, max_length=MAX_LENGTH)


class PromptDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)


train_dataset = PromptDataset(train_enc, train_labels)
test_dataset  = PromptDataset(test_enc,  test_labels)


# ==========================================
# 4. WEIGHTED LOSS TRAINER
# Punishes missing a malicious sample MALICIOUS_WEIGHT× more than a false alarm.
# This is the most important lever for recall vs precision tradeoff.
# ==========================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased", num_labels=2
)
model.to(device)

class_weights = torch.tensor([1.0, MALICIOUS_WEIGHT], dtype=torch.float).to(device)


class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits
        loss_fn = nn.CrossEntropyLoss(weight=class_weights)
        loss = loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    probs = torch.softmax(torch.tensor(pred.predictions, dtype=torch.float), dim=1)[:, 1].numpy()

    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    acc = accuracy_score(labels, preds)
    auc = roc_auc_score(labels, probs)
    tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()

    print(f"\nConfusion matrix — TP:{tp}  FP:{fp}  FN:{fn}  TN:{tn}")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    print(f"False positive rate (innocent blocked): {fpr:.4f}")
    print(f"False negative rate (attack missed):   {fnr:.4f}")

    return {
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc": auc,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


# ==========================================
# 5. TRAINING
# ==========================================
training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=32,
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True,
    warmup_ratio=0.1,           # Gradual warmup prevents early overfitting
    weight_decay=0.01,          # L2 regularisation
    learning_rate=2e-5,
    logging_steps=200,
    fp16=torch.cuda.is_available(),
)

trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=compute_metrics,
)

print(f"\nTraining on {device} — estimated ~20–30 min on GPU...")
trainer.train()


# ==========================================
# 6. FINAL EVALUATION
# ==========================================
print("\n--- FINAL TEST SET METRICS ---")
results = trainer.predict(test_dataset)
preds = results.predictions.argmax(-1)
labels_arr = results.label_ids
probs = torch.softmax(
    torch.tensor(results.predictions, dtype=torch.float), dim=1
)[:, 1].numpy()

precision, recall, f1, _ = precision_recall_fscore_support(labels_arr, preds, average="binary")
acc = accuracy_score(labels_arr, preds)
auc = roc_auc_score(labels_arr, probs)
tn, fp, fn, tp = confusion_matrix(labels_arr, preds).ravel()

print(f"Accuracy:            {acc:.4f}")
print(f"Precision:           {precision:.4f}")
print(f"Recall:              {recall:.4f}")
print(f"F1:                  {f1:.4f}")
print(f"AUC-ROC:             {auc:.4f}")
print(f"False Positive Rate: {fp/(fp+tn):.4f}  ({fp} innocent requests blocked)")
print(f"False Negative Rate: {fn/(fn+tp):.4f}  ({fn} attacks missed)")


# ==========================================
# 7. SAVE
# ==========================================
model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

# Also save the test threshold analysis so app.py can use optimal cutoff
thresholds = np.arange(0.25, 0.80, 0.025)
threshold_results = []
for t in thresholds:
    p = (probs >= t).astype(int)
    pr, re, f, _ = precision_recall_fscore_support(labels_arr, p, average="binary", zero_division=0)
    threshold_results.append({"threshold": round(float(t), 3), "precision": round(float(pr), 4),
                               "recall": round(float(re), 4), "f1": round(float(f), 4)})
pd.DataFrame(threshold_results).to_csv(os.path.join(OUTPUT_DIR, "threshold_analysis.csv"), index=False)
print(f"\nThreshold analysis saved to {OUTPUT_DIR}/threshold_analysis.csv")
print("Pick the threshold row that best balances your precision/recall tradeoff.")

shutil.make_archive(OUTPUT_DIR, "zip", OUTPUT_DIR)
print(f"\nModel saved and zipped → {OUTPUT_DIR}.zip")
