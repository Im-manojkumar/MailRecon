import argparse
import os
from pathlib import Path
import random
import sys

# Configure UTF-8 encoding on Windows to prevent UnicodeEncodeError with emoji logs
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure repository root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import List, Tuple

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from ml.dataset import PhishingDataset, get_bootstrap_dataset, load_csv_dataset
from ml.model import PhishingCnnBiGru
from ml.tokenizer import PhishingTokenizer


def set_seed(seed: int = 42):
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def train_epoch(
    model: nn.Module,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float]:
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for inputs, labels in loader:
        inputs, labels = inputs.to(device), labels.to(device)
        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * len(labels)
        preds = torch.argmax(outputs, dim=1)
        correct += (preds == labels).sum().item()
        total += len(labels)

    epoch_loss = total_loss / max(total, 1)
    epoch_acc = correct / max(total, 1)
    return epoch_loss, epoch_acc


def eval_epoch(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float]:
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0

    with torch.no_grad():
        for inputs, labels in loader:
            inputs, labels = inputs.to(device), labels.to(device)
            outputs = model(inputs)
            loss = criterion(outputs, labels)

            total_loss += loss.item() * len(labels)
            preds = torch.argmax(outputs, dim=1)
            correct += (preds == labels).sum().item()
            total += len(labels)

    epoch_loss = total_loss / max(total, 1)
    epoch_acc = correct / max(total, 1)
    return epoch_loss, epoch_acc


def export_to_onnx(
    model: nn.Module,
    output_path: Path,
    vocab_size: int,
    max_length: int = 256,
):
    model.eval()
    model_cpu = model.to("cpu")
    dummy_input = torch.randint(0, vocab_size, (1, max_length), dtype=torch.long)

    print(f"Exporting model to ONNX: {output_path}...")
    torch.onnx.export(
        model_cpu,
        dummy_input,
        str(output_path),
        export_params=True,
        opset_version=18,
        do_constant_folding=True,
        input_names=["input_ids"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
    )
    print("ONNX export completed successfully.")


def run_training(
    dataset_path: str = None,
    epochs: int = 20,
    batch_size: int = 8,
    lr: float = 0.001,
    embed_dim: int = 128,
    cnn_filters: int = 128,
    gru_dim: int = 64,
    output_dir: str = "ml/weights",
):
    set_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # 1. Load Dataset
    if dataset_path and Path(dataset_path).is_file():
        print(f"Loading custom dataset from: {dataset_path}")
        texts, labels = load_csv_dataset(dataset_path)
    else:
        print("Using bootstrap dataset (built-in phishing & benign corpus)...")
        texts, labels = get_bootstrap_dataset()

    print(f"Total dataset size: {len(texts)} samples (phishing={sum(labels)}, benign={len(labels)-sum(labels)})")

    # 2. Train / Val Split (deterministic 80/20)
    indices = list(range(len(texts)))
    random.shuffle(indices)
    split_idx = int(0.8 * len(texts))
    train_indices = indices[:split_idx]
    val_indices = indices[split_idx:]

    train_texts = [texts[i] for i in train_indices]
    train_labels = [labels[i] for i in train_indices]
    val_texts = [texts[i] for i in val_indices]
    val_labels = [labels[i] for i in val_indices]

    # 3. Build Tokenizer
    tokenizer = PhishingTokenizer(max_length=256)
    tokenizer.build_vocab(train_texts, max_vocab_size=6000, min_freq=1)
    print(f"Vocabulary size: {tokenizer.vocab_size} tokens")

    # 4. Datasets & Loaders
    train_ds = PhishingDataset(train_texts, train_labels, tokenizer)
    val_ds = PhishingDataset(val_texts, val_labels, tokenizer)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    # 5. Model, Criterion, Optimizer
    model = PhishingCnnBiGru(
        vocab_size=tokenizer.vocab_size,
        embed_dim=embed_dim,
        cnn_filters=cnn_filters,
        gru_hidden_dim=gru_dim,
        num_classes=2,
        dropout=0.3,
        padding_idx=tokenizer.pad_id,
    ).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    # 6. Training Loop
    print(f"Starting training for {epochs} epochs...")
    best_val_acc = 0.0

    for epoch in range(1, epochs + 1):
        train_loss, train_acc = train_epoch(model, train_loader, optimizer, criterion, device)
        val_loss, val_acc = eval_epoch(model, val_loader, criterion, device)

        if val_acc > best_val_acc:
            best_val_acc = val_acc

        if epoch % 5 == 0 or epoch == epochs:
            print(
                f"Epoch [{epoch:02d}/{epochs:02d}] "
                f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.1f}% | "
                f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc*100:.1f}%"
            )

    # 7. Save Artifacts
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Save tokenizer vocab
    vocab_file = out_path / "vocab.json"
    tokenizer.save(str(vocab_file))
    print(f"Saved vocabulary to: {vocab_file}")

    # Save PyTorch weights
    pt_file = out_path / "phishing_model.pt"
    torch.save(model.state_dict(), str(pt_file))
    print(f"Saved PyTorch weights to: {pt_file}")

    # Save ONNX model for lightweight zero-dependency deployment inference
    onnx_file = out_path / "phishing_model.onnx"
    export_to_onnx(model, onnx_file, tokenizer.vocab_size, tokenizer.max_length)
    print(f"Saved ONNX model to: {onnx_file}")

    print(f"\nTraining completed! Best Validation Accuracy: {best_val_acc*100:.1f}%")
    return {
        "best_val_acc": best_val_acc,
        "vocab_file": str(vocab_file),
        "onnx_file": str(onnx_file),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train 1D-CNN + Bi-GRU Phishing Detection Model")
    parser.add_argument("--dataset", type=str, default=None, help="Path to custom CSV dataset (optional)")
    parser.add_argument("--epochs", type=int, default=20, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--output-dir", type=str, default="ml/weights", help="Directory to save model weights")

    args = parser.parse_args()
    run_training(
        dataset_path=args.dataset,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        output_dir=args.output_dir,
    )
