"""
ONNX Runtime inference classifier for 1D-CNN + Bi-GRU Phishing Detection.
Loads pre-trained weights and vocabulary without requiring heavy PyTorch in production.
"""
from dataclasses import dataclass
import logging
import math
import os
from pathlib import Path
from typing import List, Optional

from app.ml.tokenizer import PhishingTokenizer

logger = logging.getLogger("mailrecon.ml.classifier")

# Common salient tokens associated with social engineering and phishing lures
HIGH_RISK_LURE_TOKENS = {
    "urgent", "immediately", "confidential", "wire", "transfer", "suspended",
    "suspend", "password", "verify", "verification", "unauthorized", "login",
    "limited", "payroll", "deposit", "invoice", "overdue", "remit", "ssn",
    "pin", "banking", "account", "tax", "refund", "parcel", "shipment",
    "<url>", "<money>", "dispute", "cancel", "bonus", "macros"
}


@dataclass
class NeuralPrediction:
    is_phishing: bool
    probability: float
    confidence: float
    risk_level: str  # "low", "medium", "high", "critical"
    salient_tokens: List[str]


class PhishingNeuralClassifier:
    """
    Singleton-capable classifier using ONNX Runtime for 1D-CNN + Bi-GRU sequence classification.
    """
    _instance: Optional["PhishingNeuralClassifier"] = None

    def __init__(self, model_path: Optional[str] = None, vocab_path: Optional[str] = None):
        self.session = None
        self.tokenizer: Optional[PhishingTokenizer] = None
        self.is_ready = False
        self._load_model_and_vocab(model_path, vocab_path)

    def _find_weights(
        self, custom_model_path: Optional[str], custom_vocab_path: Optional[str]
    ) -> tuple[Optional[Path], Optional[Path]]:
        # Candidate directories
        current_dir = Path(__file__).resolve().parent
        repo_root = current_dir.parent.parent.parent

        candidate_dirs = [
            current_dir / "weights",
            repo_root / "ml" / "weights",
            Path("/data/models"),
        ]

        model_file = None
        vocab_file = None

        if custom_model_path and Path(custom_model_path).is_file():
            model_file = Path(custom_model_path)
        if custom_vocab_path and Path(custom_vocab_path).is_file():
            vocab_file = Path(custom_vocab_path)

        if not model_file or not vocab_file:
            for d in candidate_dirs:
                m = d / "phishing_model.onnx"
                v = d / "vocab.json"
                if m.is_file() and v.is_file():
                    model_file = model_file or m
                    vocab_file = vocab_file or v
                    break

        return model_file, vocab_file

    def _load_model_and_vocab(self, model_path: Optional[str], vocab_path: Optional[str]):
        try:
            import onnxruntime as ort
        except ImportError:
            logger.warning("onnxruntime is not installed. Neural classifier will be disabled.")
            return

        model_file, vocab_file = self._find_weights(model_path, vocab_path)
        if not model_file or not vocab_file:
            logger.warning(
                f"Model or vocab files not found in search paths. Neural classifier is inactive."
            )
            return

        try:
            # Set thread options for efficient server-side inference
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = 1
            opts.inter_op_num_threads = 1
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

            self.session = ort.InferenceSession(str(model_file), sess_options=opts)
            self.tokenizer = PhishingTokenizer.load(str(vocab_file))
            self.is_ready = True
            logger.info(f"Loaded ONNX neural classifier from {model_file} with {self.tokenizer.vocab_size} tokens")
        except Exception as e:
            logger.error(f"Failed to load ONNX session from {model_file}: {e}", exc_info=True)
            self.is_ready = False

    def predict(self, text: str) -> Optional[NeuralPrediction]:
        """
        Classify input text using the 1D-CNN + Bi-GRU ONNX model.
        Returns None if classifier is not ready.
        """
        if not self.is_ready or not self.session or not self.tokenizer:
            return None

        if not text or not text.strip():
            return NeuralPrediction(
                is_phishing=False,
                probability=0.0,
                confidence=0.5,
                risk_level="low",
                salient_tokens=[],
            )

        try:
            import numpy as np
        except ImportError:
            logger.warning("numpy is not installed. Neural classifier prediction failed.")
            return None

        input_ids = self.tokenizer.encode(text)
        input_array = np.array([input_ids], dtype=np.int64)

        # Run ONNX inference
        outputs = self.session.run(None, {"input_ids": input_array})
        logits = outputs[0][0]  # [logit_benign, logit_phishing]

        # Softmax computation
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)
        benign_prob = float(probs[0])
        phishing_prob = float(probs[1])

        is_phishing = phishing_prob >= 0.5
        confidence = float(max(benign_prob, phishing_prob))

        # Determine severity level
        if phishing_prob >= 0.85:
            risk_level = "critical" if phishing_prob >= 0.95 else "high"
        elif phishing_prob >= 0.60:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Identify salient trigger tokens present in the text
        tokens = self.tokenizer.tokenize(text)
        salient: List[str] = []
        seen = set()
        for tok in tokens:
            t_lower = tok.lower()
            if t_lower in HIGH_RISK_LURE_TOKENS and t_lower not in seen:
                seen.add(t_lower)
                salient.append(tok)
                if len(salient) >= 5:
                    break

        return NeuralPrediction(
            is_phishing=is_phishing,
            probability=phishing_prob,
            confidence=confidence,
            risk_level=risk_level,
            salient_tokens=salient,
        )


_classifier_instance: Optional[PhishingNeuralClassifier] = None


def get_neural_classifier() -> PhishingNeuralClassifier:
    """Get or instantiate the global neural classifier instance."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = PhishingNeuralClassifier()
    return _classifier_instance
