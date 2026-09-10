import json
from pathlib import Path
import re
from typing import Dict, List, Optional

PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
URL_TOKEN = "<URL>"
EMAIL_TOKEN = "<EMAIL>"
NUM_TOKEN = "<NUM>"
MONEY_TOKEN = "<MONEY>"

SPECIAL_TOKENS = [PAD_TOKEN, UNK_TOKEN, URL_TOKEN, EMAIL_TOKEN, NUM_TOKEN, MONEY_TOKEN]

URL_REGEX = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'[\w.-]+@[\w.-]+\.\w+', re.IGNORECASE)
MONEY_REGEX = re.compile(r'[\$€£¥]\s*\d+(?:,\d{3})*(?:\.\d+)?|\d+\s*(?:dollars?|usd|eur|gbp)', re.IGNORECASE)
NUM_REGEX = re.compile(r'\b\d+(?:,\d{3})*(?:\.\d+)?\b')
TOKEN_REGEX = re.compile(r'<[A-Z_]+>|\w+|[^\w\s]')


class PhishingTokenizer:
    """
    Lightweight, self-contained tokenizer for phishing sequence analysis.
    Normalizes URLs, emails, numbers, and currency into semantic tokens.
    """
    def __init__(self, max_length: int = 256):
        self.max_length = max_length
        self.vocab: Dict[str, int] = {}
        self.inv_vocab: Dict[int, str] = {}
        self._init_special_tokens()

    def _init_special_tokens(self):
        self.vocab = {tok: idx for idx, tok in enumerate(SPECIAL_TOKENS)}
        self.inv_vocab = {idx: tok for idx, tok in enumerate(SPECIAL_TOKENS)}

    @property
    def pad_id(self) -> int:
        return self.vocab[PAD_TOKEN]

    @property
    def unk_id(self) -> int:
        return self.vocab[UNK_TOKEN]

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    def normalize_text(self, text: str) -> str:
        """Replace dynamic entities with semantic abstraction tokens."""
        t = text.lower()
        t = URL_REGEX.sub(f" {URL_TOKEN} ", t)
        t = EMAIL_REGEX.sub(f" {EMAIL_TOKEN} ", t)
        t = MONEY_REGEX.sub(f" {MONEY_TOKEN} ", t)
        t = NUM_REGEX.sub(f" {NUM_TOKEN} ", t)
        return t

    def tokenize(self, text: str) -> List[str]:
        """Normalize and tokenize text into token strings."""
        normalized = self.normalize_text(text)
        return TOKEN_REGEX.findall(normalized)

    def build_vocab(self, texts: List[str], max_vocab_size: int = 8000, min_freq: int = 2):
        """Build vocabulary mapping from a corpus of texts."""
        self._init_special_tokens()
        freqs: Dict[str, int] = {}

        for text in texts:
            for tok in self.tokenize(text):
                if tok not in self.vocab:
                    freqs[tok] = freqs.get(tok, 0) + 1

        # Sort tokens by frequency descending
        sorted_tokens = sorted(freqs.items(), key=lambda x: x[1], reverse=True)

        for tok, freq in sorted_tokens:
            if freq < min_freq:
                break
            if len(self.vocab) >= max_vocab_size:
                break
            idx = len(self.vocab)
            self.vocab[tok] = idx
            self.inv_vocab[idx] = tok

    def encode(self, text: str) -> List[int]:
        """Tokenize and pad/truncate sequence to max_length."""
        tokens = self.tokenize(text)
        token_ids = [self.vocab.get(tok, self.unk_id) for tok in tokens]

        # Truncate if longer than max_length
        if len(token_ids) > self.max_length:
            token_ids = token_ids[:self.max_length]
        else:
            # Pad with pad_id
            token_ids = token_ids + [self.pad_id] * (self.max_length - len(token_ids))

        return token_ids

    def decode(self, token_ids: List[int]) -> str:
        """Decode a list of token ids back to a string, skipping padding."""
        tokens = [self.inv_vocab.get(tid, UNK_TOKEN) for tid in token_ids if tid != self.pad_id]
        return " ".join(tokens)

    def save(self, file_path: str):
        """Save vocabulary to JSON file."""
        data = {
            "max_length": self.max_length,
            "vocab": self.vocab,
        }
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, file_path: str) -> "PhishingTokenizer":
        """Load vocabulary from JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        tokenizer = cls(max_length=data.get("max_length", 256))
        tokenizer.vocab = data["vocab"]
        tokenizer.inv_vocab = {int(idx): tok for tok, idx in tokenizer.vocab.items()}
        return tokenizer
