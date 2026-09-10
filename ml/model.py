import torch
import torch.nn as nn
import torch.nn.functional as F


class PhishingCnnBiGru(nn.Module):
    """
    1D-CNN + Bi-GRU hybrid neural architecture for phishing detection.
    - 1D-CNN extracts local n-gram token bursts and phrasing patterns.
    - Bi-GRU captures long-term bidirectional context and narrative coercion.
    - Global Pooling + Dense layers produce class logits [Benign, Phishing].
    """
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 128,
        cnn_filters: int = 128,
        kernel_size: int = 3,
        gru_hidden_dim: int = 64,
        num_classes: int = 2,
        dropout: float = 0.3,
        padding_idx: int = 0,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=padding_idx)

        # 1D-CNN: (batch, embed_dim, seq_len) -> (batch, cnn_filters, seq_len)
        self.conv1d = nn.Conv1d(
            in_channels=embed_dim,
            out_channels=cnn_filters,
            kernel_size=kernel_size,
            padding=kernel_size // 2,
        )
        self.relu = nn.ReLU()
        self.maxpool = nn.MaxPool1d(kernel_size=2)

        # Bidirectional GRU:
        # Input size: cnn_filters (128)
        # Output size: gru_hidden_dim * 2 (128)
        self.gru = nn.GRU(
            input_size=cnn_filters,
            hidden_size=gru_hidden_dim,
            num_layers=1,
            batch_first=True,
            bidirectional=True,
        )

        # Dense classification head
        self.dropout1 = nn.Dropout(dropout)
        self.fc1 = nn.Linear(gru_hidden_dim * 2, 64)
        self.dropout2 = nn.Dropout(dropout * 0.7)
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, seq_len)
        embedded = self.embedding(x)  # (batch_size, seq_len, embed_dim)

        # Permute for Conv1d: (batch_size, embed_dim, seq_len)
        conv_in = embedded.permute(0, 2, 1)
        conv_out = self.relu(self.conv1d(conv_in))  # (batch_size, cnn_filters, seq_len)
        pooled = self.maxpool(conv_out)  # (batch_size, cnn_filters, seq_len // 2)

        # Permute back for GRU: (batch_size, seq_len // 2, cnn_filters)
        gru_in = pooled.permute(0, 2, 1)
        gru_out, _ = self.gru(gru_in)  # (batch_size, seq_len // 2, hidden_dim * 2)

        # Global max pooling over sequence length
        global_max, _ = torch.max(gru_out, dim=1)  # (batch_size, hidden_dim * 2)

        # Classification
        h = self.dropout1(global_max)
        h = F.relu(self.fc1(h))
        h = self.dropout2(h)
        logits = self.fc2(h)  # (batch_size, 2)
        return logits
