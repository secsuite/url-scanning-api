"""
Siamese Network for logo matching.
Uses twin CNN branches (shared weights) with a ResNet-18 backbone
to produce embeddings, then computes cosine similarity.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.models as models
import config


class SiameseNetwork(nn.Module):
    """
    Siamese Network with shared-weight CNN branches.

    Architecture:
        Input pair (img1, img2)
        → Each through shared ResNet-18 backbone (pretrained)
        → Global Average Pooling (512-dim)
        → FC → BatchNorm → ReLU → FC (embedding_dim)
        → L2 normalize embeddings
        → Cosine similarity for matching
    """

    def __init__(self, embedding_dim=None, pretrained=True):
        super().__init__()

        if embedding_dim is None:
            embedding_dim = config.SIAMESE_EMBEDDING_DIM

        # Shared backbone: ResNet-18 without the final FC layer
        backbone = models.resnet18(
            weights="DEFAULT" if pretrained else None
        )
        # Remove the final FC layer — we'll add our own embedding head
        self.features = nn.Sequential(*list(backbone.children())[:-1])
        backbone_out_dim = 512  # ResNet-18 outputs 512-dim after avgpool

        # Embedding head
        self.embedding = nn.Sequential(
            nn.Linear(backbone_out_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(256, embedding_dim),
        )

        self.embedding_dim = embedding_dim

    def forward_one(self, x):
        """Forward pass through one branch."""
        x = self.features(x)
        x = x.view(x.size(0), -1)  # Flatten
        x = self.embedding(x)
        x = F.normalize(x, p=2, dim=1)  # L2 normalize
        return x

    def forward(self, img1, img2):
        """
        Forward pass through both branches.

        Args:
            img1: Tensor [B, C, H, W] — e.g., detected logo crop
            img2: Tensor [B, C, H, W] — e.g., reference logo

        Returns:
            emb1: Tensor [B, embedding_dim]
            emb2: Tensor [B, embedding_dim]
        """
        emb1 = self.forward_one(img1)
        emb2 = self.forward_one(img2)
        return emb1, emb2

    def similarity(self, img1, img2):
        """
        Compute cosine similarity between two images.

        Returns:
            Tensor [B] — similarity scores in [-1, 1]
        """
        emb1, emb2 = self.forward(img1, img2)
        return F.cosine_similarity(emb1, emb2, dim=1)

    def get_embedding(self, img):
        """Get the embedding for a single image (or batch)."""
        return self.forward_one(img)


class ContrastiveLoss(nn.Module):
    """
    Contrastive loss function.

    For positive pairs (label=1): loss = (1 - cos_sim)^2
    For negative pairs (label=0): loss = max(0, cos_sim - margin)^2

    This encourages positive pairs to have high similarity
    and negative pairs to have low similarity.
    """

    def __init__(self, margin=None):
        super().__init__()
        if margin is None:
            margin = config.SIAMESE_MARGIN
        self.margin = margin

    def forward(self, emb1, emb2, labels):
        """
        Args:
            emb1: Tensor [B, D] — L2-normalized embeddings
            emb2: Tensor [B, D] — L2-normalized embeddings
            labels: Tensor [B] — 1 for positive pair, 0 for negative

        Returns:
            loss: scalar Tensor
        """
        cos_sim = F.cosine_similarity(emb1, emb2, dim=1)

        # Positive: minimize distance (maximize similarity)
        pos_loss = labels * (1 - cos_sim).pow(2)

        # Negative: push apart (minimize similarity below margin)
        neg_loss = (1 - labels) * F.relu(cos_sim - self.margin + 1).pow(2)

        loss = (pos_loss + neg_loss).mean()
        return loss


def get_siamese_model(pretrained=True):
    """Factory function for the Siamese Network."""
    return SiameseNetwork(
        embedding_dim=config.SIAMESE_EMBEDDING_DIM,
        pretrained=pretrained,
    )
