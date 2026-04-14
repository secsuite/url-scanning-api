"""
Central configuration for the phishing detection pipeline.
All paths, hyperparameters, and constants are defined here.
"""

import os

# =============================================================================
# Paths
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Raw LogoSENSE dataset
RAW_DATA_DIR = os.path.join(DATA_DIR, "logosense_raw", "base_data")
TRAINING_SET_DIR = os.path.join(RAW_DATA_DIR, "training_set")
WILD_SET_DIR = os.path.join(RAW_DATA_DIR, "wild_set")

# Processed data (COCO format)
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
PROCESSED_IMAGES_DIR = os.path.join(PROCESSED_DIR, "images")
PROCESSED_TRAIN_JSON = os.path.join(PROCESSED_DIR, "train.json")
PROCESSED_VAL_JSON = os.path.join(PROCESSED_DIR, "val.json")
PROCESSED_TEST_JSON = os.path.join(PROCESSED_DIR, "test.json")

# Reference logos for Siamese network
REFERENCE_LOGOS_DIR = os.path.join(DATA_DIR, "reference_logos")

# Model checkpoints
CHECKPOINTS_DIR = os.path.join(BASE_DIR, "checkpoints")
FRCNN_CHECKPOINT = os.path.join(CHECKPOINTS_DIR, "frcnn_best.pth")
SIAMESE_CHECKPOINT = os.path.join(CHECKPOINTS_DIR, "siamese_best.pth")

# Outputs
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# =============================================================================
# Brand Configuration
# =============================================================================
BRAND_NAMES = [
    "alibaba",
    "aol",
    "apple",
    "boa",
    "chase",
    "dhl",
    "dropbox",
    "facebook",
    "google",
    "microsoft",
    "office",
    "orange",
    "paypal",
    "wellsfargo",
    "yahoo",
]

# Category IDs (1-indexed, 0 is background for Faster R-CNN)
BRAND_TO_ID = {name: idx + 1 for idx, name in enumerate(BRAND_NAMES)}
ID_TO_BRAND = {idx + 1: name for idx, name in enumerate(BRAND_NAMES)}
FRCNN_NUM_CLASSES = 2  # 1 object class ("logo") + 1 background

# Domain whitelist: brand -> list of legitimate domains
BRAND_DOMAINS = {
    "alibaba": ["alibaba.com", "aliexpress.com", "aliyun.com"],
    "aol": ["aol.com"],
    "apple": ["apple.com", "icloud.com"],
    "boa": ["bankofamerica.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "dropbox": ["dropbox.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "office": ["office.com", "office365.com", "microsoft.com"],
    "orange": ["orange.com", "orange.fr"],
    "paypal": ["paypal.com"],
    "wellsfargo": ["wellsfargo.com"],
    "yahoo": ["yahoo.com"],
}

# =============================================================================
# Faster R-CNN Hyperparameters
# =============================================================================
FRCNN_IMAGE_SIZE = 800  # Min size for image rescaling
FRCNN_BATCH_SIZE = 4
FRCNN_LEARNING_RATE = 0.005
FRCNN_MOMENTUM = 0.9
FRCNN_WEIGHT_DECAY = 0.0005
FRCNN_EPOCHS = 30
FRCNN_LR_STEP_SIZE = 10
FRCNN_LR_GAMMA = 0.1
FRCNN_SCORE_THRESHOLD = 0.5  # Min confidence to keep a detection

# =============================================================================
# Siamese Network Hyperparameters
# =============================================================================
SIAMESE_IMAGE_SIZE = 224  # Input size for Siamese branches
SIAMESE_EMBEDDING_DIM = 128
SIAMESE_BATCH_SIZE = 32
SIAMESE_LEARNING_RATE = 0.0005
SIAMESE_EPOCHS = 50
SIAMESE_MARGIN = 1.0  # Contrastive loss margin
SIAMESE_SIMILARITY_THRESHOLD = 0.7  # Cosine similarity threshold for matching


# =============================================================================
# Utility
# =============================================================================
def ensure_dirs():
    """Create all necessary output directories."""
    for d in [
        PROCESSED_DIR,
        PROCESSED_IMAGES_DIR,
        REFERENCE_LOGOS_DIR,
        CHECKPOINTS_DIR,
        OUTPUT_DIR,
    ]:
        os.makedirs(d, exist_ok=True)
