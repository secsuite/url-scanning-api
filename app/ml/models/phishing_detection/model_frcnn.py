"""
Faster R-CNN model for logo detection.
Uses a pretrained ResNet-50 FPN backbone from torchvision,
with the classification head replaced for our 16-class problem
(15 brands + background).
"""

import torchvision
from torchvision.models.detection import FasterRCNN
from torchvision.models.detection.rpn import AnchorGenerator
from torchvision.models.detection.faster_rcnn import FastRCNNPredictor
import config


def get_model(num_classes=None, pretrained_backbone=True):
    """
    Build a Faster R-CNN model with a ResNet-50 FPN backbone.

    Args:
        num_classes: Number of output classes (including background).
                     Defaults to config.NUM_CLASSES (16).
        pretrained_backbone: Whether to use ImageNet-pretrained backbone.

    Returns:
        model: torchvision FasterRCNN model
    """
    if num_classes is None:
        num_classes = config.FRCNN_NUM_CLASSES

    # Load pretrained Faster R-CNN (COCO weights)
    model = torchvision.models.detection.fasterrcnn_resnet50_fpn(
        weights="DEFAULT" if pretrained_backbone else None,
    )

    # Replace the classification head for our number of classes
    in_features = model.roi_heads.box_predictor.cls_score.in_features
    model.roi_heads.box_predictor = FastRCNNPredictor(in_features, num_classes)

    return model


def get_model_mobilenet(num_classes=None, pretrained_backbone=True):
    """
    Lighter alternative using MobileNetV3 backbone (faster training/inference).

    Args:
        num_classes: Number of output classes (including background).
        pretrained_backbone: Whether to use pretrained backbone.

    Returns:
        model: torchvision FasterRCNN model with MobileNet backbone
    """
    if num_classes is None:
        num_classes = config.FRCNN_NUM_CLASSES

    model = torchvision.models.detection.fasterrcnn_mobilenet_v3_large_fpn(
        weights="DEFAULT" if pretrained_backbone else None,
    )

    in_features = model.roi_heads.box_predictor.cls_score.in_features
    model.roi_heads.box_predictor = FastRCNNPredictor(in_features, num_classes)

    return model
