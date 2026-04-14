import os
import torch
import argparse
from transformers import LongformerTokenizerFast, LongformerForSequenceClassification


def classify_script(model_path, script_path):
    if not os.path.exists(model_path):
        raise ValueError(f"Model directory '{model_path}' not found. Please train the model first.")

    if not os.path.exists(script_path):
        raise ValueError(f"Script file '{script_path}' not found.")

    with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
        script_content = f.read()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"Loading model from {model_path} onto {device}...")
    tokenizer = LongformerTokenizerFast.from_pretrained(model_path)
    model = LongformerForSequenceClassification.from_pretrained(model_path)
    model.to(device)
    model.eval()

    print("Tokenizing script...")
    inputs = tokenizer(
        script_content, return_tensors="pt", padding="max_length", truncation=True, max_length=4096
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    print("Running inference...")
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=-1)
        predicted_class_id = logits.argmax().item()

    class_names = ["Benign (0)", "Malicious (1)"]
    print(f"\n--- Results ---")
    print(f"Prediction : {class_names[predicted_class_id]}")
    print(f"Confidence : {probabilities[0][predicted_class_id].item():.4f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Classify a PowerShell script as Benign or Malicious."
    )
    parser.add_argument(
        "--model_path",
        type=str,
        default="./saved_model",
        help="Path to the trained PyTorch model directory.",
    )
    parser.add_argument(
        "--script_path", type=str, required=True, help="Path to the PowerShell script to test."
    )

    args = parser.parse_args()
    classify_script(args.model_path, args.script_path)
