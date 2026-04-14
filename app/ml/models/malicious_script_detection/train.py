import os
import torch
import pandas as pd
from datasets import Dataset, DatasetDict, load_from_disk
from transformers import (
    LongformerTokenizerFast,
    LongformerForSequenceClassification,
    Trainer,
    TrainingArguments,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def compute_metrics(pred):
    labels = pred.label_ids
    # Longformer outputs logits; get argmax
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
    acc = accuracy_score(labels, preds)
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

class CustomTrainer(Trainer):
    def __init__(self, class_weights, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Convert class weights to tensor and place on the correct device
        self.class_weights = torch.tensor(class_weights, dtype=torch.float32).to(self.args.device)
        
    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.pop("labels")
        # Forward pass
        outputs = model(**inputs)
        logits = outputs.logits
        # Use CrossEntropyLoss with class weights
        loss_fct = torch.nn.CrossEntropyLoss(weight=self.class_weights)
        loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
        return (loss, outputs) if return_outputs else loss

def main():
    model_name = "allenai/longformer-base-4096"
    print(f"Loading tokenizer {model_name}...")
    tokenizer = LongformerTokenizerFast.from_pretrained(model_name)

    tokenized_data_path = "./data/tokenized_dataset"
    if os.path.exists(tokenized_data_path):
        print(f"Loading tokenized datasets from {tokenized_data_path}...")
        tokenized_datasets = load_from_disk(tokenized_data_path)
        
        # Compute class weights from loaded dataset
        labels = tokenized_datasets['train']['label']
        class_weights = compute_class_weight(
            class_weight='balanced',
            classes=np.unique(labels),
            y=labels
        )
        print(f"Computed class weights: {class_weights}")
    else:
        data_path = "./data/dataset.csv"
        if not os.path.exists(data_path):
            print(f"Dataset not found at {data_path}. Please run dataset_builder.py first.")
            return

        print("Loading dataset...")
        df = pd.read_csv(data_path)
        
        # Handle NaN explicitly just in case
        df = df.dropna(subset=['script', 'label'])
        
        # Split the dataset
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label'])
        train_df, val_df = train_test_split(train_df, test_size=0.1, random_state=42, stratify=train_df['label'])

        print(f"Train size: {len(train_df)}, Val size: {len(val_df)}, Test size: {len(test_df)}")

        # Compute class weights for handling imbalance
        labels = train_df['label'].values
        class_weights = compute_class_weight(
            class_weight='balanced',
            classes=np.unique(labels),
            y=labels
        )
        print(f"Computed class weights: {class_weights}")

        # Convert to Hugging Face Dataset
        train_dataset = Dataset.from_pandas(train_df)
        val_dataset = Dataset.from_pandas(val_df)
        test_dataset = Dataset.from_pandas(test_df)

        dataset = DatasetDict({
            'train': train_dataset,
            'validation': val_dataset,
            'test': test_dataset
        })

        def tokenize_function(examples):
            return tokenizer(examples['script'], padding='max_length', truncation=True, max_length=4096)

        print("Tokenizing datasets (this might take a while)...")
        cols_to_remove = ['script']
        if '__index_level_0__' in dataset['train'].column_names:
            cols_to_remove.append('__index_level_0__')
            
        tokenized_datasets = dataset.map(tokenize_function, batched=True, remove_columns=cols_to_remove)
        
        print(f"Saving tokenized datasets to {tokenized_data_path}...")
        tokenized_datasets.save_to_disk(tokenized_data_path)

    # Model
    print(f"Loading model {model_name}...")
    model = LongformerForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    # Training arguments optimized for AWS g6e.xlarge (L40S GPU - 48GB VRAM)
    training_args = TrainingArguments(
        output_dir='./results',
        num_train_epochs=3,
        per_device_train_batch_size=8,   # Increased batch size due to gradient checkpointing
        per_device_eval_batch_size=8,
        gradient_accumulation_steps=1,   # Effective batch size stays 8
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir='./logs',
        logging_steps=50,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        bf16=True, # L40S supports bf16 natively
        tf32=True, # Utilize Tensor Cores for FP32 matmuls
        optim="adamw_torch_fused", # Much faster fused CUDA optimizer
        gradient_checkpointing=True, # Trade a bit of compute to save VRAM and increase native batch size
        torch_compile=True, # JIT compile the model for ~20-30% speedup (PyTorch 2.x)
        dataloader_num_workers=4, # g6e.xlarge has 4 vCPUs
        report_to="none"
    )

    print("Initializing Trainer...")
    trainer = CustomTrainer(
        class_weights=class_weights,
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets['train'],
        eval_dataset=tokenized_datasets['validation'],
        processing_class=tokenizer, 
        compute_metrics=compute_metrics,
    )

    print("Starting training...")
    trainer.train()

    print("Evaluating on test set...")
    test_results = trainer.evaluate(tokenized_datasets['test'])
    print(test_results)

    print("Saving model...")
    trainer.save_model("./saved_model")
    tokenizer.save_pretrained("./saved_model")
    print("Training complete!")

if __name__ == "__main__":
    main()
