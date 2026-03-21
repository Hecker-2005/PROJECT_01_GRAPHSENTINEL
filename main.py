# main.py

import argparse
import os
import torch
import shutil
import json
import numpy as np
from gensim.models import Word2Vec
import networkx as nx
from datetime import datetime

from parser_pipeline.pipeline import SourceCodePipeline
from dataset.feature_encoder import NodeFeatureEncoder
from dataset.graph_converter import GraphConverter
from dataset.pyg_dataset import CPGDataset
from dataset.node_types import NODE_TYPES
from trainer.train import train_model
from trainer.evaluate import compute_scores
from trainer.threshold import compute_threshold
from detector.anomaly_detector import VulnerabilityDetector
from model.relational_autoencoder import RelationalGraphAutoencoder

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------
# Parse Mode
# --------------------------------------------------
def run_parse(source, workspace):
    pipeline = SourceCodePipeline()
    graph_count = pipeline.process(source_dir=source, workspace=workspace)
    print(f"Parsing complete. {graph_count} function graphs extracted.")

# --------------------------------------------------
# Train Mode
# --------------------------------------------------
def run_train(workspace, finetune=False):
    graph_dir      = os.path.join(workspace, "graphs")
    model_path     = os.path.join(workspace, "model.pt")
    embedding_path = os.path.join(_BASE_DIR, "embeddings", "word2vec.model")

    print("Loading Word2Vec...")
    w2v     = Word2Vec.load(embedding_path)
    encoder = NodeFeatureEncoder(w2v, NODE_TYPES)

    print("Loading PyG Dataset...")
    dataset   = CPGDataset(graph_dir, encoder)
    input_dim = dataset.get(0).x.shape[1]

    train_size   = int(0.8 * len(dataset))
    val_size     = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(
        dataset, [train_size, val_size])

    # ── Fine-tune: load existing weights before training ──
    existing_weights = None
    if finetune and os.path.exists(model_path):
        print("Fine-tune mode: loading existing model checkpoint...")
        existing_weights = torch.load(model_path, map_location=DEVICE)

    model, history = train_model(
        train_dataset, val_dataset,
        input_dim, DEVICE,
        epochs=50,
        pretrained_weights=existing_weights
    )

    torch.save(model.state_dict(), model_path)
    print("Model saved to:", model_path)

    # Save training history for dashboard
    history["timestamp"]      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    history["best_val_loss"]  = float(min(history["val_loss"]))
    history["mode"]           = "finetune" if finetune else "train"
    history["graph_count"]    = len(dataset)

    history_path = os.path.join(workspace, "training_history.json")
    # Append to existing history list
    all_history = []
    if os.path.exists(history_path):
        try:
            with open(history_path) as f:
                all_history = json.load(f)
        except Exception:
            all_history = []

    all_history.append(history)

    # Keep only last 10 runs to avoid huge files
    all_history = all_history[-10:]

    with open(history_path, "w") as f:
        json.dump(all_history, f, indent=2)

    print("Training history saved.")

    print("Calculating Anomaly Threshold...")
    scores    = compute_scores(model, train_dataset, DEVICE)
    threshold = compute_threshold(scores)

    stats = {
        "threshold": threshold,
        "mean":      float(np.mean(scores)),
        "std":       float(np.std(scores))
    }
    with open(os.path.join(workspace, "threshold_stats.json"), "w") as f:
        json.dump(stats, f, indent=2)

    with open(os.path.join(workspace, "threshold.txt"), "w") as f:
        f.write(str(threshold))

    print("Threshold saved.")

# --------------------------------------------------
# Detect Mode
# --------------------------------------------------
def run_detect(file_path, workspace):

    # ---------- directory scan support ----------
    if os.path.isdir(file_path):

        results = {
            "SAFE": 0,
            "PARTIALLY VULNERABLE": 0,
            "VULNERABLE": 0,
            "CRITICAL": 0
        }

        files = []

        for root, _, names in os.walk(file_path):
            for n in names:
                if n.endswith(".c") or n.endswith(".cpp"):
                    files.append(os.path.join(root, n))

        print(f"\nScanning {len(files)} files...\n")

        for f in files:
            try:
                severity = run_detect(f, workspace)
                if severity in results:
                    results[severity] += 1
            except Exception as e:
                print(f"Skipping {f}: {e}")

        print("\n=========== DATASET SCAN SUMMARY ===========")
        for k, v in results.items():
            print(f"{k}: {v}")
        print("============================================")

        return

    # ---------- single file detection ----------
    embedding_path = os.path.join(_BASE_DIR, "embeddings", "word2vec.model")
    model_path = os.path.join(workspace, "model.pt")

    # CHANGE 2: Load threshold stats from JSON instead of plain txt
    threshold_stats_path = os.path.join(workspace, "threshold_stats.json")
    with open(threshold_stats_path) as f:
        if not os.path.exists(threshold_stats_path):
            raise RuntimeError(
                "No threshold_stats.json found. "
                "Please run --mode train before detect."
            )
        with open(threshold_stats_path) as f:
            stats = json.load(f)

    threshold = stats["threshold"]

    # CHANGE 3: Use std as margin instead of hardcoded 0.005
    margin = stats["std"]

    temp_workspace = os.path.join(workspace, "temp_detect")
    temp_input = os.path.join(temp_workspace, "input")

    if os.path.exists(temp_workspace):
        shutil.rmtree(temp_workspace)

    os.makedirs(temp_input)

    target_name = os.path.basename(file_path)
    target_copy = os.path.join(temp_input, target_name)

    shutil.copy2(file_path, target_copy)

    print(f"1. Parsing Target File: {file_path}")

    pipeline = SourceCodePipeline()

    graph_count = pipeline.process(
        source_dir=temp_input,
        workspace=temp_workspace
    )

    if graph_count == 0:
        raise RuntimeError("No graphs generated for target file.")

    print("2. Encoding Graph Features...")

    # CHANGE 4: Removed duplicate encoder/converter initialization
    w2v = Word2Vec.load(embedding_path)
    encoder = NodeFeatureEncoder(w2v, NODE_TYPES)
    converter = GraphConverter(encoder)

    print("3. Loading AI Engine...")

    # Dynamically infer input_dim from the first generated graph
    temp_graphs_dir = os.path.join(temp_workspace, "graphs")
    first_graph_file = sorted(os.listdir(temp_graphs_dir))[0]

    with open(os.path.join(temp_graphs_dir, first_graph_file)) as f:
        sample_data = json.load(f)

    sample_nx = nx.node_link_graph(sample_data["graph"])
    sample_pyg = converter.convert(sample_nx, label=0)
    input_dim = sample_pyg.x.shape[1]

    model = RelationalGraphAutoencoder(input_dim=input_dim, num_relations=3)
    model.load_state_dict(torch.load(model_path, map_location=DEVICE))
    model.to(DEVICE)
    model.eval()

    print("4. Scanning for Zero-Day Anomalies...")

    detector = VulnerabilityDetector(model, threshold, DEVICE)

    graphs_dir = os.path.join(temp_workspace, "graphs")

    anomalies = []

    for graph_file in sorted(os.listdir(graphs_dir)):

        if not graph_file.endswith(".json"):
            continue

        graph_path = os.path.join(graphs_dir, graph_file)

        with open(graph_path) as f:
            graph_data = json.load(f)

        nx_graph = nx.node_link_graph(graph_data["graph"])

        pyg_graph = converter.convert(nx_graph, label=0)
        pyg_graph = pyg_graph.to(DEVICE)

        result = detector.detect(pyg_graph)

        score = result["overall_score"]
        line = result["localization"]["vulnerable_line_number"]

        if score >= threshold - margin:

            if score < threshold:
                severity = "PARTIALLY VULNERABLE"
            elif score < threshold + margin:
                severity = "VULNERABLE"
            else:
                severity = "CRITICAL"

            anomalies.append({
                "graph": graph_file,
                "score": score,
                "severity": severity,
                "line": line
            })

    # ---------- final severity ----------
    if not anomalies:
        severity = "SAFE"
    else:
        anomalies.sort(key=lambda x: x["score"], reverse=True)
        severity = anomalies[0]["severity"]

    # ---------- report ----------
    print("\n================ DETECTOR REPORT ================")
    print(f"Target File: {file_path}")
    print(f"Threshold:   {threshold:.4f}")
    print(f"Margin (1σ): {margin:.4f}")

    if not anomalies:
        print("No suspicious functions detected.")
    else:
        print("\nSuspicious Functions:")

        for item in anomalies:
            print(
                f"{item['graph']} | "
                f"{item['severity']} | "
                f"score={item['score']:.4f} | "
                f"line={item['line']}"
            )

    print("=================================================")

    return severity

# --------------------------------------------------
# CLI
# --------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["parse", "train", "finetune", "detect"])
    parser.add_argument("--source", help="Directory of source code to parse/train on")
    parser.add_argument("--workspace", required=True, help="Directory to save graphs and models")
    parser.add_argument("--file", help="Specific file or directory to scan in detect mode")

    args = parser.parse_args()

    if args.mode == "parse":
        if not args.source:
            print("Error: --source is required for parse mode.")
            return
        run_parse(args.source, args.workspace)

    elif args.mode == "train":
        run_train(args.workspace, finetune=False)

    elif args.mode == "finetune":
        run_train(args.workspace, finetune=True)

    elif args.mode == "detect":
        if not args.file:
            print("Error: --file is required for detect mode.")
            return
        run_detect(args.file, args.workspace)

if __name__ == "__main__":
    main()