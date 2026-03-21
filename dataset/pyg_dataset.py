# pyg_dataset.py

import os
import json
import networkx as nx

from torch_geometric.data import Dataset
from dataset.graph_converter import GraphConverter # Ensure explicit import path

class CPGDataset(Dataset):
    def __init__(self, graph_dir, encoder):
        super().__init__()
        self.graph_dir = graph_dir
        # Filter to ensure we only try to load valid JSON files
        self.graph_files = sorted(
            [f for f in os.listdir(graph_dir) if f.endswith(".json")]
        )
        self.converter = GraphConverter(encoder)

    def len(self):
        return len(self.graph_files)

    def get(self, idx):
        file_path = os.path.join(self.graph_dir, self.graph_files[idx])

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            graph = nx.node_link_graph(data["graph"])
            label = data.get("label", 0) # Default to safe (0) if missing

            pyg_graph = self.converter.convert(graph, label)
            return pyg_graph
            
        except Exception as e:
            # Prevent single corrupted JSONs from crashing the training loop
            print(f"Error loading graph {self.graph_files[idx]}: {e}")
            # Return an empty graph as a safe fallback
            return self.converter.convert(nx.MultiDiGraph(), 0)