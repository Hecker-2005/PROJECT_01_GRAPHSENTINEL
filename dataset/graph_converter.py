# graph_converter.py

import torch
from torch_geometric.data import Data
from dataset.edge_schema import EDGE_TYPE_MAP
import numpy as np 

class GraphConverter:
    def __init__(self, encoder):
        self.encoder = encoder

    def convert(self, graph, label):
        node_features = []
        node_id_map = {}
        line_numbers = [] # CRITICAL FIX: Array to store line numbers

        for i, (node_id, attrs) in enumerate(graph.nodes(data=True)):
            node_id_map[node_id] = i

            feature = self.encoder.encode(attrs)
            node_features.append(feature)
            
            # OPTIMIZATION: Extract line number (Joern uses 'lineNumber' or 'line')
            # Default to -1 if it's a generated node without a specific line
            line_num = (
                attrs.get("LINE_NUMBER")
                or attrs.get("lineNumber")
                or attrs.get("line")
            )

            # fallback: try to extract from raw CSV row
            if not line_num and "raw" in attrs:

                raw = attrs["raw"]

                if isinstance(raw, list) and len(raw) > 6:
                    candidate = raw[6]

                    try:
                        line_num = int(candidate)
                    except:
                        line_num = -1
            
            # Ensure it's an integer, as Joern sometimes returns string line numbers
            try:
                line_num = int(line_num)
            except (ValueError, TypeError):
                line_num = -1
                
            line_numbers.append(line_num)

        edge_index = []
        edge_types = []

        for src, dst, attrs in graph.edges(data=True):
            if src not in node_id_map or dst not in node_id_map:
                continue

            edge_index.append([
                node_id_map[src],
                node_id_map[dst]
            ])

            etype = attrs.get("type", "AST")
            edge_types.append(EDGE_TYPE_MAP.get(etype, 0))

        if len(node_features) > 0:
            x = torch.tensor(np.array(node_features), dtype=torch.float)
        else:
            x = torch.empty((0, 0), dtype=torch.float)
        
        # Handle isolated nodes (graphs with no edges)
        if len(edge_index) > 0:
            edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
            edge_type = torch.tensor(edge_types, dtype=torch.long)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_type = torch.empty((0,), dtype=torch.long)

        y = torch.tensor([label], dtype=torch.long)
        
        # Pass line numbers as a custom attribute into the PyG Data object
        line_number = torch.tensor(line_numbers, dtype=torch.long)

        return Data(
            x=x,
            edge_index=edge_index,
            edge_type=edge_type,
            y=y,
            line_number=line_number # Attached for anomaly localization!
        )