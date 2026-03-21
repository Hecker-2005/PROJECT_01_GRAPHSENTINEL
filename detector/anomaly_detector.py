# anomaly_detector.py

import torch
import torch.nn.functional as F
from model.loss import reconstruction_loss

class VulnerabilityDetector:
    def __init__(self, model, threshold, device):
        self.model = model
        self.threshold = threshold
        self.device = device

    def score_graph(self, graph):
        self.model.eval()
        graph = graph.to(self.device)
        with torch.no_grad():
            output = self.model(graph)
            loss, feat_loss, ast_loss, cfg_loss, dfg_loss = reconstruction_loss(output, graph)
            x_recon = output["x_hat"]
            node_mse_scores = torch.mean(
                (x_recon - graph.x) ** 2,
                dim=1
            )
        return loss.item(), node_mse_scores

    def detect(self, graph):
        graph_score, node_scores = self.score_graph(graph)

        # Skip tiny graphs — fewer than 8 nodes are almost always
        # simple helper functions (return stmt, single call) that
        # produce unreliable reconstruction scores
        num_nodes = graph.x.shape[0] if graph.x is not None else 0
        if num_nodes < 8:
            return {
                "vulnerable": False,
                "overall_score": 0.0,   # suppress score for tiny graphs
                "localization": {
                    "anomalous_node_idx": -1,
                    "node_anomaly_score": 0.0,
                    "vulnerable_line_number": -1
                }
            }

        is_vulnerable = graph_score > self.threshold
        
        # Find the index of the node with the highest reconstruction error
        if node_scores.numel() == 0:
            most_anomalous_node_idx = -1
            highest_node_score = 0
        else:
            most_anomalous_node_idx = torch.argmax(node_scores).item()
            highest_node_score = node_scores[most_anomalous_node_idx].item()

        # Safely extract the line number (using the attribute we added to graph_converter.py)
        vulnerable_line = -1

        if hasattr(graph, "line_number") and most_anomalous_node_idx != -1:
            
            # Step 1: Try the anomalous node's own line number directly
            direct_line = graph.line_number[most_anomalous_node_idx].item()
            
            if direct_line > 0:
                vulnerable_line = direct_line
            
            else:
                # Step 2: Fall back — scan all nodes for the closest valid line number
                # Use graph edge proximity via edge_index instead of list index
                best_distance = 1e9
                
                # Build a simple neighbour set from edge_index for the anomalous node
                neighbours = set()
                for edge_idx in range(graph.edge_index.shape[1]):
                    src = graph.edge_index[0, edge_idx].item()
                    dst = graph.edge_index[1, edge_idx].item()
                    if src == most_anomalous_node_idx:
                        neighbours.add(dst)
                    if dst == most_anomalous_node_idx:
                        neighbours.add(src)
                
                # Prefer neighbours first, then all other nodes
                search_order = (
                    list(neighbours) +
                    [i for i in range(graph.line_number.shape[0])
                    if i not in neighbours and i != most_anomalous_node_idx]
                )
                
                for i in search_order:
                    line = graph.line_number[i].item()
                    if line > 0:
                        vulnerable_line = line
                        break

        # Build a highly detailed, localization-aware output report
        report = {
            "vulnerable": is_vulnerable,
            "overall_score": round(graph_score, 4),
            "localization": {
                "anomalous_node_idx": most_anomalous_node_idx,
                "node_anomaly_score": round(highest_node_score, 4),
                "vulnerable_line_number": vulnerable_line
            }
        }

        return report