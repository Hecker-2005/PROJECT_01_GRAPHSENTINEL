# evaluate.py

import torch
from torch_geometric.loader import DataLoader
from model.loss import reconstruction_loss

def compute_scores(model, dataset, device):
    """
    Computes reconstruction error for each individual graph.
    Forces batch_size=1 to ensure per-graph anomaly scores.
    """
    model.eval()
    scores = []
    
    # CRITICAL FIX: Force batch_size=1 to prevent score averaging!
    loader = DataLoader(dataset, batch_size=1, shuffle=False)

    with torch.no_grad():
        for data in loader:
            data = data.to(device)
            output = model(data)
            
            # Since batch_size=1, this loss perfectly represents ONE graph
            loss, *_ = reconstruction_loss(output, data)
            scores.append(loss.item())

    return scores