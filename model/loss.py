import torch
import torch.nn.functional as F


# --------------------------------------------------
# Focal Loss for Sparse Graph Reconstruction
# --------------------------------------------------
def focal_loss(pred, target, gamma=2.0, eps=1e-8):

    pred = torch.nan_to_num(pred, nan=0.5)
    pred = pred.clamp(eps, 1 - eps)

    pt = torch.where(target == 1, pred, 1 - pred)

    loss = -((1 - pt) ** gamma) * torch.log(pt)

    return loss.mean()


# --------------------------------------------------
# Relational Reconstruction Loss
# --------------------------------------------------
def reconstruction_loss(output, data,
                        alpha=0.2,
                        beta=0.2,
                        gamma=0.3,
                        delta=0.3):

    x_true = data.x
    x_pred = output["x_hat"]

    # ---------- Feature loss ----------
    feature_loss = F.mse_loss(x_pred, x_true)

    # ---------- Structure losses ----------
    adj_preds = output["adj_preds"]
    adj_true_rel = output["adj_true_rel"]
    mask = output["mask"]

    # Expand mask for adjacency matrices
    mask_2d = mask.unsqueeze(1) & mask.unsqueeze(2)

    relation_losses = []

    for pred, true in zip(adj_preds, adj_true_rel):

        true = (true > 0).float()

        pred_valid = pred[mask_2d]
        true_valid = true[mask_2d]

        # Skip relations that have no valid elements
        if pred_valid.numel() == 0:
            relation_losses.append(
                torch.tensor(0.0, device=x_true.device)
            )
            continue

        relation_losses.append(
            focal_loss(pred_valid, true_valid)
        )

    # AST, CFG, DFG losses
    ast_loss = relation_losses[0]
    cfg_loss = relation_losses[1]
    dfg_loss = relation_losses[2]

    # ---------- Total loss ----------
    total_loss = (
        alpha * feature_loss
        + beta * ast_loss
        + gamma * cfg_loss
        + delta * dfg_loss
    )

    return total_loss, feature_loss, ast_loss, cfg_loss, dfg_loss