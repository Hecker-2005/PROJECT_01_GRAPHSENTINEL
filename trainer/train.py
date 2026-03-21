import torch
import copy

from torch.optim import AdamW
from torch_geometric.loader import DataLoader

from model.relational_autoencoder import RelationalGraphAutoencoder
from model.loss import reconstruction_loss


def train_model(train_dataset, val_dataset, input_dim, device,
                epochs=50, batch_size=16, pretrained_weights=None):

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_dataset,   batch_size=batch_size, shuffle=False)

    model = RelationalGraphAutoencoder(
        input_dim=input_dim,
        num_relations=3
    ).to(device)

    # Load pretrained weights if fine-tuning
    if pretrained_weights is not None:
        try:
            model.load_state_dict(pretrained_weights, strict=True)
            print("Loaded existing weights for fine-tuning.")
        except RuntimeError as e:
            print(f"Warning: weight mismatch ({e}). Training from scratch.")
        except Exception as e:
            print(f"Warning: could not load weights ({e}). Training from scratch.")

    optimizer = AdamW(
        model.parameters(),
        lr=0.001,
        weight_decay=1e-4
    )

    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=5
    )

    best_val_loss = float("inf")
    best_weights  = copy.deepcopy(model.state_dict())

    # History tracking
    history = {
        "epochs":     [],
        "train_loss": [],
        "val_loss":   [],
        "feat_loss":  [],
        "ast_loss":   [],
        "cfg_loss":   [],
        "dfg_loss":   [],
    }

    print(f"Starting Training on {device}...")

    for epoch in range(epochs):

        # ---------------- TRAIN ----------------
        model.train()
        train_loss = 0
        train_feat = 0
        train_ast  = 0
        train_cfg  = 0
        train_dfg  = 0

        for data in train_loader:
            data = data.to(device)
            optimizer.zero_grad()
            output = model(data)
            loss, f_loss, ast_loss, cfg_loss, dfg_loss = reconstruction_loss(output, data)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            train_loss += loss.item()
            train_feat += f_loss.item()
            train_ast  += ast_loss.item()
            train_cfg  += cfg_loss.item()
            train_dfg  += dfg_loss.item()

        # ---------------- VALIDATION ----------------
        model.eval()
        val_loss = 0

        with torch.no_grad():
            for data in val_loader:
                data = data.to(device)
                output = model(data)
                v_loss, *_ = reconstruction_loss(output, data)
                val_loss += v_loss.item()

        avg_train = train_loss / len(train_loader)
        avg_feat  = train_feat / len(train_loader)
        avg_ast   = train_ast  / len(train_loader)
        avg_cfg   = train_cfg  / len(train_loader)
        avg_dfg   = train_dfg  / len(train_loader)
        avg_val   = val_loss   / len(val_loader)

        # Record history
        history["epochs"].append(epoch + 1)
        history["train_loss"].append(round(avg_train, 6))
        history["val_loss"].append(round(avg_val,   6))
        history["feat_loss"].append(round(avg_feat,  6))
        history["ast_loss"].append(round(avg_ast,   6))
        history["cfg_loss"].append(round(avg_cfg,   6))
        history["dfg_loss"].append(round(avg_dfg,   6))

        print(
            f"Epoch {epoch+1:03d}/{epochs} | "
            f"Train {avg_train:.4f} | "
            f"Feat {avg_feat:.4f} | "
            f"AST {avg_ast:.4f} | "
            f"CFG {avg_cfg:.4f} | "
            f"DFG {avg_dfg:.4f} | "
            f"Val {avg_val:.4f}"
        )

        if avg_val < best_val_loss:
            best_val_loss = avg_val
            best_weights  = copy.deepcopy(model.state_dict())
            print(f"  -> New best model saved ({best_val_loss:.4f})")

        # Step scheduler based on validation loss
        scheduler.step(avg_val)

    model.load_state_dict(best_weights)
    print(f"\nTraining Complete. Best Validation Loss: {best_val_loss:.4f}")

    return model, history