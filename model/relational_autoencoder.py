import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import RGATConv, global_max_pool
from torch_geometric.utils import to_dense_batch, to_dense_adj


class RelationalGraphAutoencoder(nn.Module):

    def __init__(
        self,
        input_dim,
        num_relations=3,
        hidden_dim=128,
        latent_dim=64,
        heads=4,
        dropout=0.2
    ):
        super().__init__()

        self.num_relations = num_relations
        self.latent_dim = latent_dim

        # ---------- Encoder ----------
        self.conv1 = RGATConv(
            input_dim,
            hidden_dim // heads,
            heads=heads,
            num_relations=num_relations
        )

        self.bn1 = nn.BatchNorm1d(hidden_dim)

        self.conv2 = RGATConv(
            hidden_dim,
            latent_dim,
            heads=1,
            num_relations=num_relations
        )

        self.residual_proj = nn.Linear(hidden_dim, latent_dim)

        self.dropout = nn.Dropout(dropout)

        # ---------- Feature Decoder ----------
        self.feature_decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim)
        )

        # ---------- DistMult Relation Parameters ----------
        self.relation_diag = nn.Parameter(
            torch.empty(num_relations, latent_dim)
        )
        nn.init.xavier_uniform_(self.relation_diag)

    # --------------------------------------------------
    # Encoder
    # --------------------------------------------------
    def encode(self, x, edge_index, edge_type):

        h = self.conv1(x, edge_index, edge_type)

        h = self.bn1(h)
        h = F.leaky_relu(h, negative_slope=0.2)
        h = self.dropout(h)

        z = self.conv2(h, edge_index, edge_type)

        # prevent exploding latent vectors
        z = torch.clamp(z, -10, 10)

        # Residual connection
        z = z + self.residual_proj(h)

        return z

    # --------------------------------------------------
    # Feature Decoder
    # --------------------------------------------------
    def decode_features(self, z):

        return self.feature_decoder(z)

    # --------------------------------------------------
    # DistMult Structure Decoder
    # --------------------------------------------------
    def decode_relations(self, z_dense):

        batch_size, num_nodes, dim = z_dense.shape

        preds = []

        for r in range(self.num_relations):

            diag = self.relation_diag[r]

            z_r = z_dense * diag

            score = torch.bmm(z_r, z_dense.transpose(1, 2))

            # numerical stability
            score = torch.clamp(score, -10, 10)

            pred = torch.sigmoid(score)

            # avoid exact 0/1 probabilities
            pred = torch.clamp(pred, 1e-6, 1 - 1e-6)

            preds.append(pred)

        return preds

    # --------------------------------------------------
    # Forward
    # --------------------------------------------------
    def forward(self, data):

        x = data.x
        edge_index = data.edge_index
        edge_type = data.edge_type

        if hasattr(data, "batch") and data.batch is not None:
            batch = data.batch
        else:
            batch = torch.zeros(
                x.size(0),
                dtype=torch.long,
                device=x.device
            )

        # ---------- Encode ----------
        z = self.encode(x, edge_index, edge_type)

        # ---------- Feature Reconstruction ----------
        x_hat = self.decode_features(z)

        # ---------- Dense batching ----------
        z_dense, mask = to_dense_batch(z, batch)

        # ---------- Relation Predictions ----------
        adj_preds = self.decode_relations(z_dense)

        # ---------- True adjacency ----------
        adj_true = to_dense_adj(edge_index, batch=batch)

        # split true adjacency by relation
        adj_true_rel = []

        for r in range(self.num_relations):

            mask_r = (data.edge_type == r)

            edge_index_r = data.edge_index[:, mask_r]

            adj_r = to_dense_adj(edge_index_r, batch=batch)

            adj_true_rel.append(adj_r)

        # ---------- Graph Embedding ----------
        graph_embedding = global_max_pool(z, batch)

        return {
            "z": z,
            "x_hat": x_hat,
            "adj_preds": adj_preds,
            "adj_true_rel": adj_true_rel,
            "mask": mask,
            "graph_embedding": graph_embedding
        }