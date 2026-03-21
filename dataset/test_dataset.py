from torch_geometric.loader import DataLoader
from dataset.pyg_dataset import CPGDataset
from dataset.feature_encoder import NodeFeatureEncoder
from dataset.node_types import NODE_TYPES

from gensim.models import Word2Vec


# load trained embedding
w2v = Word2Vec.load("embeddings/word2vec.model")

encoder = NodeFeatureEncoder(w2v, NODE_TYPES)

dataset = CPGDataset("workspace/graphs/", encoder)

loader = DataLoader(
    dataset,
    batch_size=16,
    shuffle=True
)


for batch in loader:

    print("Node matrix:", batch.x.shape)
    print("Edges:", batch.edge_index.shape)
    print("Edge types:", batch.edge_type.shape)

    break