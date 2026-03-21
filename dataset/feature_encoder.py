# feature_encoder.py

import numpy as np

class NodeFeatureEncoder:
    def __init__(self, word2vec_model, node_types):
        self.w2v = word2vec_model
        self.node_type_to_idx = {
            t: i for i, t in enumerate(node_types)
        }
        self.num_types = len(node_types)

    def one_hot_type(self, node_type):
        vec = np.zeros(self.num_types)
        if node_type in self.node_type_to_idx:
            vec[self.node_type_to_idx[node_type]] = 1
        return vec

    def token_embedding(self, token):
        if not token:
            return np.zeros(self.w2v.vector_size)
        
        tokens = str(token).lower().strip().split()
        vecs = []
        for t in tokens:
            if t in self.w2v.wv:
                vecs.append(self.w2v.wv[t])
        
        if vecs:
            return np.mean(vecs, axis=0)
        return np.zeros(self.w2v.vector_size)

    def encode(self, node):
        node_type = node.get("type")
        code = node.get("code") or node.get("CODE") or node.get("name")

        type_vec = self.one_hot_type(node_type)
        token_vec = self.token_embedding(code)

        return np.concatenate([type_vec, token_vec])