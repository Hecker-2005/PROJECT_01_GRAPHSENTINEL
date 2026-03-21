# prep_word2vec.py

import os
import re
import argparse
from gensim.models import Word2Vec

# ----------------------------
# Tokenization utilities
# ----------------------------
camel_regex = re.compile(r'([a-z])([A-Z])')

def split_identifier(token):
    """Splits snake_case and CamelCase identifiers."""
    token = camel_regex.sub(r'\1 \2', token)
    parts = re.split(r'[_\W]+', token)
    return [p.lower() for p in parts if p]

def tokenize_code(code):
    raw_tokens = re.findall(r"[A-Za-z_]\w*", code)
    tokens = []
    for tok in raw_tokens:
        tokens.extend(split_identifier(tok))
    return tokens

# ----------------------------
# Corpus Builder
# ----------------------------
def build_corpus(source_dir):
    corpus = []
    for root, _, files in os.walk(source_dir):
        for file in files:
            if not file.endswith((".c", ".cpp", ".h", ".hpp")):
                continue
            path = os.path.join(root, file)
            with open(path, "r", errors="ignore") as f:
                code = f.read()
            tokens = tokenize_code(code)
            if tokens:
                corpus.append(tokens)
    return corpus

# ----------------------------
# Word2Vec Training
# ----------------------------
def train_word2vec(corpus, output_path, dim=128):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # OPTIMIZATION: sg=0 (CBOW) is heavily preferred for rigid source code syntax
    model = Word2Vec(
        sentences=corpus,
        vector_size=dim,
        window=5,
        min_count=2,
        workers=4,
        sg=0 
    )
    model.save(output_path)
    print("Word2Vec saved to:", output_path)

# ----------------------------
# Entry
# ----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="embeddings/word2vec.model")
    args = parser.parse_args()

    print("Building corpus...")
    corpus = build_corpus(args.source)
    print("Training Word2Vec...")
    train_word2vec(corpus, args.output)

if __name__ == "__main__":
    main()