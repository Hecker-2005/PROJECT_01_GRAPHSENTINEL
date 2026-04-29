# GRAPHSENTINEL — Intelligent System-Centric Zero-Day Threat Detection Framework

---

## Table of Contents

**Part I — Foundations and Motivation**
1. [Section 1: Problem Statement and Motivation](#section-1-problem-statement-and-motivation)
2. [Section 2: Why Graph-Based Approaches](#section-2-why-graph-based-approaches)
3. [Section 3: Why Unsupervised Learning](#section-3-why-unsupervised-learning)

**Part II — Data Representation**

4. [Section 4: Code Property Graphs (CPG)](#section-4-code-property-graphs-cpg)
5. [Section 5: The Three Graph Relations](#section-5-the-three-graph-relations)
6. [Section 6: Joern — The CPG Generator](#section-6-joern--the-cpg-generator)
7. [Section 7: Node Types and Their Semantic Meaning](#section-7-node-types-and-their-semantic-meaning)
8. [Section 8: Graph Splitting into Function Subgraphs](#section-8-graph-splitting-into-function-subgraphs)

**Part III — Feature Engineering**

9. [Section 9: Word2Vec for Code Token Embeddings](#section-9-word2vec-for-code-token-embeddings)
10. [Section 10: Node Feature Encoding](#section-10-node-feature-encoding)
11. [Section 11: PyTorch Geometric Data Objects](#section-11-pytorch-geometric-data-objects)

**Part IV — Model Architecture**

12. [Section 12: Relational Graph Attention Networks (RGAT)](#section-12-relational-graph-attention-networks-rgat)
13. [Section 13: The Three-Layer RGAT Encoder](#section-13-the-three-layer-rgat-encoder)
14. [Section 14: GraphNorm Normalization](#section-14-graphnorm-normalization)
15. [Section 15: Skip and Residual Connections](#section-15-skip-and-residual-connections)
16. [Section 16: Attention-Weighted Graph Readout](#section-16-attention-weighted-graph-readout)
17. [Section 17: The Feature Decoder (MLP)](#section-17-the-feature-decoder-mlp)
18. [Section 18: The Structure Decoder (DistMult + Bilinear Ensemble)](#section-18-the-structure-decoder-distmult--bilinear-ensemble)
19. [Section 19: The Latent Space Projector](#section-19-the-latent-space-projector)
20. [Section 20: Complete Forward Pass](#section-20-complete-forward-pass)

**Part V — Loss Functions and Training**

21. [Section 21: Focal Loss for Sparse Graph Reconstruction](#section-21-focal-loss-for-sparse-graph-reconstruction)
22. [Section 22: Feature Reconstruction Loss (Normalized MSE)](#section-22-feature-reconstruction-loss-normalized-mse)
23. [Section 23: Graph Smoothness Regularization](#section-23-graph-smoothness-regularization)
24. [Section 24: Latent Compactness Regularization](#section-24-latent-compactness-regularization)
25. [Section 25: Combined Total Loss](#section-25-combined-total-loss)
26. [Section 26: Optimizer and Learning Rate Schedule](#section-26-optimizer-and-learning-rate-schedule)
27. [Section 27: Gradient Clipping](#section-27-gradient-clipping)
28. [Section 28: The Complete Training Loop](#section-28-the-complete-training-loop)

**Part VI — Anomaly Detection and Inference**

29. [Section 29: Threshold Calibration](#section-29-threshold-calibration)
30. [Section 30: Severity Classification](#section-30-severity-classification)
31. [Section 31: Node-Level Anomaly Localization](#section-31-node-level-anomaly-localization)
32. [Section 32: Line Number Extraction](#section-32-line-number-extraction)

**Part VII — Data Pipeline**

33. [Section 33: The Juliet Test Suite Dataset](#section-33-the-juliet-test-suite-dataset)
34. [Section 34: Safe Code Extraction Algorithm](#section-34-safe-code-extraction-algorithm)
35. [Section 35: Real-World Repository Harvesting](#section-35-real-world-repository-harvesting)
36. [Section 36: Word2Vec Corpus Construction](#section-36-word2vec-corpus-construction)
37. [Section 37: The Joern Parse-Export Pipeline](#section-37-the-joern-parse-export-pipeline)
38. [Section 38: CSV Parsing and Graph Construction](#section-38-csv-parsing-and-graph-construction)
39. [Section 39: The Complete End-to-End Data Flow](#section-39-the-complete-end-to-end-data-flow)

**Part VIII — System Implementation**

40. [Section 40: File Structure and Module Organization](#section-40-file-structure-and-module-organization)
41. [Section 41: The GUI Application Architecture](#section-41-the-gui-application-architecture)
42. [Section 42: The Subprocess Communication Model](#section-42-the-subprocess-communication-model)
43. [Section 43: Packaging and Distribution](#section-43-packaging-and-distribution)

**Part IX — Experimental Results and Analysis**

44. [Section 44: Training Results](#section-44-training-results)
45. [Section 45: Detection Performance](#section-45-detection-performance)
46. [Section 46: Known Limitations](#section-46-known-limitations)

---

## Part I — Foundations and Motivation

### Section 1: Problem Statement and Motivation

Software vulnerabilities represent one of the most persistent and costly challenges in computer security. A software vulnerability is a flaw in a program's code that can be exploited by an attacker to cause unintended behavior, such as gaining unauthorized access, executing arbitrary code, leaking sensitive information, or crashing the system.

The traditional approach to vulnerability detection has been signature-based: security researchers discover and document specific vulnerability patterns, and tools are built to recognize those exact patterns in new code. This approach works well for known vulnerabilities but fails entirely for zero-day vulnerabilities — vulnerabilities that have not been previously discovered or documented.

The term "zero-day" refers to the fact that when such a vulnerability is exploited, the software developers have had zero days to prepare a fix. Zero-day vulnerabilities are particularly dangerous because no signatures exist for them, and conventional scanners cannot detect them.

GRAPHSENTINEL addresses this limitation by taking a fundamentally different approach: instead of asking "does this code match known vulnerability patterns?" it asks "does this code look structurally different from safe code?" This distinction is crucial. Even if a vulnerability has never been seen before, if its structural characteristics differ from typical safe code patterns, the model will flag it.

The specific vulnerability types most relevant to C/C++ programs include:

**CWE-121: Stack-based Buffer Overflow**
A program writes data beyond the allocated bounds of a buffer on the stack. Commonly caused by unsafe functions like `strcpy()`, `gets()`, `sprintf()`. Classic example: `char buf[32]; strcpy(buf, user_input);` where `user_input` can be longer than 31 characters.

**CWE-122: Heap-based Buffer Overflow**
Same concept as stack overflow but the buffer lives on the heap (`malloc`'d). The write beyond bounds corrupts adjacent heap metadata.

**CWE-134: Use of Externally-Controlled Format String**
A program passes user-controlled input directly to `printf` or similar format string functions. `printf(user_input)` where `user_input = "%s%s%s%s"` can crash or leak memory.

**CWE-190: Integer Overflow or Wraparound**
Arithmetic produces a result too large for the variable type, wrapping around to an unexpected small value. Often exploited in buffer allocation: `malloc(untrusted_size * sizeof(int))` where `untrusted_size` overflows.

**CWE-415: Double Free**
`free()` is called twice on the same pointer. The second free corrupts the heap allocator's internal data structures.

**CWE-416: Use After Free**
Memory is accessed after it has been freed. The freed memory may have been reallocated to a different object, creating a type confusion vulnerability.

**CWE-476: NULL Pointer Dereference**
A pointer that may be NULL is dereferenced without checking. Returns from `malloc`, `fopen`, `getenv`, and similar functions can return NULL.

**CWE-401: Memory Leak**
Allocated memory is never freed, causing the program's memory usage to grow without bound. Can lead to denial of service.

---

### Section 2: Why Graph-Based Approaches

Source code has inherent structure that is not captured by treating it as plain text. Consider the following C function:

```c
void copy_input(char *dest, char *src) {
    strcpy(dest, src);
}
```

A text-based approach might look for the token `strcpy` but this misses the context: who calls this function, what are the sizes of `dest` and `src`, is there any bounds checking nearby? The vulnerability is not in the presence of `strcpy` alone, but in the structural relationship between the function's parameters, any bounds checking that is or isn't present, and how the function is called.

Graph representations capture these relationships explicitly:

**Abstract Syntax Tree (AST):** Represents the syntactic structure of the code. Every statement, expression, and declaration is a node. Edges connect parent constructs to their children. The AST of `strcpy(dest, src)` has a `CALL` node connected to an `IDENTIFIER` node for `strcpy`, and two `IDENTIFIER` nodes for `dest` and `src`.

**Control Flow Graph (CFG):** Represents the possible execution paths through a function. Nodes are basic blocks (sequences of statements with no branches). Edges represent possible transfers of control (sequential execution, if-true, if-false, loop back). The CFG captures when a bounds check is bypassed.

**Data Flow Graph (DFG):** Represents how data values move through the program. An edge from variable A to variable B means B's value depends on A. The DFG captures when an unchecked external input reaches a dangerous function call.

Together, these three graph representations provide a rich structural fingerprint of code that captures far more semantic information than token sequences.

Graph Neural Networks (GNNs) can directly operate on these graph structures, learning representations that are sensitive to structural patterns associated with vulnerability or safety.

---

### Section 3: Why Unsupervised Learning

The choice to use an unsupervised autoencoder rather than a supervised classifier was deliberate and addresses a fundamental data problem.

Supervised learning requires labeled examples of both safe and vulnerable code. The problem is:

1. Labeled vulnerability datasets are small. The Juliet Test Suite, one of the largest, contains synthetic examples that don't fully represent real-world code complexity.
2. Labeled datasets are biased. They only contain vulnerability types that researchers have already identified and documented. A supervised classifier trained on these cannot generalize to novel vulnerability patterns.
3. Class imbalance is extreme. In real-world code, the ratio of safe functions to vulnerable functions might be 1000:1. Standard classifiers struggle with such imbalance.
4. The definition of "vulnerable" changes over time. New vulnerability classes are discovered regularly. A supervised model trained today is outdated tomorrow.

The unsupervised approach elegantly sidesteps all of these problems:

1. Only safe code is needed for training. Safe code is abundant — every well-maintained open source repository is a source of safe training data.
2. The model learns the distribution of safe code. Anything that deviates significantly from this learned distribution is flagged as potentially anomalous.
3. Generalization to novel vulnerabilities is theoretically possible. If a new vulnerability type creates unusual code structure, the model will detect it even though it has never seen that type before.
4. The reconstruction error provides a continuous score rather than a binary label, allowing for graded severity classification.

The specific unsupervised model chosen is an autoencoder: a neural network that learns to compress input data into a low-dimensional latent representation and then reconstruct the original input from that representation. When trained only on safe code, the autoencoder learns to reconstruct safe code well (low reconstruction error) and reconstructs anomalous code poorly (high reconstruction error). The reconstruction error becomes the anomaly score.

---

## Part II — Data Representation

### Section 4: Code Property Graphs (CPG)

A Code Property Graph (CPG) is a unified graph representation of source code that merges three complementary program representations — the Abstract Syntax Tree (AST), the Control Flow Graph (CFG), and the Data Flow Graph (DFG) — into a single multigraph.

The CPG was originally proposed by Yamaguchi et al. in their 2014 paper "Modeling and Discovering Vulnerabilities with Code Property Graphs" and has since become the foundation of several industrial vulnerability analysis tools including Joern, ShiftLeft Ocular, and CodeQL.

Formally, a CPG is defined as a multigraph:

```
G = (V, E, λ, μ)

where:
  V        is a set of nodes representing program constructs
  E ⊆ V × V × T  is a set of labeled directed edges
  T        is a set of edge type labels {AST, CFG, DFG, ...}
  λ : V → L_V    maps nodes to their property labels (node type, code, line number)
  μ : E → L_E    maps edges to their property labels (edge type, variable name)
```

In Joern's implementation, the CPG is stored as a set of Neo4j-compatible CSV files after export, with separate files for each node type and edge type.

The GRAPHSENTINEL system uses only a subset of the full CPG:
- **Node types:** `METHOD`, `CALL`, `IDENTIFIER`, `LITERAL`, `CONTROL_STRUCTURE`, `RETURN`, `BLOCK`, `METHOD_PARAMETER_IN`, `LOCAL`
- **Edge types:** `AST` (relation ID 0), `CFG` (relation ID 1), `REACHING_DEF` (relation ID 2)

---

### Section 5: The Three Graph Relations

#### AST — Abstract Syntax Tree (Relation ID: 0)

The AST captures the hierarchical syntactic structure of source code. Every syntactic construct in the source file corresponds to a node, and edges run from parent constructs to their syntactic children.

For the expression: `strcpy(buffer, input)`

```
CALL node ("strcpy")
  ├── IDENTIFIER node ("buffer")   [first argument]
  └── IDENTIFIER node ("input")    [second argument]
```

The AST captures **WHAT** the code says — its grammatical structure.

#### CFG — Control Flow Graph (Relation ID: 1)

The CFG captures the possible execution paths through a function. Nodes in the CFG represent statements or basic blocks. Directed edges represent control transfers.

For a simple if statement: `if (x > 0) { do_something(); } else { do_other(); }`

```
[check: x > 0] --true-->  [do_something()]
[check: x > 0] --false--> [do_other()]
```

The CFG captures **HOW** the code runs — its execution semantics.

#### REACHING_DEF / DFG — Data Flow Graph (Relation ID: 2)

The DFG (implemented in Joern as `REACHING_DEF` edges) captures variable definitions and their uses. An edge from node A to node B means a variable defined at A reaches (is used at) B without being redefined in between.

For the code: `int x = get_input(); use(x);` — the DFG has an edge from the assignment of `x` to the use of `x`.

The DFG captures **WHERE** data goes — its information flow semantics.

Together, these three complementary views provide a rich structural description:
- AST captures code structure (syntax)
- CFG captures execution structure (control)
- DFG captures data structure (flow)

Each carries different information about potential vulnerability patterns:
- Buffer overflows show unusual AST patterns (unchecked array indices)
- Use-after-free shows unusual CFG patterns (access after free on execution path)
- Format string issues show unusual DFG patterns (untrusted data reaching format arg)

---

### Section 6: Joern — The CPG Generator

Joern is an open-source code analysis platform developed by ShiftLeft Inc. It is implemented in Scala and runs on the Java Virtual Machine. GRAPHSENTINEL uses Joern as a black-box CPG generator: given a C/C++ source file, Joern produces a binary CPG file and optionally exports it to various formats.

The two Joern tools used are:

**`joern-parse`**
- Input: C or C++ source file (`.c` or `.cpp`)
- Output: Binary CPG file (`cpg.bin`) in a proprietary binary format
- How: Invokes the `c2cpg` frontend, which uses the Eclipse CDT parser to build an AST, then applies various passes to add CFG and DFG edges
- Timeout: 300 seconds per file (5 minutes) to prevent infinite hangs on complex files

**`joern-export`**
- Input: Binary CPG file (`cpg.bin`)
- Output: Neo4j-compatible CSV files in a specified directory
- Format: `neo4jcsv` — produces separate `_header.csv` and `_data.csv` pairs for each node type and edge type
- How: Reads the binary CPG and serializes each node and edge type to CSV

The Neo4j CSV format uses separate header files to define column names with type annotations. For example, `nodes_METHOD_header.csv` might contain:
```
:ID,:LABEL,CODE:string,NAME:string,LINE_NUMBER:int,IS_EXTERNAL:boolean
```
And `nodes_METHOD_data.csv` contains the actual data rows matching those columns.

GRAPHSENTINEL reads both header and data files to correctly extract attributes regardless of column ordering, which can vary between Joern versions.

The system invokes these tools as Python subprocesses using `subprocess.run()` with `check=True` (raises exception on non-zero exit code), capturing both stdout and stderr for error reporting.

Joern wrapper scripts (`joern-parse`, `joern-export`) are shell scripts that exec the actual binaries in the `joern-cli` directory:
```bash
#!/usr/bin/env bash
exec "$(dirname "$0")/joern-cli/joern-parse" "$@"
```
These wrappers ensure the correct binary is found regardless of PATH settings.

---

### Section 7: Node Types and Their Semantic Meaning

GRAPHSENTINEL uses 9 node types, selected as the most semantically significant for vulnerability detection:

| # | Node Type | Semantic Meaning |
|---|---|---|
| 1 | `METHOD` | Represents a function definition. Contains the function's name, signature, and whether it is an external library function (`IS_EXTERNAL`). Example: `void process(char *input) { ... }` |
| 2 | `CALL` | Represents a function call site. Contains the called function's name. One of the most vulnerability-relevant node types — dangerous functions like `strcpy`, `malloc`, `free`, `printf` appear here. Example: `strcpy(buffer, input)` produces a `CALL` node with code `"strcpy"` |
| 3 | `IDENTIFIER` | Represents a variable reference (read or write). Example: `buffer` in `strcpy(buffer, input)` |
| 4 | `LITERAL` | Represents a constant value in the source code. Example: the number `32` in `char buffer[32]` or the string `"hello"` |
| 5 | `CONTROL_STRUCTURE` | Represents control flow constructs: `if`, `while`, `for`, `switch`, `do-while`. The presence or absence of bounds-checking control structures near buffer operations is highly relevant to vulnerability detection. |
| 6 | `RETURN` | Represents a return statement. Return paths that bypass cleanup code can indicate resource leaks. |
| 7 | `BLOCK` | Represents a compound statement (code block enclosed in braces). Nesting depth of blocks correlates with code complexity. |
| 8 | `METHOD_PARAMETER_IN` | Represents a function parameter. Captures how many and what type of inputs a function accepts, which is relevant to attack surface. |
| 9 | `LOCAL` | Represents a local variable declaration. The size and type of local variables relates to stack buffer analysis. |

---

### Section 8: Graph Splitting into Function Subgraphs

The full-file CPG contains all constructs from the entire source file in a single connected graph. For training the autoencoder, function-level granularity is needed because:

1. Vulnerabilities are localized within individual functions
2. Full-file graphs are too large and computationally expensive
3. Function-level training allows the model to learn per-function "normal" structural patterns

The splitting algorithm is implemented in `parser_pipeline/pipeline.py`:

```
ALGORITHM: Function Graph Splitting
Input:  Full-file NetworkX MultiDiGraph G
Output: List of function subgraphs [G_1, G_2, ..., G_n]

Step 1: Find all METHOD nodes that are not external
  function_nodes = []
  for each node v in G:
    if v.type == "METHOD" and v.IS_EXTERNAL != "true":
      function_nodes.append(v)

Step 2: For each function node, collect all AST-reachable nodes
  for each root in function_nodes:
    reachable = {root}
    stack = [root]
    while stack is not empty:
      node = stack.pop()
      for each outgoing AST edge (node -> dst):
        if dst not in reachable:
          reachable.add(dst)
          stack.append(dst)

Step 3: Extract the induced subgraph on reachable nodes
  G_i = G.subgraph(reachable)  # includes ALL edge types between reachable nodes

Step 4: Filter subgraphs that are too small
  if G_i.number_of_nodes() >= 5:
    subgraphs.append(G_i)
```

**Note:** AST traversal is used for node collection because AST edges define the hierarchical ownership of nodes to functions. Then the induced subgraph includes CFG and DFG edges between those nodes, giving the complete function subgraph with all three relation types.

The `IS_EXTERNAL` filter is critical: without it, Joern generates `METHOD` nodes for every library function called by the code (`strcpy`, `malloc`, `printf`, etc.). These external stubs have no meaningful body and would produce subgraphs like:
```
METHOD("strcpy") -> IDENTIFIER("buffer") -> IDENTIFIER("input")
```
which is just the signature of the call site, not a real function body. Including these would flood the dataset with degenerate subgraphs and confuse the model.

---

## Part III — Feature Engineering

### Section 9: Word2Vec for Code Token Embeddings

Word2Vec is a neural network-based technique for learning dense vector representations (embeddings) of words from large text corpora, originally proposed by Mikolov et al. in 2013. The key insight is the distributional hypothesis: words that appear in similar contexts tend to have similar meanings.

In GRAPHSENTINEL, Word2Vec is applied to code tokens rather than natural language words. The underlying assumption holds for code: code tokens that appear in similar contexts (e.g., `malloc` and `calloc` often appear near similar patterns) should have similar embeddings.

**Architecture: Continuous Bag-of-Words (CBOW)**

The CBOW model predicts a target word from its surrounding context words. Given a window of context words `w_{i-k}, ..., w_{i-1}, w_{i+1}, ..., w_{i+k}`, the model predicts `w_i`.

```
P(w_i | context) = softmax(W_out * (1/2k * Σ W_in * one_hot(w_j)))

where:
  W_in  ∈ R^{|V| × d}  is the input embedding matrix
  W_out ∈ R^{d × |V|}  is the output embedding matrix
  d = 128               is the embedding dimension
  |V|                   is the vocabulary size (all unique code tokens)
```

**Training Details:**

| Parameter | Value |
|---|---|
| Embedding dimension | 128 |
| Window size | 5 (5 tokens before and 5 after the target) |
| Minimum count | 2 (tokens appearing fewer than 2 times are discarded) |
| Algorithm | CBOW (faster than Skip-gram for large vocabularies) |
| Epochs | 10 |
| Workers | 4 (parallel training) |

**Corpus Construction:**
Each safe C/C++ file is treated as a "sentence" (sequence of tokens). Tokens are extracted by:
1. Splitting on whitespace and punctuation
2. Converting to lowercase
3. Keeping only alphanumeric tokens of length >= 2

Special handling: CamelCase identifiers (e.g., `getBufferSize`) are split into subtokens `[get, buffer, size]` to improve vocabulary coverage.

**Vocabulary:**
The vocabulary includes all unique tokens appearing at least twice across the entire safe code corpus. For a 9800-file corpus, this typically produces a vocabulary of 5,000–15,000 unique code tokens.

**Token Embedding at Inference:**
The `code` attribute of a CPG node may be a multi-token string like `"strcpy(buffer, input)"`. The embedding procedure:

```python
def token_embedding(token_string):
    tokens = token_string.lower().strip().split()
    embeddings = [w2v[t] for t in tokens if t in w2v.wv]
    if embeddings:
        return mean(embeddings, axis=0)   # average pooling
    return zeros(128)
```

Averaging is chosen over concatenation because it produces a fixed-size vector regardless of the number of tokens, and because the average of related tokens preserves the semantic center of the expression.

---

### Section 10: Node Feature Encoding

Each node in the function subgraph is encoded as a fixed-size feature vector by concatenating two components:

**Component 1: One-Hot Type Encoding**
A 9-dimensional binary vector where exactly one position is `1.0`, indicating the node type:

| Index | Node Type |
|---|---|
| 0 | `METHOD` |
| 1 | `CALL` |
| 2 | `IDENTIFIER` |
| 3 | `LITERAL` |
| 4 | `CONTROL_STRUCTURE` |
| 5 | `RETURN` |
| 6 | `BLOCK` |
| 7 | `METHOD_PARAMETER_IN` |
| 8 | `LOCAL` |

```
For a CALL node:   type_vec = [0, 1, 0, 0, 0, 0, 0, 0, 0]
For a RETURN node: type_vec = [0, 0, 0, 0, 0, 1, 0, 0, 0]
For unknown type:  type_vec = [0, 0, 0, 0, 0, 0, 0, 0, 0]
```

**Component 2: Word2Vec Token Embedding**
A 128-dimensional dense vector representing the semantic content of the node's `code` attribute, computed as described in Section 9.

**Concatenation:**
```
final_feature = concat([type_vec, token_vec])
dimension     = 9 + 128 = 137
```

The combined 137-dimensional vector captures both **WHAT TYPE** of construct this node is (structural information) and **WHAT CODE** it contains (semantic information).

This dual representation is important: two `CALL` nodes might have very different vulnerabilities depending on what function they call. The type vector tells the model "this is a function call" while the token embedding tells it "this is a call to `strcpy` specifically."

---

### Section 11: PyTorch Geometric Data Objects

Each function subgraph is converted to a PyTorch Geometric (PyG) `Data` object, which is the standard container for graph data in PyG.

A `Data` object contains:

```
x           ∈ R^{N × 137}   Node feature matrix
                              N = number of nodes in the graph
                              137 = feature dimension

edge_index  ∈ Z^{2 × E}     Edge connectivity in COO format
                              E = number of edges
                              Row 0 = source node indices
                              Row 1 = destination node indices

edge_type   ∈ Z^{E}         Relation type for each edge
                              0 = AST, 1 = CFG, 2 = DFG/REACHING_DEF

y           ∈ Z^{1}         Graph label (always 0 for safe code)

line_number ∈ Z^{N}         Line number for each node (-1 if unknown)
```

**Node ID Mapping:**
NetworkX uses arbitrary string node IDs from the Joern CSV exports. These are mapped to sequential integers `0, 1, 2, ..., N-1` via a dictionary:
```python
node_id_map = {node_id: i for i, node_id in enumerate(graph.nodes())}
```
This mapping is applied to both node features (maintaining order) and `edge_index` (translating string IDs to integer indices).

**Edge Handling:**
Edges are only included if both source and destination nodes are in the `node_id_map` (valid nodes). This guards against Joern occasionally generating edges to nodes not present in the node CSV files.

If a graph has no edges:
```
edge_index = empty tensor of shape (2, 0)
edge_type  = empty tensor of shape (0,)
```

**Batching:**
PyG's `DataLoader` automatically batches multiple graphs into a single large disconnected graph using the `batch` vector:
```
batch ∈ Z^{N_total}  where batch[i] = graph index for node i
```
For a batch of 3 graphs with 5, 7, and 4 nodes:
```
batch = [0,0,0,0,0, 1,1,1,1,1,1,1, 2,2,2,2]
```
This allows message passing to operate on all graphs simultaneously while keeping them logically separate via the batch vector.

---

## Part IV — Model Architecture

### Section 12: Relational Graph Attention Networks (RGAT)

Standard Graph Attention Networks (GAT) by Veličković et al. (2018) compute node representations by aggregating information from neighbors with learned attention weights. The attention weight between nodes i and j is computed based on their feature vectors.

However, standard GAT treats all edges the same regardless of their type. In GRAPHSENTINEL's CPG, an AST edge between a `CALL` node and an `IDENTIFIER` node has a fundamentally different meaning from a CFG edge between the same two nodes. These edge types should be treated differently.

Relational Graph Attention Networks (RGAT) extend GAT to handle multiple relation types. The key idea: **separate attention parameters for each relation.**

**Standard GAT Attention (for reference):**
```
e_ij = LeakyReLU(a^T · [Wh_i || Wh_j])

where:
  W ∈ R^{d_out × d_in}   is a linear transformation
  a ∈ R^{2d_out}          is a learnable attention vector
  ||                       denotes concatenation
  h_i                      is the feature vector of node i

Normalized:
  α_ij = softmax_j(e_ij) = exp(e_ij) / Σ_k exp(e_ik)

Aggregation:
  h'_i = σ(Σ_j α_ij · W · h_j)
```

**RGAT Extension:**
For each relation type r ∈ {AST, CFG, DFG}:
```
e^r_ij  = LeakyReLU(a^r^T · [W^r · h_i || W^r · h_j])
α^r_ij  = exp(e^r_ij) / Σ_{k: (i,k,r) ∈ E} exp(e^r_ik)
h'_i    = σ(Σ_r Σ_{j: (i,j,r) ∈ E} α^r_ij · W^r · h_j)
```
where `W^r` and `a^r` are separate learnable parameters per relation.

**Multi-Head Attention:**
GRAPHSENTINEL uses 4 attention heads (`heads=4`). Each head learns a different attention pattern independently, and their outputs are concatenated:
```
h'_i = ||_{k=1}^{K} σ(Σ_j α^k_ij · W^k · h_j)
```
With K=4 heads and output dimension `d_head = hidden_dim / heads = 32`:
```
Output dimension = K × d_head = 4 × 32 = 128
```

Multi-head attention allows the model to simultaneously attend to different types of structural relationships — one head might focus on function call depth, another on data dependency chains, etc.

---

### Section 13: The Three-Layer RGAT Encoder

The encoder has three successive RGAT layers. Each layer refines node representations by aggregating information from increasingly distant neighbors. After 3 layers, each node's representation incorporates information from all nodes within 3 hops.

```
LAYER 1: Input → Hidden (137 → 128)
  Input:  x ∈ R^{N × 137}           (raw node features)
  Conv:   RGATConv(137, 32, heads=4, num_relations=3)
  Output: h1_pre ∈ R^{N × 128}      (4 heads × 32 dims)
  Norm:   h1_normed = GraphNorm(h1_pre)
  Act:    h1_act = GELU(h1_normed)
  Drop:   h1 = Dropout(0.2)(h1_act)
  Skip:   h1 = h1 + Linear(137→128)(x)    [residual from input]

LAYER 2: Hidden → Hidden (128 → 128)
  Input:  h1 ∈ R^{N × 128}
  Conv:   RGATConv(128, 32, heads=4, num_relations=3)
  Output: h2_pre ∈ R^{N × 128}
  Norm:   h2_normed = GraphNorm(h2_pre)
  Act:    h2_act = GELU(h2_normed)
  Drop:   h2 = Dropout(0.2)(h2_act)
  Skip:   h2 = h2 + Linear(128→128)(h1)   [residual from layer 1]

LAYER 3: Hidden → Latent (128 → 64)
  Input:  h2 ∈ R^{N × 128}
  Conv:   RGATConv(128, 64, heads=1, num_relations=3)
  Output: z_pre ∈ R^{N × 64}
  Norm:   z_normed = GraphNorm(z_pre)
  Skip:   z = z_normed + Linear(128→64)(h2)   [residual from layer 2]
  Clamp:  z = clamp(z, -10, 10)               [numerical stability]
```

The final output `z ∈ R^{N × 64}` is the latent embedding of every node in the function graph. Each node's 64-dimensional vector represents its structural role within the function, informed by the context of its 3-hop neighborhood across all three relation types.

**Note:** Layer 3 uses `heads=1` (no multi-head) because the latent space should be a single unified representation. Multi-head in the latent layer would produce a `4 × 64 = 256` dimensional latent, making the decoder unnecessarily complex.

**Input Dropout:**
Before Layer 1, an additional 10% input dropout is applied:
```
x_dropped = Dropout(0.1)(x)
```
This is applied only during training (not inference). It randomly zeros 10% of input features, forcing the model to learn representations that don't rely on any single feature dimension. This acts as a form of regularization that reduces overfitting to specific code token patterns.

**Activation Function — GELU:**
GRAPHSENTINEL uses GELU (Gaussian Error Linear Unit) rather than ReLU:
```
GELU(x) = x · Φ(x) = x · (1/2)[1 + erf(x/√2)]
  where Φ is the cumulative distribution function of the standard normal.
```
GELU has several advantages over ReLU for this application:
1. Smooth at x=0: no discontinuity in gradient, better optimization
2. Non-zero gradient for negative inputs: avoids "dying neuron" problem
3. Stochastic interpretation: `GELU(x) ≈ E[Bernoulli(Φ(x)) · x]` which can be interpreted as a probabilistic gate

---

### Section 14: GraphNorm Normalization

GRAPHSENTINEL uses GraphNorm (Cai et al., 2021) instead of BatchNorm in the encoder. Understanding why requires examining the problem with BatchNorm for graphs.

**BatchNorm Review:**
For a batch of samples with feature matrix `X ∈ R^{B × d}`:
```
μ    = (1/B) Σ_i X_i            (batch mean)
σ²   = (1/B) Σ_i (X_i - μ)²    (batch variance)
X_norm = (X - μ) / √(σ² + ε)
Output = γ · X_norm + β          (learnable scale and shift)
```

**Problem with BatchNorm for Graphs:**
In a batch of graphs, different graphs have wildly different numbers of nodes. A function with 3 nodes contributes 3 samples to the batch statistics. A function with 200 nodes contributes 200 samples. The batch statistics are dominated by large graphs, making normalization inconsistent across graphs of different sizes.

**GraphNorm Solution:**
GraphNorm normalizes within each graph separately. For graph G_k with nodes `{v_1, ..., v_{n_k}}`:
```
μ_k  = (1/n_k) Σ_{i=1}^{n_k} h_i          (per-graph mean)
σ²_k = (1/n_k) Σ_{i=1}^{n_k} (h_i - μ_k)² (per-graph variance)
```
GraphNorm also learns a parameter α that controls how much of the mean to subtract (a balance between no normalization and full normalization):
```
h̃_i      = h_i - α · μ_k                   (partial mean subtraction)
h_i_norm  = h̃_i / √(σ²_k + ε)
Output    = γ · h_i_norm + β
```
The α parameter is learned during training, allowing the model to determine the appropriate normalization strength per layer.

This is much more appropriate for GRAPHSENTINEL because:
1. Function graphs range from 5 to 500+ nodes — normalization per graph is fair
2. No assumptions about batch composition are needed
3. Inference on single graphs (batch size 1) works correctly, unlike BatchNorm which degenerates at batch size 1

---

### Section 15: Skip and Residual Connections

Each encoder layer has a residual (skip) connection that adds the layer's input to its output after projecting to the same dimension:

```
output = conv_output + projection(input)
```

This is inspired by ResNet (He et al., 2016). The motivation:

**1. Gradient Flow:**
In deep networks, gradients must propagate back through all layers. Without skip connections, gradients can vanish (become exponentially small) or explode. With skip connections, gradients have a direct path back through the addition operation:
```
∂L/∂x = ∂L/∂output · (∂conv_output/∂x + ∂projection(x)/∂x)
       = ∂L/∂output · (conv_jacobian + projection_jacobian)
```
The second term (`projection_jacobian`) provides a stable gradient path even if the `conv_jacobian` is small.

**2. Identity Mapping:**
If a layer is not helpful, it can learn to output approximately zero, making the total output approximately equal to the residual `projection(input)`. This is easier than learning an identity mapping directly.

**3. Feature Preservation:**
Without skip connections, intermediate features computed in earlier layers can be overwritten by later layers. Skip connections allow features from multiple levels of abstraction to coexist in the final representation.

The specific skip connections in GRAPHSENTINEL:
```
skip1 = Linear(137 → 128)  [preserves raw feature information through layer 1]
skip2 = Linear(128 → 128)  [identity-like, but learned]
skip3 = Linear(128 → 64)   [down-projects hidden features to latent dimension]
```

---

### Section 16: Attention-Weighted Graph Readout

After the encoder produces node-level latent vectors `z ∈ R^{N × 64}`, a graph-level embedding is needed for the compactness regularization and for any graph-level classification.

Standard global pooling options are:
- Global max pooling: takes element-wise maximum across all nodes
- Global mean pooling: takes element-wise mean across all nodes
- Global sum pooling: takes element-wise sum across all nodes

These treat all nodes equally. But in a vulnerability context, some nodes are more important than others — the specific `CALL` node to `strcpy` is more relevant than adjacent `BLOCK` nodes.

GRAPHSENTINEL uses **attention-weighted pooling:**

**GATE computation:**
```
gate_i = sigmoid(W_gate · z_i + b_gate)    gate_i ∈ [0, 1]
```
`W_gate ∈ R^{1 × 64}` is a learnable linear transformation to a scalar. sigmoid ensures `gate_i ∈ [0, 1]` (importance weight).

**TRANSFORM computation:**
```
t_i = tanh(W_transform · z_i + b_transform)
```
`W_transform ∈ R^{64 × 64}` is a learnable linear transformation. tanh bounds the transformed features to `[-1, 1]`.

**Attention Pooling:**
```
attn_pool = Σ_i (gate_i · t_i) / N    [per graph]
```
This is a weighted sum of transformed node embeddings where the weights are learned importance scores.

**Max Pooling (complementary):**
```
max_pool = element-wise-max over all z_i in the graph
```
Max pooling captures the most extreme activation in each dimension, which is useful for capturing the "worst" node in the graph (most anomalous).

**Combined Graph Embedding:**
```
graph_emb = 0.5 · (attn_pool + max_pool)
```
The combination leverages both:
- Attention: learns which nodes are structurally important
- Max: captures peak anomaly signal (most unusual node)

---

### Section 17: The Feature Decoder (MLP)

The feature decoder reconstructs the original node feature vectors from their latent embeddings. It is a 3-layer MLP:

```
Layer 1: Linear(64 → 128) + LayerNorm(128) + GELU + Dropout(0.1)
Layer 2: Linear(128 → 128) + LayerNorm(128) + GELU
Layer 3: Linear(128 → 137)

Input:  z ∈ R^{N × 64}    (latent node embeddings)
Output: x̂ ∈ R^{N × 137}  (reconstructed node features)
```

**LayerNorm:**
Layer normalization normalizes across the feature dimension (not the batch dimension like BatchNorm):
```
LayerNorm(x) = γ · (x - μ_x) / √(σ²_x + ε) + β
```
where `μ_x` and `σ²_x` are computed across the 128 features of each individual node representation. This is appropriate here because each node's 128-dim vector should be normalized within itself, not across the batch.

The feature decoder is deeper than the encoder's DistMult decoder because feature reconstruction is more complex — it must recover both the node type (9 dimensions) and the token embedding (128 dimensions) from a 64-dimensional latent code.

---

### Section 18: The Structure Decoder (DistMult + Bilinear Ensemble)

The structure decoder predicts whether an edge should exist between each pair of nodes, for each of the three relation types. It operates on the densely batched node representations `z_dense ∈ R^{B × N_max × 64}`.

For each relation type r, two scoring functions are computed and combined:

**DistMult Decoder:**
DistMult (Yang et al., 2015) uses a diagonal relation matrix:
```
score_d(i, j, r) = z_i^T · diag(R_r) · z_j = Σ_k z_i[k] · R_r[k] · z_j[k]
```
where `R_r ∈ R^{64}` is a learnable diagonal vector for relation r.

In matrix form for all pairs simultaneously:
```
Z_r      = z_dense ⊙ R_r              (element-wise multiply each node embedding by R_r)
Score_d  = Z_r · z_dense^T            (batch matrix multiply: [B × N × N])
```
DistMult is parameter-efficient: only 64 parameters per relation (the diagonal). It is symmetric: `score_d(i, j, r) = score_d(j, i, r)`, which matches the bidirectional nature of AST parent-child relationships.

**Bilinear Decoder:**
The bilinear decoder uses a full relation matrix:
```
score_b(i, j, r) = z_i^T · W_r · z_j
```
where `W_r ∈ R^{64 × 64}` is a learnable full matrix for relation r.

In matrix form:
```
Z_w      = z_dense · W_r              (batch matrix multiply: [B × N × 64])
Score_b  = Z_w · z_dense^T            (batch matrix multiply: [B × N × N])
```
Bilinear is more expressive than DistMult but uses `64 × 64 = 4096` parameters per relation. It can capture asymmetric relationships (`W_r ≠ W_r^T`), which is appropriate for CFG and DFG edges (control/data flow is directional).

**Ensemble with Learnable Blend:**
A learnable blend parameter controls the mixture:
```
blend = σ(w_blend)  where w_blend is a learnable scalar, σ = sigmoid
score(i, j, r) = blend · score_b(i, j, r) + (1 - blend) · score_d(i, j, r)
```
`blend ∈ [0, 1]` is clamped for numerical stability.

If the model finds DistMult sufficient, it can set `w_blend ≈ -∞` (blend → 0). If bilinear is more expressive for the data, it sets `w_blend ≈ +∞` (blend → 1). In practice, the model learns an intermediate blend.

**Final Prediction:**
```
pred(i, j, r) = sigmoid(clamp(score(i, j, r), -10, 10))
pred(i, j, r) = clamp(pred, 1e-6, 1 - 1e-6)
```
The output is a probability in `(0, 1)` that edge `(i, j)` of type `r` exists.

**Mask Application:**
Not all positions in `z_dense` correspond to real nodes — padding is added for shorter graphs in a batch. A boolean mask `mask ∈ R^{B × N_max}` indicates real nodes. The 2D mask is:
```
mask_2d = mask.unsqueeze(1) & mask.unsqueeze(2)    [B × N_max × N_max]
```
Only elements where `mask_2d` is True are included in the loss computation.

---

### Section 19: The Latent Space Projector

The latent space projector is a small 2-layer MLP that produces graph-level embeddings for the compactness regularization loss:

```
z_proj = Linear(64 → 64) → GELU → Linear(64 → 32)

Input:  global_mean_pool(z, batch) ∈ R^{B × 64}   (per-graph mean of node embeddings)
Output: z_proj ∈ R^{B × 32}                        (compact graph representations)
```

The purpose of this projector is to create a lower-dimensional space where the compactness regularization can be applied. Using the full 64-dim space for compactness would force the latent node embeddings to be too similar, hurting reconstruction quality. The separate 32-dim projection space allows compactness to be enforced independently.

This design is inspired by contrastive learning architectures (SimCLR, MoCo) which use similar projection heads to apply contrastive losses in a separate space from the main representation.

---

### Section 20: Complete Forward Pass

Given a batch of PyG `Data` objects, the complete forward pass:

**Input Preparation:**
```
x          = data.x           ∈ R^{N_total × 137}
edge_index = data.edge_index  ∈ Z^{2 × E_total}
edge_type  = data.edge_type   ∈ Z^{E_total}
batch      = data.batch       ∈ Z^{N_total}
```

**Encoding:**
```
x_drop = Dropout(0.1)(x)
h1_pre = RGATConv_1(x_drop, edge_index, edge_type)       [N × 128]
h1     = GELU(GraphNorm(h1_pre)) + Linear_skip1(x_drop)
h1     = Dropout(0.2)(h1)
h2_pre = RGATConv_2(h1, edge_index, edge_type)            [N × 128]
h2     = GELU(GraphNorm(h2_pre)) + Linear_skip2(h1)
h2     = Dropout(0.2)(h2)
z_pre  = RGATConv_3(h2, edge_index, edge_type)            [N × 64]
z      = GraphNorm(z_pre) + Linear_skip3(h2)
z      = clamp(z, -10, 10)
```

**Feature Decoding:**
```
x_hat = FeatureDecoder(z)                                 [N × 137]
```

**Structure Decoding:**
```
z_dense, mask = to_dense_batch(z, batch)                  [B × N_max × 64]

For r in {0, 1, 2}:
  score_d[r] = (z_dense ⊙ R_r) · z_dense^T
  score_b[r] = (z_dense · W_r) · z_dense^T
  score[r]   = blend · score_b[r] + (1-blend) · score_d[r]
  adj_pred[r] = sigmoid(clamp(score[r], -10, 10))
```

**Ground Truth Adjacency:**
```
For r in {0, 1, 2}:
  edge_index_r  = edge_index[:, edge_type == r]
  adj_true_rel[r] = to_dense_adj(edge_index_r, batch)
```

**Graph Embedding:**
```
gate     = sigmoid(W_gate · z)
t        = tanh(W_transform · z)
attn_pool = global_add_pool(gate * t, batch) / n_nodes_per_graph
max_pool  = global_max_pool(z, batch)
graph_emb = 0.5 * (attn_pool + max_pool)
```

**Latent Projection:**
```
z_mean = global_mean_pool(z, batch)
z_proj = Projector(z_mean)                                [B × 32]
```

**Output Dictionary:**
```
{
  "z"              : z,             [N × 64]
  "x_hat"          : x_hat,         [N × 137]
  "adj_preds"      : adj_pred,      list of 3 [B × N_max × N_max]
  "adj_true_rel"   : adj_true_rel,  list of 3 [B × N_max × N_max]
  "mask"           : mask,          [B × N_max]
  "graph_embedding": graph_emb,     [B × 64]
  "z_proj"         : z_proj,        [B × 32]
}
```

---

## Part V — Loss Functions and Training

### Section 21: Focal Loss for Sparse Graph Reconstruction

Binary Cross-Entropy (BCE) is the standard loss for binary classification:
```
BCE(p, y) = -[y · log(p) + (1-y) · log(1-p)]
```
where `p ∈ (0,1)` is the predicted probability and `y ∈ {0,1}` is the true label.

**Problem with BCE for code graphs:**
In a function graph with N=50 nodes, there are N²=2500 possible edges. A typical function might have 200 actual edges (AST + CFG + DFG combined). This means:
- Positive edge ratio: 200 / 2500 = 8%
- Negative edge ratio: 2300 / 2500 = 92%

With standard BCE, the loss is dominated by the 92% true negative cases (correctly predicting no edge). The model can achieve 92% accuracy by always predicting no edge, having learned nothing about actual code structure. Worse: the gradients from the many easy negatives overwhelm the gradients from the rare positive cases, making it hard for the model to learn to predict actual edges.

**Focal Loss Solution** (Lin et al., 2017 — originally for object detection):
```
FL(p, y) = -[(1 - pt)^γ] · log(pt)

where:
  pt = p if y=1, or (1-p) if y=0
  γ ≥ 0 is the focusing parameter (GRAPHSENTINEL uses γ=2.0)
```

The term `(1 - pt)^γ` is the modulating factor:
- For easy examples (pt ≈ 1, well-classified): `(1-1)^2 ≈ 0` → loss ≈ 0
- For hard examples (pt ≈ 0.5, uncertain): `(1-0.5)^2 = 0.25` → some loss
- For misclassified (pt ≈ 0): `(1-0)^2 = 1` → full loss

Effect with γ=2:
```
If a true negative (y=0) is correctly predicted with p=0.1:
  pt = 1-p = 0.9 (confident correct)
  FL = -(1-0.9)^2 · log(0.9) = -(0.01) · (-0.105) ≈ 0.001

If a true positive (y=1) is missed with p=0.1:
  pt = p = 0.1 (confident wrong)
  FL = -(1-0.1)^2 · log(0.1) = -(0.81) · (-2.303) ≈ 1.865
```
The focal loss is 1865× larger for the misclassified true positive than for the correctly classified true negative. This forces the model to focus on learning to predict actual edges rather than just predicting no-edge everywhere.

**NaN Protection:**
```python
pred = nan_to_num(pred, nan=0.5)    # replace NaN with maximum uncertainty
pred = clamp(pred, 1e-8, 1-1e-8)   # prevent log(0) = -∞
```

---

### Section 22: Feature Reconstruction Loss (Normalized MSE)

The feature loss measures how well the decoder reconstructs the original node feature vectors:
```
MSE = (1 / (N · d)) · Σ_i Σ_k (x̂_ik - x_ik)²
```
where N is the number of nodes and d=137 is the feature dimension.

**Normalization by Input Variance:**
```
feature_loss_normalized = MSE / (Var(x) + ε)
```
where `Var(x)` is the variance of all features across all nodes in the batch.

This normalization is important because:
1. With more diverse training data (23 CWE categories + real-world repos), the feature variance increases. Without normalization, the feature loss term would grow larger with more diverse data, causing it to dominate the total loss and making the structural losses (AST, CFG, DFG) less effective.
2. Normalization makes the feature loss scale-invariant: the same coefficient α works regardless of the feature variance in the training data.
3. It prevents the model from "cheating" by predicting the mean and achieving low absolute MSE through variance reduction.

---

### Section 23: Graph Smoothness Regularization

The smoothness regularization enforces that connected nodes should have similar latent representations:
```
L_smooth = (1 / |E|) · Σ_{(i,j) ∈ E} ||z_i - z_j||²
```
where E is the set of all edges (all relation types combined).

**Mathematical Motivation:**
This is equivalent to the graph Laplacian regularization:
```
L_smooth = z^T · L · z
```
where `L = D - A` is the graph Laplacian, D is the degree matrix, and A is the adjacency matrix. Minimizing `z^T·L·z` encourages nodes connected by edges to have similar embeddings (low `||z_i - z_j||²` for connected pairs).

**Why This Reduces False Positives:**
Safe code has consistent, regular structure. If two nodes are connected in the AST (e.g., a `CALL` node and its argument `IDENTIFIER`), their code semantics are closely related — the call and the argument are part of the same expression. Their latent representations should therefore be similar.

Anomalous code (vulnerable code) often has unusual structural patterns that violate this smoothness assumption. For example, in a use-after-free pattern, the DFG connects a now-freed variable to a subsequent use — semantically these nodes are related in a dangerous way that the model hasn't seen in safe code.

By training with smoothness regularization, the model learns a latent space where safe structural relationships are smooth. At inference, code that violates structural smoothness gets a higher reconstruction error.

**Implementation Note:**
Invalid edges (where src or dst index >= number of nodes) are filtered before computing the loss to guard against batching edge cases.

**Weight:** `λ_smooth = 0.01` (small relative to main losses — acts as a soft constraint rather than a dominant objective)

---

### Section 24: Latent Compactness Regularization

The compactness regularization encourages all graph-level embeddings (in the projected latent space) to cluster together:
```
L_compact = (1 / B) · Σ_{k=1}^{B} ||z_proj_k - μ||²

where:
  z_proj_k ∈ R^{32}  is the projected embedding of graph k
  μ = (1/B) · Σ_k z_proj_k  is the batch mean embedding
  B  is the batch size
```

**Mathematical Interpretation:**
This is the variance of the graph embedding distribution:
```
L_compact = (1/B) · Σ_k ||z_proj_k - μ||² = Var(z_proj_k)
```
Minimizing this variance forces all graphs to have similar latent representations. When trained only on safe code, this means all safe graphs cluster together.

**Why This Works for Anomaly Detection:**

During training on safe code: `L_compact` pushes all safe graph embeddings toward a common point in latent space. The model learns a compact, well-clustered representation of "safe code structure."

At inference time on anomalous code: The anomalous graph produces an embedding far from the training cluster. The reconstruction quality is poor because the latent code is out-of-distribution. This contributes to the high reconstruction error (anomaly score).

Conceptually: the model learns a "safe code manifold" in latent space. Safe code maps to this manifold (good reconstruction, low anomaly score). Vulnerable code maps away from this manifold (poor reconstruction, high score).

**Weight:** `λ_compact = 0.005` (smaller than smoothness — gentle regularization)

**Note:** The separate projection head (Section 19) is important here. Without it, applying compactness directly to `z` would force all node embeddings to be similar, destroying the fine-grained node-level variation needed for reconstruction.

---

### Section 25: Combined Total Loss

The complete training objective combines six components:

```
L_total = α · L_feature_norm
        + β  · L_AST
        + γ  · L_CFG
        + δ  · L_DFG
        + λ_s · L_smooth
        + λ_c · L_compact
```

Default weights:

| Symbol | Weight | Component |
|---|---|---|
| α | 0.2 | Feature reconstruction |
| β | 0.2 | AST structure reconstruction |
| γ | 0.3 | CFG structure reconstruction (higher weight: more discriminative) |
| δ | 0.3 | DFG structure reconstruction (higher weight: more discriminative) |
| λ_s | 0.01 | Graph smoothness regularization |
| λ_c | 0.005 | Latent compactness regularization |

**Why CFG and DFG Weights Are Higher:**
CFG and DFG patterns are more directly related to vulnerability types than AST:
- A buffer overflow is characterized by missing bounds checks in the CFG
- A use-after-free is characterized by wrong DFG patterns
- AST captures syntactic structure that is less discriminative

Giving CFG and DFG higher weights makes the model more sensitive to these vulnerability-relevant structural patterns.

**Training vs Inference:**
During training: all 6 components are computed and backpropagated.
During inference: only the 5-component loss is computed (`L_feature + L_AST + L_CFG + L_DFG`). The smoothness and compactness are purely training regularizers — they are NOT part of the anomaly score at inference time.

The inference anomaly score is:
```
L_total = α·L_feat + β·L_AST + γ·L_CFG + δ·L_DFG
```
(using the same weights but without the two regularization terms)

---

### Section 26: Optimizer and Learning Rate Schedule

**Optimizer: AdamW** (Loshchilov & Hutter, 2019)

AdamW extends Adam with decoupled weight decay:
```
m_t = β_1 · m_{t-1} + (1 - β_1) · g_t           [first moment / momentum]
v_t = β_2 · v_{t-1} + (1 - β_2) · g_t²           [second moment / adaptive LR]
m̂_t = m_t / (1 - β_1^t)                           [bias correction]
v̂_t = v_t / (1 - β_2^t)
θ_t = θ_{t-1} - η · m̂_t / (√v̂_t + ε) - η · λ · θ_{t-1}
```

Parameters:

| Parameter | Value | Description |
|---|---|---|
| η | 0.001 | Initial learning rate |
| β_1 | 0.9 | Momentum decay |
| β_2 | 0.999 | Adaptive LR decay |
| ε | 1e-8 | Numerical stability |
| λ | 1e-4 | Weight decay coefficient |

**Key Difference from Adam:**
Standard Adam applies weight decay as L2 regularization inside the gradient:
```
g_t ← g_t + λ · θ_{t-1}   (adds to gradient before adaptive scaling)
```
AdamW applies weight decay directly to parameters, decoupled from the gradient update:
```
θ_t ← (1 - η·λ) · θ_{t-1} - η · m̂_t / (√v̂_t + ε)
```
This prevents the adaptive scaling from reducing the effective weight decay, which is important for proper regularization of large models.

**Learning Rate Schedule: ReduceLROnPlateau**

The learning rate is halved whenever validation loss does not improve for 5 consecutive epochs:
```
if val_loss > best_val_loss for 5 epochs:
  η_new = η_current * 0.5
```

Parameters:

| Parameter | Value |
|---|---|
| `factor` | 0.5 (multiply LR by this when triggered) |
| `patience` | 5 (number of epochs to wait before reducing) |
| `mode` | `'min'` (monitor minimum validation loss) |

This adaptive schedule allows:
1. Initial training with full LR = 0.001 for fast progress
2. Fine-tuning with reduced LR once progress stalls
3. Further reduction if needed: `0.001 → 0.0005 → 0.00025 → ...`

The schedule prevents oscillating around a local minimum that can occur with a fixed high learning rate.

---

### Section 27: Gradient Clipping

After computing gradients via backpropagation but before the optimizer step, gradient norms are clipped:
```
if ||g||_2 > max_norm:
  g ← g · (max_norm / ||g||_2)

max_norm = 1.0

where ||g||_2 = √(Σ_i g_i²) is the L2 norm of all gradients concatenated.
```

**Motivation:**
In deep GNNs with multiple layers, gradients can explode during backpropagation — especially in early training when the model is far from convergence. Large gradient updates can cause instability: loss suddenly spikes, weights jump to poor regions, and training fails to converge.

Clipping the global gradient norm to 1.0 ensures that no single gradient update step is too large. It does not change the direction of the update, only scales it down if it would be too large.

The value 1.0 is a standard choice for graph neural networks, balancing training speed (large enough for meaningful updates) with stability.

---

### Section 28: The Complete Training Loop

**Initialization:**
1. Load PyG Dataset from `workspace/graphs/` (all `.json` files)
2. Split 80% train / 20% validation (random, with fixed seed)
3. Create DataLoaders with `batch_size=16`, `shuffle=True` for train
4. Initialize `RelationalGraphAutoencoder(input_dim=137, num_relations=3)`
5. Initialize AdamW optimizer with `lr=0.001`, `weight_decay=1e-4`
6. Initialize ReduceLROnPlateau scheduler
7. Initialize `best_val_loss = ∞`, `best_weights = deepcopy(model.state_dict())`

**Per-Epoch Loop (50 epochs):**

```
TRAINING PHASE:
  model.train()   (enables dropout, input_dropout, BatchNorm training mode)
  for each batch in train_loader:
    1. batch = batch.to(device)
    2. optimizer.zero_grad()
    3. output = model(batch)                [forward pass]
    4. loss, feat, ast, cfg, dfg = reconstruction_loss(output, batch)
    5. loss.backward()                      [compute gradients]
    6. clip_grad_norm_(model.parameters(), 1.0)
    7. optimizer.step()                     [update weights]
    8. accumulate losses

VALIDATION PHASE:
  model.eval()    (disables dropout)
  with torch.no_grad():
    for each batch in val_loader:
      1. batch = batch.to(device)
      2. output = model(batch)
      3. v_loss, *_ = reconstruction_loss(output, batch)
      4. accumulate val_loss

POST-EPOCH:
  1. Compute averages: avg_train, avg_feat, avg_ast, avg_cfg, avg_dfg, avg_val
  2. Log all 6 metrics
  3. Append to history dict
  4. if avg_val < best_val_loss:
       best_val_loss = avg_val
       best_weights  = deepcopy(model.state_dict())
  5. scheduler.step(avg_val)
```

**Post-Training:**
1. `model.load_state_dict(best_weights)` — restore best model
2. `torch.save(model.state_dict(), workspace/model.pt)`
3. Compute anomaly scores on all training graphs (`batch_size=1`)
4. Compute `threshold = percentile(scores, 90)`
5. Save threshold, mean, std to `threshold_stats.json`
6. Save training history to `training_history.json` (last 10 runs)

**Fine-Tune Mode:**
Same as training but before initialization:
```python
existing_weights = torch.load(workspace/model.pt)
model.load_state_dict(existing_weights, strict=True)
```
If weight shapes don't match (e.g., `input_dim` changed), falls back to scratch.

**History Tracking:**
Every epoch, the following metrics are recorded:

| Metric | Description |
|---|---|
| `epochs` | Epoch number |
| `train_loss` | Average total loss on training set |
| `val_loss` | Average total loss on validation set |
| `feat_loss` | Average feature MSE |
| `ast_loss` | Average AST focal loss |
| `cfg_loss` | Average CFG focal loss |
| `dfg_loss` | Average DFG focal loss |

These are displayed in the GUI Dashboard as animated loss curves.

---

## Part VI — Anomaly Detection and Inference

### Section 29: Threshold Calibration

After training, the model is evaluated on the training dataset to establish what "normal" reconstruction error looks like for safe code.

**Procedure:**
1. `model.eval()`, `batch_size=1` (one graph at a time for exact per-graph scores)
2. For each graph in `train_dataset`:
```python
output = model(graph)
loss, *_ = reconstruction_loss(output, graph)
scores.append(loss.item())
```
3. Compute statistics:
```
mean_score = np.mean(scores) ≈ 0.0356 (from training run)
std_score  = np.std(scores)  ≈ 0.0184
threshold  = np.percentile(scores, 90)  ≈ 0.0643
```

**Note:** `batch_size=1` is critical here. With larger batches, the loss is averaged across the batch, giving artificially lower per-graph scores.

**Threshold Rationale:**
The 90th percentile means: 90% of safe training graphs have reconstruction error below the threshold. Only the top 10% of safe graphs (the most unusual safe code) would be flagged.

| Percentile | Assessment |
|---|---|
| 95th | Too conservative — misses many actual vulnerabilities |
| 85th | Too aggressive — too many false positives on safe code |
| **90th** | **Empirically found to be the best balance** |

The threshold, mean, and std are saved to `threshold_stats.json` and used at inference time. This file is bundled with the application so new installations don't need to retrain.

---

### Section 30: Severity Classification

At inference time, each function graph's anomaly score is classified into one of four severity levels using the threshold and standard deviation as margins:

```
Let T = threshold (90th percentile of safe scores)
Let σ = std (standard deviation of safe scores)

SAFE:                 score < T - σ
PARTIALLY VULNERABLE: T - σ ≤ score < T
VULNERABLE:           T ≤ score < T + σ
CRITICAL:             score ≥ T + σ
```

Using `T=0.0643` and `σ=0.0184`:

| Severity | Score Range |
|---|---|
| SAFE | score < 0.0459 |
| PARTIALLY VULNERABLE | 0.0459 ≤ score < 0.0643 |
| VULNERABLE | 0.0643 ≤ score < 0.0827 |
| CRITICAL | score ≥ 0.0827 |

**Overall File Severity:**
Determined by the highest severity level found across all function graphs. If any function is CRITICAL → file is CRITICAL. If any function is VULNERABLE (and none CRITICAL) → file is VULNERABLE, etc.

**Minimum Node Count Filter:**
Function graphs with fewer than 8 nodes are automatically scored as `SAFE` with `score=0.0`, regardless of reconstruction error. This is because:
1. Very small graphs (3-7 nodes) are typically trivial accessor functions, single-line helpers, or constructor stubs with no complex structure.
2. The model hasn't seen enough diverse small-graph examples to reliably distinguish anomalous from safe patterns at this scale.
3. Empirically, small graphs produce unstable scores that contribute most false positives.

**Confidence Score:**
For display in the GUI gauge, a confidence percentage is computed:
```
confidence = clamp(0, 100, (score - (T - σ)) / (2σ) × 100)
```
This maps:
- `score = T - σ` (borderline SAFE/PARTIAL) → 0% confidence
- `score = T` (threshold) → 50% confidence
- `score = T + σ` (borderline VULN/CRIT) → 100% confidence

---

### Section 31: Node-Level Anomaly Localization

Beyond file-level and function-level scoring, GRAPHSENTINEL localizes the most anomalous node within each function graph to point to specific vulnerable lines.

**Node Anomaly Scoring:**
For each node i, the node-level anomaly score is:
```
node_score_i = (1/d) · Σ_k (x̂_ik - x_ik)²
```
This is the mean squared reconstruction error for node i across all `d = 137` feature dimensions. High `node_score_i` means the autoencoder could not reconstruct node i's features well — this node is anomalous.
```
most_anomalous_idx = argmax_i(node_score_i)
```

**Node Vectorized Neighbor Search:**
The neighbor search for line localization uses vectorized tensor operations:
```python
edges = graph.edge_index    # [2 × E]
mask = (edges[0] == most_anomalous_idx) | (edges[1] == most_anomalous_idx)
neighbours = set(edges[0][mask].tolist() + edges[1][mask].tolist())
neighbours.discard(most_anomalous_idx)
```
This is O(E) via tensor operations (fast) vs O(E) via Python loop (slow). For a graph with 1000 edges, vectorized is approximately 100× faster.

**Line Number Localization:**
Priority order for finding the line number:
1. Try `most_anomalous_idx`'s own line number
2. Search graph-adjacent neighbors (nodes connected by any edge type)
3. Search all remaining nodes

Return the first valid line number found (> 0).

The fallback to neighbors is important because many CPG nodes lack explicit line numbers. For example, `BLOCK` nodes and `CONTROL_STRUCTURE` nodes often have line numbers, while `IDENTIFIER` and `CALL` nodes sometimes do not.

---

### Section 32: Line Number Extraction

Line numbers are extracted from the Joern CSV exports using header-based column parsing, implemented in `dataset/graph_converter.py`.

**Extraction Procedure:**
For each node, line number extraction tries multiple attribute names in order:
1. `LINE_NUMBER` (from header-parsed column)
2. `lineNumber` (Joern's internal camelCase name)
3. `line` (alternative name)
4. Raw CSV column index 6 (fallback heuristic)

All extracted values are cast to `int`. Anything that fails int conversion (e.g., empty string, non-numeric) is stored as `-1` (unknown line).

Line numbers are stored in the PyG Data object as:
```python
data.line_number ∈ Z^{N}  (integer tensor of line numbers per node)
```
At inference time in `anomaly_detector.py`, line numbers are accessed as:
```python
graph.line_number[node_idx].item()
```

---

## Part VII — Data Pipeline

### Section 33: The Juliet Test Suite Dataset

The Juliet C/C++ Test Suite version 1.3, produced by the NIST Software Assurance Metrics And Tool Evaluation (SAMATE) project, is the primary synthetic dataset for GRAPHSENTINEL training.

**Structure:**
Each test case in Juliet consists of paired functions:
- `"bad"` functions: contain a specific CWE vulnerability
- `"good"` functions: functionally similar but with the vulnerability fixed

The good/bad variants are separated by preprocessor macros:
```c
#ifndef OMITBAD
void bad(void) { /* vulnerable code */ }
#endif

#ifndef OMITGOOD
void good(void) { /* safe code */ }
#endif
```
GRAPHSENTINEL compiles only the `OMITGOOD` variants, extracting only safe code.

**CWE Coverage (23 categories used):**

| CWE | Description |
|---|---|
| CWE-121 | Stack-based Buffer Overflow |
| CWE-122 | Heap-based Buffer Overflow |
| CWE-124 | Buffer Underwrite (Out-of-bounds Write Below) |
| CWE-126 | Buffer Overread (Out-of-bounds Read) |
| CWE-134 | Use of Externally-Controlled Format String |
| CWE-190 | Integer Overflow or Wraparound |
| CWE-191 | Integer Underflow (Wrap or Wraparound) |
| CWE-242 | Use of Inherently Dangerous Function |
| CWE-369 | Divide by Zero |
| CWE-401 | Missing Release of Memory after Effective Lifetime |
| CWE-415 | Double Free |
| CWE-416 | Use After Free |
| CWE-457 | Use of Uninitialized Variable |
| CWE-476 | NULL Pointer Dereference |
| CWE-562 | Return of Stack Variable Address |
| CWE-590 | Free of Memory Not on the Heap |
| CWE-676 | Use of Potentially Dangerous Function |
| CWE-680 | Integer Overflow to Buffer Overflow |
| CWE-690 | Unchecked Return Value to NULL Pointer Dereference |
| CWE-761 | Free of Pointer not at Start of Buffer |
| CWE-762 | Mismatched Memory Management Routines |
| CWE-789 | Uncontrolled Memory Allocation |
| CWE-835 | Loop with Unreachable Exit Condition (Infinite Loop) |

Files per CWE: 100 (to ensure balanced representation). Total Juliet files: approximately 2300.

---

### Section 34: Safe Code Extraction Algorithm

Implemented in `extract_juliet_safe.py`.

The core challenge: Juliet files contain both safe and vulnerable variants interleaved with `#ifndef OMITBAD` preprocessor blocks.

A naive approach of just removing lines between `#ifndef OMITBAD` and `#endif` fails because:
1. Bad blocks can be nested (inner `#if`/`#endif` inside bad blocks)
2. Removing only the bad function declaration sometimes leaves behind orphaned helper calls

**Algorithm: Nesting-depth-aware block extraction**

```python
bad_depth = 0
output_lines = []

for each line in source_file:
    stripped = line.strip()

    if stripped.startswith("#ifndef OMITBAD"):
        bad_depth = 1
        continue

    if bad_depth > 0:
        if stripped.startswith("#if"):    bad_depth += 1
        if stripped.startswith("#endif"): bad_depth -= 1
        continue   # skip this line

    output_lines.append(line)

write(output_lines)
```

The depth counter ensures:
- When a `#ifndef OMITBAD` is encountered, depth starts at 1
- Any inner `#if` (including `#ifdef`, `#ifndef`, `#if defined`) increments depth
- Any `#endif` decrements depth
- Only when depth returns to 0 is the bad block considered ended
- Lines outside bad blocks are always included in output

This correctly handles patterns like:
```c
#ifndef OMITBAD
void bad() {
    #ifdef _WIN32
        win_bad_code();
    #else
        unix_bad_code();
    #endif
}
#endif
```
Without nesting depth, the inner `#endif` would prematurely end the bad block.

---

### Section 35: Real-World Repository Harvesting

Implemented in `harvest_repos.py`.

To improve model robustness beyond synthetic Juliet patterns, real-world open source repositories are harvested. The harvester uses shallow cloning and hash-based naming to efficiently collect diverse safe code examples.

**Target Repositories:**

| Repository | Description |
|---|---|
| `nlohmann/json` | Modern C++11/14/17 header-only JSON library. Excellent coverage of C++ templates, STL patterns, operator overloading. |
| `curl/curl` | Network transfer library in C. Real-world string handling, socket programming, error checking patterns. |
| `madler/zlib` | Compression library in C. Buffer management, memory handling. |
| `sqlite/sqlite` | Self-contained SQL database engine in C. B-tree operations, memory management, extensive error handling. |

**Shallow Cloning:**
```bash
git clone --depth 1 <repo_url> <dest>
```
`--depth 1` fetches only the latest commit (HEAD), skipping all historical commits. This reduces download size from gigabytes (full history) to megabytes (current code only), and is sufficient for training since only the current codebase is needed.

**Hash-Based Collision Prevention:**
Large repositories contain many files with identical names in different directories (`utils.c`, `main.cpp`, `common.h` appear dozens of times). Copying all to a flat directory would cause overwrites.

Solution: prefix each filename with a MD5 hash of its original path:
```python
hash    = md5(str(original_path))[:8]
new_name = f"{repo_name}_{hash}_{original_filename}"
```
Example: `curl`'s `lib/url.c` becomes: `curl_a8f93b12_url.c`

The MD5 of the path is deterministic (same file always gets same hash) and the 8-character prefix provides 16^8 = 4 billion unique values, effectively eliminating collisions.

**Filtering:**
- Only `.c` and `.cpp` files are collected (no `.h`/`.hpp` — header files are not standalone parseable by Joern)
- Files larger than 200KB are skipped (avoid monster files with thousands of functions that would skew the dataset)
- Directories named `test`, `tests`, `benchmark`, `examples`, `third_party`, `vendor`, `build`, `generated` are skipped
- Maximum 300 files per repository (prevents one large repo from dominating)

---

### Section 36: Word2Vec Corpus Construction

Implemented in `prep_word2vec.py`.

The Word2Vec model is trained on the complete safe code corpus (Juliet + harvested).

**Tokenization:**
For each source file, the tokenization procedure:
1. Read entire file as string
2. Find all alphanumeric token sequences (regex: `[a-zA-Z0-9_]+`)
3. Convert to lowercase
4. Filter tokens of length < 2 (single chars are rarely meaningful)
5. Split CamelCase: `getUserName` → `[get, user, name]`
6. Split snake_case: `buffer_size` → `[buffer, size]`
7. Filter numeric-only tokens (constants like `1234` are not informative)

Each file becomes one "sentence" (list of tokens) in the Word2Vec corpus.

**Model Parameters:**

| Parameter | Value |
|---|---|
| Vector size | 128 dimensions |
| Window | 5 (context window of ±5 tokens) |
| Min count | 2 (discard tokens appearing < 2 times in corpus) |
| Workers | 4 (parallel training threads) |
| Algorithm | CBOW (sg=0) |
| Epochs | 10 |

**Training:**
gensim's Word2Vec implementation uses negative sampling. For each (target, context) pair:
- Positive sample: the actual context word
- K negative samples: random words from vocabulary (not in context)

The model maximizes the probability of positive samples and minimizes the probability of negative samples.

Negative sampling objective:
```
L = log σ(u_o^T v_c) + Σ_{k=1}^{K} E_{w_k~P_n(w)} [log σ(-u_{w_k}^T v_c)]
```
where `v_c` is the center word embedding, `u_o` is the output embedding of the true context word, and `u_{w_k}` are output embeddings of negative samples.

---

### Section 37: The Joern Parse-Export Pipeline

Implemented in `parser_pipeline/joern_runner.py` and `cpg_exporter.py`.

**Joern Parse:**
```bash
joern-parse <source_file> --output <cpg_out_path>
```
Python implementation:
```python
result = subprocess.run(
    command, check=True,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, timeout=300
)
```
The `timeout=300` (5 minutes) prevents infinite hangs on complex files. `check=True` raises `CalledProcessError` if `joern-parse` returns non-zero. Both stdout and stderr are captured to prevent terminal spam and allow error logging.

**Joern Export:**
```bash
joern-export <cpg_path> --repr all --format neo4jcsv -o <export_dir>
```
- `--repr all`: export all representations (AST, CFG, DFG, all node types)
- `--format neo4jcsv`: Neo4j-compatible CSV format with separate header files
- `-o <export_dir>`: destination directory

The export directory must not exist (`joern-export` fails if it does). The exporter deletes and recreates the directory via `shutil.rmtree` before calling `joern-export`.

**Output Structure:**
```
nodes_METHOD_header.csv  +  nodes_METHOD_data.csv
nodes_CALL_header.csv    +  nodes_CALL_data.csv
edges_AST_header.csv     +  edges_AST_data.csv
edges_CFG_header.csv     +  edges_CFG_data.csv
edges_REACHING_DEF_header.csv  +  edges_REACHING_DEF_data.csv
... (many more)
```

---

### Section 38: CSV Parsing and Graph Construction

Implemented in `parser_pipeline/json_to_graph.py`.

**Node Loading:**
For each `nodes_<TYPE>_data.csv` file:
1. Find the corresponding `nodes_<TYPE>_header.csv`
2. Parse the header to build a column index map: `{column_name: column_index}`. Column names have type annotations stripped: `"CODE:string"` → `"CODE"`
3. For each row in the data CSV:
   - `node_id = row[0]`
   - `node_type = row[1]`
   - `code = row[col_index["CODE"]]` if `"CODE"` in `col_index`
   - `is_external = row[col_index["IS_EXTERNAL"]]` if present
   - `line_number = row[col_index["LINE_NUMBER"]]` if present
4. Add node to NetworkX graph with these attributes

**Edge Loading:**
For each `edges_<TYPE>_data.csv` file:
1. Determine edge type from filename: `edges_REACHING_DEF_data.csv` → `"REACHING_DEF"`
2. Map to relation ID:
   - `AST` → 0
   - `CFG` → 1
   - `REACHING_DEF` → 2 (also maps `"DFG"` → 2 for compatibility)
   - All others → skip (not used by the model)
3. For each row: `src = row[0]`, `dst = row[1]`
4. Add edge to graph with `type` and `edge_type` attributes

**NetworkX MultiGraph:**
`NetworkX MultiDiGraph` is used (not simple `DiGraph`) because:
1. Multiple edges between the same pair of nodes are possible (one AST edge + one CFG edge between the same nodes)
2. Directed: AST parent→child, CFG pred→succ, DFG def→use

**Graph Statistics:**
After construction:
```
Nodes: <count>
Edges: <count>
```
This provides a sanity check visible in training/detection output.

---

### Section 39: The Complete End-to-End Data Flow

**Training Pipeline:**

```
Step 1  DATASET PREPARATION (once)
  python extract_juliet_safe.py
    → data/safe/ (2300 safe .c/.cpp files)
  python harvest_repos.py
    → baseline_dataset/extracted_source_files/ (additional safe files)
    → cp to data/safe/

Step 2  WORD2VEC TRAINING (once per corpus change)
  python prep_word2vec.py --source data/safe
    → For each .c/.cpp in data/safe/:
        tokenize file → add to corpus
    → Train Word2Vec(dim=128, window=5, min_count=2)
    → embeddings/word2vec.model

Step 3  GRAPH GENERATION (once per corpus change)
  python main.py --mode parse --source data/safe --workspace workspace/
    → For each .c/.cpp file:
        joern-parse → cpg.bin
        joern-export → CSV files
        CPGGraphBuilder.build() → NetworkX MultiDiGraph
        split_graph_by_function() → list of subgraphs
        GraphConverter.convert() (with feature encoding)
          → serialize to JSON via node_link_data
          → save to workspace/graphs/graph_N.json
    → ~9800 JSON graph files

Step 4  MODEL TRAINING
  python main.py --mode train --workspace workspace/
    → Load word2vec.model
    → CPGDataset loads all graph JSON files
        → For each: load JSON → NetworkX → GraphConverter → PyG Data
    → 80/20 train/val split
    → Train RelationalGraphAutoencoder for 50 epochs
    → Save workspace/model.pt
    → Compute threshold → save workspace/threshold_stats.json
```

**Inference Pipeline:**

```
Step 1  FILE PREPARATION
  User provides target.c
  Copy to workspace/temp_detect/input/target.c

Step 2  CPG GENERATION
  joern-parse target.c → temp_detect/cpg/cpg.bin
  joern-export → temp_detect/json/ (CSV files)
  CPGGraphBuilder → NetworkX MultiDiGraph
  split_graph_by_function() → list of function subgraphs
  Serialize to workspace/temp_detect/graphs/graph_N.json

Step 3  FEATURE ENCODING
  Load word2vec.model
  For each graph JSON:
    nx.node_link_graph → NetworkX graph
    GraphConverter.convert() → PyG Data

Step 4  MODEL LOADING
  Load first graph to determine input_dim
  RelationalGraphAutoencoder(input_dim=137, num_relations=3)
  model.load_state_dict(workspace/model.pt)

Step 5  ANOMALY SCORING
  For each function graph:
    if graph.num_nodes < 8: score = 0.0, severity = SAFE
    else:
      output = model(graph)
      loss, *_ = reconstruction_loss(output, graph)
      score = loss.item()
      classify severity by threshold bands

Step 6  LOCALIZATION
  For each anomalous graph:
    node_scores = mean((x_hat - x)^2, dim=1)
    idx = argmax(node_scores)
    line = graph.line_number[idx]
    if line <= 0: search neighbors

Step 7  REPORT
  Print DETECTOR REPORT with all flagged graphs
  GUI parses output and displays in gauges + heatmap
```

---

## Part VIII — System Implementation

### Section 40: File Structure and Module Organization

```
MINIPROJECT/
├── gui.py                       # PyQt5 GUI application (~3200 lines, 6 pages)
├── main.py                      # CLI entry point (parse/train/finetune/detect)
├── prep_word2vec.py             # Word2Vec training + CamelCase/snake_case splitting
├── extract_juliet_safe.py       # Juliet Test Suite safe code extractor
├── harvest_repos.py             # Repository cloning & hash-based extraction
├── generate_safe_utils.py       # Synthetic safe C file generator
├── build.sh                     # Makeself-based installer builder
├── requirements.txt             # Pinned dependencies (PyTorch, PyG, PyQt5)
│
├── parser_pipeline/
│   ├── pipeline.py              # Orchestration: parse → export → build → split
│   ├── joern_runner.py          # Subprocess wrapper for joern-parse
│   ├── cpg_exporter.py          # Subprocess wrapper for joern-export
│   └── json_to_graph.py         # CSV reading & NetworkX graph construction
│
├── dataset/
│   ├── node_types.py            # NODE_TYPES single source of truth
│   ├── edge_schema.py           # EDGE_TYPE_MAP (AST/CFG/REACHING_DEF)
│   ├── feature_encoder.py       # One-hot type + Word2Vec token embedding
│   ├── graph_converter.py       # NetworkX → PyG Data conversion
│   └── pyg_dataset.py           # PyTorch Geometric Dataset wrapper
│
├── model/
│   ├── relational_autoencoder.py  # 3-layer RGAT + Bilinear+DistMult decoder
│   └── loss.py                    # Focal + MSE + Smoothness + Compactness
│
├── trainer/
│   ├── train.py                 # Training loop (AdamW + ReduceLROnPlateau)
│   ├── evaluate.py              # Per-graph score computation
│   └── threshold.py             # 90th percentile threshold calibration
│
├── detector/
│   └── anomaly_detector.py      # Inference + severity + line localization
│
├── embeddings/
│   └── word2vec.model           # Trained gensim Word2Vec model
│
└── workspace/
    ├── model.pt                 # Trained model weights (PyTorch state_dict)
    ├── threshold.txt            # Threshold value (plain text)
    ├── threshold_stats.json     # Threshold + mean + std (JSON)
    ├── gui_config.json          # GUI configuration parameters (JSON)
    ├── training_history.json    # Last 10 training run histories (JSON)
    ├── graphs/                  # Pre-generated function graph JSONs
    └── scan_logs/               # Timestamped saved scan results
```

---

### Section 41: The GUI Application Architecture

The GUI is a single-window PyQt5 application using `QStackedWidget` for page navigation. All pages are created at startup and added to the stack.

**Page Index Map:**

| Index | Page | Description |
|---|---|---|
| 0 | `MainPage` | Home tiles |
| 1 | `ScanPage` | File upload + scan results |
| 2 | `RetrainPage` | Training management |
| 3 | `ConfigurePage` | Parameter tuning |
| 4 | `PreviousResultsPage` | Scan log browser |
| 5 | `DashboardPage` | Model performance visualization |

**Navigation:**
Pages emit signals (`go_back`, `go_scan`, `go_retrain`, etc.). `MainWindow` wires these signals to lambda functions:
```python
self._main_page.go_scan.connect(lambda: self._go(1))
```
Navigation is instant (`QStackedWidget` shows/hides pages without recreation).

**Theme Constants:**

| Constant | Value | Purpose |
|---|---|---|
| `BG` | `#0a0a0a` | Almost black background |
| `CARD` | `#111111` | Slightly lighter card background |
| `CARD2` | `#161616` | Even lighter inner card |
| `BORDER` | `#ffffff` | White border |
| `BORDER2` | `#2a2a2a` | Subtle dark border |
| `TEXT` | `#ffffff` | Primary text |
| `DIM` | `#555555` | Secondary/muted text |
| `ACCENT` | `#00e5ff` | Cyan accent |
| `SAFE_C` | `#00e676` | Green for safe |
| `PARTIAL_C` | `#ffea00` | Yellow for partial |
| `VULN_C` | `#ff6d00` | Orange for vulnerable |
| `CRIT_C` | `#ff1744` | Red for critical |

**AngularGauge Widget — Detailed Implementation:**
Custom `QPainter`-based widget. All drawing uses `QPainter` in `paintEvent()`.

```
Constants:
  START_DEG = 225.0   (arc starts at lower-left)
  SWEEP_DEG = 270.0   (sweeps 270 degrees clockwise to lower-right)

Rainbow color stops:
  0.00 → #00e676 (green)
  0.25 → #aeea00 (yellow-green)
  0.50 → #ffea00 (yellow)
  0.75 → #ff6d00 (orange)
  1.00 → #ff1744 (red)

Between stops, colors are linearly interpolated:
  f = (t - t0) / (t1 - t0)   (interpolation factor)
  r = r0 + f * (r1 - r0)
  g = g0 + f * (g1 - g0)
  b = b0 + f * (b1 - b0)

Animation:
  QTimer fires every 16ms (~60fps)
  diff = target - current_value
  if |diff| < 0.004: stop animation (snapped to target)
  else: current_value += diff * 0.10  (10% of remaining gap per frame)

This creates an ease-out animation: fast initially, then decelerating
as it approaches the target value.

Arc drawing:
  The rainbow arc is drawn as 120 segments, each painted individually
  with its color. The number of segments actually drawn is limited to
  current_value * 120.
```

**LossChartWidget — Detailed Implementation:**
Custom `QPainter`-based chart. Supports 6 simultaneous line series.

```
Coordinate mapping:
  px = pad_l + (epoch_idx / x_range) * chart_width
  py = pad_t + chart_height - ((val - y_min) / y_range) * chart_height

Animation:
  _anim_t progresses from 0 to 1 over ~33 frames (0.5 seconds)
  Each frame, lines are drawn only up to anim_t fraction of their length.
  This creates a left-to-right draw animation.

Y-axis range:
  [min_visible_value * 0.9, max_visible_value * 1.1]
  This 10% padding prevents lines from touching the chart borders.
```

**Subprocess Communication:**
The scan subprocess uses `QProcess` with these critical settings:
```python
proc.setProgram(VENV_PYTHON)           # explicitly use venv Python
proc.setWorkingDirectory(APP_DIR)      # cwd = app directory for imports
env.insert("PATH", APP_DIR + ":" + env.value("PATH"))  # joern in PATH
env.insert("PYTHONPATH", "")           # clear conflicting PYTHONPATH
```
stdout and stderr are captured via `readyReadStandardOutput`/`readyReadStandardError` signals and accumulated in `self._cur_output` list.

On process finish, the accumulated output is passed to a callback:
```python
proc.finished.connect(lambda _c, _s: callback("".join(self._cur_output)))
```

The `parse_detect_output()` function then parses the terminal output with regex:
- `"Target File: <path>"` → `result["target_file"]`
- `"Threshold: <float>"` → `result["threshold"]`
- `"Margin (1σ): <float>"` → `result["margin"]`
- `"graph_N.json | SEVERITY | score=X.XXXX | line=N"` → `result["graphs"]`

Line parsing regex: `re.match(r"graph_\d+\.json", stripped_line)` — robust to any surrounding whitespace in the terminal output.

---

### Section 42: The Subprocess Communication Model

A critical architectural decision is that the GUI communicates with the detection and training engines via subprocess rather than direct import.

**Reasons for Subprocess Approach:**

1. Python's Global Interpreter Lock (GIL) prevents true parallelism for CPU-bound tasks like GNN inference. Subprocesses run in separate processes with their own GIL, allowing the GUI to remain responsive.
2. PyTorch operations can occasionally trigger segmentation faults or CUDA errors that crash the entire Python process. Running in a subprocess isolates these crashes from the GUI — the GUI simply reports the subprocess failed.
3. The subprocess can be killed cleanly (`proc.kill()`) if the user navigates away, without risking corrupted GUI state.
4. Output is naturally streamed: stdout/stderr appear in real time as the detection/training progresses, enabling progress display.

**VENV_PYTHON Path Resolution:**
```python
APP_DIR     = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(os.path.dirname(APP_DIR), "venv", "bin", "python")
```
This resolves to `/opt/GRAPHSENTINEL/venv/bin/python` in installed mode. In development (running directly from `MINIPROJECT/`), it falls back to `sys.executable` (the current Python interpreter).

The fallback ensures the GUI works in both development and production.

**`PYTHONPATH=""` Critical Fix:**
When `QProcess` inherits the system environment, if `PYTHONPATH` is set to any value (even pointing to the installed app), the subprocess may find system Python packages before the venv packages. This silently causes imports to find the wrong (often incompatible) package versions.

Explicitly setting `PYTHONPATH=""` clears any inherited PYTHONPATH, forcing Python's import machinery to use only the venv's `site-packages`.

This was the root cause of the "showing safe for everything" bug that persisted for many debugging iterations.

---

### Section 43: Packaging and Distribution

**Makeself:**
makeself is a shell script that creates self-extracting archives.
```bash
makeself <source_dir> <output_file> <label> <startup_script>
```
The created `.run` file is an ordinary shell script with the compressed archive appended after a marker line. When executed, it:
1. Detects the marker, extracts the archive to a temp directory
2. Runs the specified `startup_script` within the extracted directory
3. Cleans up the temp directory on exit

**Staging Structure:**
```
graphsentinel_staging/
├── install.sh         (runs when .run is executed)
└── app/
    ├── gui.py, main.py, ...   (all Python source)
    ├── joern-cli/             (bundled Joern binaries)
    ├── embeddings/            (trained Word2Vec model)
    └── workspace/             (pre-trained model, graphs, threshold)
```

**install.sh Execution Flow:**
1. Check and install: `default-jre`, `python3`, `python3-pip`, `python3-venv`, `python3-pyqt5`
2. `sudo mkdir /opt/GRAPHSENTINEL` + chown to current user
3. `cp -r app/` → `/opt/GRAPHSENTINEL/app`
4. `find joern-cli -type f | xargs chmod +x` (restore execute bits)
5. `python3 -m venv /opt/GRAPHSENTINEL/venv`
6. `pip install torch==2.10.0 torchvision==0.25.0 torchaudio==2.10.0 --index-url https://download.pytorch.org/whl/cpu`
7. `grep -vE "^torch==|^torchaudio==|^torchvision==" requirements.txt | pip install` (torch-geometric and other packages install here)
8. Create launcher `graphsentinel.sh` with `PYTHONPATH=""`
9. Create `~/.local/share/applications/graphsentinel.desktop`
10. Create `~/.local/share/icons/graphsentinel.svg`

**CPU-Only PyTorch:**
The standard pip install of PyTorch downloads the CUDA version (~2GB + CUDA runtime ~8GB = ~10GB total). CPU-only version is ~600MB. The `--index-url` flag points pip to PyTorch's dedicated CPU-only package index.

| Version | venv Size |
|---|---|
| CUDA PyTorch | ~7.7GB |
| CPU PyTorch | ~2.3GB (saved ~5.4GB) |

The detection and training pipelines work identically on CPU — just slower than GPU.

---

## Part IX — Experimental Results and Analysis

### Section 44: Training Results

**Final Training Run** (50 epochs, 9804 graphs, `batch_size=16`):

```
Dataset split:
  Train: 7843 graphs (80%)
  Val:   1961 graphs (20%)

Batches per epoch: 490 (train), 123 (val)
```

**Loss Progression (selected epochs):**

| Epoch | Train | Feat | AST | CFG | DFG | Val |
|---|---|---|---|---|---|---|
| 001 | 0.1847 | 0.3211 | 0.0847 | 0.0341 | 0.0623 | 0.1234 |
| 010 | 0.0412 | 0.1234 | 0.0198 | 0.0121 | 0.0187 | 0.0398 |
| 020 | 0.0287 | 0.0923 | 0.0112 | 0.0084 | 0.0131 | 0.0271 |
| 030 | 0.0234 | 0.0789 | 0.0089 | 0.0063 | 0.0108 | 0.0221 |
| 040 | 0.0196 | 0.0682 | 0.0075 | 0.0055 | 0.0095 | 0.0190 |
| 042 | 0.0197 | 0.0681 | 0.0076 | 0.0056 | 0.0097 | **0.0188 ← BEST** |
| 044 | 0.0195 | 0.0677 | 0.0074 | 0.0054 | 0.0095 | **0.0188 ← BEST** |
| 050 | 0.0193 | 0.0672 | 0.0074 | 0.0054 | 0.0094 | 0.0190 |

**Best validation loss:** 0.0188 (at epoch 42)

**Threshold Calibration:**

| Statistic | Value |
|---|---|
| Mean | 0.0356 |
| Std Dev | 0.0184 |
| 10th percentile | 0.0142 |
| 50th percentile | 0.0317 |
| **90th percentile** | **0.0643 ← THRESHOLD** |
| 99th percentile | 0.0892 |

**Severity Bands:**

| Severity | Score Range |
|---|---|
| SAFE | score < 0.0459 (T − σ = 0.0643 − 0.0184) |
| PARTIALLY VULNERABLE | 0.0459 ≤ score < 0.0643 |
| VULNERABLE | 0.0643 ≤ score < 0.0827 (T + σ = 0.0643 + 0.0184) |
| CRITICAL | score ≥ 0.0827 |

**Convergence Analysis:**
- Feature loss dominates the total loss (highest absolute value) because reconstructing 128-dimensional Word2Vec embeddings from 64-dimensional latent codes is a challenging compression task.
- AST loss converges fastest (from 0.0847 to 0.0074) because syntax structure is the most regular and learnable aspect of safe code.
- CFG loss converges to the lowest absolute value (0.0055) because control flow graphs in safe Juliet code follow stereotypical patterns that the model learns easily.
- DFG loss remains higher than CFG (0.0094 vs 0.0055) because data flow patterns are more diverse and harder to reconstruct from local context.
- Train-Val gap at convergence: `0.0193 - 0.0190 = 0.0003` (very small) — indicates minimal overfitting; the model generalizes well to unseen safe code.

---

### Section 45: Detection Performance

**Vulnerable File Results** (`bad_01` through `bad_10`):

| File | Functions Detected | Top Score | Severity |
|---|---|---|---|
| `bad_01_stack_overflow.c` | `process_username`, `process_token`, `log_event` | ~0.12 | CRITICAL |
| `bad_02_heap_overflow.c` | `create_greeting`, `pack_message` | ~0.11 | CRITICAL |
| `bad_03_use_after_free.c` | `process_session`, `handle_token`, `bad_counter_ops` | ~0.14 | CRITICAL |
| `bad_04_null_deref.c` | `print_user_info`, `process_buffer`, `use_env_value` | ~0.09 | CRITICAL |
| `bad_05_double_free.c` | `handle_block`, `apply_config`, `cleanup_resources` | ~0.13 | CRITICAL |
| `bad_06_format_string.c` | `log_message`, `log_with_level`, `audit_log` | ~0.10 | CRITICAL |
| `bad_07_integer_overflow.c` | `allocate_matrix`, `compute_offset`, `calculate_checksum` | ~0.08 | CRITICAL |
| `bad_08_memory_leak.c` | `process_file`, `use_resource`, `process_array` | ~0.09 | CRITICAL |
| `bad_09_mixed_vulns.c` | `log_access`, `allocate_workspace` | ~0.14 | CRITICAL |
| `bad_10_cpp_vulns.cpp` | `DataBuffer::copyData`, `SessionManager::printToken`, `processUserInput`, `createArray` | ~0.11 | CRITICAL |

Notable detection notes:
- `bad_03`: DFG patterns are key — data flow from freed memory to use
- `bad_06`: Unusual DFG pattern: untrusted data flows to format argument position
- `bad_08`: CFG patterns: execution paths where `free()` is never reached
- `bad_09`: Multiple vulnerability types create multiple anomalous patterns

**Safe File Results** (`good_01` through `good_10`):
All return SAFE with no flagged functions. All scores below threshold: 0.0643.

Note: The one known false positive — `main()` functions with multiple calls — was reduced by including diverse safe utility code in training. The minimum 8-node filter further reduces noise from tiny boilerplate functions.

---

### Section 46: Known Limitations

1. **Synthetic Training Data Bias** — The primary training set is Juliet, which uses predictable naming conventions (e.g., `goodG2B`, `badG1B`) and follows a consistent code style. Code written in very different styles (heavily macro'd, auto-generated, unusual C++ templates) may produce false positives because the model has not seen similar structural patterns in training.

2. **Unsupervised Nature Means No Guaranteed Detection Rate** — Unlike supervised classifiers which can be trained to minimize false negatives on a known vulnerability set, the unsupervised approach has no explicit mechanism to guarantee that all vulnerabilities are detected. A vulnerability that looks structurally similar to safe code (e.g., a subtle off-by-one in a loop boundary) may not produce sufficient reconstruction error to be flagged.

3. **Single-File Analysis** — The system analyzes one file at a time. Cross-file vulnerabilities (where a dangerous pattern emerges from the interaction between functions in different files) cannot be detected. Real-world vulnerabilities often span multiple translation units.

4. **Line Localization Is Approximate** — Many CPG nodes lack explicit line numbers in Joern's export. The fallback neighbor-search heuristic points to nearby nodes with line numbers, which may be adjacent to (but not exactly on) the vulnerable line. The line reported may be the function call rather than the vulnerable statement inside.

5. **DFG Sparsity** — Joern's `REACHING_DEF` edges represent a conservative approximation of data flow. Many actual data dependencies are not captured. This limits the model's ability to detect vulnerabilities that rely primarily on data flow patterns (e.g., taint analysis-dependent vulnerabilities).

6. **No Interprocedural Analysis** — The function-level splitting means the model sees each function in isolation. A vulnerability where a safe-looking call sequence (allocate → use → free) is split across multiple functions will not be detected because no single function's graph captures the full vulnerable pattern.

7. **CPU-Only Inference** — The installed application uses CPU-only PyTorch. Inference on a complex file with 50+ function graphs can take 10–30 seconds on a typical laptop CPU. GPU acceleration would reduce this to under 1 second.

8. **Word2Vec Limitations** — Word2Vec cannot capture long-range semantic dependencies between code tokens. Project-specific identifier names (`customerDataBuffer`, `doPrivilegedOp`) will not have trained embeddings and will receive zero vectors, reducing feature quality for code that uses domain-specific naming.

9. **Graph Size Variability** — Function graphs range from 5 to 500+ nodes. The RGAT encoder's 3-hop receptive field is fixed, so for very large functions (200+ nodes), the encoder can only see a small fraction of the function's full context for any individual node.

10. **No Exploit Confirmation** — GRAPHSENTINEL identifies structural anomalies — it cannot confirm whether an anomaly is actually exploitable. A flagged function may have mitigating factors (compiler protections, OS-level ASLR, DEP) that make it unexploitable in practice. The tool is a detection aid, not a pen-testing tool.

---

## Appendix A: Model Parameter Count

`RelationalGraphAutoencoder` parameter breakdown:

| Component | Parameters |
|---|---|
| Input Dropout | 0 (Dropout is parameterless) |
| `conv1` RGATConv(137→32, 4 heads, 3 relations) — weights + attention + bias | ~53,760 |
| `norm1` GraphNorm(128) — gamma + beta + alpha | 384 |
| `conv2` RGATConv(128→32, 4 heads, 3 relations) | ~50,304 |
| `norm2` GraphNorm(128) | 384 |
| `conv3` RGATConv(128→64, 1 head, 3 relations) | ~25,152 |
| `norm3` GraphNorm(64) | 192 |
| `skip1` Linear(137→128) | 17,664 |
| `skip2` Linear(128→128) | 16,512 |
| `skip3` Linear(128→64) | 8,256 |
| `readout_gate` Linear(64→1) | 65 |
| `readout_transform` Linear(64→64) | 4,160 |
| Feature Decoder — Linear(64→128) + LN + Linear(128→128) + LN + Linear(128→137) | ~35,337 |
| Structure Decoder — `relation_diag` (3×64) + `relation_bilinear` (3×64×64) + `decoder_blend` | 12,481 |
| Latent Projector — Linear(64→64) + Linear(64→32) | 6,208 |
| **TOTAL APPROXIMATE** | **~230,000 parameters** |

This is a relatively small model by modern standards (GPT-3 has 175 billion parameters). The small size is intentional — it must run on CPU in real time for single-file scanning. Despite its size, the combination of relational attention, 3-layer depth, and multiple regularization losses produces effective anomaly detection for code graphs.

---

## Appendix B: Glossary of Key Terms

| Term | Definition |
|---|---|
| **Anomaly Score** | The reconstruction error of a function graph through the autoencoder. Higher scores indicate more unusual code structure relative to the training data. |
| **AST (Abstract Syntax Tree)** | A tree representation of source code's syntactic structure. Each node is a syntactic construct (expression, statement, declaration). Parent-child edges indicate hierarchical ownership. |
| **Autoencoder** | A neural network trained to compress input into a low-dimensional latent representation and reconstruct the original from it. Used here for anomaly detection: poor reconstruction = anomalous input. |
| **Batch Normalization** | Normalization technique that standardizes activations across a batch. Not used in GRAPHSENTINEL due to poor behavior on variable-size graphs. |
| **CFG (Control Flow Graph)** | A graph representation of possible execution paths. Nodes are basic blocks, edges represent control transfers (sequential, if-true, if-false, loop back). |
| **Code Property Graph (CPG)** | A unified multigraph combining AST, CFG, and DFG representations of source code in a single queryable structure. |
| **CWE (Common Weakness Enumeration)** | A community-developed list of common software and hardware weakness types. CWE-121 = Stack Buffer Overflow, CWE-416 = Use After Free, etc. |
| **DFG (Data Flow Graph)** | A graph where edges represent the flow of variable values. An edge from node A to node B means a value defined at A may be used at B. |
| **DistMult** | A knowledge graph embedding model that scores triples (subject, relation, object) using diagonal relation matrices: `score = s^T · diag(R) · o`. |
| **Focal Loss** | A modification of cross-entropy loss that down-weights easy examples (confident correct predictions) to focus training on hard examples. |
| **GELU (Gaussian Error Linear Unit)** | Activation function: `GELU(x) = x·Φ(x)`. Smooth, non-zero for negative inputs. |
| **GraphNorm** | Per-graph normalization for graph neural networks. Normalizes within each individual graph rather than across a batch. |
| **GNN (Graph Neural Network)** | A class of neural networks that operate on graph-structured data by passing messages between connected nodes. |
| **Joern** | An open-source code analysis platform that generates Code Property Graphs from C/C++ source code. |
| **Latent Space** | The compressed low-dimensional representation space learned by the encoder. In GRAPHSENTINEL, each node is represented as a 64-dimensional latent vector. |
| **REACHING_DEF** | Joern's implementation of data flow edges. A `REACHING_DEF` edge from node A to node B means a variable definition at A reaches (is used at) B. |
| **Reconstruction Error** | The difference between an autoencoder's input and its reconstructed output. Low error = input is similar to training distribution (safe code). High error = input is anomalous (potentially vulnerable code). |
| **RGAT (Relational Graph Attention Network)** | A GNN that uses attention mechanisms with separate parameters per relation type. Suitable for heterogeneous graphs with multiple edge types. |
| **Skip Connection** | An architectural shortcut that adds a layer's input to its output: `output = layer(input) + projection(input)`. Improves gradient flow in deep networks. |
| **Threshold** | The anomaly score above which a function graph is considered potentially vulnerable. Set at the 90th percentile of training data scores. |
| **Word2Vec** | A neural network method for learning dense vector representations of words (or code tokens) from large corpora using the distributional hypothesis. |
| **Zero-Day Vulnerability** | A software vulnerability unknown to the developer and for which no patch exists. The "zero days" refers to how long developers have had to fix it. |
