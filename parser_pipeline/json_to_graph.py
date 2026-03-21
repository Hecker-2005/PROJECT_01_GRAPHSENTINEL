# json_to_graph.py

import os
import csv
import networkx as nx


# ---------- RELATION MAPPING ----------
# Only these 3 relations will be used by the model
EDGE_TYPE_MAP = {
    "AST": 0,
    "CFG": 1,
    "REACHING_DEF": 2   # treated as DFG
}


class CPGGraphBuilder:

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def _get_value(self, row, keys):
        """
        Helper to fetch the first existing key from possible alternatives.
        """
        for k in keys:
            if k in row and row[k] != "":
                return row[k]
        return None

    def load_nodes(self, json_dir):

        for file in os.listdir(json_dir):
            if not (file.startswith("nodes_") and file.endswith("_data.csv")):
                continue

            # Derive header filename from data filename
            header_file = file.replace("_data.csv", "_header.csv")
            header_path = os.path.join(json_dir, header_file)
            data_path = os.path.join(json_dir, file)

            # Parse column positions from header
            col_index = {}
            if os.path.exists(header_path):
                with open(header_path, newline="", encoding="utf-8") as hf:
                    reader = csv.reader(hf)
                    for row in reader:
                        for i, col in enumerate(row):
                            # Normalize: strip type hints like :boolean, :int etc
                            col_name = col.split(":")[0].strip()
                            col_index[col_name] = i
                        break  # only first row is the header

            with open(data_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)

                for row in reader:
                    if len(row) < 2:
                        continue

                    node_id = row[0]
                    node_type = row[1]

                    # Safely extract CODE using header-derived index
                    code = ""
                    if "CODE" in col_index and len(row) > col_index["CODE"]:
                        code = row[col_index["CODE"]]

                    # Extract IS_EXTERNAL (only meaningful for METHOD nodes)
                    is_external = "false"
                    if "IS_EXTERNAL" in col_index and len(row) > col_index["IS_EXTERNAL"]:
                        is_external = row[col_index["IS_EXTERNAL"]].strip().lower()

                    # Extract LINE_NUMBER
                    line_number = ""
                    if "LINE_NUMBER" in col_index and len(row) > col_index["LINE_NUMBER"]:
                        line_number = row[col_index["LINE_NUMBER"]].strip()

                    attrs = {
                        "type": node_type,
                        "code": code,
                        "raw": row,
                        "IS_EXTERNAL": is_external,
                        "LINE_NUMBER": line_number
                    }

                    self.graph.add_node(node_id, **attrs)

    def load_edges(self, json_dir):

        for file in os.listdir(json_dir):
            if file.startswith("edges_") and file.endswith("_data.csv"):

                edge_type = file.split("_")[1]

                # Normalize Joern relation names
                if edge_type.startswith("REACHING"):
                    edge_type = "REACHING_DEF"

                # ---------- FILTER ONLY 3 RELATIONS ----------
                if edge_type not in EDGE_TYPE_MAP:
                    continue
                # --------------------------------------------

                path = os.path.join(json_dir, file)

                with open(path, newline="", encoding="utf-8") as f:
                    reader = csv.reader(f)

                    for row in reader:
                        if len(row) < 2:
                            continue

                        src = row[0]
                        dst = row[1]

                        self.graph.add_edge(
                            src,
                            dst,
                            type=edge_type,
                            edge_type=EDGE_TYPE_MAP[edge_type]  # numeric relation id
                        )

    def build(self, json_dir):

        self.load_nodes(json_dir)
        self.load_edges(json_dir)

        print("Graph stats:")
        print("Nodes:", self.graph.number_of_nodes())
        print("Edges:", self.graph.number_of_edges())

        return self.graph