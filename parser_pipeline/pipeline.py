# pipeline.py

from parser_pipeline.joern_runner import JoernRunner
from parser_pipeline.cpg_exporter import CPGExporter
from parser_pipeline.json_to_graph import CPGGraphBuilder
from networkx.readwrite import json_graph

import networkx as nx
import os
import shutil
import json


class SourceCodePipeline:
    def __init__(self):
        self.joern = JoernRunner()
        self.exporter = CPGExporter()

    # -------- Function graph splitter --------
    def split_graph_by_function(self, graph):

        function_nodes = []

        for node_id, attrs in graph.nodes(data=True):

            node_type = (
                attrs.get("type")
                or attrs.get("_LABEL")
                or attrs.get("label")
            )

            if node_type == "METHOD":

                # FIX: Skip external/library stubs — they have no real body
                # and fragment the vulnerability context across subgraphs
                is_external = (
                    attrs.get("IS_EXTERNAL")
                    or attrs.get("isExternal")
                    or attrs.get("is_external")
                )

                if is_external in (True, "true", "True", "1"):
                    continue

                # Also skip methods with no code body as a secondary guard
                code = (
                    attrs.get("code")
                    or attrs.get("name")
                    or ""
                )

                if code.strip() == "<empty>":
                    continue

                function_nodes.append(node_id)

        subgraphs = []

        for root in function_nodes:

            reachable = {root}
            stack = [root]

            while stack:
                node = stack.pop()

                for _, dst, data in graph.out_edges(node, data=True):

                    edge_type = data.get("type")

                    if edge_type == "AST" and dst not in reachable:
                        reachable.add(dst)
                        stack.append(dst)

            sub = graph.subgraph(reachable).copy()

            # Skip extremely small graphs
            if sub.number_of_nodes() < 5:
                continue

            subgraphs.append(sub)

        return subgraphs

    # -------- Main pipeline --------
    def process(self, source_dir, workspace):

        graphs_dir = os.path.join(workspace, "graphs")
        cpg_dir = os.path.join(workspace, "cpg")
        json_dir = os.path.join(workspace, "json")

        # Ensure workspace exists but do NOT delete it
        os.makedirs(workspace, exist_ok=True)

        # Clean only internal output folders
        if os.path.exists(graphs_dir):
            shutil.rmtree(graphs_dir)

        if os.path.exists(cpg_dir):
            shutil.rmtree(cpg_dir)

        if os.path.exists(json_dir):
            shutil.rmtree(json_dir)

        os.makedirs(graphs_dir)
        os.makedirs(cpg_dir)
        os.makedirs(json_dir)

        files = []

        for root, _, filenames in os.walk(source_dir):
            for f in filenames:
                if f.endswith(".c") or f.endswith(".cpp"):
                    files.append(os.path.join(root, f))

        print(f"Found {len(files)} source files.")

        graph_count = 0

        for idx, file in enumerate(files):

            src_path = file

            print(f"\nProcessing {file} ({idx+1}/{len(files)})")

            cpg_file_dir = os.path.join(cpg_dir, f"cpg_{idx}")
            json_file_dir = os.path.join(json_dir, f"json_{idx}")

            os.makedirs(cpg_file_dir)
            os.makedirs(json_file_dir)

            print("1. Parsing with Joern...")
            cpg_path = self.joern.parse_source(src_path, cpg_file_dir)

            print("2. Exporting CPG...")
            self.exporter.export_json(cpg_path, json_file_dir)

            print("3. Building graph...")
            builder = CPGGraphBuilder()
            graph = builder.build(json_file_dir)

            if graph.number_of_nodes() == 0:
                print("Skipping empty graph.")
                continue

            # -------- Split graph into functions --------
            subgraphs = self.split_graph_by_function(graph)

            print(f"Extracted {len(subgraphs)} function graphs.")

            for sub in subgraphs:

                graph_data = json_graph.node_link_data(sub)

                graph_file = os.path.join(
                    graphs_dir,
                    f"graph_{graph_count}.json"
                )

                with open(graph_file, "w") as f:
                    json.dump(
                        {
                            "graph": graph_data,
                            "label": 0
                        },
                        f
                    )

                graph_count += 1

        print(f"\nCreated {graph_count} graphs.")

        return graph_count


if __name__ == "__main__":

    pipeline = SourceCodePipeline()

    graph_count = pipeline.process(
        source_dir="sample_code/",
        workspace="workspace/"
    )

    print(f"Total graphs created: {graph_count}")