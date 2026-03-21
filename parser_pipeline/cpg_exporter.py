import subprocess
import os
import shutil

class CPGExporter:
    def __init__(self, joern_export="joern-export"):
        self.joern_export = joern_export

    def export_json(self, cpg_path, export_dir):

        # Ensure the export directory does NOT exist
        if os.path.exists(export_dir):
            shutil.rmtree(export_dir)

        command = [
            self.joern_export,
            cpg_path,
            "--repr", "all",
            "--format", "neo4jcsv",
            "-o", export_dir
        ]

        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

        except subprocess.CalledProcessError as e:
            print("Joern Export Failed:")
            print(e.stderr)
            raise e

        return export_dir