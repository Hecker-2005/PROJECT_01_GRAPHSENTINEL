# joern_runner.py

import subprocess
import os

class JoernRunner:
    # Use the dedicated joern-parse CLI tool instead of the interactive shell
    def __init__(self, joern_parse_path="joern-parse"):
        self.joern_parse_path = joern_parse_path

    def parse_source(self, source_path, output_dir):
        """
        Runs joern-parse to generate a CPG binary from source code.
        """
        os.makedirs(output_dir, exist_ok=True)
        cpg_out_path = os.path.join(output_dir, "cpg.bin")

        command = [
            self.joern_parse_path,
            source_path,
            "--output",
            cpg_out_path
        ]

        try:
            # Added timeout and output capturing to prevent infinite hangs
            result = subprocess.run(
                command, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=300 # 5 minute timeout per file
            )
        except subprocess.CalledProcessError as e:
            print(f"Joern Parse Failed: {e.stderr}")
            raise e

        return cpg_out_path