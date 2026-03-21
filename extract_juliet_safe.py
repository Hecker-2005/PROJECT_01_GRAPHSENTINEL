# extract_juliet_safe.py

import os
import shutil

JULIET_SRC = os.path.expanduser("~/Downloads/C")
DEST_DIR = os.path.join(os.getcwd(), "data", "safe")

# --------------------------------------------------
# Targeted CWE categories for balanced training
# --------------------------------------------------
TARGET_CWES = [
    # Tier 1 — Core memory safety
    "CWE121", "CWE122", "CWE190", "CWE401",
    "CWE415", "CWE416", "CWE476", "CWE690",
    # Tier 2 — Broader memory/pointer
    "CWE124", "CWE126", "CWE134", "CWE369",
    "CWE457", "CWE562", "CWE590", "CWE680",
    "CWE762", "CWE789",
    # Tier 3 — Code quality/logic
    "CWE191", "CWE242", "CWE676", "CWE761", "CWE835",
]

def extract_safe_code(max_files_per_cwe=100):
    """
    Extracts safe code from targeted CWE categories.
    Caps each CWE at max_files_per_cwe for a balanced dataset.
    """
    os.makedirs(DEST_DIR, exist_ok=True)

    # Copy Juliet support headers
    support_dir = os.path.join(JULIET_SRC, "testcasesupport")
    for header in ["std_testcase.h", "std_testcase_io.h"]:
        src_header = os.path.join(support_dir, header)
        if os.path.exists(src_header):
            shutil.copy(src_header, DEST_DIR)

    testcases_dir = os.path.join(JULIET_SRC, "testcases")

    total_count = 0
    cwe_counts = {}

    print("Extracting safe C/C++ code from targeted CWE categories...")
    print(f"Target: {len(TARGET_CWES)} CWEs × {max_files_per_cwe} files = "
          f"~{len(TARGET_CWES) * max_files_per_cwe} files\n")

    for cwe in TARGET_CWES:

        cwe_count = 0

        # Find the matching directory (CWE folder names have full descriptions)
        cwe_dir = None
        for folder in os.listdir(testcases_dir):
            if folder.startswith(cwe):
                cwe_dir = os.path.join(testcases_dir, folder)
                break

        if not cwe_dir or not os.path.exists(cwe_dir):
            print(f"  [{cwe}] Directory not found, skipping.")
            continue

        for root, _, files in os.walk(cwe_dir):
            for file in files:
                if not (file.endswith(".c") or file.endswith(".cpp")):
                    continue

                # Skip Windows-specific files
                if "w32" in file.lower() or "wchar_t" in file.lower():
                    continue

                if cwe_count >= max_files_per_cwe:
                    break

                src_path = os.path.join(root, file)
                dest_path = os.path.join(DEST_DIR, f"{cwe}_{file}")

                try:
                    with open(src_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()

                    clean_lines = []
                    in_bad_block = False
                    bad_depth = 0

                    for line in lines:

                        if "#ifndef OMITBAD" in line:
                            in_bad_block = True
                            bad_depth = 1
                            continue

                        if in_bad_block:
                            if line.strip().startswith("#if"):
                                bad_depth += 1
                            elif line.strip().startswith("#endif"):
                                bad_depth -= 1
                                if bad_depth == 0:
                                    in_bad_block = False
                            continue

                        clean_lines.append(line)

                    with open(dest_path, "w", encoding="utf-8") as f:
                        f.writelines(clean_lines)

                    cwe_count += 1
                    total_count += 1

                except Exception as e:
                    print(f"  Skipping {file}: {e}")

            if cwe_count >= max_files_per_cwe:
                break

        cwe_counts[cwe] = cwe_count
        print(f"  [{cwe}] {cwe_count} files extracted.")

    print(f"\nDone! Total: {total_count} files extracted to {DEST_DIR}")
    print("\nCWE breakdown:")
    for cwe, count in cwe_counts.items():
        print(f"  {cwe}: {count}")

if __name__ == "__main__":
    extract_safe_code(max_files_per_cwe=100)