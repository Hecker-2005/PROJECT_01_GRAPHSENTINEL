#!/usr/bin/env bash
# build.sh — assembles the GRAPHSENTINEL self-extracting installer (makeself .run)
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGING="$PROJECT_DIR/graphsentinel_staging"
JOERN_SRC="/home/feanor/bin/joern/joern-cli"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     GRAPHSENTINEL — .run Installer Builder                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Project : $PROJECT_DIR"
echo "Staging : $STAGING"
echo ""

# ── Clean staging ────────────────────────────────────────
echo "[1/7] Cleaning staging area..."
rm -rf "$STAGING"
mkdir -p "$STAGING/app"

# ── Copy Python source files ─────────────────────────────
echo "[2/7] Copying Python source..."
cp "$PROJECT_DIR/gui.py"                 "$STAGING/app/"
cp "$PROJECT_DIR/main.py"                "$STAGING/app/"
cp "$PROJECT_DIR/prep_word2vec.py"       "$STAGING/app/"
cp "$PROJECT_DIR/extract_juliet_safe.py" "$STAGING/app/"
cp "$PROJECT_DIR/requirements.txt"       "$STAGING/app/"

for dir in dataset model trainer detector parser_pipeline; do
    cp -r "$PROJECT_DIR/$dir" "$STAGING/app/$dir"
done

# ── Copy embeddings ──────────────────────────────────────
echo "[3/7] Copying Word2Vec embeddings..."
mkdir -p "$STAGING/app/embeddings"
cp -r "$PROJECT_DIR/embeddings/." "$STAGING/app/embeddings/"

# ── Copy workspace artifacts ─────────────────────────────
echo "[4/7] Copying workspace artifacts..."
mkdir -p "$STAGING/app/workspace/graphs"
mkdir -p "$STAGING/app/workspace/scan_logs"

for f in model.pt threshold.txt threshold_stats.json \
          gui_config.json training_history.json; do
    [ -f "$PROJECT_DIR/workspace/$f" ] && \
        cp "$PROJECT_DIR/workspace/$f" "$STAGING/app/workspace/"
done

echo "    Copying graphs (may take a moment)..."
cp -r "$PROJECT_DIR/workspace/graphs/." "$STAGING/app/workspace/graphs/"

echo "    Copying safe dataset..."
mkdir -p "$STAGING/app/data/safe"
cp -r "$PROJECT_DIR/data/safe/." "$STAGING/app/data/safe/"

# ── Bundle Joern ─────────────────────────────────────────
echo "[5/7] Bundling Joern CLI..."
cp -r "$JOERN_SRC" "$STAGING/app/joern-cli"

# ── Write install.sh ─────────────────────────────────────
echo "[6/7] Writing installer script..."

cat > "$STAGING/install.sh" << 'INSTALL_EOF'
#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/GRAPHSENTINEL"
LAUNCHER="$INSTALL_DIR/graphsentinel.sh"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons"
VENV_DIR="$INSTALL_DIR/venv"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     GRAPHSENTINEL — Installer                                ║"
echo "║     INTELLIGENT SYSTEM-CENTRIC ZERO-DAY THREAT DETECTION    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Dependency checks ────────────────────────────────────
echo "Checking dependencies..."
MISSING=()
if ! command -v java &> /dev/null; then MISSING+=("default-jre"); fi
if ! command -v python3 &> /dev/null; then MISSING+=("python3"); fi
if ! command -v pip3 &> /dev/null; then MISSING+=("python3-pip"); fi
if ! dpkg -l python3-venv &> /dev/null 2>&1; then MISSING+=("python3-venv"); fi
if ! dpkg -l python3-pyqt5 &> /dev/null 2>&1; then MISSING+=("python3-pyqt5"); fi

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Installing missing system dependencies: ${MISSING[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING[@]}"
fi
echo "All system dependencies satisfied."
echo ""

# ── Create install directory ─────────────────────────────
echo "[1/6] Creating install directory at $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"

# ── Copy app files ───────────────────────────────────────
echo "[2/6] Copying application files..."
cp -r app/. "$INSTALL_DIR/app"

# ── Configure Joern ──────────────────────────────────────
echo "[3/6] Configuring Joern..."
find "$INSTALL_DIR/app/joern-cli" -type f | xargs chmod +x 2>/dev/null || true

cat > "$INSTALL_DIR/app/joern-parse" << 'JOERN_EOF'
#!/usr/bin/env bash
exec "$(dirname "$0")/joern-cli/joern-parse" "$@"
JOERN_EOF

cat > "$INSTALL_DIR/app/joern-export" << 'JOERN_EOF'
#!/usr/bin/env bash
exec "$(dirname "$0")/joern-cli/joern-export" "$@"
JOERN_EOF

chmod +x "$INSTALL_DIR/app/joern-parse"
chmod +x "$INSTALL_DIR/app/joern-export"

# ── Create Python venv and install deps ──────────────────
echo "[4/6] Creating Python virtual environment..."
echo "    Installing CPU-only PyTorch (no CUDA — saves ~5GB)."
echo "    Requires internet. May take 5-10 minutes..."
echo ""

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

# Install CPU-only PyTorch first
"$VENV_DIR/bin/pip" install \
    torch==2.10.0 torchvision==0.25.0 torchaudio==2.10.0 \
    --index-url https://download.pytorch.org/whl/cpu \
    --quiet \
    --progress-bar on

# Install remaining requirements
# Skip only the 3 torch packages already installed above
grep -vE "^torch==|^torchaudio==|^torchvision==" \
    "$INSTALL_DIR/app/requirements.txt" > /tmp/gs_reqs.txt
"$VENV_DIR/bin/pip" install \
    --requirement /tmp/gs_reqs.txt \
    --quiet \
    --progress-bar on
rm -f /tmp/gs_reqs.txt

echo ""
echo "Python environment ready."

# ── Create launcher ──────────────────────────────────────
echo "[5/6] Creating launcher..."

cat > "$LAUNCHER" << 'LAUNCH_EOF'
#!/usr/bin/env bash
INSTALL_DIR="/opt/GRAPHSENTINEL"
APP_DIR="$INSTALL_DIR/app"
VENV_PYTHON="$INSTALL_DIR/venv/bin/python"

export PATH="$APP_DIR:$PATH"
export PYTHONPATH=""

cd "$APP_DIR"
exec "$VENV_PYTHON" gui.py
LAUNCH_EOF

chmod +x "$LAUNCHER"

# ── Desktop entry + icon ─────────────────────────────────
echo "[6/6] Creating desktop entry..."
mkdir -p "$DESKTOP_DIR"
mkdir -p "$ICON_DIR"

cat > "$ICON_DIR/graphsentinel.svg" << 'SVG_EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" rx="18" fill="#0a0a0a"/>
  <circle cx="50" cy="45" r="28" fill="none"
          stroke="#00e5ff" stroke-width="4"/>
  <line x1="50" y1="45" x2="73" y2="28"
        stroke="#ffffff" stroke-width="2.5"
        stroke-linecap="round"/>
  <circle cx="50" cy="45" r="4" fill="#00e5ff"/>
  <text x="50" y="88" font-family="monospace" font-size="9"
        fill="#00e5ff" text-anchor="middle"
        letter-spacing="1">GRAPHSENTINEL</text>
</svg>
SVG_EOF

cat > "$DESKTOP_DIR/graphsentinel.desktop" << DESKTOP_EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=GRAPHSENTINEL
Comment=Intelligent System-Centric Zero-Day Threat Detection Framework
Exec=$LAUNCHER
Icon=$ICON_DIR/graphsentinel.svg
Terminal=false
Categories=Development;Security;
Keywords=vulnerability;security;static analysis;zero-day;
StartupNotify=true
DESKTOP_EOF

chmod +x "$DESKTOP_DIR/graphsentinel.desktop"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Installation Complete!                                      ║"
echo "║                                                              ║"
echo "║  Launch GRAPHSENTINEL from:                                  ║"
echo "║  • Application menu → GRAPHSENTINEL                         ║"
echo "║  • Terminal: /opt/GRAPHSENTINEL/graphsentinel.sh             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
INSTALL_EOF

chmod +x "$STAGING/install.sh"

# ── Check staging size ───────────────────────────────────
echo ""
echo "Staging area size:"
du -sh "$STAGING"
echo ""

# ── Build .run ───────────────────────────────────────────
echo "[7/7] Building self-extracting installer..."
echo "      (compressing — be patient)"

export TMPDIR="$PROJECT_DIR/tmp_makeself"
mkdir -p "$TMPDIR"

TMPDIR="$PROJECT_DIR/tmp_makeself" makeself \
    --gzip \
    --nomd5 \
    "$STAGING" \
    "$PROJECT_DIR/GRAPHSENTINEL_Installer.run" \
    "GRAPHSENTINEL — Zero-Day Threat Detection" \
    "./install.sh"

# Cleanup
rm -rf "$TMPDIR"
rm -rf "$STAGING"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Build Complete!                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Output:"
du -sh "$PROJECT_DIR/GRAPHSENTINEL_Installer.run"
echo ""
echo "To install:"
echo "  chmod +x GRAPHSENTINEL_Installer.run"
echo "  ./GRAPHSENTINEL_Installer.run"
echo ""
echo "To uninstall:"
echo "  sudo rm -rf /opt/GRAPHSENTINEL"
echo "  rm -f ~/.local/share/applications/graphsentinel.desktop"
echo "  rm -f ~/.local/share/icons/graphsentinel.svg"
echo ""