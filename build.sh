#!/usr/bin/env bash
# build.sh — builds GRAPHSENTINEL.deb installer package
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
JOERN_SRC="/home/feanor/bin/joern/joern-cli"
PKG_NAME="graphsentinel"
PKG_VERSION="1.0"
PKG_ARCH="amd64"
DEB_DIR="$PROJECT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"
INSTALL_DIR="$DEB_DIR/opt/GRAPHSENTINEL"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     GRAPHSENTINEL — .deb Package Builder                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Project : $PROJECT_DIR"
echo "Package : $DEB_DIR"
echo ""

# ── Check dpkg-deb is available ──────────────────────────
if ! command -v dpkg-deb &>/dev/null; then
    echo "Installing dpkg-deb..."
    sudo apt-get install -y dpkg
fi

# ── Clean previous build ─────────────────────────────────
echo "[1/9] Cleaning previous build..."
rm -rf "$DEB_DIR"
rm -f "$PROJECT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

# ── Create .deb directory structure ──────────────────────
echo "[2/9] Creating package structure..."
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$INSTALL_DIR/app"
mkdir -p "$INSTALL_DIR/app/workspace/graphs"
mkdir -p "$INSTALL_DIR/app/workspace/scan_logs"
mkdir -p "$INSTALL_DIR/app/data/safe"
mkdir -p "$INSTALL_DIR/app/embeddings"
mkdir -p "$DEB_DIR/usr/share/applications"
mkdir -p "$DEB_DIR/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$DEB_DIR/usr/local/bin"

# ── Copy Python source files ─────────────────────────────
echo "[3/9] Copying Python source..."
cp "$PROJECT_DIR/gui.py"                 "$INSTALL_DIR/app/"
cp "$PROJECT_DIR/main.py"                "$INSTALL_DIR/app/"
cp "$PROJECT_DIR/prep_word2vec.py"       "$INSTALL_DIR/app/"
cp "$PROJECT_DIR/extract_juliet_safe.py" "$INSTALL_DIR/app/"
cp "$PROJECT_DIR/requirements.txt"       "$INSTALL_DIR/app/"

for dir in dataset model trainer detector parser_pipeline; do
    cp -r "$PROJECT_DIR/$dir" "$INSTALL_DIR/app/$dir"
done

# ── Copy embeddings ──────────────────────────────────────
echo "[4/9] Copying Word2Vec embeddings..."
cp -r "$PROJECT_DIR/embeddings/." "$INSTALL_DIR/app/embeddings/"

# ── Copy workspace artifacts ─────────────────────────────
echo "[5/9] Copying workspace artifacts..."
for f in model.pt threshold.txt threshold_stats.json \
          gui_config.json training_history.json; do
    [ -f "$PROJECT_DIR/workspace/$f" ] && \
        cp "$PROJECT_DIR/workspace/$f" "$INSTALL_DIR/app/workspace/"
done

echo "    Copying graphs (may take a moment)..."
cp -r "$PROJECT_DIR/workspace/graphs/." "$INSTALL_DIR/app/workspace/graphs/"

echo "    Copying safe dataset..."
cp -r "$PROJECT_DIR/data/safe/." "$INSTALL_DIR/app/data/safe/"

# ── Bundle Joern ─────────────────────────────────────────
echo "[6/9] Bundling Joern CLI..."
cp -r "$JOERN_SRC" "$INSTALL_DIR/app/joern-cli"

# ── Create Joern wrapper scripts ─────────────────────────
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
chmod +x "$INSTALL_DIR/app/joern-cli/"*

# ── Create launcher script ────────────────────────────────
echo "[7/9] Creating launcher..."

cat > "$INSTALL_DIR/graphsentinel.sh" << 'LAUNCH_EOF'
#!/usr/bin/env bash
INSTALL_DIR="/opt/GRAPHSENTINEL"
APP_DIR="$INSTALL_DIR/app"
VENV_PYTHON="$INSTALL_DIR/venv/bin/python"

export PATH="$APP_DIR:$PATH"

cd "$APP_DIR"
exec "$VENV_PYTHON" gui.py
LAUNCH_EOF

chmod +x "$INSTALL_DIR/graphsentinel.sh"

# Symlink so 'graphsentinel' works from terminal
ln -sf "/opt/GRAPHSENTINEL/graphsentinel.sh" \
       "$DEB_DIR/usr/local/bin/graphsentinel"

# ── Create SVG icon ───────────────────────────────────────
cat > "$DEB_DIR/usr/share/icons/hicolor/scalable/apps/graphsentinel.svg" << 'SVG_EOF'
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

# ── Create .desktop entry ─────────────────────────────────
cat > "$DEB_DIR/usr/share/applications/graphsentinel.desktop" << 'DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=GRAPHSENTINEL
GenericName=Vulnerability Detector
Comment=Intelligent System-Centric Zero-Day Threat Detection Framework
Exec=/opt/GRAPHSENTINEL/graphsentinel.sh
Icon=graphsentinel
Terminal=false
Categories=Development;Security;
Keywords=vulnerability;security;static analysis;zero-day;
StartupNotify=true
DESKTOP_EOF

# ── Write DEBIAN/control ──────────────────────────────────
echo "[8/9] Writing package metadata..."

cat > "$DEB_DIR/DEBIAN/control" << CONTROL_EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $PKG_ARCH
Maintainer: GRAPHSENTINEL <graphsentinel@localhost>
Depends: default-jre, python3, python3-pip, python3-venv, python3-pyqt5
Section: security
Priority: optional
Description: Intelligent System-Centric Zero-Day Threat Detection Framework
 GRAPHSENTINEL is an AI-driven static vulnerability detection system
 for C/C++ code that detects zero-day vulnerabilities using graph
 anomaly detection and relational graph neural networks.
CONTROL_EOF

# ── Write DEBIAN/postinst (runs after package install) ────
cat > "$DEB_DIR/DEBIAN/postinst" << 'POSTINST_EOF'
#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/GRAPHSENTINEL"
VENV_DIR="$INSTALL_DIR/venv"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GRAPHSENTINEL — Post-Install Setup                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Determine the real user (not root)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"

# Fix ownership so user can write to workspace
chown -R "$REAL_USER":"$REAL_USER" "$INSTALL_DIR" 2>/dev/null || true

# Fix Joern execute permissions (dpkg strips +x from bundled files)
find "$INSTALL_DIR/app/joern-cli" -type f | xargs chmod +x
chmod +x "$INSTALL_DIR/app/joern-parse"
chmod +x "$INSTALL_DIR/app/joern-export"

echo "Setting up Python virtual environment..."
echo "Requires internet. May take 5-10 minutes."
echo ""

sudo -u "$REAL_USER" python3 -m venv "$VENV_DIR"
# Install CPU-only PyTorch first (saves ~5GB vs CUDA version)
sudo -u "$REAL_USER" "$VENV_DIR/bin/pip" install \
    torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cpu \
    --quiet \
    --progress-bar on

# Then install remaining requirements (skip torch lines)
grep -v "^torch" "$INSTALL_DIR/app/requirements.txt" > /tmp/gs_reqs.txt
sudo -u "$REAL_USER" "$VENV_DIR/bin/pip" install \
    --requirement /tmp/gs_reqs.txt \
    --quiet \
    --progress-bar on
rm -f /tmp/gs_reqs.txt

# Update icon and desktop caches
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Installation Complete!                                      ║"
echo "║                                                              ║"
echo "║  Launch GRAPHSENTINEL from:                                  ║"
echo "║  • Application menu → GRAPHSENTINEL                         ║"
echo "║  • Terminal: graphsentinel                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
POSTINST_EOF

chmod 755 "$DEB_DIR/DEBIAN/postinst"

# ── Write DEBIAN/prerm (runs before uninstall) ────────────
cat > "$DEB_DIR/DEBIAN/prerm" << 'PRERM_EOF'
#!/usr/bin/env bash
set -e
echo "Removing GRAPHSENTINEL..."
rm -rf /opt/GRAPHSENTINEL
PRERM_EOF

chmod 755 "$DEB_DIR/DEBIAN/prerm"

# ── Set correct permissions ───────────────────────────────
echo "[9/9] Setting permissions and building .deb..."
find "$DEB_DIR" -type f | xargs chmod 644
find "$DEB_DIR" -type d | xargs chmod 755

# Restore execute bits
chmod 755 "$INSTALL_DIR/graphsentinel.sh"
chmod 755 "$INSTALL_DIR/app/joern-parse"
chmod 755 "$INSTALL_DIR/app/joern-export"
chmod 755 "$INSTALL_DIR/app/joern-cli/"*
chmod 755 "$DEB_DIR/DEBIAN/postinst"
chmod 755 "$DEB_DIR/DEBIAN/prerm"
# chmod 755 "$DEB_DIR/usr/local/bin/graphsentinel"

# ── Build the .deb ────────────────────────────────────────
dpkg-deb --build --root-owner-group "$DEB_DIR" \
    "$PROJECT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

# ── Cleanup build directory ───────────────────────────────
rm -rf "$DEB_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Build Complete!                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Output:"
du -sh "$PROJECT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
echo ""
echo "To install — just double-click the .deb file!"
echo "OR from terminal:"
echo "  sudo dpkg -i graphsentinel_1.0_amd64.deb"
echo ""
echo "To uninstall:"
echo "  sudo apt remove graphsentinel"
echo ""