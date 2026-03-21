#!/usr/bin/env python3
"""
GRAPHSENTINEL — AI-Driven Zero-Day C/C++ Vulnerability Detector
Single-window PyQt5 GUI Application
"""

import sys
import os
import json
import math
import re
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, QLabel,
    QTextEdit, QScrollArea, QFileDialog, QSlider,
    QSpinBox, QDoubleSpinBox, QFrame, QSizePolicy,
    QMessageBox, QListWidget, QDialog
)

from PyQt5.QtCore import Qt, QTimer, QProcess, pyqtSignal, QRectF, QPointF
from PyQt5.QtCore import QProcessEnvironment

from PyQt5.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QPalette
)

# ═══════════════════════════════════════════════════════════
# THEME
# ═══════════════════════════════════════════════════════════
BG        = "#0a0a0a"
CARD      = "#111111"
CARD2     = "#161616"
BORDER    = "#ffffff"
BORDER2   = "#2a2a2a"
TEXT      = "#ffffff"
DIM       = "#555555"
ACCENT    = "#00e5ff"
SAFE_C    = "#00e676"
PARTIAL_C = "#ffea00"
VULN_C    = "#ff6d00"
CRIT_C    = "#ff1744"

# Resolve paths relative to gui.py location so it works both
# in development and when installed to /opt/GRAPHSENTINEL/app
APP_DIR     = os.path.dirname(os.path.abspath(__file__))
WORKSPACE   = os.path.join(APP_DIR, "workspace")
VENV_PYTHON = os.path.join(os.path.dirname(APP_DIR), "venv", "bin", "python")
# Fall back to sys.executable if venv python not found
if not os.path.exists(VENV_PYTHON):
    VENV_PYTHON = sys.executable
LOG_DIR     = os.path.join(WORKSPACE, "scan_logs")
CONFIG_PATH = os.path.join(WORKSPACE, "gui_config.json")
STATS_PATH  = os.path.join(WORKSPACE, "threshold_stats.json")

DEFAULT_CONFIG = {
    "threshold_percentile": 90,
    "max_files_per_cwe": 100,
    "epochs": 50,
    "batch_size": 16,
    "alpha": 0.2,
    "beta": 0.2,
    "gamma": 0.3,
    "delta": 0.3
}

STYLE = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: 'Segoe UI', 'Ubuntu', 'Cantarell', sans-serif;
    font-size: 13px;
}}
QFrame#card {{
    background-color: {CARD};
    border: 1px solid {BORDER2};
    border-radius: 4px;
}}
QPushButton {{
    background-color: transparent;
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 3px;
    padding: 8px 16px;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: rgba(255,255,255,0.07);
}}
QPushButton:pressed {{
    background-color: rgba(255,255,255,0.14);
}}
QPushButton:disabled {{
    color: {DIM};
    border-color: {DIM};
}}
QPushButton#accent {{
    border-color: {ACCENT};
    color: {ACCENT};
}}
QPushButton#accent:hover {{
    background-color: rgba(0,229,255,0.08);
}}
QPushButton#exit_btn {{
    border-color: {CRIT_C};
    color: {CRIT_C};
    font-size: 11px;
    padding: 5px 10px;
}}
QScrollBar:vertical {{
    background: {CARD};
    width: 5px;
    border-radius: 2px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {DIM};
    border-radius: 2px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
QScrollBar:horizontal {{
    background: {CARD};
    height: 5px;
    border-radius: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {DIM};
    border-radius: 2px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}
QTextEdit {{
    background-color: {CARD2};
    color: {TEXT};
    border: 1px solid {BORDER2};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    padding: 8px;
    border-radius: 3px;
}}
QLabel#header_title {{
    font-size: 22px;
    font-weight: bold;
    color: {ACCENT};
    letter-spacing: 4px;
}}
QLabel#section_title {{
    font-size: 14px;
    font-weight: bold;
    color: {TEXT};
    letter-spacing: 1px;
    margin-top: 2px;
}}
QSlider::groove:horizontal {{
    background: {CARD2};
    border: 1px solid {BORDER2};
    height: 4px;
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {ACCENT};
    border: none;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}
QSlider::sub-page:horizontal {{
    background: {ACCENT};
    border-radius: 2px;
}}
QSpinBox, QDoubleSpinBox {{
    background-color: {CARD2};
    color: {TEXT};
    border: 1px solid {BORDER2};
    padding: 4px 6px;
    border-radius: 3px;
}}
QListWidget {{
    background: {CARD};
    border: 1px solid {BORDER2};
    color: {TEXT};
    font-size: 12px;
    border-radius: 3px;
    outline: none;
}}
QListWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {BORDER2}; }}
QListWidget::item:selected {{ background: rgba(0,229,255,0.12); color: {ACCENT}; }}
QListWidget::item:hover {{ background: rgba(255,255,255,0.04); }}
"""

# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def load_stats():
    if os.path.exists(STATS_PATH):
        try:
            with open(STATS_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {"threshold": 0.05, "mean": 0.02, "std": 0.01}

def save_stats(stats):
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

def count_graphs():
    gdir = os.path.join(WORKSPACE, "graphs")
    if os.path.exists(gdir):
        return len([f for f in os.listdir(gdir) if f.endswith(".json")])
    return 0

def severity_to_key(sev: str) -> str:
    s = sev.strip().upper()
    if "CRITICAL" in s:
        return "critical"
    if "PARTIALLY" in s or "PARTIAL" in s:
        return "partial"
    if "VULNERABLE" in s:
        return "vulnerable"
    return "safe"

def severity_color(key: str) -> str:
    return {
        "safe": SAFE_C, "partial": PARTIAL_C,
        "vulnerable": VULN_C, "critical": CRIT_C
    }.get(key, SAFE_C)

def normalize_score(score: float, threshold: float, margin: float) -> float:
    max_val = threshold + 3 * margin
    if max_val <= 0:
        return 0.0
    return min(1.0, max(0.0, score / max_val))

def parse_detect_output(text: str, stats: dict) -> dict:
    result = {
        "threshold": stats.get("threshold", 0.05),
        "margin": stats.get("std", 0.01),
        "graphs": [],
        "overall_severity": "safe",
        "target_file": "",
        "raw_output": text
    }
    for line in text.splitlines():
        ls = line.strip()
        if ls.startswith("Target File:"):
            result["target_file"] = ls.split(":", 1)[1].strip()
        elif ls.startswith("Threshold:"):
            try:
                result["threshold"] = float(ls.split(":", 1)[1].strip())
            except Exception:
                pass
        elif ls.startswith("Margin"):
            try:
                result["margin"] = float(ls.split(":", 1)[1].strip())
            except Exception:
                pass
        elif re.match(r"graph_\d+\.json", ls):
            parts = [p.strip() for p in ls.split("|")]
            if len(parts) >= 4:
                score, line_num = 0.0, -1
                try:
                    score = float(parts[2].split("=")[1])
                except Exception:
                    pass
                try:
                    line_num = int(parts[3].split("=")[1])
                except Exception:
                    pass
                sev_key = severity_to_key(parts[1])
                result["graphs"].append({
                    "name": parts[0],
                    "severity": sev_key,
                    "severity_label": parts[1],
                    "score": score,
                    "line": line_num
                })
    if result["graphs"]:
        for s in ["critical", "vulnerable", "partial", "safe"]:
            if any(g["severity"] == s for g in result["graphs"]):
                result["overall_severity"] = s
                break
    return result

# ═══════════════════════════════════════════════════════════
# WIDGETS
# ═══════════════════════════════════════════════════════════
class HSep(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.HLine)
        self.setFixedHeight(1)
        self.setStyleSheet(f"background: {BORDER2}; border: none;")

class AngularGauge(QWidget):
    START_DEG = 225.0
    SWEEP_DEG = 270.0

    RAINBOW = [
        (0.00, QColor("#00e676")),
        (0.25, QColor("#aeea00")),
        (0.50, QColor("#ffea00")),
        (0.75, QColor("#ff6d00")),
        (1.00, QColor("#ff1744")),
    ]

    def __init__(self, label="", size="small", parent=None):
        super().__init__(parent)
        self._value       = 0.0
        self._target      = 0.0
        self._active      = False
        self._severity    = "safe"
        self._label       = label
        self._score_text  = "—"
        self._state_text  = ""
        self._confidence  = 0.0   # 0–100 float

        self._anim = QTimer(self)
        self._anim.timeout.connect(self._step)

        if size == "large":
            self.setMinimumSize(170, 220)
            self.setMaximumSize(220, 270)
        else:
            self.setMinimumSize(105, 150)
            self.setMaximumSize(140, 178)

        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)

    def activate(self, score: float, severity: str,
                 threshold: float, margin: float):
        self._active    = True
        self._severity  = severity
        self._score_text = f"{score:.4f}"
        self._state_text = {
            "safe":       "SAFE",
            "partial":    "PART. VULN",
            "vulnerable": "VULNERABLE",
            "critical":   "CRITICAL",
        }.get(severity, "SAFE")

        self._target = normalize_score(score, threshold, margin)

        # Confidence: how far past the safe mean the score is,
        # expressed as 0–100%.
        # 0%   = score at or below (threshold - margin)  → clearly safe
        # 50%  = score exactly at threshold              → boundary
        # 100% = score at threshold + margin or beyond   → confirmed anomaly
        low  = max(0.0, threshold - margin)
        high = threshold + margin
        if high <= low:
            self._confidence = 0.0
        else:
            self._confidence = min(100.0, max(0.0,
                (score - low) / (high - low) * 100.0))

        self._anim.start(16)

    def reset(self):
        self._active     = False
        self._value      = 0.0
        self._target     = 0.0
        self._score_text = "—"
        self._state_text = ""
        self._severity   = "safe"
        self._confidence = 0.0
        self._anim.stop()
        self.update()

    def set_label(self, label: str):
        self._label = label
        self.update()

    def _step(self):
        diff = self._target - self._value
        if abs(diff) < 0.004:
            self._value = self._target
            self._anim.stop()
        else:
            self._value += diff * 0.10
        self.update()

    def _rainbow_color(self, t: float) -> QColor:
        t = max(0.0, min(1.0, t))
        stops = self.RAINBOW
        for i in range(len(stops) - 1):
            t0, c0 = stops[i]
            t1, c1 = stops[i + 1]
            if t0 <= t <= t1:
                f = (t - t0) / (t1 - t0)
                r = int(c0.red()   + f * (c1.red()   - c0.red()))
                g = int(c0.green() + f * (c1.green() - c0.green()))
                b = int(c0.blue()  + f * (c1.blue()  - c0.blue()))
                return QColor(r, g, b)
        return stops[-1][1]

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h  = self.width(), self.height()
        pad   = 10
        cx    = w / 2
        cy    = h * 0.44
        r     = min(w - pad * 2, cy - pad) * 0.80
        arc_w = max(6, r * 0.18)

        rect = QRectF(cx - r, cy - r, r * 2, r * 2)

        # ── Background arc ──────────────────────────────
        bg_pen = QPen(QColor("#1e1e1e") if self._active else QColor("#181818"))
        bg_pen.setWidthF(arc_w)
        bg_pen.setCapStyle(Qt.FlatCap)
        p.setPen(bg_pen)
        p.drawArc(rect,
                  int(self.START_DEG * 16),
                  int(-self.SWEEP_DEG * 16))

        # ── Rainbow arc ─────────────────────────────────
        if self._active:
            segments = 120
            for i in range(segments):
                t_start = i       / segments
                t_end   = (i + 1) / segments
                t_mid   = (t_start + t_end) / 2.0
                if t_mid > self._value:
                    break
                col     = self._rainbow_color(t_mid)
                seg_pen = QPen(col)
                seg_pen.setWidthF(arc_w)
                seg_pen.setCapStyle(Qt.FlatCap)
                p.setPen(seg_pen)
                a_start = self.START_DEG - t_start * self.SWEEP_DEG
                a_span  = -(t_end - t_start) * self.SWEEP_DEG
                p.drawArc(rect,
                          int(a_start * 16),
                          int(a_span  * 16))

        # ── Tick marks ──────────────────────────────────
        for i in range(11):
            ang   = math.radians(self.START_DEG - (i / 10.0) * self.SWEEP_DEG)
            outer = r * 0.88
            inner = r * 0.76 if i % 5 == 0 else r * 0.82
            tp    = QPen(QColor(50, 50, 50))
            tp.setWidthF(1.5 if i % 5 == 0 else 0.8)
            p.setPen(tp)
            p.drawLine(
                QPointF(cx + outer * math.cos(ang), cy - outer * math.sin(ang)),
                QPointF(cx + inner * math.cos(ang), cy - inner * math.sin(ang))
            )

        # ── Needle ──────────────────────────────────────
        ang        = math.radians(self.START_DEG - self._value * self.SWEEP_DEG)
        needle_len = r * 0.74
        nx = cx + needle_len * math.cos(ang)
        ny = cy - needle_len * math.sin(ang)
        np_ = QPen(QColor("#ffffff") if self._active else QColor(DIM))
        np_.setWidthF(1.2)
        np_.setCapStyle(Qt.RoundCap)
        p.setPen(np_)
        p.drawLine(QPointF(cx, cy), QPointF(nx, ny))

        # Center pin
        p.setPen(Qt.NoPen)
        pin_col = self._rainbow_color(self._value) if self._active else QColor(DIM)
        p.setBrush(QBrush(pin_col))
        cap_r = max(3, r * 0.07)
        p.drawEllipse(QPointF(cx, cy), cap_r, cap_r)

        # ── Confidence % (large, center below arc) ───────
        text_top = cy + r * 0.18

        if self._active:
            # Animated confidence — interpolate from 0 to final
            animated_conf = self._value * self._confidence / max(self._target, 0.001) \
                            if self._target > 0.001 else 0.0
            animated_conf = min(self._confidence, animated_conf)
            conf_str = f"{animated_conf:.0f}%"
        else:
            conf_str = "—"

        cf = QFont("Consolas", max(7, int(r * 0.19)), QFont.Bold)
        p.setFont(cf)
        p.setPen(QPen(QColor("#ffffff")))
        p.drawText(
            QRectF(0, text_top, w, r * 0.36),
            Qt.AlignCenter, conf_str
        )

        # ── Raw score (smaller, below confidence) ────────
        sf = QFont("Consolas", max(6, int(r * 0.16)))
        p.setFont(sf)
        p.setPen(QPen(QColor(DIM)))
        p.drawText(
            QRectF(0, text_top + r * 0.34, w, r * 0.26),
            Qt.AlignCenter, self._score_text
        )

        # ── State text ───────────────────────────────────
        if self._active and self._state_text:
            stf = QFont("Segoe UI", max(6, int(r * 0.155)))
            p.setFont(stf)
            p.setPen(QPen(QColor(ACCENT)))
            p.drawText(
                QRectF(0, text_top + r * 0.58, w, r * 0.28),
                Qt.AlignCenter, self._state_text
            )

# ── Graph label ──────────────────────────────────────────────────────
        lf = QFont("Segoe UI", max(8, int(r * 0.20)), QFont.Bold)
        p.setFont(lf)
        p.setPen(QPen(QColor("#ffffff")))
        p.drawText(QRectF(0, h - 26, w, 24), Qt.AlignCenter, self._label)

# ═══════════════════════════════════════════════════════════
# LOSS CHART WIDGET
# ═══════════════════════════════════════════════════════════
class LossChartWidget(QWidget):
    """Custom painted multi-line loss curve chart."""

    LINES = [
        ("train_loss", TEXT,      "Total Train"),
        ("val_loss",   ACCENT,    "Validation"),
        ("feat_loss",  SAFE_C,    "Feature"),
        ("ast_loss",   PARTIAL_C, "AST"),
        ("cfg_loss",   VULN_C,    "CFG"),
        ("dfg_loss",   CRIT_C,    "DFG"),
    ]

    def __init__(self, history: dict, parent=None):
        super().__init__(parent)
        self._history  = history
        self._visible  = {k: True for k, _, _ in self.LINES}
        self._anim_t   = 0.0
        self._timer    = QTimer(self)
        self._timer.timeout.connect(self._step)
        self.setMinimumSize(500, 280)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_history(self, history: dict):
        self._history = history
        self._anim_t  = 0.0
        self._timer.start(16)

    def toggle_line(self, key: str):
        self._visible[key] = not self._visible.get(key, True)
        self.update()

    def start_animation(self):
        self._anim_t = 0.0
        self._timer.start(16)

    def _step(self):
        self._anim_t += 0.03
        if self._anim_t >= 1.0:
            self._anim_t = 1.0
            self._timer.stop()
        self.update()

    def paintEvent(self, _):
        if not self._history:
            return

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h   = self.width(), self.height()
        pad_l  = 58
        pad_r  = 20
        pad_t  = 20
        pad_b  = 36
        cw     = w - pad_l - pad_r
        ch     = h - pad_t - pad_b

        epochs = self._history.get("epochs", [])
        if not epochs:
            return

        # Find global min/max across visible lines
        all_vals = []
        for key, _, _ in self.LINES:
            if self._visible.get(key, True):
                all_vals.extend(self._history.get(key, []))

        if not all_vals:
            return

        y_min = min(all_vals) * 0.9
        y_max = max(all_vals) * 1.1
        y_range = max(y_max - y_min, 1e-8)
        x_range = max(len(epochs) - 1, 1)

        def to_xy(ep_idx, val):
            prog = min(ep_idx / x_range, self._anim_t)
            px   = pad_l + prog * cw
            py   = pad_t + ch - ((val - y_min) / y_range) * ch
            return QPointF(px, py)

        # ── Grid ─────────────────────────────────────
        grid_pen = QPen(QColor("#181818"))
        grid_pen.setWidthF(1.0)
        for i in range(5):
            gy  = pad_t + (i / 4) * ch
            gv  = y_max - (i / 4) * y_range
            p.setPen(grid_pen)
            p.drawLine(QPointF(pad_l, gy), QPointF(pad_l + cw, gy))
            lf = QFont("Consolas", 8)
            p.setFont(lf)
            p.setPen(QPen(QColor(DIM)))
            p.drawText(
                QRectF(0, gy - 8, pad_l - 4, 16),
                Qt.AlignRight | Qt.AlignVCenter,
                f"{gv:.4f}"
            )

        # ── X axis labels ────────────────────────────
        n_ticks = min(10, len(epochs))
        for i in range(n_ticks + 1):
            ep_idx = int(i / n_ticks * (len(epochs) - 1))
            px     = pad_l + (ep_idx / x_range) * cw
            p.setPen(QPen(QColor(DIM)))
            lf = QFont("Consolas", 8)
            p.setFont(lf)
            p.drawText(
                QRectF(px - 16, pad_t + ch + 4, 32, 20),
                Qt.AlignCenter,
                str(epochs[ep_idx])
            )

        # ── Axes ─────────────────────────────────────
        ax_pen = QPen(QColor("#2e2e2e"))
        ax_pen.setWidthF(1.5)
        p.setPen(ax_pen)
        p.drawLine(QPointF(pad_l, pad_t),
                   QPointF(pad_l, pad_t + ch))
        p.drawLine(QPointF(pad_l, pad_t + ch),
                   QPointF(pad_l + cw, pad_t + ch))

        # ── Lines ────────────────────────────────────
        for key, color, _ in self.LINES:
            if not self._visible.get(key, True):
                continue
            vals = self._history.get(key, [])
            if len(vals) < 2:
                continue

            lp = QPen(QColor(color))
            lp.setWidthF(1.8)
            lp.setCapStyle(Qt.RoundCap)
            lp.setJoinStyle(Qt.RoundJoin)
            p.setPen(lp)

            # Only draw up to animated progress
            max_idx = max(1, int(self._anim_t * (len(vals) - 1)))
            for i in range(min(max_idx, len(vals) - 1)):
                p.drawLine(to_xy(i, vals[i]), to_xy(i + 1, vals[i + 1]))

        # ── X axis title ─────────────────────────────
        p.setPen(QPen(QColor(DIM)))
        lf = QFont("Segoe UI", 9)
        p.setFont(lf)
        p.drawText(
            QRectF(pad_l, pad_t + ch + 20, cw, 14),
            Qt.AlignCenter, "Epoch"
        )

# ═══════════════════════════════════════════════════════════
# MAIN PAGE
# ═══════════════════════════════════════════════════════════
class MainPage(QWidget):
    go_scan      = pyqtSignal()
    go_results   = pyqtSignal()
    go_retrain   = pyqtSignal()
    go_config    = pyqtSignal()
    go_dashboard = pyqtSignal()
    do_exit      = pyqtSignal()

    TILES = [
        (
            "⬡  Scan C / C++ File",
            "Upload and scan a C/C++ file\nor folder for vulnerabilities.",
            "Analyze any C or C++ source file using the trained AI model.\nDetects zero-day vulnerabilities via graph anomaly detection.\nSupports single files and entire folders.",
            "go_scan"
        ),
        (
            "⟳  Retrain AI Model",
            "Retrain the GNN autoencoder\non the safe code dataset.",
            "Retrains the Relational Graph Autoencoder on the Juliet safe\ncode dataset. Use this after changing the dataset or config.\nStreams training output in real time.",
            "go_retrain"
        ),
        (
            "◈  Previous Results",
            "View and copy previously\nsaved scan reports.",
            "Browse all scan logs saved from previous detection runs.\nSelect any log to view its full report and copy the contents.",
            "go_results"
        ),
        (
            "⚙  Configure",
            "Adjust sensitivity, loss weights\nand training parameters.",
            "Tune the anomaly detection threshold, loss weight balance\n(α/β/γ/δ), epochs, batch size and dataset size.\nChanges take effect on the next retrain.",
            "go_config"
        ),
        (
            "📊  Model Dashboard",
            "View loss curves, threshold stats\nand scan log statistics.",
            "Visualize training loss curves per epoch, threshold calibration\ndata, and a breakdown of all previous scan severities.\nHelps track model improvement over time.",
            "go_dashboard"
        ),
    ]

    SIGNALS = ["go_scan", "go_retrain", "go_results", "go_config"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 24)
        root.setSpacing(0)

        # ── Top 1/4 — branding ──────────────────────────
        top = QVBoxLayout()
        top.setSpacing(4)
        title = QLabel("GRAPHSENTINEL")
        title.setObjectName("header_title")
        sub = QLabel("INTELLIGENT SYSTEM-CENTRIC ZERO-DAY THREAT DETECTION FRAMEWORK")
        sub.setStyleSheet(
            f"color: {TEXT}; font-size: 18px; letter-spacing: 3px;")
        top.addWidget(title)
        top.addWidget(sub)
        top.addSpacing(10)
        top.addWidget(HSep())
        root.addLayout(top, 1)          # 1 part out of 4 total → top 1/4

        # ── Bottom 3/4 — 2×2 tile grid ──────────────────
        grid_w = QWidget()
        grid_w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        grid = QGridLayout(grid_w)
        grid.setContentsMargins(0, 16, 0, 0)
        grid.setSpacing(16)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)

        positions = [(0, 0), (0, 1), (1, 0), (1, 1), (2, 0)]
        grid.setRowStretch(2, 1)
        for (row, col), (label, desc, tooltip, sig_name) in zip(
            positions, self.TILES
        ):
            tile = self._make_tile(label, desc, tooltip, sig_name)
            if row == 2 and col == 0:
                # Dashboard tile spans both columns
                grid.addWidget(tile, row, 0, 1, 2)
            else:
                grid.addWidget(tile, row, col)

        root.addWidget(grid_w, 3)       # 3 parts → bottom 3/4
        root.addStretch()

        # ── Exit button bottom-left ──────────────────────
        root.addSpacing(10)
        exit_row = QHBoxLayout()
        eb = QPushButton("✕   Exit")
        eb.setObjectName("exit_btn")
        eb.setFixedSize(100, 30)
        eb.clicked.connect(self.do_exit)
        exit_row.addWidget(eb)
        exit_row.addStretch()
        root.addLayout(exit_row)

    def _make_tile(self, label: str, desc: str, tooltip: str,
                   sig_name: str) -> QPushButton:
        btn = QPushButton()
        btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        btn.setToolTip(tooltip)

        # Custom painted tile — rounded rect, matte grey
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1c1c1c;
                border: 1px solid #2e2e2e;
                border-radius: 14px;
                text-align: left;
                padding: 0px;
            }}
            QPushButton:hover {{
                background-color: #232323;
                border: 1px solid {ACCENT};
            }}
            QPushButton:pressed {{
                background-color: #191919;
                border: 1px solid {ACCENT};
            }}
        """)

        # Tooltip styling (app-wide override is fine here)
        QApplication.instance().setStyleSheet(
            QApplication.instance().styleSheet() +
            f"""
            QToolTip {{
                background-color: #1a1a1a;
                color: {TEXT};
                border: 1px solid {ACCENT};
                padding: 8px 12px;
                font-size: 12px;
                border-radius: 4px;
            }}
            """
        )

        # Inner layout painted on top of the button
        layout = QVBoxLayout(btn)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(8)

        # Label
        lbl = QLabel(label)
        lbl.setStyleSheet(f"""
            color: {TEXT};
            font-size: 15px;
            font-weight: bold;
            letter-spacing: 1px;
            background: transparent;
            border: none;
        """)
        lbl.setAttribute(Qt.WA_TransparentForMouseEvents)

        # Description
        dlbl = QLabel(desc)
        dlbl.setStyleSheet(f"""
            color: {DIM};
            font-size: 11px;
            line-height: 1.5;
            background: transparent;
            border: none;
        """)
        dlbl.setAttribute(Qt.WA_TransparentForMouseEvents)
        dlbl.setWordWrap(True)

        layout.addWidget(lbl)
        layout.addWidget(dlbl)
        layout.addStretch()

        # Wire signal
        sig = getattr(self, sig_name)
        btn.clicked.connect(sig)

        return btn

# ═══════════════════════════════════════════════════════════
# HEAT-MAP DIALOG
# ═══════════════════════════════════════════════════════════
class HeatmapDialog(QDialog):
    """Shows source code with anomaly-score-based line highlighting."""

    def __init__(self, file_path: str, graphs: list,
                 threshold: float, margin: float, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Anomaly Heatmap — {os.path.basename(file_path)}")
        self.setMinimumSize(780, 580)
        self.setStyleSheet(f"QDialog {{ background: {BG}; }}")

        self._file_path = file_path
        self._graphs    = graphs
        self._threshold = threshold
        self._margin    = margin

        # Build line → (score, severity) map from all graphs
        self._line_map  = self._build_line_map()

        self._build_ui()

    def _build_line_map(self) -> dict:
        """Maps line_number → (score, severity) keeping highest score per line."""
        lmap = {}
        for g in self._graphs:
            ln  = g.get("line", -1)
            sc  = g.get("score", 0.0)
            sev = g.get("severity", "safe")
            if ln > 0:
                if ln not in lmap or sc > lmap[ln][0]:
                    lmap[ln] = (sc, sev)
        return lmap

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(10)

        # ── Header ───────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("Anomaly Heatmap")
        title.setStyleSheet(
            f"color: {ACCENT}; font-size: 14px;"
            f" font-weight: bold; letter-spacing: 1px;")
        hdr.addWidget(title)
        hdr.addStretch()

        # Legend
        for sev, label in [
            ("partial",    "Part. Vuln"),
            ("vulnerable", "Vulnerable"),
            ("critical",   "Critical"),
        ]:
            dot = QLabel(f"⬤  {label}")
            dot.setStyleSheet(
                f"color: {severity_color(sev)};"
                f" font-size: 11px; margin-left: 12px;")
            hdr.addWidget(dot)

        root.addLayout(hdr)
        root.addWidget(HSep())

        # ── Stats row ────────────────────────────────────
        flagged = len(self._line_map)
        stats_lbl = QLabel(
            f"File: {self._file_path}    │    "
            f"Flagged lines: {flagged}    │    "
            f"Threshold: {self._threshold:.4f}"
        )
        stats_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        root.addWidget(stats_lbl)

        # ── Code viewer ──────────────────────────────────
        self._viewer = QTextEdit()
        self._viewer.setReadOnly(True)
        self._viewer.setTextInteractionFlags(Qt.NoTextInteraction)
        self._viewer.setStyleSheet(f"""
            QTextEdit {{
                background: #0d0d0d;
                color: {TEXT};
                border: 1px solid #2e2e2e;
                border-radius: 8px;
                font-family: Consolas, monospace;
                font-size: 12px;
                padding: 4px;
                line-height: 1.6;
            }}
        """)
        root.addWidget(self._viewer, 1)

        # ── Bottom buttons ────────────────────────────────
        root.addWidget(HSep())
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid #2e2e2e;
                border-radius: 10px;
                color: {TEXT};
                font-size: 12px;
                padding: 6px 20px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
                color: {ACCENT};
            }}
        """)
        close_btn.setFixedHeight(36)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

        # Load and render code
        self._render_code()

    def _render_code(self):
        """Reads the source file and renders it with HTML line highlights."""
        try:
            with open(self._file_path, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            self._viewer.setPlainText(f"Could not read file:\n{e}")
            return

        # Severity → background color (semi-transparent)
        bg_colors = {
            "partial":    "rgba(255, 234,   0, 0.13)",
            "vulnerable": "rgba(255, 109,   0, 0.18)",
            "critical":   "rgba(255,  23,  68, 0.22)",
        }
        border_colors = {
            "partial":    PARTIAL_C,
            "vulnerable": VULN_C,
            "critical":   CRIT_C,
        }

        html_lines = []
        html_lines.append(f"""
        <style>
            body {{
                background: transparent;
                color: {TEXT};
                font-family: Consolas, monospace;
                font-size: 12px;
                margin: 0; padding: 0;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            td {{ padding: 1px 0px; vertical-align: top; }}
            .ln {{
                color: {DIM};
                text-align: right;
                padding-right: 14px;
                padding-left: 8px;
                user-select: none;
                min-width: 36px;
                border-right: 1px solid #1e1e1e;
            }}
            .code {{ padding-left: 14px; white-space: pre; }}
        </style>
        <body><table>
        """)

        for i, line in enumerate(lines):
            ln       = i + 1
            code_esc = (line.rstrip()
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;"))

            if ln in self._line_map:
                score, sev = self._line_map[ln]
                bg         = bg_colors.get(sev, "transparent")
                border     = border_colors.get(sev, "transparent")
                conf       = min(100, max(0,
                    (score - (self._threshold - self._margin)) /
                    (2 * self._margin + 1e-8) * 100))

                row = f"""
                <tr style="background:{bg};
                            border-left: 3px solid {border};">
                    <td class="ln"
                        style="color:{border}; font-weight:bold;">
                        {ln}
                    </td>
                    <td class="code">{code_esc}</td>
                    <td style="padding-left:12px; padding-right:8px;
                               white-space:nowrap; vertical-align:middle;">
                        <span style="color:{border};
                                     font-size:10px;
                                     font-family:Consolas;">
                            ◀ {conf:.0f}% conf
                        </span>
                    </td>
                </tr>
                """
            else:
                row = f"""
                <tr>
                    <td class="ln">{ln}</td>
                    <td class="code">{code_esc}</td>
                    <td></td>
                </tr>
                """
            html_lines.append(row)

        html_lines.append("</table></body>")
        self._viewer.setHtml("".join(html_lines))

        # Scroll to first flagged line
        if self._line_map:
            first_ln = min(self._line_map.keys())
            cursor   = self._viewer.document().find(f"{first_ln}")
            if not cursor.isNull():
                self._viewer.setTextCursor(cursor)
                self._viewer.ensureCursorVisible()

# ═══════════════════════════════════════════════════════════
# SCAN PAGE
# ═══════════════════════════════════════════════════════════
class ScanPage(QWidget):
    go_back = pyqtSignal()

    RECO = {
        "safe":       "✓  No action required. Code structure appears normal.",
        "partial":    "⚠  Review flagged functions. Minor structural anomalies detected.",
        "vulnerable": "✗  Refactor flagged functions. Dangerous patterns identified.",
        "critical":   "✗✗ Redesign flagged code sections immediately. Critical anomalies found.",
    }

    BTN_STYLE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid #2e2e2e;
            border-radius: 12px;
            color: {TEXT};
            font-size: 13px;
        }}
        QPushButton:hover {{
            background-color: #232323;
            border: 1px solid {ACCENT};
            color: {ACCENT};
        }}
        QPushButton:pressed {{
            background-color: #191919;
        }}
        QPushButton:disabled {{
            color: {DIM};
            border-color: #1e1e1e;
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_list   = []
        self._file_idx    = 0
        self._results     = []
        self._log_text    = ""
        self._scanning    = False
        self._scan_proc   = None
        self._cur_output  = []
        self._scan_idx    = 0
        self._all_outputs = []
        self._stats       = load_stats()
        self._generation  = 0
        self._build_ui()

    # ── UI BUILD ────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 20, 14)
        root.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        hv  = QVBoxLayout(); hv.setSpacing(2)
        hv.addWidget(self._lbl("GRAPHSENTINEL", "header_title"))
        hv.addWidget(self._lbl("Scan C / C++ File", "section_title"))
        hdr.addLayout(hv); hdr.addStretch()
        root.addLayout(hdr)
        root.addWidget(HSep())
        root.addSpacing(6)

        # ── Upload row ──────────────────────────────────
        upload_row = QHBoxLayout()
        upload_row.setSpacing(12)

        self._upload_btn = QPushButton("⬆   Upload C File\nor Folder")
        self._upload_btn.setStyleSheet(self.BTN_STYLE)
        self._upload_btn.setFixedSize(180, 62)
        self._upload_btn.clicked.connect(self._on_upload)
        upload_row.addWidget(self._upload_btn)

        # File info (shown after upload, replaces button)
        self._file_info_w = QFrame()
        self._file_info_w.setStyleSheet(
            f"QFrame {{ background: #1c1c1c; border: 1px solid {ACCENT};"
            f" border-radius: 12px; }}")
        self._file_info_w.setFixedSize(180, 62)
        fi_l = QVBoxLayout(self._file_info_w)
        fi_l.setContentsMargins(12, 6, 12, 6); fi_l.setSpacing(2)
        self._fname_lbl = QLabel("—")
        self._fname_lbl.setStyleSheet(
            f"color: {TEXT}; font-size: 12px; font-weight: bold; border: none;")
        self._fpath_lbl = QLabel("—")
        self._fpath_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 9px; border: none;")
        fi_l.addWidget(self._fname_lbl)
        fi_l.addWidget(self._fpath_lbl)
        self._file_info_w.hide()
        upload_row.addWidget(self._file_info_w)

        self._scan_btn = QPushButton("▶  Scan")
        self._scan_btn.setStyleSheet(self.BTN_STYLE.replace(
            "#1c1c1c", "#151515").replace("#2e2e2e", ACCENT).replace(
            f"color: {TEXT}", f"color: {ACCENT}"))
        self._scan_btn.setFixedSize(100, 62)
        self._scan_btn.hide()
        self._scan_btn.clicked.connect(self._on_scan)
        upload_row.addWidget(self._scan_btn)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet(f"color: {DIM}; font-size: 11px;")
        upload_row.addWidget(self._status_lbl)
        upload_row.addStretch()

        # Folder nav arrows
        self._nav_w = QWidget(); nav_r = QHBoxLayout(self._nav_w)
        nav_r.setContentsMargins(0,0,0,0); nav_r.setSpacing(6)
        self._prev_btn = QPushButton("◀"); self._next_btn = QPushButton("▶")
        self._file_counter = QLabel("1 / 1")
        self._file_counter.setStyleSheet(f"color: {DIM}; font-size: 11px;")
        self._file_counter.setAlignment(Qt.AlignCenter)
        for b in [self._prev_btn, self._next_btn]:
            b.setStyleSheet(self.BTN_STYLE)
            b.setFixedSize(32, 32)
        self._prev_btn.clicked.connect(self._on_prev)
        self._next_btn.clicked.connect(self._on_next)
        nav_r.addWidget(self._prev_btn)
        nav_r.addWidget(self._file_counter)
        nav_r.addWidget(self._next_btn)
        self._nav_w.hide()
        upload_row.addWidget(self._nav_w)

        root.addLayout(upload_row)
        root.addSpacing(4)

        # ── Main 3-column area ──────────────────────────
        cols = QHBoxLayout()
        cols.setSpacing(12)

        # LEFT 1/4 — text summary ─────────────────────────
        left_f = QFrame(); left_f.setObjectName("card")
        lfl    = QVBoxLayout(left_f)
        lfl.setContentsMargins(10, 10, 10, 10); lfl.setSpacing(6)
        sum_lbl = QLabel("File Summary")
        sum_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        lfl.addWidget(sum_lbl); lfl.addWidget(HSep())

        self._summary = QTextEdit()
        self._summary.setReadOnly(True)
        self._summary.setTextInteractionFlags(Qt.NoTextInteraction)
        self._summary.setPlaceholderText("Analysis summary will\nappear after scanning…")
        self._summary.setStyleSheet(
            f"QTextEdit {{ background: transparent; border: none;"
            f" color: {TEXT}; font-size: 11px; font-family: Consolas; }}")
        lfl.addWidget(self._summary)
        cols.addWidget(left_f, 1)            # 1/4 width

        # MIDDLE 1/4 — overall gauge + recommendation ──────
        mid_f = QFrame(); mid_f.setObjectName("card")
        mfl   = QVBoxLayout(mid_f)
        mfl.setContentsMargins(10, 10, 10, 10)
        mfl.setSpacing(6)

        ov_lbl = QLabel("Overall Score")
        ov_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        ov_lbl.setAlignment(Qt.AlignCenter)
        mfl.addWidget(ov_lbl)
        mfl.addWidget(HSep())

        self._main_gauge = AngularGauge("Overall", size="large")
        mfl.addWidget(self._main_gauge, alignment=Qt.AlignCenter)

        mfl.addWidget(HSep())

        reco_lbl = QLabel("Recommendation")
        reco_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        mfl.addWidget(reco_lbl)

        self._reco_text = QTextEdit()
        self._reco_text.setReadOnly(True)
        self._reco_text.setTextInteractionFlags(Qt.NoTextInteraction)
        self._reco_text.setPlaceholderText(
            "Recommendations will appear after scanning…")
        self._reco_text.setStyleSheet(f"""
            QTextEdit {{
                background: transparent;
                border: none;
                color: {TEXT};
                font-size: 11px;
                font-family: Consolas, monospace;
            }}
        """)
        self._reco_text.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding)
        mfl.addWidget(self._reco_text, 1)   # ← stretch factor 1 fills remaining space

        cols.addWidget(mid_f, 1)             # 1/4 width

        # RIGHT 2/4 — 3-column scrollable gauges ───────────
        right_f = QFrame(); right_f.setObjectName("card")
        rfl     = QVBoxLayout(right_f)
        rfl.setContentsMargins(8, 10, 8, 10); rfl.setSpacing(6)
        gr_lbl = QLabel("Function Graphs")
        gr_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        gr_lbl.setAlignment(Qt.AlignCenter)
        rfl.addWidget(gr_lbl); rfl.addWidget(HSep())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self._gauge_container = QWidget()
        self._gauge_container.setStyleSheet("background: transparent;")
        self._gauge_grid = QGridLayout(self._gauge_container)
        self._gauge_grid.setSpacing(6)
        self._gauge_grid.setAlignment(Qt.AlignTop)
        self._small_gauges = []
        self._init_default_gauges(15)

        scroll.setWidget(self._gauge_container)
        rfl.addWidget(scroll)
        cols.addWidget(right_f, 2)           # 2/4 width

        root.addLayout(cols, 1)

        # ── Bottom buttons ──────────────────────────────
        root.addWidget(HSep())
        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        self._save_btn    = QPushButton("💾  Save")
        self._nosave_btn  = QPushButton("✕  Don't Save")
        self._reset_btn   = QPushButton("↺  Reset")
        self._heatmap_btn = QPushButton("🌡  View Heatmap")
        self._back_btn    = QPushButton("←  Back")

        for b in [self._save_btn, self._nosave_btn,
                  self._reset_btn, self._back_btn]:
            b.setStyleSheet(self.BTN_STYLE)
            b.setFixedHeight(36)

        self._heatmap_btn.setStyleSheet(
            self.BTN_STYLE.replace("#2e2e2e", PARTIAL_C)
                          .replace(f"color: {TEXT}", f"color: {PARTIAL_C}"))
        self._heatmap_btn.setFixedHeight(36)
        self._heatmap_btn.setEnabled(False)

        self._save_btn.clicked.connect(self._on_save)
        self._nosave_btn.clicked.connect(self._reset)
        self._reset_btn.clicked.connect(self._reset)
        self._heatmap_btn.clicked.connect(self._on_heatmap)
        self._back_btn.clicked.connect(self.go_back)

        btn_row.addWidget(self._save_btn)
        btn_row.addWidget(self._nosave_btn)
        btn_row.addWidget(self._reset_btn)
        btn_row.addWidget(self._heatmap_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._back_btn)
        root.addLayout(btn_row)

    # ── GAUGE HELPERS ───────────────────────────────────────
    def _init_default_gauges(self, count: int):
        while self._gauge_grid.count():
            item = self._gauge_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._small_gauges = []
        for i in range(count):
            g = AngularGauge(f"Function_{i+1:02d}")
            row, col = divmod(i, 3)
            self._gauge_grid.addWidget(g, row, col, Qt.AlignCenter)
            self._small_gauges.append(g)

    def _rebuild_gauges(self, count: int, names: list):
        total = max(15, count)
        while self._gauge_grid.count():
            item = self._gauge_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._small_gauges = []
        for i in range(total):
            if i < len(names):
                # Extract actual number from graph name e.g. graph_11 → Function_12
                raw = names[i]  # e.g. "graph_11" or "graph_2"
                try:
                    num = int(raw.replace("graph_", "").replace("function_", "")) + 1
                    label = f"Function_{num:02d}"
                except ValueError:
                    label = f"Function_{i+1:02d}"
            else:
                label = f"Function_{i+1:02d}"
            g = AngularGauge(label)
            row, col = divmod(i, 3)
            self._gauge_grid.addWidget(g, row, col, Qt.AlignCenter)
            self._small_gauges.append(g)

    # ── UPLOAD / SCAN ───────────────────────────────────────
    def _lbl(self, t, obj):
        l = QLabel(t); l.setObjectName(obj); return l

    def _on_upload(self):
        choice = QMessageBox(self)
        choice.setWindowTitle("Select Input")
        choice.setText("Scan a single file or a folder?")
        choice.setStyleSheet(f"background: {BG}; color: {TEXT}; font-size: 13px;")
        f_btn = choice.addButton("Single File", QMessageBox.AcceptRole)
        d_btn = choice.addButton("Folder",      QMessageBox.AcceptRole)
        choice.addButton("Cancel",              QMessageBox.RejectRole)
        choice.exec_()
        if choice.clickedButton() == f_btn:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select C/C++ File", ".", "C/C++ Files (*.c *.cpp)")
            if path:
                self._file_list = [path]
                self._file_idx  = 0
                self._show_file_info(path, folder_mode=False)
        elif choice.clickedButton() == d_btn:
            folder = QFileDialog.getExistingDirectory(self, "Select Folder")
            if folder:
                files = []
                for root, _, fnames in os.walk(folder):
                    for fn in fnames:
                        if fn.endswith((".c", ".cpp")):
                            files.append(os.path.join(root, fn))
                if files:
                    self._file_list = files
                    self._file_idx  = 0
                    self._show_file_info(files[0], folder_mode=len(files) > 1)
                else:
                    self._status_lbl.setText("No C/C++ files found.")

    def _show_file_info(self, path: str, folder_mode: bool):
        self._fname_lbl.setText(os.path.basename(path))
        self._fpath_lbl.setText(path)
        self._upload_btn.hide()
        self._file_info_w.show()
        self._scan_btn.show()
        if folder_mode:
            self._file_counter.setText(f"1 / {len(self._file_list)}")

    def _on_scan(self):
        if self._scanning:
            return
        self._results     = []
        self._log_text    = ""
        self._all_outputs = []
        self._scan_idx    = 0
        self._scan_btn.setEnabled(False)
        self._status_lbl.setText("Scanning…")
        self._main_gauge.reset()
        self._reco_text.setPlainText("—")
        self._summary.clear()
        if len(self._file_list) == 1:
            self._scan_file(self._file_list[0], self._on_single_done)
        else:
            self._scan_next_file()

    def _scan_file(self, path: str, callback):
        self._scanning   = True
        self._cur_output = []
        proc = QProcess(self)

        proc.setProgram(VENV_PYTHON)
        proc.setWorkingDirectory(APP_DIR)
        proc.setArguments([
            "-u", os.path.join(APP_DIR, "main.py"),
            "--mode", "detect",
            "--file", path,
            "--workspace", WORKSPACE
        ])
        # Inherit full system environment then add joern path
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PATH", APP_DIR + ":" + env.value("PATH"))
        proc.setProcessEnvironment(env)

        proc.readyReadStandardOutput.connect(
            lambda: self._cur_output.append(
                proc.readAllStandardOutput().data().decode("utf-8", errors="replace")))
        proc.readyReadStandardError.connect(
            lambda: self._cur_output.append(
                proc.readAllStandardError().data().decode("utf-8", errors="replace")))
        proc.finished.connect(lambda _c, _s: callback("".join(self._cur_output)))
        proc.start()
        self._scan_proc = proc

    def _on_single_done(self, output: str):
        self._scanning = False
        self._scan_btn.setEnabled(True)
        self._stats  = load_stats()
        result = parse_detect_output(output, self._stats)
        self._results  = [result]
        self._log_text = output
        self._display_results(0)
        n     = len(result["graphs"])
        label = "SAFE — No suspicious functions." if not n else \
                f"Found {n} suspicious function{'s' if n != 1 else ''}."
        self._status_lbl.setText(label)
        self._heatmap_btn.setEnabled(True)

    def _scan_next_file(self):
        if self._scan_idx >= len(self._file_list):
            self._on_all_done(); return
        path = self._file_list[self._scan_idx]
        self._status_lbl.setText(
            f"Scanning {self._scan_idx+1}/{len(self._file_list)}: "
            f"{os.path.basename(path)}")
        self._scan_file(path, self._on_one_file_done)

    def _on_one_file_done(self, output: str):
        self._all_outputs.append(output)
        self._scan_idx += 1
        self._scan_next_file()

    def _on_all_done(self):
        self._scanning = False
        self._scan_btn.setEnabled(True)
        self._stats   = load_stats()
        self._results = [parse_detect_output(o, self._stats)
                         for o in self._all_outputs]
        self._log_text = ("\n\n" + "─"*60 + "\n\n").join(self._all_outputs)
        self._file_idx = 0
        self._display_results(0)
        self._nav_w.show()
        self._update_nav()
        self._status_lbl.setText(f"Scanned {len(self._file_list)} files.")
        self._heatmap_btn.setEnabled(True)

    # ── DISPLAY ─────────────────────────────────────────────
    def _display_results(self, idx: int):
        if idx >= len(self._results):
            return

        # Bump generation — cancels all pending singleShot callbacks
        self._generation += 1
        gen = self._generation

        r         = self._results[idx]
        threshold = r["threshold"]
        margin    = r["margin"]
        graphs    = r.get("graphs", [])

        # File info
        fp = r.get("target_file") or (
            self._file_list[idx] if idx < len(self._file_list) else "")
        self._fname_lbl.setText(os.path.basename(fp))
        self._fpath_lbl.setText(fp)
        self._upload_btn.hide()
        self._file_info_w.show()

        # ── Summary table (HTML) ─────────────────────────
        sev_colors = {
            "safe":       SAFE_C,
            "partial":    PARTIAL_C,
            "vulnerable": VULN_C,
            "critical":   CRIT_C,
        }
        sev_labels = {
            "safe":       "SAFE",
            "partial":    "PART. VULN",
            "vulnerable": "VULNERABLE",
            "critical":   "CRITICAL",
        }

        def td(content, color=None, align="left", bold=False):
            style = (
                f"padding:4px 6px;"
                f"border-bottom:1px solid #1e1e1e;"
                f"white-space:nowrap;"
            )
            if color:
                style += f"color:{color};"
            if bold:
                style += "font-weight:bold;"
            return f'<td style="{style}" align="{align}">{content}</td>'

        def th(content):
            style = (
                f"padding:4px 6px;"
                f"border-bottom:1px solid #2e2e2e;"
                f"color:{DIM};"
                f"font-size:10px;"
                f"letter-spacing:1px;"
                f"white-space:nowrap;"
            )
            return f'<th style="{style}" align="left">{content}</th>'

        html = f"""
        <style>
            body {{ background: transparent; color: {TEXT};
                    font-family: Consolas, monospace; font-size: 11px; }}
            table {{ border-collapse: collapse; width: 100%; }}
        </style>
        <body>

        <!-- File info block -->
        <table>
            <tr>
                {th("FILE")}
                {td(os.path.basename(fp), color=ACCENT, bold=True)}
            </tr>
            <tr>
                {th("PATH")}
                {td(fp, color=DIM)}
            </tr>
            <tr>
                {th("GRAPHS")}
                {td(str(len(graphs)), color=TEXT)}
            </tr>
            <tr>
                {th("THRESHOLD")}
                {td(f"{threshold:.4f}", color=TEXT)}
            </tr>
        </table>

        <br>
        """

        if not graphs:
            html += f'<p style="color:{SAFE_C}; padding:4px;">✓&nbsp; SAFE — No anomalies detected.</p>'
        else:
            html += f"""
            <!-- Graph results table -->
            <table>
                <thead>
                    <tr>
                        {th("GRAPH")}
                        {th("SEVERITY")}
                        {th("SCORE")}
                        {th("LINE")}
                    </tr>
                </thead>
                <tbody>
            """
            for g in graphs:
                col    = sev_colors.get(g["severity"], TEXT)
                label  = sev_labels.get(g["severity"], "?")
                ln     = g["line"]
                ln_str = f"L{ln}" if ln > 0 else "—"
                name   = g["name"].replace(".json", "")
                html  += f"""
                    <tr>
                        {td(name,              color=TEXT)}
                        {td(label,             color=col,  bold=True)}
                        {td(f"{g['score']:.4f}", color=TEXT, align="right")}
                        {td(ln_str,            color=DIM,  align="center")}
                    </tr>
                """
            html += "</tbody></table>"

        html += "</body>"
        self._summary.setHtml(html)

# ── Rebuild gauges ───────────────────────────────
        names = [g["name"].replace(".json", "") for g in graphs]
        self._rebuild_gauges(len(graphs), names)

        # Capture gauge list for this generation
        gauges_snapshot = list(self._small_gauges)

        for i, graph in enumerate(graphs):
            def _activate_small(i=i, graph=graph, gen=gen):
                if gen != self._generation:
                    return
                if i < len(gauges_snapshot):
                    gauges_snapshot[i].activate(
                        graph["score"], graph["severity"],
                        threshold, margin)
            QTimer.singleShot(i * 160 + 50, _activate_small)

        # ── Overall gauge ────────────────────────────────
        if graphs:
            top = max(graphs, key=lambda x: x["score"])

            def _activate_main(gen=gen):
                if gen != self._generation:
                    return
                self._main_gauge.activate(
                    top["score"], r["overall_severity"],
                    threshold, margin)
            QTimer.singleShot(len(graphs) * 160 + 200, _activate_main)

            # ── Per-graph recommendation ──────────────────
            reco_lines = []
            for g in graphs:
                name     = g["name"].replace(".json", "")
                fn_label = name.replace("graph_", "function_")
                ln       = g["line"]
                ln_str   = f"  (line {ln})" if ln > 0 else ""
                sev      = g["severity"]

                if sev == "critical":
                    action = "Redesign required — critical anomaly detected."
                elif sev == "vulnerable":
                    action = "Refactoring needed — dangerous pattern found."
                elif sev == "partial":
                    action = "Review advised — minor structural anomaly."
                else:
                    action = "No action required."

                reco_lines.append(
                    f"{name} / {fn_label}{ln_str} :\n"
                    f"   → {action}"
                )

            self._reco_text.setPlainText("\n\n".join(reco_lines))

        else:
            self._main_gauge.reset()
            self._reco_text.setPlainText("✓  SAFE — No suspicious functions detected.")

    # ── NAV ─────────────────────────────────────────────────
    def _on_prev(self):
        if self._file_idx > 0:
            self._file_idx -= 1
            self._display_results(self._file_idx)
            self._update_nav()

    def _on_next(self):
        if self._file_idx < len(self._results) - 1:
            self._file_idx += 1
            self._display_results(self._file_idx)
            self._update_nav()

    def _update_nav(self):
        self._file_counter.setText(
            f"{self._file_idx+1} / {len(self._file_list)}")
        self._prev_btn.setEnabled(self._file_idx > 0)
        self._next_btn.setEnabled(self._file_idx < len(self._results)-1)

    # ── SAVE / RESET ─────────────────────────────────────────
    def _on_save(self):
        if not self._log_text.strip():
            self._status_lbl.setText("Nothing to save yet.")
            return
        os.makedirs(LOG_DIR, exist_ok=True)
        ts       = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_path = os.path.join(LOG_DIR, f"scan_{ts}.txt")
        with open(log_path, "w") as f:
            f.write(self._log_text)
        self._status_lbl.setText(f"Saved: {os.path.basename(log_path)}")

    def _on_heatmap(self):
        if not self._results or self._file_idx >= len(self._results):
            return

        r = self._results[self._file_idx]

        # Get the actual source file path for current result
        fp = r.get("target_file") or (
            self._file_list[self._file_idx]
            if self._file_idx < len(self._file_list) else "")

        if not fp or not os.path.exists(fp):
            mb = QMessageBox(self)
            mb.setWindowTitle("File Not Found")
            mb.setText(
                "Source file could not be located for heatmap display.\n"
                "The file may have been moved or deleted.")
            mb.setStyleSheet(f"QMessageBox {{ background: {BG}; }}"
                             f" QLabel {{ color: {TEXT}; }}")
            mb.exec_()
            return

        dlg = HeatmapDialog(
            file_path = fp,
            graphs    = r.get("graphs", []),
            threshold = r["threshold"],
            margin    = r["margin"],
            parent    = self
        )
        dlg.exec_()

    def _reset(self):
        self._file_list   = []
        self._file_idx    = 0
        self._results     = []
        self._log_text    = ""
        self._scanning    = False
        self._upload_btn.show()
        self._file_info_w.hide()
        self._scan_btn.hide()
        self._nav_w.hide()
        self._status_lbl.setText("")
        self._main_gauge.reset()
        self._reco_text.setPlainText("—")
        self._summary.clear()
        self._init_default_gauges(15)
        self._heatmap_btn.setEnabled(False)

    def refresh_stats(self):
        self._stats = load_stats()

# ═══════════════════════════════════════════════════════════
# RETRAIN PAGE
# ═══════════════════════════════════════════════════════════
class RetrainPage(QWidget):
    go_back      = pyqtSignal()
    go_configure = pyqtSignal()

    BTN_STYLE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid #2e2e2e;
            border-radius: 10px;
            color: {TEXT};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{
            background-color: #232323;
            border: 1px solid {ACCENT};
            color: {ACCENT};
        }}
        QPushButton:pressed {{ background-color: #191919; }}
        QPushButton:disabled {{ color: {DIM}; border-color: #1e1e1e; }}
    """

    BTN_RED = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid {CRIT_C};
            border-radius: 10px;
            color: {CRIT_C};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{ background-color: #2a1010; }}
        QPushButton:pressed {{ background-color: #1a0808; }}
    """

    BTN_ORANGE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid {VULN_C};
            border-radius: 10px;
            color: {VULN_C};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{ background-color: #1f1510; }}
        QPushButton:pressed {{ background-color: #170f08; }}
    """

    BTN_GREEN = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid {SAFE_C};
            border-radius: 10px;
            color: {SAFE_C};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{ background-color: #0f1f10; }}
        QPushButton:pressed {{ background-color: #081508; }}
    """

    CARD_STYLE = f"""
        QFrame {{
            background-color: #111111;
            border: 1px solid #2e2e2e;
            border-radius: 12px;
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process      = None
        self._training     = False
        self._dataset_path = os.path.join(WORKSPACE, "graphs")
        self._build_ui()

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(28, 24, 24, 18)
        root.setSpacing(20)

        # ── LEFT INFO ─────────────────────────────────────
        left = QVBoxLayout()
        left.setSpacing(12)

        left.addWidget(self._lbl("GRAPHSENTINEL", "header_title"))
        left.addWidget(self._lbl("Retrain AI Model", "section_title"))
        left.addWidget(HSep())
        left.addSpacing(8)

        # Dataset card
        ds_card = QFrame()
        ds_card.setStyleSheet(self.CARD_STYLE)
        ds_card.setFixedWidth(240)
        dl = QVBoxLayout(ds_card)
        dl.setContentsMargins(14, 12, 14, 12)
        dl.setSpacing(8)

        ds_hdr = QHBoxLayout()
        ds_hdr.addWidget(self._sub_lbl("Dataset"))
        self._change_btn = QPushButton("Change")
        self._change_btn.setStyleSheet(self.BTN_RED)
        self._change_btn.setFixedSize(66, 26)
        self._change_btn.clicked.connect(self._on_change_dataset)
        ds_hdr.addStretch()
        ds_hdr.addWidget(self._change_btn)
        dl.addLayout(ds_hdr)

        self._dataset_name_lbl = QLabel("Juliet Test Suite (Safe)")
        self._dataset_name_lbl.setStyleSheet(
            f"color: {TEXT}; font-size: 12px; border: none;"
            f" background: transparent;")
        self._dataset_name_lbl.setWordWrap(True)
        dl.addWidget(self._dataset_name_lbl)

        dl.addWidget(HSep())
        dl.addWidget(self._sub_lbl("Directory"))

        self._data_dir_lbl = QLabel(self._dataset_path)
        self._data_dir_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; border: none;"
            f" background: transparent;")
        self._data_dir_lbl.setWordWrap(True)
        dl.addWidget(self._data_dir_lbl)

        dl.addWidget(HSep())

        self._graph_count_lbl = QLabel("Graphs: —")
        self._graph_count_lbl.setStyleSheet(
            f"color: {ACCENT}; font-size: 13px; border: none;"
            f" background: transparent;")
        dl.addWidget(self._graph_count_lbl)
        left.addWidget(ds_card)

        # Config summary card
        cfg_card = QFrame()
        cfg_card.setStyleSheet(self.CARD_STYLE)
        cfg_card.setFixedWidth(240)
        cl = QVBoxLayout(cfg_card)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(6)

        cfg_hdr = QLabel("Current Config")
        cfg_hdr.setStyleSheet(
            f"color: {ACCENT}; font-size: 10px;"
            f" letter-spacing: 2px; border: none; background: transparent;")
        cl.addWidget(cfg_hdr)
        cl.addWidget(HSep())

        self._cfg_labels = {}
        for key, display in [
            ("epochs",               "Epochs"),
            ("batch_size",           "Batch Size"),
            ("threshold_percentile", "Threshold %ile"),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(display + ":")
            lbl.setStyleSheet(
                f"color: {DIM}; font-size: 11px; border: none;"
                f" background: transparent;")
            row.addWidget(lbl)
            vl = QLabel("—")
            vl.setStyleSheet(
                f"color: {TEXT}; font-size: 11px; border: none;"
                f" background: transparent;")
            row.addWidget(vl, alignment=Qt.AlignRight)
            cl.addLayout(row)
            self._cfg_labels[key] = vl

        left.addWidget(cfg_card)
        left.addStretch()

        # Buttons
        self._back_btn = QPushButton("←  Back")
        self._back_btn.setStyleSheet(self.BTN_STYLE)
        self._back_btn.setFixedHeight(38)
        self._back_btn.clicked.connect(self._on_back)
        left.addWidget(self._back_btn)

        self._config_btn = QPushButton("⚙  Configure Settings")
        self._config_btn.setStyleSheet(self.BTN_ORANGE)
        self._config_btn.setFixedHeight(38)
        self._config_btn.clicked.connect(self.go_configure)
        left.addWidget(self._config_btn)

        self._finetune_btn = QPushButton("⚡  Fine-Tune")
        self._finetune_btn.setStyleSheet(self.BTN_STYLE.replace(
            "#2e2e2e", PARTIAL_C).replace(
            f"color: {TEXT}", f"color: {PARTIAL_C}"))
        self._finetune_btn.setFixedHeight(38)
        self._finetune_btn.setToolTip(
            "Continues training from the existing checkpoint.\n"
            "Faster than full retraining. Does NOT delete old artifacts.")
        self._finetune_btn.clicked.connect(self._on_finetune_clicked)
        left.addWidget(self._finetune_btn)

        self._train_btn = QPushButton("⟳  Re-Train")
        self._train_btn.setStyleSheet(self.BTN_GREEN)
        self._train_btn.setFixedHeight(38)
        self._train_btn.clicked.connect(self._on_train_clicked)
        left.addWidget(self._train_btn)

        root.addLayout(left)

        # ── RIGHT OUTPUT ──────────────────────────────────
        right_f = QFrame()
        right_f.setStyleSheet(self.CARD_STYLE)
        rl = QVBoxLayout(right_f)
        rl.setContentsMargins(12, 12, 12, 10)
        rl.setSpacing(8)

        out_hdr = QHBoxLayout()
        out_lbl = QLabel("Training Output")
        out_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 11px; letter-spacing: 1px;")
        out_hdr.addWidget(out_lbl)
        out_hdr.addStretch()

        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet(self.BTN_STYLE)
        copy_btn.setFixedSize(72, 28)
        copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(
                self._output.toPlainText()))
        out_hdr.addWidget(copy_btn)
        rl.addLayout(out_hdr)
        rl.addWidget(HSep())

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setStyleSheet(f"""
            QTextEdit {{
                background-color: #0d0d0d;
                color: {TEXT};
                border: none;
                font-family: Consolas, monospace;
                font-size: 12px;
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        self._output.setPlaceholderText("Training output will appear here…")
        rl.addWidget(self._output)

        root.addWidget(right_f, 1)

    # ── HELPERS ──────────────────────────────────────────────
    def _lbl(self, t, obj):
        l = QLabel(t); l.setObjectName(obj); return l

    def _sub_lbl(self, t):
        l = QLabel(t)
        l.setStyleSheet(
            f"color: {DIM}; font-size: 11px;"
            f" border: none; background: transparent;")
        return l

    def refresh(self):
        cfg = load_config()
        for key, lbl in self._cfg_labels.items():
            lbl.setText(str(cfg.get(key, "—")))
        self._update_graph_count()

    def _update_graph_count(self):
        path = self._dataset_path
        if os.path.exists(path):
            n = len([f for f in os.listdir(path) if f.endswith(".json")])
        else:
            n = 0
        self._graph_count_lbl.setText(f"Graphs in dataset: {n}")

    # ── CHANGE DATASET ────────────────────────────────────────
    def _on_change_dataset(self):
        mb = QMessageBox(self)
        mb.setWindowTitle("⚠  Dataset Change Warning")
        mb.setTextFormat(Qt.RichText)
        mb.setText(
            "<b>Changing Dataset induces a ROOT change in how the model "
            "detects vulnerabilities.</b><br><br>"
            "<b>Make sure that the dataset only contains graphs generated by "
            "parsing accepted (C &amp; C++) files and only those that are "
            "safe (free from vulnerable code sections).</b><br><br>"
            "<b>Continue?</b>"
        )
        mb.setStyleSheet(f"""
            QMessageBox {{
                background-color: {BG};
            }}
            QLabel {{
                color: {TEXT};
                font-size: 13px;
                min-width: 480px;
                max-width: 480px;
            }}
            QMessageBox QLabel {{
                qproperty-wordWrap: true;
            }}
        """)

        yes_btn = mb.addButton("  Yes  ", QMessageBox.AcceptRole)
        no_btn  = mb.addButton("  No   ", QMessageBox.RejectRole)

        yes_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {CRIT_C};
                border-radius: 8px;
                color: {CRIT_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #2a1010; }}
        """)
        no_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {SAFE_C};
                border-radius: 8px;
                color: {SAFE_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #0f1f10; }}
        """)

        mb.exec_()

        if mb.clickedButton() != yes_btn:
            return

        # Open folder dialog
        folder = QFileDialog.getExistingDirectory(
            self, "Select Graph Dataset Folder")
        if not folder:
            return

        # Validate — must contain .json files directly
        jsons = [f for f in os.listdir(folder) if f.endswith(".json")]
        if not jsons:
            err = QMessageBox(self)
            err.setWindowTitle("Invalid Dataset")
            err.setText(
                "Selected folder contains no .json graph files.\n"
                "Please select a folder with graph JSON files directly inside it.")
            err.setStyleSheet(
                f"QMessageBox {{ background: {BG}; }}"
                f" QLabel {{ color: {TEXT}; font-size: 13px; }}")
            err.exec_()
            return

        # Accept
        self._dataset_path = folder
        self._data_dir_lbl.setText(folder)
        self._dataset_name_lbl.setText(os.path.basename(folder))
        self._update_graph_count()

    # ── RETRAIN ───────────────────────────────────────────────
    def _on_train_clicked(self):
        if self._training:
            return

        # 2-step verification popup
        mb = QMessageBox(self)
        mb.setWindowTitle("2 Step Verification")
        mb.setTextFormat(Qt.RichText)
        mb.setText(
            "Continue with Retrain?<br><br>"
            "<b>⚠ WARNING:</b> Will delete old artifacts created from training.<br><br>"
            "Continue?"
        )
        mb.setStyleSheet(f"""
            QMessageBox {{
                background-color: {BG};
            }}
            QLabel {{
                color: {TEXT};
                font-size: 13px;
                min-width: 360px;
            }}
        """)

        yes_btn = mb.addButton("  Yes  ", QMessageBox.AcceptRole)
        no_btn  = mb.addButton("  No   ", QMessageBox.RejectRole)

        yes_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {SAFE_C};
                border-radius: 8px;
                color: {SAFE_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #0f1f10; }}
        """)
        no_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {CRIT_C};
                border-radius: 8px;
                color: {CRIT_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #2a1010; }}
        """)

        mb.exec_()

        if mb.clickedButton() != yes_btn:
            return

        self._start_training(finetune=False)

    def _on_finetune_clicked(self):
        if self._training:
            return

        # Check checkpoint exists
        model_path = os.path.join(WORKSPACE, "model.pt")
        if not os.path.exists(model_path):
            mb = QMessageBox(self)
            mb.setWindowTitle("No Checkpoint Found")
            mb.setText(
                "No existing model checkpoint found.\n"
                "Please run a full Re-Train first before fine-tuning.")
            mb.setStyleSheet(
                f"QMessageBox {{ background: {BG}; }}"
                f" QLabel {{ color: {TEXT}; font-size: 13px; }}")
            mb.exec_()
            return

        mb = QMessageBox(self)
        mb.setWindowTitle("2 Step Verification")
        mb.setTextFormat(Qt.RichText)
        mb.setText(
            "Continue with Fine-Tune?<br><br>"
            "<b>⚡ Fine-Tune</b> continues training from the existing checkpoint.<br><br>"
            "Old artifacts are <b>preserved</b>.<br>"
            "Only the model weights and threshold will be updated.<br><br>"
            "Continue?"
        )
        mb.setStyleSheet(f"""
            QMessageBox {{ background-color: {BG}; }}
            QLabel {{
                color: {TEXT};
                font-size: 13px;
                min-width: 480px;
                max-width: 480px
            }}
        """)
        yes_btn = mb.addButton("  Yes  ", QMessageBox.AcceptRole)
        no_btn  = mb.addButton("  No   ", QMessageBox.RejectRole)
        yes_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {SAFE_C};
                border-radius: 8px;
                color: {SAFE_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #0f1f10; }}
        """)
        no_btn.setStyleSheet(f"""
            QPushButton {{
                background: #1c1c1c;
                border: 1px solid {CRIT_C};
                border-radius: 8px;
                color: {CRIT_C};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background: #2a1010; }}
        """)
        mb.exec_()

        if mb.clickedButton() != yes_btn:
            return

        self._start_training(finetune=True)

    def _start_training(self, finetune=False):
        self._training = True
        self._train_btn.setEnabled(False)
        self._finetune_btn.setEnabled(False)
        self._output.clear()

        if finetune:
            self._output.append("Fine-tune mode: loading existing checkpoint…\n")
            mode_arg = "finetune"
        else:
            self._output.append("Deleting old training artifacts…\n")
            for artifact in ["model.pt", "threshold.txt", "threshold_stats.json"]:
                path = os.path.join(WORKSPACE, artifact)
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass
            mode_arg = "train"

        self._output.append("Starting training…\n")

        self._process = QProcess(self)
        self._process.setProgram(VENV_PYTHON)
        self._process.setWorkingDirectory(APP_DIR)
        self._process.setArguments([
            "-u", os.path.join(APP_DIR, "main.py"),
            "--mode", mode_arg,
            "--workspace", WORKSPACE
        ])
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PATH", APP_DIR + ":" + env.value("PATH"))
        self._process.setProcessEnvironment(env)
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_train_done)
        self._process.start()

    def _on_stdout(self):
        data = self._process.readAllStandardOutput().data().decode(
            "utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self._output.append(line)
        self._output.verticalScrollBar().setValue(
            self._output.verticalScrollBar().maximum())

    def _on_stderr(self):
        data = self._process.readAllStandardError().data().decode(
            "utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self._output.append(f"[err] {line}")
        self._output.verticalScrollBar().setValue(
            self._output.verticalScrollBar().maximum())

    def _on_train_done(self, code, _):
        self._training = False
        self._train_btn.setEnabled(True)
        self._finetune_btn.setEnabled(True)
        sep = "─" * 50
        msg = ("✓  Training complete."
               if code == 0
               else f"✗  Training exited (code {code}).")
        self._output.append(f"\n{sep}\n{msg}")
        self.refresh()

    def _on_back(self):
        if self._training and self._process:
            self._process.kill()
            self._training = False
            self._train_btn.setEnabled(True)
            self._finetune_btn.setEnabled(True)
        self.go_back.emit()

# ═══════════════════════════════════════════════════════════
# CONFIGURE PAGE
# ═══════════════════════════════════════════════════════════
class ConfigurePage(QWidget):
    go_back    = pyqtSignal()
    go_retrain = pyqtSignal()

    BTN_STYLE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid #2e2e2e;
            border-radius: 10px;
            color: {TEXT};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{
            background-color: #232323;
            border: 1px solid {ACCENT};
            color: {ACCENT};
        }}
        QPushButton:pressed {{ background-color: #191919; }}
        QPushButton:disabled {{ color: {DIM}; border-color: #1e1e1e; }}
    """

    BTN_ORANGE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid {VULN_C};
            border-radius: 10px;
            color: {VULN_C};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{ background-color: #1f1510; }}
        QPushButton:pressed {{ background-color: #170f08; }}
    """

    SPIN_STYLE = f"""
        QSpinBox, QDoubleSpinBox {{
            background-color: #1c1c1c;
            color: {TEXT};
            border: 1px solid #2e2e2e;
            border-radius: 8px;
            padding: 4px 8px;
            font-size: 12px;
        }}
        QSpinBox:hover, QDoubleSpinBox:hover {{
            border-color: {ACCENT};
        }}
        QSpinBox::up-button, QSpinBox::down-button,
        QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
            background: #232323;
            border-radius: 4px;
            width: 16px;
        }}
    """

    SLIDER_STYLE = f"""
        QSlider::groove:horizontal {{
            background: #1c1c1c;
            border: 1px solid #2e2e2e;
            height: 4px;
            border-radius: 2px;
        }}
        QSlider::handle:horizontal {{
            background: {ACCENT};
            border: none;
            width: 14px;
            height: 14px;
            margin: -5px 0;
            border-radius: 7px;
        }}
        QSlider::sub-page:horizontal {{
            background: {ACCENT};
            border-radius: 2px;
        }}
    """

    def _make_card(self, title: str) -> QFrame:
        f = QFrame()
        f.setStyleSheet(f"""
            QFrame {{
                background-color: #111111;
                border: 1px solid #2e2e2e;
                border-radius: 12px;
            }}
        """)
        l = QVBoxLayout(f)
        l.setContentsMargins(16, 13, 16, 13)
        l.setSpacing(10)
        t = QLabel(title)
        t.setStyleSheet(
            f"color: {ACCENT}; font-size: 10px;"
            f" letter-spacing: 2px; border: none;"
            f" background: transparent;")
        l.addWidget(t)
        l.addWidget(HSep())
        return f

    def _row(self, label: str, widget: QWidget) -> QHBoxLayout:
        r   = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {DIM}; font-size: 12px;")
        r.addWidget(lbl)
        r.addStretch()
        r.addWidget(widget)
        return r

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 18)
        root.setSpacing(8)

        title = QLabel("GRAPHSENTINEL"); title.setObjectName("header_title")
        sect  = QLabel("Configure");  sect.setObjectName("section_title")
        root.addWidget(title)
        root.addWidget(sect)
        root.addWidget(HSep())
        root.addSpacing(8)

        content = QHBoxLayout()
        content.setSpacing(20)

        # ── LEFT ─────────────────────────────────────────
        left = QVBoxLayout()
        left.setSpacing(14)

        # Sensitivity card
        sens_card = self._make_card("ANOMALY DETECTION SENSITIVITY")
        sf = sens_card.layout()

        self._pct_lbl = QLabel("Threshold Percentile: 90")
        self._pct_lbl.setStyleSheet(
            f"color: {TEXT}; font-size: 13px; border: none;"
            f" background: transparent;")
        self._pct_slider = QSlider(Qt.Horizontal)
        self._pct_slider.setStyleSheet(self.SLIDER_STYLE)
        self._pct_slider.setRange(80, 99)
        self._pct_slider.setValue(90)
        self._pct_slider.valueChanged.connect(
            lambda v: self._pct_lbl.setText(
                f"Threshold Percentile: {v}"))
        sf.addWidget(self._pct_lbl)
        sf.addWidget(self._pct_slider)
        sf.addSpacing(4)

        stats = load_stats()
        self._thresh_info = QLabel(
            f"mean = {stats.get('mean', 0):.4f}"
            f"   ±   std = {stats.get('std', 0):.4f}\n"
            f"threshold = {stats.get('threshold', 0):.4f}"
        )
        self._thresh_info.setStyleSheet(
            f"color: {DIM}; font-size: 11px;"
            f" font-family: Consolas; border: none;"
            f" background: transparent;")
        sf.addWidget(self._thresh_info)
        sf.addSpacing(4)

        self._thresh_spin = QDoubleSpinBox()
        self._thresh_spin.setStyleSheet(self.SPIN_STYLE)
        self._thresh_spin.setRange(0.0, 1.0)
        self._thresh_spin.setSingleStep(0.001)
        self._thresh_spin.setDecimals(4)
        self._thresh_spin.setValue(0.0)
        self._thresh_spin.setFixedWidth(120)
        sf.addLayout(self._row("Manual Override (0 = auto):", self._thresh_spin))

        note0 = QLabel("  Set to 0 to use percentile-based auto threshold.")
        note0.setStyleSheet(
            f"color: {DIM}; font-size: 10px;"
            f" border: none; background: transparent;")
        sf.addWidget(note0)
        left.addWidget(sens_card)

        # Training params card
        train_card = self._make_card("TRAINING PARAMETERS")
        tf = train_card.layout()

        self._param_spins = {}
        for label, key, lo, hi, default, SpinCls in [
            ("Epochs",            "epochs",            10, 200, 50,  QSpinBox),
            ("Batch Size",        "batch_size",         4,  64,  16, QSpinBox),
            ("Max Files per CWE", "max_files_per_cwe", 50, 500, 100, QSpinBox),
        ]:
            spin = SpinCls()
            spin.setStyleSheet(self.SPIN_STYLE)
            spin.setRange(lo, hi)
            spin.setValue(default)
            spin.setFixedWidth(100)
            tf.addLayout(self._row(label + ":", spin))
            self._param_spins[key] = spin

        note = QLabel("* Parameters take effect on next Retrain.")
        note.setStyleSheet(
            f"color: {DIM}; font-size: 10px;"
            f" margin-top: 4px; border: none; background: transparent;")
        tf.addWidget(note)
        left.addWidget(train_card)
        left.addStretch()
        content.addLayout(left, 1)

        # ── RIGHT ─────────────────────────────────────────
        right = QVBoxLayout()
        right.setSpacing(14)

        loss_card = self._make_card("LOSS WEIGHTS")
        lf = loss_card.layout()

        info = QLabel(
            "Controls how much each graph component\n"
            "contributes to the reconstruction error.\n"
            "Weights should sum to approximately 1.0"
        )
        info.setStyleSheet(
            f"color: {DIM}; font-size: 11px;"
            f" border: none; background: transparent;")
        lf.addWidget(info)
        lf.addSpacing(4)

        self._loss_spins = {}
        for label, key, default in [
            ("Feature Loss  (α)", "alpha", 0.20),
            ("AST Loss      (β)", "beta",  0.20),
            ("CFG Loss      (γ)", "gamma", 0.30),
            ("DFG Loss      (δ)", "delta", 0.30),
        ]:
            spin = QDoubleSpinBox()
            spin.setStyleSheet(self.SPIN_STYLE)
            spin.setRange(0.0, 1.0)
            spin.setSingleStep(0.05)
            spin.setDecimals(2)
            spin.setValue(default)
            spin.setFixedWidth(90)
            lf.addLayout(self._row(label + ":", spin))
            self._loss_spins[key] = spin

        right.addWidget(loss_card)
        right.addStretch()
        content.addLayout(right, 1)
        root.addLayout(content, 1)

        # ── Bottom buttons ───────────────────────────────
        root.addWidget(HSep())
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        back_btn = QPushButton("←  Back")
        back_btn.setStyleSheet(self.BTN_STYLE)
        back_btn.setFixedHeight(38)
        back_btn.clicked.connect(self.go_back)

        reset_btn = QPushButton("↺  Reset to Defaults")
        reset_btn.setStyleSheet(self.BTN_STYLE)
        reset_btn.setFixedHeight(38)
        reset_btn.clicked.connect(self._reset_defaults)

        save_btn = QPushButton("💾  Save Configuration")
        save_btn.setStyleSheet(self.BTN_STYLE.replace(
            "#2e2e2e", ACCENT).replace(f"color: {TEXT}", f"color: {ACCENT}"))
        save_btn.setFixedHeight(38)
        save_btn.clicked.connect(self._save)

        retrain_btn = QPushButton("⟳  Save and Retrain Model")
        retrain_btn.setStyleSheet(self.BTN_ORANGE)
        retrain_btn.setFixedHeight(38)
        retrain_btn.clicked.connect(self._save_and_retrain)

        btn_row.addWidget(back_btn)
        btn_row.addStretch()
        btn_row.addWidget(reset_btn)
        btn_row.addSpacing(4)
        btn_row.addWidget(save_btn)
        btn_row.addSpacing(4)
        btn_row.addWidget(retrain_btn)
        root.addLayout(btn_row)

    def refresh(self):
        cfg   = load_config()
        stats = load_stats()
        self._pct_slider.setValue(cfg.get("threshold_percentile", 90))
        for k, s in self._param_spins.items():
            s.setValue(cfg.get(k, s.value()))
        for k, s in self._loss_spins.items():
            s.setValue(cfg.get(k, s.value()))
        self._thresh_info.setText(
            f"mean = {stats.get('mean', 0):.4f}"
            f"   ±   std = {stats.get('std', 0):.4f}\n"
            f"threshold = {stats.get('threshold', 0):.4f}"
        )

    def _reset_defaults(self):
        cfg = DEFAULT_CONFIG.copy()
        self._pct_slider.setValue(cfg["threshold_percentile"])
        for k, s in self._param_spins.items():
            s.setValue(cfg[k])
        for k, s in self._loss_spins.items():
            s.setValue(cfg[k])
        self._thresh_spin.setValue(0.0)

    def _save(self):
        cfg = {
            "threshold_percentile": self._pct_slider.value(),
            **{k: s.value() for k, s in self._param_spins.items()},
            **{k: s.value() for k, s in self._loss_spins.items()},
        }
        save_config(cfg)

        override = self._thresh_spin.value()
        if override > 0.0:
            s = load_stats()
            s["threshold"] = override
            save_stats(s)

        mb = QMessageBox(self)
        mb.setWindowTitle("Saved")
        mb.setText("Configuration saved successfully.")
        mb.setStyleSheet(f"background: {BG}; color: {TEXT};")
        mb.exec_()

    def _save_and_retrain(self):
        # Save first silently
        cfg = {
            "threshold_percentile": self._pct_slider.value(),
            **{k: s.value() for k, s in self._param_spins.items()},
            **{k: s.value() for k, s in self._loss_spins.items()},
        }
        save_config(cfg)

        override = self._thresh_spin.value()
        if override > 0.0:
            s = load_stats()
            s["threshold"] = override
            save_stats(s)

        # Navigate to retrain page — user must click Re-Train themselves
        self.go_retrain.emit()
# ═══════════════════════════════════════════════════════════
# PREVIOUS RESULTS PAGE
# ═══════════════════════════════════════════════════════════
class PreviousResultsPage(QWidget):
    go_back = pyqtSignal()

    BTN_STYLE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid #2e2e2e;
            border-radius: 10px;
            color: {TEXT};
            font-size: 12px;
            padding: 4px 10px;
        }}
        QPushButton:hover {{
            background-color: #232323;
            border: 1px solid {ACCENT};
            color: {ACCENT};
        }}
        QPushButton:pressed {{ background-color: #191919; }}
        QPushButton:disabled {{ color: {DIM}; border-color: #1e1e1e; }}
    """

    BTN_RED = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid {CRIT_C};
            border-radius: 10px;
            color: {CRIT_C};
            font-size: 12px;
            padding: 4px 10px;
        }}
        QPushButton:hover {{ background-color: #2a1010; }}
        QPushButton:pressed {{ background-color: #1a0808; }}
        QPushButton:disabled {{ color: {DIM}; border-color: #2e2e2e; }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 24, 18)
        root.setSpacing(8)

        title = QLabel("GRAPHSENTINEL"); title.setObjectName("header_title")
        sect  = QLabel("Previous Scan Results"); sect.setObjectName("section_title")
        root.addWidget(title)
        root.addWidget(sect)
        root.addWidget(HSep())
        root.addSpacing(6)

        content = QHBoxLayout()
        content.setSpacing(16)

        # ── Left — log list ──────────────────────────────
        left = QVBoxLayout()
        left.setSpacing(8)

        list_lbl = QLabel("Saved Scans")
        list_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 11px; letter-spacing: 1px;")
        left.addWidget(list_lbl)

        self._log_list = QListWidget()
        self._log_list.setFixedWidth(250)
        self._log_list.setStyleSheet(f"""
            QListWidget {{
                background: #111111;
                border: 1px solid #2e2e2e;
                border-radius: 8px;
                color: {TEXT};
                font-size: 12px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 7px 10px;
                border-bottom: 1px solid #1e1e1e;
            }}
            QListWidget::item:selected {{
                background: rgba(0,229,255,0.10);
                color: {ACCENT};
            }}
            QListWidget::item:hover {{
                background: rgba(255,255,255,0.04);
            }}
        """)
        self._log_list.currentRowChanged.connect(self._on_select)
        left.addWidget(self._log_list, 1)

        # Refresh + Clear All
        ref_btn = QPushButton("↺  Refresh")
        ref_btn.setStyleSheet(self.BTN_STYLE)
        ref_btn.setFixedHeight(34)
        ref_btn.clicked.connect(self.refresh)
        left.addWidget(ref_btn)

        clear_btn = QPushButton("🗑  Clear All")
        clear_btn.setStyleSheet(self.BTN_RED)
        clear_btn.setFixedHeight(34)
        clear_btn.clicked.connect(self._on_clear_all)
        left.addWidget(clear_btn)

        content.addLayout(left)

        # ── Right — log content ──────────────────────────
        right_f = QFrame()
        right_f.setObjectName("card")
        rl = QVBoxLayout(right_f)
        rl.setContentsMargins(12, 12, 12, 10)
        rl.setSpacing(8)

        out_hdr = QHBoxLayout()
        out_hdr.setSpacing(8)

        out_lbl = QLabel("Scan Log")
        out_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 11px; letter-spacing: 1px;")
        out_hdr.addWidget(out_lbl)
        out_hdr.addStretch()

        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet(self.BTN_STYLE)
        copy_btn.setFixedSize(72, 28)
        copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(
                self._output.toPlainText()))
        out_hdr.addWidget(copy_btn)

        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet(self.BTN_RED)
        del_btn.setFixedSize(72, 28)
        del_btn.clicked.connect(self._on_delete)
        out_hdr.addWidget(del_btn)

        rl.addLayout(out_hdr)
        rl.addWidget(HSep())

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText(
            "Select a scan log from the left to view its contents.")
        rl.addWidget(self._output)

        content.addWidget(right_f, 1)
        root.addLayout(content, 1)

        root.addWidget(HSep())
        btn_row = QHBoxLayout()
        back_btn = QPushButton("←  Back")
        back_btn.setStyleSheet(self.BTN_STYLE)
        back_btn.setFixedHeight(36)
        back_btn.clicked.connect(self.go_back)
        btn_row.addWidget(back_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

    def refresh(self):
        self._log_list.clear()
        self._output.clear()
        if not os.path.exists(LOG_DIR):
            return
        logs = sorted(
            [f for f in os.listdir(LOG_DIR) if f.endswith(".txt")],
            reverse=True
        )
        for i, log in enumerate(logs, start=1):
            display = f"{i:02d}.  {log.replace('.txt', '')}"
            self._log_list.addItem(display)
        if logs:
            self._log_list.setCurrentRow(0)

    def _on_select(self, row: int):
        if row < 0:
            return
        item = self._log_list.item(row)
        if not item:
            return
        # Strip the index prefix to get the filename
        raw      = item.text()
        filename = raw.split("  ", 1)[1].strip() + ".txt"
        log_path = os.path.join(LOG_DIR, filename)
        if os.path.exists(log_path):
            with open(log_path) as f:
                self._output.setPlainText(f.read())

    def _on_delete(self):
        row  = self._log_list.currentRow()
        item = self._log_list.item(row)
        if not item:
            return

        raw      = item.text()
        filename = raw.split("  ", 1)[1].strip() + ".txt"
        log_path = os.path.join(LOG_DIR, filename)

        mb = QMessageBox(self)
        mb.setWindowTitle("Confirm Delete")
        mb.setText(f"Delete  {filename} ?")
        mb.setStyleSheet(f"background: {BG}; color: {TEXT};")
        yes = mb.addButton("Delete", QMessageBox.DestructiveRole)
        mb.addButton("Cancel",       QMessageBox.RejectRole)
        mb.exec_()

        if mb.clickedButton() == yes:
            if os.path.exists(log_path):
                os.remove(log_path)
            self.refresh()

    def _on_clear_all(self):
        if not os.path.exists(LOG_DIR):
            return

        logs = [f for f in os.listdir(LOG_DIR) if f.endswith(".txt")]
        if not logs:
            return

        mb = QMessageBox(self)
        mb.setWindowTitle("Confirm Clear All")
        mb.setText(f"Delete all {len(logs)} scan log(s)? This cannot be undone.")
        mb.setStyleSheet(f"background: {BG}; color: {TEXT};")
        yes = mb.addButton("Clear All", QMessageBox.DestructiveRole)
        mb.addButton("Cancel",          QMessageBox.RejectRole)
        mb.exec_()

        if mb.clickedButton() == yes:
            for f in logs:
                try:
                    os.remove(os.path.join(LOG_DIR, f))
                except Exception:
                    pass
            self._output.clear()
            self.refresh()

# ═══════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════
class DashboardPage(QWidget):
    go_back = pyqtSignal()

    BTN_STYLE = f"""
        QPushButton {{
            background-color: #1c1c1c;
            border: 1px solid #2e2e2e;
            border-radius: 10px;
            color: {TEXT};
            font-size: 12px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{
            background-color: #232323;
            border: 1px solid {ACCENT};
            color: {ACCENT};
        }}
        QPushButton:pressed {{ background-color: #191919; }}
    """

    CARD_STYLE = f"""
        QFrame {{
            background-color: #111111;
            border: 1px solid #2e2e2e;
            border-radius: 12px;
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_history = []
        self._run_idx     = 0
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(8)

        # ── Header ───────────────────────────────────────
        title = QLabel("GRAPHSENTINEL"); title.setObjectName("header_title")
        sect  = QLabel("Model Performance Dashboard")
        sect.setObjectName("section_title")
        root.addWidget(title)
        root.addWidget(sect)
        root.addWidget(HSep())
        root.addSpacing(6)

        content = QHBoxLayout()
        content.setSpacing(14)

        # ── LEFT — run selector + stats ──────────────────
        left = QVBoxLayout()
        left.setSpacing(10)

        runs_card = QFrame(); runs_card.setStyleSheet(self.CARD_STYLE)
        runs_card.setFixedWidth(220)
        rl = QVBoxLayout(runs_card)
        rl.setContentsMargins(12, 12, 12, 12); rl.setSpacing(8)
        rl.addWidget(self._dim_lbl("TRAINING RUNS"))
        rl.addWidget(HSep())
        self._run_list = QListWidget()
        self._run_list.setStyleSheet(f"""
            QListWidget {{
                background: transparent;
                border: none;
                color: {TEXT};
                font-size: 11px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 6px 8px;
                border-bottom: 1px solid #1e1e1e;
                border-radius: 4px;
            }}
            QListWidget::item:selected {{
                background: rgba(0,229,255,0.10);
                color: {ACCENT};
            }}
            QListWidget::item:hover {{
                background: rgba(255,255,255,0.04);
            }}
        """)
        self._run_list.currentRowChanged.connect(self._on_run_select)
        rl.addWidget(self._run_list, 1)
        left.addWidget(runs_card)

        # Stats card
        stats_card = QFrame(); stats_card.setStyleSheet(self.CARD_STYLE)
        stats_card.setFixedWidth(220)
        sl = QVBoxLayout(stats_card)
        sl.setContentsMargins(12, 12, 12, 12); sl.setSpacing(8)
        sl.addWidget(self._dim_lbl("RUN STATISTICS"))
        sl.addWidget(HSep())

        self._stat_labels = {}
        for key, display in [
            ("timestamp",     "Date"),
            ("mode",          "Mode"),
            ("graph_count",   "Graphs"),
            ("best_val_loss", "Best Val Loss"),
            ("epochs",        "Epochs"),
        ]:
            row = QHBoxLayout()
            lk  = QLabel(display + ":")
            lk.setStyleSheet(
                f"color: {DIM}; font-size: 11px; border: none;"
                f" background: transparent;")
            row.addWidget(lk)
            vl = QLabel("—")
            vl.setStyleSheet(
                f"color: {TEXT}; font-size: 11px; border: none;"
                f" background: transparent;")
            vl.setAlignment(Qt.AlignRight)
            row.addWidget(vl)
            sl.addLayout(row)
            self._stat_labels[key] = vl

        left.addWidget(stats_card)

        # Threshold card
        thresh_card = QFrame(); thresh_card.setStyleSheet(self.CARD_STYLE)
        thresh_card.setFixedWidth(220)
        tl = QVBoxLayout(thresh_card)
        tl.setContentsMargins(12, 12, 12, 12); tl.setSpacing(8)
        tl.addWidget(self._dim_lbl("THRESHOLD CALIBRATION"))
        tl.addWidget(HSep())

        self._thresh_labels = {}
        for key, display in [
            ("threshold", "Threshold"),
            ("mean",      "Safe Mean"),
            ("std",       "Std Dev"),
        ]:
            row = QHBoxLayout()
            lk  = QLabel(display + ":")
            lk.setStyleSheet(
                f"color: {DIM}; font-size: 11px; border: none;"
                f" background: transparent;")
            row.addWidget(lk)
            vl = QLabel("—")
            vl.setStyleSheet(
                f"color: {ACCENT}; font-size: 11px; border: none;"
                f" background: transparent; font-family: Consolas;")
            vl.setAlignment(Qt.AlignRight)
            row.addWidget(vl)
            tl.addLayout(row)
            self._thresh_labels[key] = vl

        left.addWidget(thresh_card)
        left.addStretch()
        content.addLayout(left)

        # ── RIGHT — chart + toggles ───────────────────────
        right = QVBoxLayout()
        right.setSpacing(10)

        chart_card = QFrame(); chart_card.setStyleSheet(self.CARD_STYLE)
        cl = QVBoxLayout(chart_card)
        cl.setContentsMargins(14, 12, 14, 12); cl.setSpacing(8)

        # Chart header
        ch_hdr = QHBoxLayout()
        ch_lbl = QLabel("Loss Curves")
        ch_lbl.setStyleSheet(
            f"color: {DIM}; font-size: 10px; letter-spacing: 1px;")
        ch_hdr.addWidget(ch_lbl)
        ch_hdr.addStretch()

        # Line toggle buttons
        self._toggle_btns = {}
        for key, color, label in LossChartWidget.LINES:
            tb = QPushButton(label)
            tb.setCheckable(True)
            tb.setChecked(True)
            tb.setFixedHeight(24)
            tb.setStyleSheet(f"""
                QPushButton {{
                    background: #1c1c1c;
                    border: 1px solid {color};
                    border-radius: 6px;
                    color: {color};
                    font-size: 10px;
                    padding: 2px 8px;
                }}
                QPushButton:checked {{
                    background: rgba({self._hex_to_rgb(color)}, 0.15);
                }}
                QPushButton:!checked {{
                    background: #111111;
                    color: {DIM};
                    border-color: #2e2e2e;
                }}
            """)
            tb.clicked.connect(
                lambda checked, k=key: self._chart.toggle_line(k))
            ch_hdr.addWidget(tb)
            self._toggle_btns[key] = tb

        cl.addLayout(ch_hdr)
        cl.addWidget(HSep())

        self._chart = LossChartWidget({})
        self._chart.setToolTip(
            "LOSS CURVES — Training Progress\n"
            "─────────────────────────────────────\n"
            "Total Train  : Overall weighted loss.\n"
            "               Should decrease steadily.\n"
            "\n"
            "Validation   : Loss on held-out 20% data.\n"
            "               Tracks generalization.\n"
            "               High gap = overfitting.\n"
            "\n"
            "Feature      : Node token reconstruction\n"
            "               error (Word2Vec embeddings).\n"
            "\n"
            "AST          : Syntax structure edge error.\n"
            "CFG          : Control flow edge error.\n"
            "DFG          : Data flow edge error.\n"
            "\n"
            "HOW TO READ\n"
            "─────────────────────────────────────\n"
            "• All lines should trend downward.\n"
            "• Train and Val should stay close.\n"
            "• Toggle buttons show/hide lines.\n"
            "• Sudden spike = instability."
        )
        self._chart.setStyleSheet(f"""
            QToolTip {{
                background-color: #111111;
                color: {TEXT};
                border: 1px solid {ACCENT};
                padding: 12px 14px;
                font-size: 11px;
                font-family: Consolas, monospace;
                max-width: 380px;
                border-radius: 8px;
                opacity: 240;
            }}
        """)
        self._chart.setAttribute(Qt.WA_AlwaysShowToolTips, True)
        cl.addWidget(self._chart, 1)

        right.addWidget(chart_card, 1)

        # Detection rate card
        det_card = QFrame(); det_card.setStyleSheet(self.CARD_STYLE)
        det_card.setFixedHeight(90)
        dl2 = QVBoxLayout(det_card)
        dl2.setContentsMargins(14, 10, 14, 10); dl2.setSpacing(6)
        dl2.addWidget(self._dim_lbl("SCAN LOG STATISTICS"))
        dl2.addWidget(HSep())

        stats_row = QHBoxLayout(); stats_row.setSpacing(0)
        self._scan_stat_labels = {}
        for key, label, color in [
            ("total",       "Total Scans",  TEXT),
            ("safe",        "Safe",         SAFE_C),
            ("partial",     "Part. Vuln",   PARTIAL_C),
            ("vulnerable",  "Vulnerable",   VULN_C),
            ("critical",    "Critical",     CRIT_C),
        ]:
            col_w = QWidget()
            col_l = QVBoxLayout(col_w)
            col_l.setContentsMargins(0, 0, 0, 0); col_l.setSpacing(2)
            nv = QLabel("—")
            nv.setStyleSheet(
                f"color: {color}; font-size: 16px;"
                f" font-weight: bold; border: none; background: transparent;")
            nv.setAlignment(Qt.AlignCenter)
            lv = QLabel(label)
            lv.setStyleSheet(
                f"color: {DIM}; font-size: 9px; letter-spacing: 1px;"
                f" border: none; background: transparent;")
            lv.setAlignment(Qt.AlignCenter)
            col_l.addWidget(nv); col_l.addWidget(lv)
            stats_row.addWidget(col_w, 1)
            self._scan_stat_labels[key] = nv

        dl2.addLayout(stats_row)
        right.addWidget(det_card)
        content.addLayout(right, 1)
        root.addLayout(content, 1)

        # ── Bottom ───────────────────────────────────────
        root.addWidget(HSep())
        btn_row = QHBoxLayout()
        ref_btn = QPushButton("↺  Refresh")
        ref_btn.setStyleSheet(self.BTN_STYLE)
        ref_btn.setFixedHeight(36)
        ref_btn.clicked.connect(self.refresh)
        back_btn = QPushButton("←  Back")
        back_btn.setStyleSheet(self.BTN_STYLE)
        back_btn.setFixedHeight(36)
        back_btn.clicked.connect(self.go_back)
        btn_row.addWidget(ref_btn)
        btn_row.addStretch()
        btn_row.addWidget(back_btn)
        root.addLayout(btn_row)

    # ── HELPERS ──────────────────────────────────────────────
    def _dim_lbl(self, text):
        l = QLabel(text)
        l.setStyleSheet(
            f"color: {ACCENT}; font-size: 10px; letter-spacing: 2px;"
            f" border: none; background: transparent;")
        return l

    def _hex_to_rgb(self, hex_color: str) -> str:
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"{r},{g},{b}"

    def refresh(self):
        self._load_history()
        self._load_scan_stats()

    def _load_history(self):
        history_path = os.path.join(WORKSPACE, "training_history.json")
        self._all_history = []
        if os.path.exists(history_path):
            try:
                with open(history_path) as f:
                    self._all_history = json.load(f)
            except Exception:
                pass

        self._run_list.clear()
        for i, h in enumerate(self._all_history):
            ts   = h.get("timestamp", f"Run {i+1}")
            mode = h.get("mode", "train")
            ep   = len(h.get("epochs", []))
            self._run_list.addItem(f"{i+1:02d}.  {ts}  [{mode}, {ep}ep]")

        if self._all_history:
            self._run_list.setCurrentRow(len(self._all_history) - 1)
        else:
            self._chart.set_history({})

        # Threshold stats
        stats = load_stats()
        for key, lbl in self._thresh_labels.items():
            lbl.setText(f"{stats.get(key, 0):.4f}")

    def _load_scan_stats(self):
        counts = {
            "total": 0, "safe": 0,
            "partial": 0, "vulnerable": 0, "critical": 0
        }
        if os.path.exists(LOG_DIR):
            for fname in os.listdir(LOG_DIR):
                if not fname.endswith(".txt"):
                    continue
                counts["total"] += 1
                path = os.path.join(LOG_DIR, fname)
                try:
                    with open(path) as f:
                        content_upper = f.read().upper()
                    if "CRITICAL" in content_upper:
                        counts["critical"] += 1
                    elif "PARTIALLY VULNERABLE" in content_upper:
                        counts["partial"] += 1
                    elif "VULNERABLE" in content_upper:
                        counts["vulnerable"] += 1
                    elif "NO SUSPICIOUS FUNCTIONS" in content_upper:
                        counts["safe"] += 1
                    else:
                        counts["safe"] += 1
                except Exception:
                    pass

        for key, lbl in self._scan_stat_labels.items():
            lbl.setText(str(counts.get(key, 0)))

    def _on_run_select(self, row: int):
        if row < 0 or row >= len(self._all_history):
            return
        h = self._all_history[row]

        # Update stats
        ep_count = len(h.get("epochs", []))
        self._stat_labels["timestamp"].setText(
            h.get("timestamp", "—"))
        self._stat_labels["mode"].setText(
            h.get("mode", "train").upper())
        self._stat_labels["graph_count"].setText(
            str(h.get("graph_count", "—")))
        self._stat_labels["best_val_loss"].setText(
            f"{h.get('best_val_loss', 0):.6f}")
        self._stat_labels["epochs"].setText(str(ep_count))

        # Update chart
        self._chart.set_history(h)

# ═══════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GRAPHSENTINEL — Intelligent Zero-Day Threat Detection")
        self.resize(1120, 740)
        self.setMinimumSize(920, 620)
        self.setStyleSheet(STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()
        root.addWidget(self._stack)

        # Pages
        self._main_page    = MainPage()
        self._scan_page    = ScanPage()
        self._retrain_page = RetrainPage()
        self._config_page  = ConfigurePage()
        self._results_page   = PreviousResultsPage()
        self._dashboard_page = DashboardPage()

        for page in [self._main_page, self._scan_page, self._retrain_page,
                     self._config_page, self._results_page,
                     self._dashboard_page]:
            self._stack.addWidget(page)

        # ── Wiring ──────────────────────────────────────
        self._main_page.go_scan.connect(lambda: self._go(1))
        self._main_page.go_retrain.connect(self._open_retrain)
        self._main_page.go_config.connect(self._open_config)
        self._main_page.go_results.connect(self._open_results)
        self._main_page.go_dashboard.connect(self._open_dashboard)
        self._main_page.do_exit.connect(self.close)

        self._scan_page.go_back.connect(lambda: self._go(0))
        self._retrain_page.go_back.connect(lambda: self._go(0))
        self._retrain_page.go_configure.connect(self._open_config)
        self._config_page.go_back.connect(lambda: self._go(0))
        self._config_page.go_retrain.connect(self._open_retrain)
        self._results_page.go_back.connect(lambda: self._go(0))
        self._dashboard_page.go_back.connect(lambda: self._go(0))

    def _go(self, idx: int):
        self._stack.setCurrentIndex(idx)

    def _open_retrain(self):
        self._retrain_page.refresh()
        self._go(2)

    def _open_config(self):
        self._config_page.refresh()
        self._go(3)

    def _open_results(self):
        self._results_page.refresh()
        self._go(4)

    def _open_dashboard(self):
        self._dashboard_page.refresh()
        self._go(5)

# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════
def main():
    os.makedirs(WORKSPACE, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    app = QApplication(sys.argv)
    app.setApplicationName("GRAPHSENTINEL")

    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor(BG))
    palette.setColor(QPalette.WindowText,      QColor(TEXT))
    palette.setColor(QPalette.Base,            QColor(CARD))
    palette.setColor(QPalette.AlternateBase,   QColor(CARD2))
    palette.setColor(QPalette.Text,            QColor(TEXT))
    palette.setColor(QPalette.Button,          QColor(CARD))
    palette.setColor(QPalette.ButtonText,      QColor(TEXT))
    palette.setColor(QPalette.Highlight,       QColor(ACCENT))
    palette.setColor(QPalette.HighlightedText, QColor(BG))
    app.setPalette(palette)

    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()