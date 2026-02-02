"""
main.py
Forensic 3D Watermarking Suite — PyQt5 GUI Application
"""

import sys
import os
import traceback
import logging
from pathlib import Path
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit, QTabWidget,
    QGroupBox, QGridLayout, QSpinBox, QDoubleSpinBox, QFrame, QSizePolicy,
    QPlainTextEdit, QHeaderView, QTreeWidget, QTreeWidgetItem, QSplitter,
    QComboBox, QCheckBox, QStatusBar, QProgressBar, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QDragEnterEvent, QDropEvent, QIcon

# ─── Logging bridge: capture Python logging into the GUI ─────────────────────

class GuiLogHandler(logging.Handler):
    def __init__(self, signal):
        super().__init__()
        self._signal = signal

    def emit(self, record):
        self._signal.emit(self.format(record))


# ─── Worker threads for non-blocking backend execution ──────────────────────

class ProtectWorker(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)  # success, output_path

    def __init__(self, input_path, output_path, keyfile_path, secret_key, password, coefficients, safety_divisor):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path
        self.keyfile_path = keyfile_path
        self.secret_key = secret_key
        self.password = password
        self.coefficients = coefficients
        self.safety_divisor = safety_divisor

    def run(self):
        try:
            from mesh_io import load_mesh, save_mesh
            from spectral_engine import embed_watermark
            from dna_keyfile import save_dna_keyfile

            self.log_signal.emit("[INFO] Loading mesh...")
            vertices, faces = load_mesh(self.input_path)
            self.log_signal.emit(f"[INFO] Loaded {len(vertices)} vertices, {len(faces)} faces")

            self.log_signal.emit("[INFO] Computing spectral basis (Laplacian eigenvectors)...")
            watermarked_verts, metadata = embed_watermark(
                vertices, faces, self.secret_key,
                num_coefficients=self.coefficients,
                safety_divisor=self.safety_divisor
            )
            self.log_signal.emit(f"[INFO] Spectral analysis complete — {metadata['num_coefficients']} modes extracted")

            max_disp = float(max(
                (watermarked_verts - vertices).max(),
                abs((watermarked_verts - vertices).min())
            ))
            self.log_signal.emit(f"[INFO] DNA injected — max displacement: {max_disp:.2e} units")
            self.log_signal.emit(f"[DEBUG] avg_edge_length = {metadata['avg_edge_length']:.8f}")
            self.log_signal.emit(f"[DEBUG] displacement_scale = {metadata['displacement_scale']:.2e}")
            self.log_signal.emit(f"[DEBUG] displacement / edge ratio = 1/{self.safety_divisor:.0f}")
            self.log_signal.emit(f"[DEBUG] eigenvalues = {metadata['eigenvalues'].tolist()}")
            self.log_signal.emit(f"[DEBUG] payload = {metadata['payload'].tolist()}")

            self.log_signal.emit(f"[INFO] Saving watermarked mesh → {Path(self.output_path).name}")
            save_mesh(self.output_path, watermarked_verts, faces)
            self.log_signal.emit("[INFO] Watermarked mesh saved")

            self.log_signal.emit(f"[INFO] Encrypting master deed → {Path(self.keyfile_path).name}")
            save_dna_keyfile(self.keyfile_path, metadata, self.password)
            self.log_signal.emit("[INFO] Master deed saved and encrypted")
            self.log_signal.emit("[INFO] ── Protection Complete ──")

            self.finished_signal.emit(True, self.output_path)
        except Exception as e:
            self.log_signal.emit(f"[ERROR] {e}")
            self.log_signal.emit(f"[ERROR] {traceback.format_exc()}")
            self.finished_signal.emit(False, str(e))


class AuditWorker(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, object)  # success, AuditResult or error string

    def __init__(self, suspect_path, keyfile_path, password, threshold):
        super().__init__()
        self.suspect_path = suspect_path
        self.keyfile_path = keyfile_path
        self.password = password
        self.threshold = threshold

    def run(self):
        try:
            from forensic_audit import run_audit
            self.log_signal.emit("[INFO] Loading suspect mesh and decrypting keyfile...")
            self.log_signal.emit(f"[DEBUG] suspect = {self.suspect_path}")
            self.log_signal.emit(f"[DEBUG] keyfile = {self.keyfile_path}")
            self.log_signal.emit(f"[DEBUG] threshold = {self.threshold}")

            self.log_signal.emit("[INFO] Normalizing meshes (center + scale)...")
            self.log_signal.emit("[INFO] Running ICP alignment (skeleton → suspect)...")
            self.log_signal.emit("[INFO] Performing topology transfer (shrink-wrap)...")
            self.log_signal.emit("[INFO] Extracting and comparing spectral signatures...")

            result = run_audit(
                self.suspect_path,
                self.keyfile_path,
                self.password,
                correlation_threshold=self.threshold
            )

            self.log_signal.emit(f"[DEBUG] suspect_verts = {result.suspect_verts}")
            self.log_signal.emit(f"[DEBUG] original_verts = {result.original_verts}")
            self.log_signal.emit(f"[DEBUG] icp_error = {result.icp_error}")
            self.log_signal.emit(f"[DEBUG] correlation = {result.correlation}")
            self.log_signal.emit(f"[INFO] ── Audit Complete: {result.verdict} ({result.match_percentage:.2f}%) ──")

            self.finished_signal.emit(True, result)
        except Exception as e:
            self.log_signal.emit(f"[ERROR] {e}")
            self.log_signal.emit(f"[ERROR] {traceback.format_exc()}")
            self.finished_signal.emit(False, str(e))


class InfoWorker(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, object)

    def __init__(self, keyfile_path, password):
        super().__init__()
        self.keyfile_path = keyfile_path
        self.password = password

    def run(self):
        try:
            from dna_keyfile import load_dna_keyfile
            self.log_signal.emit(f"[INFO] Decrypting keyfile: {Path(self.keyfile_path).name}")
            keydata = load_dna_keyfile(self.keyfile_path, self.password)
            self.log_signal.emit("[INFO] Decrypted successfully")
            self.log_signal.emit(f"[DEBUG] secret_key_hash = {keydata['secret_key_hash']}")
            self.log_signal.emit(f"[DEBUG] num_coefficients = {keydata['num_coefficients']}")
            self.log_signal.emit(f"[DEBUG] safety_divisor = {keydata['safety_divisor']}")
            self.log_signal.emit(f"[DEBUG] avg_edge_length = {keydata['avg_edge_length']}")
            self.log_signal.emit(f"[DEBUG] displacement_scale = {keydata['displacement_scale']}")
            self.log_signal.emit(f"[DEBUG] original_vertices.shape = {keydata['original_vertices'].shape}")
            self.log_signal.emit(f"[DEBUG] faces.shape = {keydata['faces'].shape}")
            self.log_signal.emit(f"[DEBUG] eigenvalues = {keydata['eigenvalues'].tolist()}")
            self.log_signal.emit(f"[DEBUG] payload = {keydata['payload'].tolist()}")
            self.log_signal.emit("[INFO] ── Keyfile Inspection Complete ──")
            self.finished_signal.emit(True, keydata)
        except Exception as e:
            self.log_signal.emit(f"[ERROR] {e}")
            self.log_signal.emit(f"[ERROR] {traceback.format_exc()}")
            self.finished_signal.emit(False, str(e))


# ─── Reusable UI Components ──────────────────────────────────────────────────

class DropZone(QFrame):
    """A drag-and-drop file input that also supports click-to-browse."""
    file_dropped = pyqtSignal(str)

    def __init__(self, accepted_extensions=None, parent=None):
        super().__init__(parent)
        self.accepted_extensions = accepted_extensions or [".obj", ".stl"]
        self._path = ""
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.StyledPanel)
        self.setLineWidth(1)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        self.icon_label = QLabel("⬇")
        self.icon_label.setFont(QFont("Segoe UI", 28))
        self.icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_label)

        self.hint_label = QLabel("Drop .obj or .stl file here\nor click to browse")
        self.hint_label.setAlignment(Qt.AlignCenter)
        self.hint_label.setFont(QFont("Segoe UI", 9))
        layout.addWidget(self.hint_label)

        self.path_label = QLabel("")
        self.path_label.setAlignment(Qt.AlignCenter)
        self.path_label.setFont(QFont("Consolas", 8))
        layout.addWidget(self.path_label)

        self.setMinimumHeight(120)
        self._apply_idle_style()

    def _apply_idle_style(self):
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a4a5c;
                border-radius: 10px;
                background-color: #1a1f2e;
            }
            DropZone:hover {
                border-color: #4fc3f7;
                background-color: #1e2440;
            }
        """)
        self.icon_label.setStyleSheet("color: #3a4a5c;")
        self.hint_label.setStyleSheet("color: #5a6a7c;")

    def _apply_loaded_style(self):
        self.setStyleSheet("""
            DropZone {
                border: 2px solid #4fc3f7;
                border-radius: 10px;
                background-color: #1e2a3a;
            }
        """)
        self.icon_label.setStyleSheet("color: #4fc3f7;")
        self.hint_label.setStyleSheet("color: #8ab4c8;")

    def _apply_hover_style(self):
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #4fc3f7;
                border-radius: 10px;
                background-color: #1e2440;
            }
        """)

    @property
    def path(self):
        return self._path

    def set_path(self, path: str):
        self._path = path
        if path:
            self.path_label.setText(Path(path).name)
            self.icon_label.setText("✓")
            self.hint_label.setText("Click to change file")
            self._apply_loaded_style()
        else:
            self.path_label.setText("")
            self.icon_label.setText("⬇")
            self.hint_label.setText("Drop .obj or .stl file here\nor click to browse")
            self._apply_idle_style()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._browse()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Mesh File", "",
            "Mesh Files (*.obj *.stl);;OBJ Files (*.obj);;STL Files (*.stl);;All Files (*)"
        )
        if path:
            self.set_path(path)
            self.file_dropped.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if len(urls) == 1:
                ext = Path(urls[0].toLocalFile()).suffix.lower()
                if ext in self.accepted_extensions:
                    event.acceptProposedAction()
                    self._apply_hover_style()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        if self._path:
            self._apply_loaded_style()
        else:
            self._apply_idle_style()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.set_path(path)
            self.file_dropped.emit(path)
        if self._path:
            self._apply_loaded_style()
        else:
            self._apply_idle_style()


class KeyfileDropZone(DropZone):
    """Specialised drop zone that accepts .dna.npz files."""
    def __init__(self, parent=None):
        super().__init__(accepted_extensions=[".npz"], parent=parent)
        self.hint_label.setText("Drop .dna.npz keyfile here\nor click to browse")

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Master Deed Keyfile", "",
            "DNA Keyfiles (*.dna.npz *.npz);;All Files (*)"
        )
        if path:
            self.set_path(path)
            self.file_dropped.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if len(urls) == 1:
                name = urls[0].toLocalFile()
                if name.endswith(".npz"):
                    event.acceptProposedAction()
                    self._apply_hover_style()
                    return
        event.ignore()


# ─── Log Panel ───────────────────────────────────────────────────────────────

class LogPanel(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 8))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        self._log_lines = []

    def append_log(self, message: str):
        self._log_lines.append(message)
        timestamp = datetime.now().strftime("%H:%M:%S")

        if "[ERROR]" in message:
            color = "#f85149"
        elif "[DEBUG]" in message:
            color = "#8b949e"
        elif "[INFO]" in message:
            color = "#7ee787"
        else:
            color = "#c9d1d9"

        # Strip the tag for display, show timestamp instead
        display = message
        for tag in ["[ERROR] ", "[DEBUG] ", "[INFO] "]:
            display = display.replace(tag, "")

        html = f'<span style="color:#484f58;">[{timestamp}]</span> <span style="color:{color};">{message[:12]}</span><span style="color:#c9d1d9;"> {display}</span>'
        self.appendHtml(html)
        # Auto-scroll
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def clear_log(self):
        self._log_lines.clear()
        self.clear()


# ─── Debugger Panel ──────────────────────────────────────────────────────────

class DebuggerPanel(QWidget):
    """
    Shows live internal state: all [DEBUG] variables captured during a run,
    plus eigenvalue / payload arrays visualised as mini bar charts.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Toolbar row
        toolbar = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Variables", "Scalars Only", "Arrays Only"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                color: #8b949e;
                border: 1px solid #21262d;
                border-radius: 4px;
                padding: 3px 8px;
                font-family: Consolas;
                font-size: 8pt;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; border: none; }
        """)
        self.filter_combo.currentIndexChanged.connect(self._refilter)
        toolbar.addWidget(self.filter_combo)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(52)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 4px;
                font-family: Consolas;
                font-size: 8pt;
                padding: 2px 6px;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        self.clear_btn.clicked.connect(self.clear_state)
        toolbar.addWidget(self.clear_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Variable tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Variable", "Type", "Value"])
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #21262d;
                border-radius: 6px;
                font-family: Consolas;
                font-size: 8pt;
                alternate-row-colors: true;
            }
            QTreeWidget::item { padding: 3px 6px; }
            QTreeWidget::item:selected { background-color: #1f6feb; color: #ffffff; }
            QTreeWidgetItem { border-bottom: 1px solid #1c2128; }
            QHeaderView::section {
                background-color: #161b22;
                color: #8b949e;
                border: none;
                border-bottom: 1px solid #21262d;
                padding: 4px 6px;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.tree)

        self._all_items = []  # (name, type_tag, value_str, item)

    def _refilter(self):
        idx = self.filter_combo.currentIndex()
        for name, type_tag, value_str, item in self._all_items:
            if idx == 0:
                item.setHidden(False)
            elif idx == 1:
                item.setHidden(type_tag == "array")
            elif idx == 2:
                item.setHidden(type_tag == "scalar")

    def ingest_log_line(self, message: str):
        """Parse a [DEBUG] line and inject into the variable tree."""
        if "[DEBUG]" not in message:
            return
        # Extract "var = value" from "[DEBUG] var = value"
        text = message.replace("[DEBUG]", "").strip()
        if " = " not in text:
            return
        name, _, value_str = text.partition(" = ")
        name = name.strip()
        value_str = value_str.strip()

        # Detect type
        if value_str.startswith("[") and value_str.endswith("]"):
            type_tag = "array"
            type_label = "list"
            # Truncate long arrays
            if len(value_str) > 120:
                value_str = value_str[:117] + "..."
        elif value_str.startswith("(") and value_str.endswith(")"):
            type_tag = "array"
            type_label = "tuple"
        else:
            type_tag = "scalar"
            # Try to detect sub-type
            try:
                float(value_str)
                type_label = "float" if "." in value_str or "e" in value_str.lower() else "int"
            except ValueError:
                type_label = "str"

        # Check if variable already exists → update value
        for i, (n, tt, vs, item) in enumerate(self._all_items):
            if n == name:
                item.setText(2, value_str)
                self._all_items[i] = (n, type_tag, value_str, item)
                return

        # New variable
        item = QTreeWidgetItem([name, type_label, value_str])
        # Colour-code type
        if type_tag == "array":
            item.setForeground(0, QColor("#ffa657"))
        else:
            item.setForeground(0, QColor("#79c0ff"))
        item.setForeground(1, QColor("#484f58"))
        self.tree.addTopLevelItem(item)
        self._all_items.append((name, type_tag, value_str, item))

        # Apply current filter
        idx = self.filter_combo.currentIndex()
        if idx == 1 and type_tag == "array":
            item.setHidden(True)
        elif idx == 2 and type_tag == "scalar":
            item.setHidden(True)

    def clear_state(self):
        self.tree.clear()
        self._all_items.clear()


# ─── Tab: Protect ────────────────────────────────────────────────────────────

class ProtectTab(QWidget):
    run_protect = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Drop zone
        self.drop_zone = DropZone()
        layout.addWidget(self.drop_zone)

        # Options group
        opts = QGroupBox("Injection Parameters")
        opts.setStyleSheet("""
            QGroupBox {
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 8px;
                color: #8b949e;
                font-family: 'Segoe UI';
                font-size: 9pt;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
            }
        """)
        grid = QGridLayout(opts)
        grid.setSpacing(8)
        grid.setContentsMargins(12, 16, 12, 12)

        # Secret Key
        grid.addWidget(self._make_label("Secret Key"), 0, 0)
        self.secret_key_edit = QLineEdit()
        self.secret_key_edit.setEchoMode(QLineEdit.Password)
        self.secret_key_edit.setPlaceholderText("Your unique branding key")
        self._style_line_edit(self.secret_key_edit)
        grid.addWidget(self.secret_key_edit, 0, 1)

        # Password
        grid.addWidget(self._make_label("Keyfile Password"), 1, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Encryption password for .dna.npz")
        self._style_line_edit(self.password_edit)
        grid.addWidget(self.password_edit, 1, 1)

        # Spectral Modes
        grid.addWidget(self._make_label("Spectral Modes"), 2, 0)
        self.coefficients_spin = QSpinBox()
        self.coefficients_spin.setRange(3, 50)
        self.coefficients_spin.setValue(20)
        self._style_spinbox(self.coefficients_spin)
        grid.addWidget(self.coefficients_spin, 2, 1)

        # Safety Divisor
        grid.addWidget(self._make_label("Safety Divisor"), 3, 0)
        self.safety_spin = QDoubleSpinBox()
        self.safety_spin.setRange(10.0, 1000.0)
        self.safety_spin.setValue(50.0)
        self.safety_spin.setDecimals(1)
        self._style_spinbox(self.safety_spin)
        grid.addWidget(self.safety_spin, 3, 1)

        layout.addWidget(opts)

        # Spacing before button
        layout.addSpacing(20)

        # Run button
        self.run_btn = QPushButton("Inject Digital DNA")
        self.run_btn.setFixedHeight(45)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #1a7a4a, stop:1 #1e8f5a);
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-family: 'Segoe UI';
                font-size: 10pt;
                font-weight: bold;
                letter-spacing: 0.5px;
                margin: 4px 0px;
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #20916d, stop:1 #25a86b); }
            QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #156638, stop:1 #1a7a4a); }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.run_btn.clicked.connect(self._on_run)
        layout.addWidget(self.run_btn)

        layout.addStretch()

    def _make_label(self, text):
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 9))
        lbl.setStyleSheet("color: #8b949e;")
        lbl.setFixedWidth(130)
        return lbl

    def _style_line_edit(self, widget):
        widget.setFont(QFont("Consolas", 9))
        widget.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QLineEdit:focus { border-color: #4fc3f7; }
            QLineEdit::placeholder { color: #484f58; }
        """)

    def _style_spinbox(self, widget):
        widget.setFont(QFont("Consolas", 9))
        widget.setStyleSheet("""
            QSpinBox, QDoubleSpinBox {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QSpinBox:focus, QDoubleSpinBox:focus { border-color: #4fc3f7; }
            QSpinBox::up-button, QDoubleSpinBox::up-button,
            QSpinBox::down-button, QDoubleSpinBox::down-button {
                background-color: #161b22;
                border: none;
                border-radius: 3px;
            }
        """)

    def _on_run(self):
        if not self.drop_zone.path:
            return
        if not self.secret_key_edit.text().strip():
            return
        if not self.password_edit.text().strip():
            return

        input_path = self.drop_zone.path
        stem = Path(input_path).stem
        suffix = Path(input_path).suffix
        output_path = str(Path(input_path).parent / f"{stem}_watermarked{suffix}")
        keyfile_path = str(Path(input_path).parent / f"{stem}.dna.npz")

        self.run_protect.emit({
            "input_path": input_path,
            "output_path": output_path,
            "keyfile_path": keyfile_path,
            "secret_key": self.secret_key_edit.text(),
            "password": self.password_edit.text(),
            "coefficients": self.coefficients_spin.value(),
            "safety_divisor": self.safety_spin.value(),
        })


# ─── Tab: Audit ──────────────────────────────────────────────────────────────

class AuditTab(QWidget):
    run_audit = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Suspect model
        lbl = QLabel("Suspect Model")
        lbl.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl.setStyleSheet("color: #8b949e; margin-bottom: 2px;")
        layout.addWidget(lbl)
        self.suspect_drop = DropZone()
        layout.addWidget(self.suspect_drop)

        # Keyfile
        lbl2 = QLabel("Master Deed (.dna.npz)")
        lbl2.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl2.setStyleSheet("color: #8b949e; margin-top: 8px; margin-bottom: 2px;")
        layout.addWidget(lbl2)
        self.keyfile_drop = KeyfileDropZone()
        layout.addWidget(self.keyfile_drop)

        # Password + threshold
        opts = QGroupBox("Audit Parameters")
        opts.setStyleSheet("""
            QGroupBox {
                border: 1px solid #21262d;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 8px;
                color: #8b949e;
                font-family: 'Segoe UI';
                font-size: 9pt;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
            }
        """)
        grid = QGridLayout(opts)
        grid.setSpacing(8)
        grid.setContentsMargins(12, 16, 12, 12)

        grid.addWidget(self._make_label("Keyfile Password"), 0, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Password used during protection")
        self._style_line_edit(self.password_edit)
        grid.addWidget(self.password_edit, 0, 1)

        grid.addWidget(self._make_label("Match Threshold"), 1, 0)
        self.threshold_spin = QDoubleSpinBox()
        self.threshold_spin.setRange(0.01, 1.0)
        self.threshold_spin.setValue(0.15)
        self.threshold_spin.setDecimals(2)
        self.threshold_spin.setSuffix(" (15%)")
        self._style_spinbox(self.threshold_spin)
        grid.addWidget(self.threshold_spin, 1, 1)

        layout.addWidget(opts)

        # Result display
        self.result_frame = QFrame()
        self.result_frame.setVisible(False)
        self.result_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #0d1117;
            }
        """)
        result_layout = QVBoxLayout(self.result_frame)
        result_layout.setContentsMargins(16, 12, 16, 12)
        self.verdict_label = QLabel("")
        self.verdict_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self.verdict_label.setAlignment(Qt.AlignCenter)
        result_layout.addWidget(self.verdict_label)

        self.correlation_bar = QProgressBar()
        self.correlation_bar.setRange(0, 100)
        self.correlation_bar.setFixedHeight(22)
        self.correlation_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #21262d;
                border-radius: 6px;
                background-color: #161b22;
                text-align: center;
                color: #c9d1d9;
                font-family: Consolas;
                font-size: 8pt;
            }
            QProgressBar::chunk { border-radius: 6px; }
        """)
        result_layout.addWidget(self.correlation_bar)

        self.details_label = QLabel("")
        self.details_label.setFont(QFont("Segoe UI", 8))
        self.details_label.setStyleSheet("color: #8b949e;")
        self.details_label.setWordWrap(True)
        self.details_label.setAlignment(Qt.AlignCenter)
        result_layout.addWidget(self.details_label)
        layout.addWidget(self.result_frame)

        # Spacing before button
        layout.addSpacing(20)

        # Run button
        self.run_btn = QPushButton("Run Forensic Audit")
        self.run_btn.setFixedHeight(45)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #1a5276, stop:1 #2e86c1);
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-family: 'Segoe UI';
                font-size: 10pt;
                font-weight: bold;
                margin: 4px 0px;
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #1f6391, stop:1 #3498db); }
            QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #154360, stop:1 #1a5276); }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.run_btn.clicked.connect(self._on_run)
        layout.addWidget(self.run_btn)

        layout.addStretch()

    def _make_label(self, text):
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 9))
        lbl.setStyleSheet("color: #8b949e;")
        lbl.setFixedWidth(130)
        return lbl

    def _style_line_edit(self, widget):
        widget.setFont(QFont("Consolas", 9))
        widget.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QLineEdit:focus { border-color: #4fc3f7; }
            QLineEdit::placeholder { color: #484f58; }
        """)

    def _style_spinbox(self, widget):
        widget.setFont(QFont("Consolas", 9))
        widget.setStyleSheet("""
            QSpinBox, QDoubleSpinBox {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QSpinBox:focus, QDoubleSpinBox:focus { border-color: #4fc3f7; }
            QSpinBox::up-button, QDoubleSpinBox::up-button,
            QSpinBox::down-button, QDoubleSpinBox::down-button {
                background-color: #161b22;
                border: none;
                border-radius: 3px;
            }
        """)

    def _on_run(self):
        if not self.suspect_drop.path or not self.keyfile_drop.path:
            return
        if not self.password_edit.text().strip():
            return
        self.result_frame.setVisible(False)
        self.run_audit.emit({
            "suspect_path": self.suspect_drop.path,
            "keyfile_path": self.keyfile_drop.path,
            "password": self.password_edit.text(),
            "threshold": self.threshold_spin.value(),
        })

    def show_result(self, result):
        self.result_frame.setVisible(True)
        pct = max(0, min(100, int(result.match_percentage)))
        self.correlation_bar.setValue(pct)
        self.correlation_bar.setFormat(f"{result.match_percentage:.2f}%")

        if result.verdict == "OWNERSHIP CONFIRMED":
            self.verdict_label.setText("✓  OWNERSHIP CONFIRMED")
            self.verdict_label.setStyleSheet("color: #7ee787; font-size: 14pt; font-weight: bold;")
            self.correlation_bar.setStyleSheet(self.correlation_bar.styleSheet().replace(
                "QProgressBar::chunk { border-radius: 6px; }",
                "QProgressBar::chunk { border-radius: 6px; background-color: #238636; }"
            ))
        else:
            self.verdict_label.setText("✗  NO MATCH")
            self.verdict_label.setStyleSheet("color: #f85149; font-size: 14pt; font-weight: bold;")
            self.correlation_bar.setStyleSheet(self.correlation_bar.styleSheet().replace(
                "QProgressBar::chunk { border-radius: 6px; }",
                "QProgressBar::chunk { border-radius: 6px; background-color: #da3633; }"
            ))

        self.details_label.setText(result.details)


# ─── Tab: Info ───────────────────────────────────────────────────────────────

class HelpTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # Title
        title = QLabel("How to Use")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setStyleSheet("color: #58a6ff; margin-bottom: 8px;")
        layout.addWidget(title)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background-color: transparent; border: none; }")
        
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(20)
        content_layout.setContentsMargins(0, 0, 16, 0)

        help_text = """
<div style='color: #c9d1d9; font-family: Segoe UI; font-size: 10pt; line-height: 1.6;'>

<h3 style='color: #58a6ff; margin-top: 0;'>🛡 Protect Tab</h3>
<p><b>Purpose:</b> Embed an invisible watermark into your 3D model.</p>
<ol style='margin-left: 20px;'>
<li><b>Load Model:</b> Drag & drop your .obj file or click to browse.</li>
<li><b>Secret Key:</b> Enter a unique identifier (e.g., your brand name, project code).</li>
<li><b>Keyfile Password:</b> Create a strong password to encrypt the master deed.</li>
<li><b>Spectral Modes:</b> 20 recommended (higher = more robust, default at max security).</li>
<li><b>Safety Divisor:</b> 50 recommended (lower = stronger signal, default at max security).</li>
<li><b>Click "Inject Digital DNA":</b> Generates two files:
   <ul style='margin-left: 20px; margin-top: 8px;'>
   <li><code>yourmodel_watermarked.obj</code> — The protected model you distribute</li>
   <li><code>yourmodel.dna.npz</code> — Master deed (keep this secret & safe!)</li>
   </ul>
</li>
</ol>

<h3 style='color: #58a6ff; margin-top: 24px;'>🔍 Audit Tab</h3>
<p><b>Purpose:</b> Verify if a suspect model contains your watermark.</p>
<ol style='margin-left: 20px;'>
<li><b>Load Suspect:</b> Drag & drop the model you want to check.</li>
<li><b>Load Master Deed:</b> Drag & drop your .dna.npz keyfile.</li>
<li><b>Enter Password:</b> The same password used during protection.</li>
<li><b>Click "Verify Ownership":</b> Returns:
   <ul style='margin-left: 20px; margin-top: 8px;'>
   <li><b style='color: #3fb950;'>OWNERSHIP CONFIRMED</b> — Watermark detected (correlation ≥ 15%)</li>
   <li><b style='color: #f85149;'>NO MATCH</b> — No watermark or different source</li>
   </ul>
</li>
</ol>

<h3 style='color: #58a6ff; margin-top: 24px;'>📄 Info Tab</h3>
<p><b>Purpose:</b> Inspect technical details stored in a master deed keyfile.</p>
<p>Load a .dna.npz file and enter its password to view metadata (hash, spectral modes, displacement scale, etc.).</p>

<h3 style='color: #58a6ff; margin-top: 24px;'>⚠️ Important Notes</h3>
<ul style='margin-left: 20px;'>
<li><b>Keep your .dna.npz keyfile safe!</b> It's the only proof of ownership.</li>
<li><b>The watermark survives:</b> Scaling, rotation, vertex reordering, stretching, Blender export.</li>
<li><b>Higher correlation = stronger proof:</b> 90%+ is perfect, 15%+ is the threshold.</li>
<li><b>ICP error indicates shape match:</b> < 0.05 means same mesh, > 0.05 means different shapes.</li>
</ul>

<h3 style='color: #58a6ff; margin-top: 24px;'>📖 Technical Details</h3>
<p>This system uses spectral watermarking via Laplacian eigenvector embedding. The watermark is invisible to the eye but mathematically recoverable even after geometric transformations. See the debug panel for detailed technical logs during operations.</p>

</div>
"""
        
        help_label = QLabel(help_text)
        help_label.setWordWrap(True)
        help_label.setTextFormat(Qt.RichText)
        help_label.setOpenExternalLinks(True)
        help_label.setStyleSheet("background-color: transparent;")
        content_layout.addWidget(help_label)
        content_layout.addStretch()
        
        scroll.setWidget(content)
        layout.addWidget(scroll)


class CreditsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(24)
        layout.setContentsMargins(24, 24, 24, 24)

        # Center content
        layout.addStretch()

        # Title
        title = QLabel("Forensic 3D Watermarking Suite")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Version
        version = QLabel("Version 1.0")
        version.setFont(QFont("Segoe UI", 11))
        version.setStyleSheet("color: #8b949e; margin-top: -8px;")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)

        # Spacer
        spacer = QLabel()
        spacer.setFixedHeight(32)
        layout.addWidget(spacer)

        # Creator
        creator = QLabel("Created by <b>Orfeas Dialinos</b>")
        creator.setFont(QFont("Segoe UI", 12))
        creator.setStyleSheet("color: #c9d1d9;")
        creator.setAlignment(Qt.AlignCenter)
        layout.addWidget(creator)

        # GitHub link
        github_label = QLabel('<a href="https://github.com/archtecgr" style="color: #58a6ff; text-decoration: none;">github.com/archtecgr</a>')
        github_label.setFont(QFont("Segoe UI", 11))
        github_label.setAlignment(Qt.AlignCenter)
        github_label.setOpenExternalLinks(True)
        github_label.setTextFormat(Qt.RichText)
        github_label.setStyleSheet("margin-top: 8px;")
        layout.addWidget(github_label)

        # Spacer
        spacer2 = QLabel()
        spacer2.setFixedHeight(32)
        layout.addWidget(spacer2)

        # Description
        desc = QLabel(
            "Advanced spectral watermarking for 3D models using Laplacian eigenvector embedding.\n"
            "Invisible, robust, and mathematically verifiable proof of ownership."
        )
        desc.setFont(QFont("Segoe UI", 10))
        desc.setStyleSheet("color: #8b949e;")
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setMaximumWidth(600)
        layout.addWidget(desc, 0, Qt.AlignCenter)

        # Technology
        spacer3 = QLabel()
        spacer3.setFixedHeight(24)
        layout.addWidget(spacer3)

        tech = QLabel(
            "Built with: Python • NumPy • SciPy • PyQt5\n"
            "Techniques: Spectral Graph Theory • ICP Alignment • Matched Filtering"
        )
        tech.setFont(QFont("Consolas", 9))
        tech.setStyleSheet("color: #484f58;")
        tech.setAlignment(Qt.AlignCenter)
        layout.addWidget(tech)

        layout.addStretch()


class InfoTab(QWidget):
    run_info = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        lbl = QLabel("Master Deed Keyfile")
        lbl.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl.setStyleSheet("color: #8b949e; margin-bottom: 2px;")
        layout.addWidget(lbl)

        self.keyfile_drop = KeyfileDropZone()
        layout.addWidget(self.keyfile_drop)

        # Password
        row = QHBoxLayout()
        pwd_lbl = QLabel("Password")
        pwd_lbl.setFont(QFont("Segoe UI", 9))
        pwd_lbl.setStyleSheet("color: #8b949e;")
        pwd_lbl.setFixedWidth(70)
        row.addWidget(pwd_lbl)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Keyfile decryption password")
        self.password_edit.setFont(QFont("Consolas", 9))
        self.password_edit.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QLineEdit:focus { border-color: #4fc3f7; }
            QLineEdit::placeholder { color: #484f58; }
        """)
        row.addWidget(self.password_edit)
        layout.addLayout(row)

        # Info display
        self.info_frame = QFrame()
        self.info_frame.setVisible(False)
        self.info_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #0d1117;
            }
        """)
        info_layout = QGridLayout(self.info_frame)
        info_layout.setContentsMargins(16, 12, 16, 12)
        info_layout.setSpacing(6)

        self._info_labels = {}
        fields = [
            ("Key Hash", "key_hash"),
            ("Spectral Modes", "num_coefficients"),
            ("Safety Divisor", "safety_divisor"),
            ("Avg Edge Length", "avg_edge_length"),
            ("Displacement Scale", "displacement_scale"),
            ("Original Vertices", "orig_verts"),
            ("Original Faces", "orig_faces"),
            ("Eigenvalues", "eigenvalues"),
            ("Payload Coefficients", "payload_len"),
        ]
        for row_idx, (display_name, key) in enumerate(fields):
            lbl = QLabel(display_name)
            lbl.setFont(QFont("Segoe UI", 9))
            lbl.setStyleSheet("color: #484f58;")
            info_layout.addWidget(lbl, row_idx, 0)
            val_lbl = QLabel("—")
            val_lbl.setFont(QFont("Consolas", 8))
            val_lbl.setStyleSheet("color: #c9d1d9;")
            info_layout.addWidget(val_lbl, row_idx, 1)
            self._info_labels[key] = val_lbl

        layout.addWidget(self.info_frame)

        # Spacing before button
        layout.addSpacing(20)

        # Run button
        self.run_btn = QPushButton("Inspect Keyfile")
        self.run_btn.setFixedHeight(45)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #6a1b9a, stop:1 #9c27b0);
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-family: 'Segoe UI';
                font-size: 10pt;
                font-weight: bold;
                margin: 4px 0px;
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #7b1fa2, stop:1 #ab47bc); }
            QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #4a148c, stop:1 #6a1b9a); }
            QPushButton:disabled { background-color: #21262d; color: #484f58; }
        """)
        self.run_btn.clicked.connect(self._on_run)
        layout.addWidget(self.run_btn)

        layout.addStretch()

    def _on_run(self):
        if not self.keyfile_drop.path or not self.password_edit.text().strip():
            return
        self.info_frame.setVisible(False)
        self.run_info.emit({
            "keyfile_path": self.keyfile_drop.path,
            "password": self.password_edit.text(),
        })

    def show_info(self, keydata: dict):
        self.info_frame.setVisible(True)
        self._info_labels["key_hash"].setText(keydata["secret_key_hash"][:32] + "...")
        self._info_labels["num_coefficients"].setText(str(keydata["num_coefficients"]))
        self._info_labels["safety_divisor"].setText(f"{keydata['safety_divisor']:.0f}x")
        self._info_labels["avg_edge_length"].setText(f"{keydata['avg_edge_length']:.8f}")
        self._info_labels["displacement_scale"].setText(f"{keydata['displacement_scale']:.2e}")
        self._info_labels["orig_verts"].setText(str(len(keydata["original_vertices"])))
        self._info_labels["orig_faces"].setText(str(len(keydata["faces"])))
        self._info_labels["eigenvalues"].setText(str(len(keydata["eigenvalues"])))
        self._info_labels["payload_len"].setText(str(len(keydata["payload"])))


# ─── Main Window ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Forensic 3D Watermarking Suite V. 1.0 — Created by Orfeas Dialinos")
        self.setMinimumSize(900, 780)
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QTabWidget::pane {
                border: 1px solid #21262d;
                border-radius: 8px;
                background-color: #161b22;
                margin-top: -1px;
            }
            QTabBar::tab {
                background-color: #0d1117;
                color: #8b949e;
                border: 1px solid transparent;
                border-bottom: none;
                border-radius: 6px 6px 0 0;
                padding: 10px 28px;
                font-family: 'Segoe UI';
                font-size: 9pt;
                margin-right: 4px;
                min-width: 80px;
            }
            QTabBar::tab:selected {
                background-color: #161b22;
                color: #c9d1d9;
                border-color: #21262d;
                border-bottom-color: #161b22;
            }
            QTabBar::tab:hover { color: #ffffff; }
            QStatusBar {
                background-color: #0d1117;
                color: #484f58;
                border-top: 1px solid #21262d;
                font-family: Consolas;
                font-size: 8pt;
                padding: 2px 8px;
            }
        """)

        # Central widget with main splitter
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Header ──
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #21262d;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)

        title_lbl = QLabel("WATERMARK")
        title_lbl.setFont(QFont("Consolas", 16, QFont.Bold))
        title_lbl.setStyleSheet("color: #4fc3f7; letter-spacing: 3px;")
        header_layout.addWidget(title_lbl)

        subtitle = QLabel("Forensic 3D Watermarking Suite v1.0")
        subtitle.setFont(QFont("Segoe UI", 8))
        subtitle.setStyleSheet("color: #484f58; margin-left: 12px;")
        header_layout.addWidget(subtitle)

        header_layout.addStretch()

        # Generate test mesh button in header
        self.gen_btn = QPushButton("⚙ Generate Test Mesh")
        self.gen_btn.setFixedHeight(28)
        self.gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 5px;
                font-family: 'Segoe UI';
                font-size: 8pt;
                padding: 0 10px;
            }
            QPushButton:hover { background-color: #30363d; color: #c9d1d9; }
        """)
        self.gen_btn.clicked.connect(self._generate_test_mesh)
        header_layout.addWidget(self.gen_btn)
        main_layout.addWidget(header)

        # ── Body: top tabs + bottom debug splitter ──
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { height: 4px; background-color: #21262d; }")

        # Top: tab widget
        self.tabs = QTabWidget()
        self.protect_tab = ProtectTab()
        self.audit_tab = AuditTab()
        self.info_tab = InfoTab()
        self.help_tab = HelpTab()
        self.credits_tab = CreditsTab()
        self.tabs.addTab(self.protect_tab, "🛡  Protect")
        self.tabs.addTab(self.audit_tab, "🔍  Audit")
        self.tabs.addTab(self.info_tab, "📄  Info")
        self.tabs.addTab(self.help_tab, "❓  Help")
        self.tabs.addTab(self.credits_tab, "ℹ️  Credits")

        # Wire signals
        self.protect_tab.run_protect.connect(self._start_protect)
        self.audit_tab.run_audit.connect(self._start_audit)
        self.info_tab.run_info.connect(self._start_info)

        splitter.addWidget(self.tabs)

        # Bottom: log + debugger in a horizontal splitter
        bottom = QWidget()
        bottom_layout = QHBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(0)

        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.setStyleSheet("QSplitter::handle { width: 4px; background-color: #21262d; }")

        # Log panel with header
        log_container = QWidget()
        log_container.setStyleSheet("background-color: #161b22;")
        log_layout = QVBoxLayout(log_container)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(0)

        log_header = QWidget()
        log_header.setFixedHeight(28)
        log_header.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #21262d;")
        log_header_layout = QHBoxLayout(log_header)
        log_header_layout.setContentsMargins(8, 0, 8, 0)
        log_title = QLabel("OUTPUT LOG")
        log_title.setFont(QFont("Consolas", 8, QFont.Bold))
        log_title.setStyleSheet("color: #4fc3f7; letter-spacing: 1px;")
        log_header_layout.addWidget(log_title)
        log_header_layout.addStretch()
        self.clear_log_btn = QPushButton("Clear")
        self.clear_log_btn.setFixedSize(44, 18)
        self.clear_log_btn.setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #484f58;
                border: 1px solid #30363d;
                border-radius: 3px;
                font-family: Consolas;
                font-size: 7pt;
            }
            QPushButton:hover { background-color: #30363d; color: #8b949e; }
        """)
        self.clear_log_btn.clicked.connect(self._clear_all)
        log_header_layout.addWidget(self.clear_log_btn)
        log_layout.addWidget(log_header)

        self.log_panel = LogPanel()
        log_layout.addWidget(self.log_panel)
        bottom_splitter.addWidget(log_container)

        # Debugger panel with header
        debug_container = QWidget()
        debug_container.setStyleSheet("background-color: #161b22;")
        debug_layout = QVBoxLayout(debug_container)
        debug_layout.setContentsMargins(0, 0, 0, 0)
        debug_layout.setSpacing(0)

        debug_header = QWidget()
        debug_header.setFixedHeight(28)
        debug_header.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #21262d;")
        debug_header_layout = QHBoxLayout(debug_header)
        debug_header_layout.setContentsMargins(8, 0, 8, 0)
        debug_title = QLabel("DEBUGGER — LIVE VARIABLES")
        debug_title.setFont(QFont("Consolas", 8, QFont.Bold))
        debug_title.setStyleSheet("color: #ffa657; letter-spacing: 1px;")
        debug_header_layout.addWidget(debug_title)
        debug_layout.addWidget(debug_header)

        self.debugger = DebuggerPanel()
        debug_layout.addWidget(self.debugger)
        bottom_splitter.addWidget(debug_container)

        bottom_splitter.setSizes([500, 400])
        bottom_layout.addWidget(bottom_splitter)
        splitter.addWidget(bottom)

        splitter.setSizes([480, 260])
        main_layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    # ─── Actions ────────────────────────────────────────────────────────────

    def _clear_all(self):
        self.log_panel.clear_log()
        self.debugger.clear_state()

    def _generate_test_mesh(self):
        from generate_test_mesh import generate_sphere, save_obj
        path, _ = QFileDialog.getSaveFileName(self, "Save Test Mesh", "test_sphere.obj", "OBJ Files (*.obj)")
        if path:
            verts, faces = generate_sphere()
            save_obj(path, verts, faces, "Generated by Forensic 3D Watermarking Suite")
            self.log_panel.append_log(f"[INFO] Test sphere generated → {Path(path).name}")
            self.status_bar.showMessage(f"Generated: {Path(path).name}")

    def _start_protect(self, params: dict):
        self._clear_all()
        self.status_bar.showMessage("Running — Protect...")
        self.protect_tab.run_btn.setEnabled(False)

        self.worker = ProtectWorker(
            params["input_path"], params["output_path"], params["keyfile_path"],
            params["secret_key"], params["password"],
            params["coefficients"], params["safety_divisor"]
        )
        self.worker.log_signal.connect(self._on_log)
        self.worker.finished_signal.connect(self._on_protect_done)
        self.worker.start()

    def _on_protect_done(self, success: bool, info: str):
        self.protect_tab.run_btn.setEnabled(True)
        if success:
            self.status_bar.showMessage(f"Done — {Path(info).name} created")
        else:
            self.status_bar.showMessage("Failed — see log")

    def _start_audit(self, params: dict):
        self._clear_all()
        self.status_bar.showMessage("Running — Audit...")
        self.audit_tab.run_btn.setEnabled(False)

        self.worker = AuditWorker(
            params["suspect_path"], params["keyfile_path"],
            params["password"], params["threshold"]
        )
        self.worker.log_signal.connect(self._on_log)
        self.worker.finished_signal.connect(self._on_audit_done)
        self.worker.start()

    def _on_audit_done(self, success: bool, result):
        self.audit_tab.run_btn.setEnabled(True)
        if success:
            self.audit_tab.show_result(result)
            self.status_bar.showMessage(f"Audit complete — {result.verdict}")
        else:
            self.status_bar.showMessage("Audit failed — see log")

    def _start_info(self, params: dict):
        self._clear_all()
        self.status_bar.showMessage("Running — Inspect...")
        self.info_tab.run_btn.setEnabled(False)

        self.worker = InfoWorker(params["keyfile_path"], params["password"])
        self.worker.log_signal.connect(self._on_log)
        self.worker.finished_signal.connect(self._on_info_done)
        self.worker.start()

    def _on_info_done(self, success: bool, result):
        self.info_tab.run_btn.setEnabled(True)
        if success:
            self.info_tab.show_info(result)
            self.status_bar.showMessage("Keyfile inspected successfully")
        else:
            self.status_bar.showMessage("Inspection failed — see log")

    def _on_log(self, message: str):
        self.log_panel.append_log(message)
        self.debugger.ingest_log_line(message)


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Dark palette baseline
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#0d1117"))
    palette.setColor(QPalette.WindowText, QColor("#c9d1d9"))
    palette.setColor(QPalette.Base, QColor("#0d1117"))
    palette.setColor(QPalette.AlternateBase, QColor("#161b22"))
    palette.setColor(QPalette.Text, QColor("#c9d1d9"))
    palette.setColor(QPalette.Button, QColor("#21262d"))
    palette.setColor(QPalette.ButtonText, QColor("#c9d1d9"))
    palette.setColor(QPalette.Highlight, QColor("#1f6feb"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
