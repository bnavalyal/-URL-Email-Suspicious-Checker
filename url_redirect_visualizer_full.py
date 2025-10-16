import sys
import re
import os
import pandas as pd
from urllib.parse import urlparse
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QGraphicsOpacityEffect,
    QGraphicsDropShadowEffect, QFileDialog
)
from PyQt5.QtGui import QColor, QFont, QPixmap
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, pyqtProperty

# ----------------------
# Detection Logic
# ----------------------
def check_url(url):
    score = 0
    issues = []

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            issues.append("Invalid URL format")
            score += 5
    except:
        issues.append("Malformed URL")
        score += 5

    if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
        issues.append("Contains IP address")
        score += 3

    if re.search(r'(free|login|verify|update|secure|bank|paypal|confirm|account)', url, re.IGNORECASE):
        issues.append("Suspicious keywords")
        score += 2

    if re.match(r'http[s]?://(bit\.ly|tinyurl\.com|goo\.gl|t\.co)', url):
        issues.append("Shortened URL")
        score += 2

    if re.search(r'[@]{1,}', url):
        issues.append("Contains @ symbol")
        score += 2

    if re.search(r'[\?\=\&]{3,}', url):
        issues.append("Excessive symbols")
        score += 1

    if re.search(r'goog1e|facebo0k|paypa1', url, re.IGNORECASE):
        issues.append("Possible phishing domain")
        score += 3

    score = min(score, 10)
    if score == 0:
        issues.append("No obvious issues found")

    return score, issues

def check_email(email):
    score = 0
    issues = []

    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(pattern, email):
        issues.append("Invalid email format")
        score += 5

    if re.search(r'(admin|support|verify|noreply|security|alert)', email, re.IGNORECASE):
        issues.append("Suspicious keywords")
        score += 3

    if email.endswith(('.xyz', '.club', '.top', '.online')):
        issues.append("Suspicious TLD")
        score += 2

    score = min(score, 10)
    if score == 0:
        issues.append("No obvious issues found")

    return score, issues

# ----------------------
# Animated QLabel for counting
# ----------------------
class AnimatedLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0

    def getValue(self):
        return self._value

    def setValue(self, val):
        self._value = val
        parts = self.text().split("\n")
        title = parts[0] if parts else ""
        self.setText(f"{title}\n{int(val)}")

    value = pyqtProperty(int, fget=getValue, fset=setValue)

# ----------------------
# Main Application
# ----------------------
class SuspiciousChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL & Email Suspicious Checker")
        self.setGeometry(50, 50, 1300, 720)
        self.results = []
        self.history_file = "history.csv"
        self.slideshow_index = 0
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self._active_animations = []
        self.active_slide_animations = []
        self.initUI()

    def initUI(self):
        # ---------------- Background ----------------
        bg_label = QLabel(self)
        bg_label.setGeometry(0, 0, self.width(), self.height())
        bg_path = os.path.join(self.script_dir, "images", "bg.jpg")
        if os.path.exists(bg_path):
            bg_pix = QPixmap(bg_path)
            bg_pix = bg_pix.scaled(self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            bg_label.setPixmap(bg_pix)
        opacity_effect = QGraphicsOpacityEffect()
        opacity_effect.setOpacity(0.25)
        bg_label.setGraphicsEffect(opacity_effect)
        bg_label.lower()

        # ---------------- Main Layout ----------------
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # ---------------- Left Buttons ----------------
        left_layout = QVBoxLayout()
        buttons_info = [
            ("Analyze", self.analyze_input, "#4caf50", "#81c784"),
            ("History", self.show_history, "#ff9800", "#ffb74d"),
            ("Export CSV", self.export_csv, "#f44336", "#e57373")
        ]
        for txt, func, start_col, end_col in buttons_info:
            btn = QPushButton(txt)
            btn.setFont(QFont("Segoe UI", 12, QFont.Bold))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                                stop:0 {start_col}, stop:1 {end_col});
                    border-radius:15px;
                    color:white;
                    padding:15px;
                }}
                QPushButton:hover {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                                stop:0 {end_col}, stop:1 {start_col});
                    color:white;
                }}
            """)
            shadow_btn = QGraphicsDropShadowEffect()
            shadow_btn.setBlurRadius(25)
            shadow_btn.setXOffset(0)
            shadow_btn.setYOffset(5)
            shadow_btn.setColor(QColor(0,0,0,160))
            btn.setGraphicsEffect(shadow_btn)
            btn.clicked.connect(func)
            left_layout.addWidget(btn)
        left_layout.addStretch()
        main_layout.addLayout(left_layout)

        # ---------------- Right Content ----------------
        content_layout = QVBoxLayout()

        title = QLabel("URL & Email Suspicious Checker")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 28, QFont.Bold))
        title.setStyleSheet("color:#1565c0;")
        content_layout.addWidget(title)

        # ---------------- Slideshow ----------------
        self.slideshow = QLabel()
        self.slideshow.setFixedSize(1000, 200)
        self.slideshow.setAlignment(Qt.AlignCenter)
        self.slideshow.setStyleSheet("""
            border-radius:15px;
            background-color: rgba(255,255,255,0.6);
        """)
        self.slideshow_opacity = QGraphicsOpacityEffect(self.slideshow)
        self.slideshow.setGraphicsEffect(self.slideshow_opacity)
        self.slideshow_opacity.setOpacity(1.0)
        content_layout.addWidget(self.slideshow)
        self.load_slideshow()
        self.start_slideshow()

        # ---------------- Input ----------------
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter URLs or Emails (one per line)")
        self.input_text.setStyleSheet("""
            background-color: rgba(255,255,255,0.85);
            color:black;
            font-size:13pt;
            border-radius:12px;
            padding:10px;
        """)
        shadow_input = QGraphicsDropShadowEffect()
        shadow_input.setBlurRadius(15)
        shadow_input.setXOffset(0)
        shadow_input.setYOffset(5)
        shadow_input.setColor(QColor(0,0,0,100))
        self.input_text.setGraphicsEffect(shadow_input)
        self.input_text.setFixedHeight(120)
        content_layout.addWidget(self.input_text)

        # ---------------- Table ----------------
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Input","Issues","Score","Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeToContents)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(255,255,255,0.55);
                color:black;
                gridline-color:#999;
                font-size:12pt;
                border-radius:15px;
            }
            QTableWidget::item:hover {
                background-color: rgba(33, 150, 243, 0.25);
                color: black;
            }
            QHeaderView::section {
                background-color: #1565c0;
                color:white;
                font-weight:bold;
                font-size:12pt;
            }
        """)
        shadow_table = QGraphicsDropShadowEffect()
        shadow_table.setBlurRadius(25)
        shadow_table.setXOffset(0)
        shadow_table.setYOffset(5)
        shadow_table.setColor(QColor(0,0,0,160))
        self.results_table.setGraphicsEffect(shadow_table)
        content_layout.addWidget(self.results_table)

        # ---------------- Dashboard ----------------
        card_layout = QHBoxLayout()
        self.safe_card = AnimatedLabel()
        self.risk_card = AnimatedLabel()
        self.suspicious_card = AnimatedLabel()
        self.safe_card.setText("✅ SAFE\n0")
        self.risk_card.setText("⚠️ POTENTIAL\n0")
        self.suspicious_card.setText("❌ SUSPICIOUS\n0")

        for card, col in zip([self.safe_card, self.risk_card, self.suspicious_card],
                             ["#4caf50", "#ff9800", "#f44336"]):
            card.setAlignment(Qt.AlignCenter)
            card.setFont(QFont("Segoe UI", 14, QFont.Bold))
            card.setStyleSheet(f"""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                           stop:0 {col}, stop:1 #ffffff);
                border-radius:20px;
                color:black;
                padding:20px;
            """)
            shadow_card = QGraphicsDropShadowEffect()
            shadow_card.setBlurRadius(25)
            shadow_card.setXOffset(0)
            shadow_card.setYOffset(5)
            shadow_card.setColor(QColor(0,0,0,150))
            card.setGraphicsEffect(shadow_card)
            card_layout.addWidget(card)
        content_layout.addLayout(card_layout)
        main_layout.addLayout(content_layout)

    # ---------------- Slideshow with center crop ----------------
    def load_slideshow(self):
        self.images = []
        images_dir = os.path.join(self.script_dir, "images")
        if not os.path.exists(images_dir):
            os.makedirs(images_dir)
        for file in sorted(os.listdir(images_dir)):
            if file.lower().endswith((".png",".jpg",".jpeg")) and file.lower() != "bg.jpg":
                path = os.path.join(images_dir,file)
                if os.path.exists(path):
                    pix = QPixmap(path)
                    # Scale image to fill box and crop center
                    scaled_pix = pix.scaled(self.slideshow.width(), self.slideshow.height(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
                    x = (scaled_pix.width() - self.slideshow.width()) // 2
                    y = (scaled_pix.height() - self.slideshow.height()) // 2
                    cropped = scaled_pix.copy(x, y, self.slideshow.width(), self.slideshow.height())
                    self.images.append(cropped)
        if self.images:
            self.slideshow.setPixmap(self.images[0])
        else:
            self.slideshow.setText("No slideshow images found")

    def start_slideshow(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.next_slide)
        self.timer.start(3000)

    def next_slide(self):
        if not getattr(self, "images", None):
            return
        self.slideshow_index = (self.slideshow_index + 1) % len(self.images)
        next_pix = self.images[self.slideshow_index]

        fade_out = QPropertyAnimation(self.slideshow_opacity, b"opacity")
        fade_out.setDuration(400)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.finished.connect(lambda: self._switch_slide(next_pix))
        fade_out.start()
        self.active_slide_animations.append(fade_out)

    def _switch_slide(self, pix):
        self.slideshow.setPixmap(pix)
        fade_in = QPropertyAnimation(self.slideshow_opacity, b"opacity")
        fade_in.setDuration(400)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.start()
        self.active_slide_animations.append(fade_in)

    # ---------------- Analysis ----------------
    def analyze_input(self):
        text = self.input_text.toPlainText().strip()
        if not text:
            return
        self.results_table.setRowCount(0)
        self.results = []
        safe_count = risk_count = suspicious_count = 0
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        for entry in lines:
            if "@" in entry:
                score, issues = check_email(entry)
            else:
                score, issues = check_url(entry)

            if score >= 5:
                status = "SUSPICIOUS ❌"
                suspicious_count += 1
            elif score > 0:
                status = "POTENTIAL ⚠️"
                risk_count += 1
            else:
                status = "SAFE ✅"
                safe_count += 1

            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(entry))
            self.results_table.setItem(row, 1, QTableWidgetItem(", ".join(issues)))
            self.results_table.setItem(row, 2, QTableWidgetItem(str(score)))
            self.results_table.setItem(row, 3, QTableWidgetItem(status))

            self.results.append({
                "Input": entry,
                "Issues": ", ".join(issues),
                "Score": score,
                "Status": status
            })

        self.animate_count(self.safe_card, safe_count)
        self.animate_count(self.risk_card, risk_count)
        self.animate_count(self.suspicious_card, suspicious_count)

        if os.path.exists(self.history_file):
            try:
                df_existing = pd.read_csv(self.history_file)
                df = pd.concat([df_existing, pd.DataFrame(self.results)], ignore_index=True)
            except Exception:
                df = pd.DataFrame(self.results)
        else:
            df = pd.DataFrame(self.results)
        df.to_csv(self.history_file, index=False)

    def animate_count(self, label, final_value):
        anim = QPropertyAnimation(label, b"value")
        anim.setDuration(700)
        anim.setStartValue(0)
        anim.setEndValue(final_value)
        anim.start()
        self._active_animations.append(anim)
        def _cleanup():
            try:
                self._active_animations.remove(anim)
            except ValueError:
                pass
        anim.finished.connect(_cleanup)

    def export_csv(self):
        if not self.results:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            df = pd.DataFrame(self.results)
            df.to_csv(path, index=False)

    def show_history(self):
        if not os.path.exists(self.history_file):
            return
        df = pd.read_csv(self.history_file)
        self.results_table.setRowCount(0)
        safe_count = risk_count = suspicious_count = 0
        for _, entry in df.iterrows():
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            for col, val in enumerate([entry["Input"], entry["Issues"], str(entry["Score"]), entry["Status"]]):
                self.results_table.setItem(row, col, QTableWidgetItem(val))
            s = str(entry["Status"])
            if "❌" in s:
                suspicious_count += 1
            elif "⚠" in s:
                risk_count += 1
            else:
                safe_count += 1
        self.animate_count(self.safe_card, safe_count)
        self.animate_count(self.risk_card, risk_count)
        self.animate_count(self.suspicious_card, suspicious_count)

# ---------------- Run ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = SuspiciousChecker()
    w.show()
    sys.exit(app.exec_())
