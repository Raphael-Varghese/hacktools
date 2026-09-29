#!/usr/bin/env python3
import base64
import binascii
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PySide6.QtCore import Qt, QThread, Signal, QSize
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QLineEdit, QPushButton, QLabel, QComboBox,
    QTreeWidget, QTreeWidgetItem, QCheckBox, QSpinBox,
    QGroupBox, QFormLayout, QHeaderView, QMenu, QMenuBar,
    QFileDialog, QMessageBox, QInputDialog, QPlainTextEdit,
    QStatusBar, QToolBar, QFrame, QStackedWidget, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QProgressBar,
    QRadioButton, QButtonGroup, QKeySequenceEdit, QShortcut
)
import httpx


CA_CERT_PATH = os.path.expanduser("~/.pyburp/ca.crt")
CA_KEY_PATH = os.path.expanduser("~/.pyburp/ca.key")
CERTS_DIR = os.path.expanduser("~/.pyburp/certs")


def ensure_ca():
    os.makedirs(os.path.dirname(CA_CERT_PATH), exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "PyBurp"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "PyBurp CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 10)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def get_host_cert(hostname: str):
    os.makedirs(CERTS_DIR, exist_ok=True)
    path = os.path.join(CERTS_DIR, f"{hostname}.pem")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "PyBurp"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 1)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False).sign(ca_key, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    with open(path, "wb") as f:
        f.write(pem)
    return pem


class ProxyItem:
    def __init__(self, req_id: int, method: str, url: str, status: int = 0, length: int = 0, mime: str = "", extension: str = "", comment: str = ""):
        self.id = req_id
        self.method = method
        self.url = url
        self.status = status
        self.length = length
        self.mime = mime
        self.extension = extension
        self.comment = comment
        self.request_raw = b""
        self.response_raw = b""
        self.host = ""
        self.port = 80
        self.ssl = False
        self.time = datetime.now().isoformat()


class ProxyThread(QThread):
    new_request = Signal(object)
    request_ready = Signal(int, object)
    def __init__(self, parent, port: int = 8080):
        super().__init__(parent)
        self.port = port
        self.intercept = False
        self.running = True
        self.lock = threading.Lock()
        self.pending: Dict[int, Dict] = {}
        self.counter = 0
        self.parent = parent
        ensure_ca()

    def set_intercept(self, enabled: bool):
        with self.lock:
            self.intercept = enabled

    def forward(self, req_id: int, modified_request: Optional[bytes] = None):
        with self.lock:
            if req_id in self.pending:
                self.pending[req_id]["action"] = "forward"
                if modified_request:
                    self.pending[req_id]["modified"] = modified_request
                self.pending[req_id]["event"].set()

    def drop(self, req_id: int):
        with self.lock:
            if req_id in self.pending:
                self.pending[req_id]["action"] = "drop"
                self.pending[req_id]["event"].set()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(100)
        sock.settimeout(1.0)
        while self.running:
            try:
                client, addr = sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()

    def _handle_client(self, client: socket.socket):
        try:
            client.settimeout(30.0)
            data = client.recv(65536)
            if not data:
                client.close()
                return
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                client.close()
                return
            headers = data[:header_end].decode("utf-8", errors="ignore")
            lines = headers.split("\r\n")
            if not lines:
                client.close()
                return
            first_line = lines[0]
            if first_line.startswith("CONNECT"):
                self._handle_connect(client, first_line, data)
                return
            self._handle_http(client, first_line, headers, data)
        except Exception:
            client.close()

    def _handle_connect(self, client: socket.socket, first_line: str, raw: bytes):
        parts = first_line.split()
        if len(parts) < 2:
            client.close()
            return
        host_port = parts[1]
        host, port = host_port.split(":") if ":" in host_port else (host_port, "443")
        port = int(port)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_pem = get_host_cert(host)
        ctx.load_cert_chain(certfile=os.path.join(CERTS_DIR, f"{host}.pem"))
        ssl_client = ctx.wrap_socket(client, server_side=True)
        try:
            data = ssl_client.recv(65536)
            if not data:
                ssl_client.close()
                return
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                ssl_client.close()
                return
            headers = data[:header_end].decode("utf-8", errors="ignore")
            lines = headers.split("\r\n")
            self._handle_http(ssl_client, lines[0], headers, data, ssl=True, host=host, port=port)
        except Exception:
            ssl_client.close()

    def _handle_http(self, client, first_line: str, headers_str: str, raw: bytes, ssl: bool = False, host: str = "", port: int = 80):
        parts = first_line.split()
        if len(parts) < 3:
            client.close()
            return
        method = parts[0]
        path = parts[1]
        hdr_lines = headers_str.split("\r\n")[1:]
        hdrs = {}
        for h in hdr_lines:
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()
        target_host = hdrs.get("Host", host)
        if not target_host:
            client.close()
            return
        if ":" in target_host:
            target_host, target_port = target_host.split(":")
            target_port = int(target_port)
        else:
            target_port = 443 if ssl else 80
        if port != 80 and port != 443:
            target_port = port
        url = f"{'https' if ssl else 'http'}://{target_host}:{target_port}{path}"
        with self.lock:
            self.counter += 1
            req_id = self.counter
        item = ProxyItem(req_id, method, url)
        item.host = target_host
        item.port = target_port
        item.ssl = ssl
        item.request_raw = raw
        self.new_request.emit(item)
        with self.lock:
            do_intercept = self.intercept
        if do_intercept:
            import threading
            evt = threading.Event()
            pending_data = {"event": evt, "action": "", "modified": None}
            with self.lock:
                self.pending[req_id] = pending_data
            self.request_ready.emit(req_id, item)
            evt.wait()
            with self.lock:
                action = pending_data["action"]
                modified = pending_data.get("modified")
                del self.pending[req_id]
            if action == "drop":
                client.close()
                return
            if modified:
                raw = modified
                item.request_raw = modified
        body = raw[raw.find(b"\r\n\r\n") + 4:] if b"\r\n\r\n" in raw else b""
        try:
            if ssl:
                remote = socket.create_connection((target_host, target_port), timeout=30)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                remote = ctx.wrap_socket(remote, server_hostname=target_host)
            else:
                remote = socket.create_connection((target_host, target_port), timeout=30)
            remote.sendall(raw)
            resp = b""
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                resp += chunk
            remote.close()
            item.response_raw = resp
            status = 0
            try:
                first = resp.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                m = re.search(r"\s(\d{3})\s", first)
                if m:
                    status = int(m.group(1))
            except Exception:
                pass
            item.status = status
            item.length = len(resp)
            self.new_request.emit(item)
            client.sendall(resp)
        except Exception as e:
            err = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(e))}\r\n\r\n{str(e)}".encode()
            client.sendall(err)
        client.close()


class InterceptTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.current_id = 0
        self.layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.intercept_btn = QPushButton("Intercept is off")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.setStyleSheet("QPushButton { background-color: #888; color: white; font-weight: bold; } QPushButton:checked { background-color: #e74c3c; }")
        self.intercept_btn.toggled.connect(self.toggle_intercept)
        top.addWidget(self.intercept_btn)
        self.forward_btn = QPushButton("Forward")
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self.do_forward)
        top.addWidget(self.forward_btn)
        self.drop_btn = QPushButton("Drop")
        self.drop_btn.setEnabled(False)
        self.drop_btn.clicked.connect(self.do_drop)
        top.addStretch()
        self.layout.addLayout(top)
        splitter = QSplitter(Qt.Vertical)
        self.req_edit = QPlainTextEdit()
        self.req_edit.setPlaceholderText("Intercepted request will appear here...")
        font = QFont("Consolas", 10)
        self.req_edit.setFont(font)
        splitter.addWidget(self._wrap("Request", self.req_edit))
        self.resp_edit = QPlainTextEdit()
        self.resp_edit.setPlaceholderText("Response will appear here...")
        self.resp_edit.setFont(font)
        self.resp_edit.setReadOnly(True)
        splitter.addWidget(self._wrap("Response", self.resp_edit))
        self.layout.addWidget(splitter)

    def _wrap(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(widget)
        return box

    def toggle_intercept(self, checked: bool):
        self.parent.proxy_thread.set_intercept(checked)
        self.intercept_btn.setText("Intercept is on" if checked else "Intercept is off")

    def load_request(self, req_id: int, item: ProxyItem):
        self.current_id = req_id
        self.req_edit.setPlainText(item.request_raw.decode("utf-8", errors="replace"))
        self.resp_edit.setPlainText("")
        self.forward_btn.setEnabled(True)
        self.drop_btn.setEnabled(True)

    def do_forward(self):
        raw = self.req_edit.toPlainText().encode("utf-8")
        self.parent.proxy_thread.forward(self.current_id, raw)
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)

    def do_drop(self):
        self.parent.proxy_thread.drop(self.current_id)
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)


class ProxyHistoryTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["#", "Host", "Method", "URL", "Status", "Length", "MIME", "Comment"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)
        self.table.itemClicked.connect(self.item_clicked)
        self.layout.addWidget(self.table)
        self.items: Dict[int, ProxyItem] = {}
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter...")
        self.layout.addWidget(self.filter_edit)
        bottom = QSplitter(Qt.Horizontal)
        self.req_view = QPlainTextEdit()
        self.req_view.setReadOnly(True)
        self.resp_view = QPlainTextEdit()
        self.resp_view.setReadOnly(True)
        bottom.addWidget(self._wrap("Request", self.req_view))
        bottom.addWidget(self._wrap("Response", self.resp_view))
        self.layout.addWidget(bottom)

    def _wrap(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(widget)
        return box

    def add_or_update(self, item: ProxyItem):
        self.items[item.id] = item
        row = item.id - 1
        if row >= self.table.rowCount():
            self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(item.id)))
        self.table.setItem(row, 1, QTableWidgetItem(item.host))
        self.table.setItem(row, 2, QTableWidgetItem(item.method))
        self.table.setItem(row, 3, QTableWidgetItem(item.url))
        self.table.setItem(row, 4, QTableWidgetItem(str(item.status) if item.status else ""))
        self.table.setItem(row, 5, QTableWidgetItem(str(item.length)))
        self.table.setItem(row, 6, QTableWidgetItem(item.mime))
        self.table.setItem(row, 7, QTableWidgetItem(item.comment))
        if item.status >= 400:
            self.table.item(row, 4).setBackground(QColor("#ffcccc"))
        elif item.status in (301, 302, 307):
            self.table.item(row, 4).setBackground(QColor("#ffffcc"))
        elif item.status == 200:
            self.table.item(row, 4).setBackground(QColor("#ccffcc"))

    def item_clicked(self):
        row = self.table.currentRow()
        req_id = int(self.table.item(row, 0).text())
        item = self.items.get(req_id)
        if item:
            self.req_view.setPlainText(item.request_raw.decode("utf-8", errors="replace"))
            self.resp_view.setPlainText(item.response_raw.decode("utf-8", errors="replace") if item.response_raw else "")

    def context_menu(self, pos):
        menu = QMenu(self)
        send_repeater = QAction("Send to Repeater", self)
        send_repeater.triggered.connect(self.to_repeater)
        menu.addAction(send_repeater)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def to_repeater(self):
        row = self.table.currentRow()
        req_id = int(self.table.item(row, 0).text())
        item = self.items.get(req_id)
        if item:
            self.parent.repeater_tab.load_request(item.request_raw.decode("utf-8", errors="replace"))
            self.parent.tabs.setCurrentIndex(2)


class RepeaterTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_request)
        top.addWidget(self.send_btn)
        top.addStretch()
        self.layout.addLayout(top)
        splitter = QSplitter(Qt.Vertical)
        self.req_edit = QPlainTextEdit()
        self.req_edit.setPlaceholderText("Paste raw HTTP request here...")
        font = QFont("Consolas", 10)
        self.req_edit.setFont(font)
        splitter.addWidget(self._wrap("Request", self.req_edit))
        self.resp_edit = QPlainTextEdit()
        self.resp_edit.setReadOnly(True)
        self.resp_edit.setFont(font)
        splitter.addWidget(self._wrap("Response", self.resp_edit))
        self.layout.addWidget(splitter)

    def _wrap(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(widget)
        return box

    def load_request(self, raw: str):
        self.req_edit.setPlainText(raw)

    def send_request(self):
        raw = self.req_edit.toPlainText().encode("utf-8")
        self.resp_edit.setPlainText("Sending...")
        threading.Thread(target=self._do_send, args=(raw,), daemon=True).start()

    def _do_send(self, raw: bytes):
        try:
            lines = raw.split(b"\r\n")
            if not lines:
                return
            first = lines[0].decode("utf-8", errors="ignore")
            parts = first.split()
            if len(parts) < 3:
                return
            method = parts[0]
            path = parts[1]
            hdrs = {}
            host = ""
            for line in lines[1:]:
                if line == b"":
                    break
                if b":" in line:
                    k, v = line.split(b":", 1)
                    hdrs[k.strip().decode("utf-8", errors="ignore")] = v.strip().decode("utf-8", errors="ignore")
                    if k.strip().lower() == b"host":
                        host = v.strip().decode("utf-8", errors="ignore")
            if not host:
                return
            body = raw[raw.find(b"\r\n\r\n") + 4:] if b"\r\n\r\n" in raw else b""
            url = f"http://{host}{path}"
            if path.startswith("http"):
                url = path
            r = httpx.request(method, url, headers=hdrs, content=body, timeout=30.0, verify=False)
            resp = f"HTTP/{r.http_version} {r.status_code} {r.reason_phrase}\r\n"
            for k, v in r.headers.items():
                resp += f"{k}: {v}\r\n"
            resp += "\r\n"
            resp += r.text
            self.resp_edit.setPlainText(resp)
        except Exception as e:
            self.resp_edit.setPlainText(f"Error: {e}")


class DecoderTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText("Enter data to decode/encode...")
        font = QFont("Consolas", 10)
        self.input_edit.setFont(font)
        self.layout.addWidget(self._wrap("Input", self.input_edit))
        btn_row = QHBoxLayout()
        self.url_enc = QPushButton("URL Encode")
        self.url_enc.clicked.connect(self.do_url_enc)
        btn_row.addWidget(self.url_enc)
        self.url_dec = QPushButton("URL Decode")
        self.url_dec.clicked.connect(self.do_url_dec)
        btn_row.addWidget(self.url_dec)
        self.b64_enc = QPushButton("Base64 Encode")
        self.b64_enc.clicked.connect(self.do_b64_enc)
        btn_row.addWidget(self.b64_enc)
        self.b64_dec = QPushButton("Base64 Decode")
        self.b64_dec.clicked.connect(self.do_b64_dec)
        btn_row.addWidget(self.b64_dec)
        self.hex_enc = QPushButton("Hex Encode")
        self.hex_enc.clicked.connect(self.do_hex_enc)
        btn_row.addWidget(self.hex_enc)
        self.hex_dec = QPushButton("Hex Decode")
        self.hex_dec.clicked.connect(self.do_hex_dec)
        btn_row.addWidget(self.hex_dec)
        self.html_enc = QPushButton("HTML Encode")
        self.html_enc.clicked.connect(self.do_html_enc)
        btn_row.addWidget(self.html_enc)
        self.html_dec = QPushButton("HTML Decode")
        self.html_dec.clicked.connect(self.do_html_dec)
        btn_row.addWidget(self.html_dec)
        btn_row.addStretch()
        self.layout.addLayout(btn_row)
        self.output_edit = QPlainTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFont(font)
        self.layout.addWidget(self._wrap("Output", self.output_edit))

    def _wrap(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(widget)
        return box

    def do_url_enc(self):
        self.output_edit.setPlainText(urllib.parse.quote(self.input_edit.toPlainText()))

    def do_url_dec(self):
        try:
            self.output_edit.setPlainText(urllib.parse.unquote(self.input_edit.toPlainText()))
        except Exception as e:
            self.output_edit.setPlainText(f"Error: {e}")

    def do_b64_enc(self):
        self.output_edit.setPlainText(base64.b64encode(self.input_edit.toPlainText().encode()).decode())

    def do_b64_dec(self):
        try:
            self.output_edit.setPlainText(base64.b64decode(self.input_edit.toPlainText()).decode("utf-8", errors="replace"))
        except Exception as e:
            self.output_edit.setPlainText(f"Error: {e}")

    def do_hex_enc(self):
        self.output_edit.setPlainText(self.input_edit.toPlainText().encode().hex())

    def do_hex_dec(self):
        try:
            self.output_edit.setPlainText(bytes.fromhex(self.input_edit.toPlainText()).decode("utf-8", errors="replace"))
        except Exception as e:
            self.output_edit.setPlainText(f"Error: {e}")

    def do_html_enc(self):
        import html
        self.output_edit.setPlainText(html.escape(self.input_edit.toPlainText()))

    def do_html_dec(self):
        import html
        self.output_edit.setPlainText(html.unescape(self.input_edit.toPlainText()))


class ScannerTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.layout = QVBoxLayout(self)
        form = QFormLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        form.addRow("Target URL:", self.target_input)
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        form.addRow(self.scan_btn)
        self.layout.addLayout(form)
        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        font = QFont("Consolas", 10)
        self.results.setFont(font)
        self.layout.addWidget(self._wrap("Results", self.results))

    def _wrap(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(widget)
        return box

    def log(self, msg: str):
        self.results.appendPlainText(msg)

    def start_scan(self):
        url = self.target_input.text().strip()
        if not url:
            return
        self.results.setPlainText("")
        self.log(f"[*] Starting scan of {url}")
        threading.Thread(target=self._scan, args=(url,), daemon=True).start()

    def _scan(self, url: str):
        try:
            r = httpx.get(url, timeout=30.0, verify=False)
            self.log(f"[+] Status: {r.status_code}")
            server = r.headers.get("Server", "Unknown")
            self.log(f"[+] Server: {server}")
            security_headers = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"]
            for h in security_headers:
                if h not in r.headers:
                    self.log(f"[-] Missing security header: {h}")
                else:
                    self.log(f"[+] {h}: {r.headers[h]}")
            common_paths = ["/admin", "/login", "/.env", "/robots.txt", "/phpinfo.php", "/.git/config", "/api", "/swagger-ui.html"]
            for path in common_paths:
                try:
                    full = url.rstrip("/") + path
                    resp = httpx.get(full, timeout=10.0, verify=False)
                    if resp.status_code in (200, 301, 302, 401, 403):
                        self.log(f"[!] Found: {full} ({resp.status_code})")
                except Exception:
                    pass
            self.log("[*] Scan complete")
        except Exception as e:
            self.log(f"[!] Scan error: {e}")


class TargetTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Target", "Details"])
        self.layout.addWidget(self.tree)

    def add_target(self, host: str, item: ProxyItem):
        nodes = self.tree.findItems(host, Qt.MatchExactly, 0)
        if not nodes:
            node = QTreeWidgetItem(self.tree)
            node.setText(0, host)
            node.setText(1, f"{item.port} {'SSL' if item.ssl else ''}")
            self.tree.addTopLevelItem(node)
        else:
            node = nodes[0]
        child = QTreeWidgetItem(node)
        child.setText(0, item.method)
        child.setText(1, item.url)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyBurp Suite")
        self.setGeometry(100, 100, 1400, 900)
        self.proxy_thread = ProxyThread(self, port=8080)
        self.proxy_thread.new_request.connect(self.on_proxy_update)
        self.proxy_thread.request_ready.connect(self.on_intercept_request)
        self.proxy_thread.start()
        self.build_ui()
        self.statusBar().showMessage("Proxy running on 127.0.0.1:8080")

    def build_ui(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.intercept_tab = InterceptTab(self)
        self.tabs.addTab(self.intercept_tab, "Intercept")
        self.proxy_history_tab = ProxyHistoryTab(self)
        self.tabs.addTab(self.proxy_history_tab, "Proxy History")
        self.target_tab = TargetTab(self)
        self.tabs.addTab(self.target_tab, "Target")
        self.repeater_tab = RepeaterTab(self)
        self.tabs.addTab(self.repeater_tab, "Repeater")
        self.decoder_tab = DecoderTab(self)
        self.tabs.addTab(self.decoder_tab, "Decoder")
        self.scanner_tab = ScannerTab(self)
        self.tabs.addTab(self.scanner_tab, "Scanner")
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        proxy_menu = menu.addMenu("Proxy")
        ca_action = QAction("Export CA Cert", self)
        ca_action.triggered.connect(self.export_ca)
        proxy_menu.addAction(ca_action)

    def on_proxy_update(self, item: ProxyItem):
        self.proxy_history_tab.add_or_update(item)
        self.target_tab.add_target(item.host, item)

    def on_intercept_request(self, req_id: int, item: ProxyItem):
        self.intercept_tab.load_request(req_id, item)

    def export_ca(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CA Certificate", "pyburp-ca.crt", "CRT (*.crt)")
        if path:
            with open(CA_CERT_PATH, "rb") as f:
                data = f.read()
            with open(path, "wb") as f:
                f.write(data)
            QMessageBox.information(self, "CA Cert", f"CA certificate exported to {path}")

    def closeEvent(self, event):
        self.proxy_thread.running = False
        self.proxy_thread.wait(2000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PyBurp Suite")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
