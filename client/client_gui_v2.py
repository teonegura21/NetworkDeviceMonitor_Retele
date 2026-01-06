#!/usr/bin/env python3
"""
NMS Client - Modern PyQt6 UI (No Qt Designer)
Professional SIEM Dashboard Interface
"""

import sys
import socket
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QDialog, QDialogButtonBox,
    QFormLayout, QComboBox, QMessageBox, QHeaderView, QGridLayout,
    QGroupBox, QSpinBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor

# Matplotlib imports
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# ==============================================================================
# STYLING - Modern Dark Theme
# ==============================================================================
DARK_STYLESHEET = """
/* Main Application */
QMainWindow, QDialog, QWidget {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #3d3d3d;
    background-color: #252525;
}

QTabBar::tab {
    background-color: #2d2d2d;
    color: #a0a0a0;
    padding: 8px 16px;
    border: 1px solid #3d3d3d;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background-color: #252525;
    color: #ffffff;
    border-bottom: 2px solid #0078d4;
}

QTabBar::tab:hover {
    background-color: #3d3d3d;
}

/* Buttons */
QPushButton {
    background-color: #0078d4;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #1084d8;
}

QPushButton:pressed {
    background-color: #006cbd;
}

QPushButton:disabled {
    background-color: #3d3d3d;
    color: #666666;
}

/* Input Fields */
QLineEdit, QTextEdit, QSpinBox {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    padding: 6px;
}

QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #0078d4;
}

/* Tables */
QTableWidget {
    background-color: #2d2d2d;
    border: 1px solid #3d3d3d;
    gridline-color: #3d3d3d;
}

QTableWidget::item {
    padding: 4px;
    color: #e0e0e0;
}

QTableWidget::item:selected {
    background-color: #0078d4;
}

QHeaderView::section {
    background-color: #252525;
    color: #ffffff;
    padding: 6px;
    border: 1px solid #3d3d3d;
    font-weight: bold;
}

/* Group Boxes */
QGroupBox {
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: bold;
}

QGroupBox::title {
    color: #0078d4;
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}

/* ComboBox */
QComboBox {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    padding: 6px;
}

QComboBox::drop-down {
    border: none;
}

QComboBox::down-arrow {
    image: none;
    border-style: solid;
    border-width: 4px;
    border-color: #e0e0e0 transparent transparent transparent;
}

/* Status Bar */
QStatusBar {
    background-color: #252525;
    color: #a0a0a0;
    border-top: 1px solid #3d3d3d;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #2d2d2d;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #555555;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #0078d4;
}

/* Spinner Arrows - Modern Style */
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #3d3d3d;
    border: none;
    width: 20px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #0078d4;
}

QSpinBox::up-arrow {
    image: none;
    border-style: solid;
    border-width: 5px;
    border-color: transparent transparent #e0e0e0 transparent;
    width: 0px;
    height: 0px;
}

QSpinBox::down-arrow {
    image: none;
    border-style: solid;
    border-width: 5px;
    border-color: #e0e0e0 transparent transparent transparent;
    width: 0px;
    height: 0px;
}
"""

# ==============================================================================
# NETWORK CLIENT (Unchanged from original)
# ==============================================================================
class NetworkClient:
    """Handles communication with C++ server"""
    
    def __init__(self):
        self.sock = None
        self.connected = False
        self.buffer_size = 4096

    def connect(self, ip: str, port: int) -> tuple[bool, str]:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect((ip, port))
            self.sock.settimeout(None)
            self.connected = True
            welcome = self.sock.recv(self.buffer_size).decode('utf-8', errors='ignore')
            return True, f"Connected! {welcome.strip()}"
        except Exception as e:
            self.connected = False
            return False, f"Connection failed: {e}"

    def send(self, message: str) -> bool:
        if not self.connected:
            return False
        try:
            self.sock.sendall((message + "\n").encode('utf-8'))
            return True
        except:
            self.connected = False
            return False

    def receive(self) -> str:
        if not self.connected:
            return ""
        try:
            data = self.sock.recv(self.buffer_size)
            return data.decode('utf-8', errors='ignore').strip() if data else ""
        except:
            return ""

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.connected = False


# ==============================================================================
# LOGIN DIALOG - Modern styled login window
# ==============================================================================
class LoginDialog(QDialog):
    """Professional login dialog with validation"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NMS Client - Login")
        self.setModal(True)
        self.setMinimumSize(900, 600)
        self.resize(900, 600)
        
        # Results
        self.credentials = None
        self.login_attempts = 0
        self.max_attempts = 5
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("🔐 Network Monitoring System")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont("Segoe UI", 16, QFont.Weight.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #0078d4; margin-bottom: 10px;")
        layout.addWidget(title)
        
        subtitle = QLabel("Security Information & Event Management")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #a0a0a0; font-size: 9pt;")
        layout.addWidget(subtitle)
        
        # Simple form layout (no group boxes to avoid render issues)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        form_layout.setContentsMargins(10, 20, 10, 20)
        form_layout.setVerticalSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Server section label
        server_lbl = QLabel("Server Connection")
        server_lbl.setStyleSheet("color: #0078d4; font-weight: bold; margin-top: 10px;")
        form_layout.addRow(server_lbl)
        
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setMinimumHeight(35)
        form_layout.addRow("Server IP:", self.ip_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        self.port_input.setMinimumHeight(35)
        form_layout.addRow("Port:", self.port_input)
        
        # Auth section label
        auth_lbl = QLabel("Authentication")
        auth_lbl.setStyleSheet("color: #0078d4; font-weight: bold; margin-top: 15px;")
        form_layout.addRow(auth_lbl)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setMinimumHeight(35)
        form_layout.addRow("Username:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(35)
        form_layout.addRow("Password:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(35)
        self.login_btn.clicked.connect(self.validate_and_accept)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(35)
        self.cancel_btn.setStyleSheet("background-color: #3d3d3d;")
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.login_btn)
        layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #ff6b6b; font-size: 9pt;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
        # Enter key triggers login
        self.password_input.returnPressed.connect(self.validate_and_accept)
    
    def validate_and_accept(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        ip = self.ip_input.text().strip()
        port = self.port_input.value()
        
        if not username or not password:
            self.status_label.setText("⚠ Please enter both username and password")
            return
        
        if not ip:
            self.status_label.setText("⚠ Please enter server IP")
            return
        
        # Increment attempts
        self.login_attempts += 1
        
        self.credentials = {
            'username': username,
            'password': password,
            'ip': ip,
            'port': port
        }
        self.accept()


# ==============================================================================
# MAIN WINDOW - To be continued in next part...
# ==============================================================================
class MainWindow(QMainWindow):
    """Main application window - SIEM Dashboard"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NMS SIEM Dashboard")
        self.setGeometry(100, 100, 1400, 900)
        
        # Network client
        self.client = NetworkClient()
        self.current_user = ""
        self.user_role = ""
        
        # Timer for refresh
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        
        # First show login (loop until success or cancel)
        if not self._login_loop():
            sys.exit(0)
        
        # Build UI after successful login
        self._setup_ui()
        self._connect_server()
    
    def _login_loop(self) -> bool:
        """Loop login dialog until success or user cancels"""
        while True:
            dialog = LoginDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False  # User cancelled
            
            self.credentials = dialog.credentials
            
            # Try to connect and login
            if self._try_login():
                return True  # Success!
            
            # Failed - check attempts
            if dialog.login_attempts >= dialog.max_attempts:
                QMessageBox.critical(self, "Max Attempts Reached", 
                                     f"Failed to login after {dialog.max_attempts} attempts.")
                return False
            
            # Show error and loop back to dialog
            # (dialog will be shown again)
    
    def _try_login(self) -> bool:
        """Attempt to connect and login with current credentials"""
        creds = self.credentials
        
        # Connect
        success, msg = self.client.connect(creds['ip'], creds['port'])
        if not success:
            QMessageBox.critical(self, "Connection Error", 
                                 f"Could not connect to server.\n\n{msg}")
            return False
        
        # Login
        login_cmd = f"LOGIN {creds['username']} {creds['password']}"
        if not self.client.send(login_cmd):
            QMessageBox.critical(self, "Error", "Failed to send login command")
            self.client.disconnect()
            return False
        
        resp = self.client.receive()
        
        # Check response
        if "Login successful" in resp:
            # Success!
            self.current_user = creds['username']
            return True
        else:
            # Failed
            QMessageBox.warning(self, "Login Failed", 
                                f"Invalid credentials.\n\nServer: {resp}\n\nPlease try again.")
            self.client.disconnect()
            return False
    
    def _setup_ui(self):
        """Build the main interface"""
        # Central widget with tabs
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QVBoxLayout()
        central.setLayout(layout)
        
        # Status bar at top
        status_widget = self._create_status_bar()
        layout.addWidget(status_widget)
        
        # Tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Add tabs
        self.tabs.addTab(self._create_events_tab(), "📋 Events")
        self.tabs.addTab(self._create_dashboard_tab(), "📊 Dashboard")
        self.tabs.addTab(self._create_alerts_tab(), "🚨 Alerts")
        self.tabs.addTab(self._create_console_tab(), "💻 Console")
        
        # Admin-only tab
        # We'll add this after we know the user role
        
        # Status bar at bottom
        self.statusBar().showMessage("Ready")
    
    def _create_status_bar(self) -> QWidget:
        """Create status/connection bar"""
        widget = QWidget()
        widget.setFixedHeight(50)
        widget.setStyleSheet("background-color: #252525; border-bottom: 1px solid #3d3d3d;")
        
        layout = QHBoxLayout()
        widget.setLayout(layout)
        
        # Server info
        self.connection_status = QLabel("⚪ Disconnected")
        self.connection_status.setStyleSheet("font-weight: bold; color: #ff6b6b;")
        layout.addWidget(self.connection_status)
        
        layout.addStretch()
        
        # User info
        self.user_label = QLabel(f"👤 {self.credentials['username']}")
        self.user_label.setStyleSheet("color: #0078d4; font-weight: bold;")
        layout.addWidget(self.user_label)
        
        # Disconnect button
        disconnect_btn = QPushButton("Disconnect")
        disconnect_btn.setFixedWidth(100)
        disconnect_btn.setStyleSheet("background-color: #d13438;")
        disconnect_btn.clicked.connect(self.disconnect_and_exit)
        layout.addWidget(disconnect_btn)
        
        return widget
    
    def _create_events_tab(self) -> QWidget:
        """Events table with filtering"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Filter toolbar
        filter_toolbar = QWidget()
        filter_layout = QHBoxLayout()
        filter_toolbar.setLayout(filter_layout)
        
        filter_layout.addWidget(QLabel("🔍 Search:"))
        self.event_search = QLineEdit()
        self.event_search.setPlaceholderText("Search messages...")
        self.event_search.setFixedWidth(300)
        self.event_search.textChanged.connect(self._filter_events)
        filter_layout.addWidget(self.event_search)
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "0-Emergency", "1-Alert", "2-Critical", "3-Error", "4-Warning", "5-Notice", "6-Info", "7-Debug"])
        self.severity_filter.currentIndexChanged.connect(self._filter_events)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Limit:"))
        self.event_limit = QSpinBox()
        self.event_limit.setRange(10, 500)
        self.event_limit.setValue(100)
        filter_layout.addWidget(self.event_limit)
        
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self._fetch_events)
        filter_layout.addWidget(refresh_btn)
        
        filter_layout.addStretch()
        
        export_btn = QPushButton("📄 Export CSV")
        export_btn.setStyleSheet("background-color: #2d7d2d;")
        export_btn.clicked.connect(self._export_events)
        filter_layout.addWidget(export_btn)
        
        layout.addWidget(filter_toolbar)
        
        # Table
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Source", "Severity", "Type", "Message"])
        
        header = self.events_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        self.events_table.setSortingEnabled(True)
        layout.addWidget(self.events_table)
        
        # Stats
        self.event_stats = QLabel("Events: 0")
        self.event_stats.setStyleSheet("color: #a0a0a0; padding: 5px;")
        layout.addWidget(self.event_stats)
        
        # Store all events
        self.all_events = []
        
        return widget
    
    def _create_dashboard_tab(self) -> QWidget:
        """Dashboard with metrics charts"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Stats cards at top
        cards_layout = QHBoxLayout()
        
        self.total_events_card = self._create_stat_card("📊 Total Events", "0")
        cards_layout.addWidget(self.total_events_card)
        
        self.severity_high_card = self._create_stat_card("⚠️ Critical+", "0")
        cards_layout.addWidget(self.severity_high_card)
        
        self.sources_card = self._create_stat_card("💻 Sources", "0")
        cards_layout.addWidget(self.sources_card)
        
        layout.addLayout(cards_layout)
        
        # Charts
        charts_layout = QGridLayout()
        
        # 1. Events over time (line)
        self.fig_line = Figure(figsize=(6, 3), dpi=100, facecolor='#1e1e1e')
        self.canvas_line = FigureCanvas(self.fig_line)
        self.ax_line = self.fig_line.add_subplot(111, facecolor='#2d2d2d')
        self.ax_line.set_title("Events per Hour (Last 24h)", color='#e0e0e0')
        self.ax_line.tick_params(colors='#e0e0e0')
        charts_layout.addWidget(self.canvas_line, 0, 0, 1, 2)
        
        # 2. Severity distribution (pie)
        self.fig_pie = Figure(figsize=(4, 3), dpi=100, facecolor='#1e1e1e')
        self.canvas_pie = FigureCanvas(self.fig_pie)
        self.ax_pie = self.fig_pie.add_subplot(111, facecolor='#2d2d2d')
        self.ax_pie.set_title("Severity Distribution", color='#e0e0e0')
        charts_layout.addWidget(self.canvas_pie, 1, 0)
        
        # 3. Top sources (bar)
        self.fig_bar = Figure(figsize=(4, 3), dpi=100, facecolor='#1e1e1e')
        self.canvas_bar = FigureCanvas(self.fig_bar)
        self.ax_bar = self.fig_bar.add_subplot(111, facecolor='#2d2d2d')
        self.ax_bar.set_title("Top Log Sources", color='#e0e0e0')
        self.ax_bar.tick_params(colors='#e0e0e0')
        charts_layout.addWidget(self.canvas_bar, 1, 1)
        
        layout.addLayout(charts_layout)
        
        return widget
    
    def _create_stat_card(self, title, value) -> QGroupBox:
        """Create stats card widget"""
        card = QGroupBox(title)
        card.setStyleSheet("""
            QGroupBox {
                background-color: #252525;
                border: 2px solid #0078d4;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #0078d4;
            }
        """)
        layout = QVBoxLayout()
        card.setLayout(layout)
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("font-size: 24pt; color: #4caf50; font-weight: bold;")
        value_label.setObjectName("value")
        layout.addWidget(value_label)
        
        return card
    
    def _create_alerts_tab(self) -> QWidget:
        """Create the Alerts tab UI"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        widget.setLayout(layout)
        
        # Header
        header = QLabel("🚨 ML Anomaly Alerts")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #e74c3c;")
        layout.addWidget(header)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.alert_state_filter = QComboBox()
        self.alert_state_filter.addItems(["All", "Open", "Acknowledged", "Closed"])
        self.alert_state_filter.currentTextChanged.connect(self._on_alert_filter_changed)
        toolbar.addWidget(QLabel("State:"))
        toolbar.addWidget(self.alert_state_filter)
        
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self._fetch_alerts)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addStretch()
        self.alerts_stats_label = QLabel("0 alerts")
        self.alerts_stats_label.setStyleSheet("font-weight: bold; color: #e74c3c;")
        toolbar.addWidget(self.alerts_stats_label)
        
        layout.addLayout(toolbar)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(8)
        self.alerts_table.setHorizontalHeaderLabels([
            "ID", "Time", "Rule", "Severity", "State", "Score", "Source", "Message"
        ])
        
        # Style
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                gridline-color: #34495e;
                border: none;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: #ecf0f1;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
        """)
        
        # Column widths
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # ID
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Rule
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Severity
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # State
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Score
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Source
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)  # Message
        
        layout.addWidget(self.alerts_table)
        
        return widget
    
    def _fetch_alerts(self):
        """Fetch alerts from server"""
        if not self.client or not self.current_user:
            return
        
        cmd = f"QUERY_ALERTS {self.current_user} 100"
        if self.client.send(cmd):
            response = self.client.receive()
            if response and "ACK RESULTS" in response:
                self._populate_alerts_table(response)
    
    def _populate_alerts_table(self, response: str):
        """Parse and display alerts"""
        try:
            # Parse: ACK RESULTS count=N;id|time|rule|sev|state|score|src|msg;...
            parts = response.split(';', 1)
            if len(parts) < 2:
                return
            
            count_part = parts[0].split('count=')[1] if 'count=' in parts[0] else '0'
            count = int(count_part)
            
            self.alerts_stats_label.setText(f"{count} alerts")
            
            if count == 0:
                self.alerts_table.setRowCount(0)
                return
            
            # Parse alert data
            alert_data = parts[1].strip()
            alerts = alert_data.split(';')
            
            self.alerts_table.setRowCount(len(alerts) - 1 if alerts[-1] == '' else len(alerts))
            
            row = 0
            for alert in alerts:
                if not alert:
                    continue
                
                fields = alert.split('|')
                if len(fields) < 8:
                    continue
                
                alert_id, created_at, rule_id, severity, state, ml_score, src_ip, message = fields[:8]
                
                # ID
                self.alerts_table.setItem(row, 0, QTableWidgetItem(alert_id))
                
                # Time (just date + time, no milliseconds)
                time_str = created_at[:19] if len(created_at) > 19 else created_at
                self.alerts_table.setItem(row, 1, QTableWidgetItem(time_str))
                
                # Rule
                rule_item = QTableWidgetItem(rule_id)
                self.alerts_table.setItem(row, 2, rule_item)
                
                # Severity with color
                sev_item = QTableWidgetItem(severity)
                sev_int = int(severity) if severity.isdigit() else 6
                if sev_int <= 2:  # Critical/Alert
                    sev_item.setBackground(QColor(231, 76, 60))  # Red
                elif sev_int <= 4:  # Error/Warning
                    sev_item.setBackground(QColor(230, 126, 34))  # Orange
                else:
                    sev_item.setBackground(QColor(52, 152, 219))  # Blue
                self.alerts_table.setItem(row, 3, sev_item)
                
                # State
                state_item = QTableWidgetItem(state.capitalize())
                if state == 'open':
                    state_item.setForeground(QColor(231, 76, 60))
                elif state == 'acknowledged':
                    state_item.setForeground(QColor(230, 126, 34))
                else:
                    state_item.setForeground(QColor(46, 204, 113))
                self.alerts_table.setItem(row, 4, state_item)
                
                # ML Score
                self.alerts_table.setItem(row, 5, QTableWidgetItem(ml_score))
                
                # Source
                self.alerts_table.setItem(row, 6, QTableWidgetItem(src_ip))
                
                # Message (truncated)
                msg_preview = message[:100] + "..." if len(message) > 100 else message
                self.alerts_table.setItem(row, 7, QTableWidgetItem(msg_preview))
                
                row += 1
                
        except Exception as e:
            print(f"Error populating alerts: {e}")
    
    def _on_alert_filter_changed(self, state: str):
        """Filter alerts by state"""
        # For now just refresh - TODO: add state parameter to query
        self._fetch_alerts()
    
    def _create_console_tab(self) -> QWidget:
        """Interactive console - can send commands to server"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Output area (read-only)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console)
        
        # Input area
        input_layout = QHBoxLayout()
        
        input_label = QLabel("Command:")
        input_layout.addWidget(input_label)
        
        self.console_input = QLineEdit()
        self.console_input.setPlaceholderText("Enter server command (e.g., QUERY_EVENTS admin 10)")
        self.console_input.returnPressed.connect(self._send_console_command)
        input_layout.addWidget(self.console_input)
        
        send_btn = QPushButton("Send")
        send_btn.setFixedWidth(80)
        send_btn.clicked.connect(self._send_console_command)
        input_layout.addWidget(send_btn)
        
        layout.addLayout(input_layout)
        
        return widget
    
    def _send_console_command(self):
        """Send command from console input to server"""
        cmd = self.console_input.text().strip()
        if not cmd:
            return
        
        self.log(f">>> {cmd}")
        
        if self.client.send(cmd):
            resp = self.client.receive()
            if resp:
                self.log(f"<<< {resp}")
            else:
                self.log("<<< (no response)")
        else:
            self.log("❌ Failed to send (not connected)")
        
        # Clear input
        self.console_input.clear()
    
    def _connect_server(self):
        """Setup after successful login"""
        creds = self.credentials
        self.log(f"Connected to {creds['ip']}:{creds['port']} as {creds['username']}")
        
        # Update UI
        self.connection_status.setText("🟢 Connected")
        self.connection_status.setStyleSheet("font-weight: bold; color: #4caf50;")
        self.statusBar().showMessage(f"Logged in as {self.current_user}")
        self.log("✅ Authentication successful!")
        
        # Start refresh timer
        self.refresh_timer.start(5000)
        self.refresh_data()
    
    def log(self, message: str):
        """Add message to console"""
        timestamp = time.strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")
    
    def _on_timer(self):
        """Periodic update for active tabs"""
        if not self.client.connected:
            return

        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Events tab
            self._fetch_events()
        elif current_tab == 1:  # Dashboard tab
            self._fetch_metrics()
        elif current_tab == 2:  # Alerts tab
            self._fetch_alerts()
    
    def refresh_data(self):
        """Periodic data refresh - now handled by _on_timer based on active tab"""
        # This method is now largely superseded by _on_timer
        # It's kept for initial data load or if specific full refresh is needed
        if not self.client.connected:
            return
        
        # Fetch events
        self._fetch_events()
        
        # Fetch metrics (if on dashboard tab)
        if hasattr(self, 'tabs') and self.tabs.currentIndex() == 1:  # Dashboard is tab 1
            self._fetch_metrics()
    
    def _fetch_events(self):
        """Fetch events from server"""
        limit = self.event_limit.value() if hasattr(self, 'event_limit') else 100
        cmd = f"QUERY_EVENTS {self.current_user} {limit}"
        
        if self.client.send(cmd):
            resp = self.client.receive()
            if resp.startswith("RESULTS"):
                self.all_events = []
                try:
                    parts = resp.split(';', 1)
                    if len(parts) > 1:
                        events_str = parts[1]
                        events = events_str.split(';')
                        for evt in events:
                            if not evt: continue
                            fields = evt.split('|')
                            if len(fields) >= 5:
                                # New format: id|timestamp|src_ip|event_type|message
                                event_data = {
                                    'id': fields[0],
                                    'timestamp': fields[1][:19],
                                    'source': fields[2],
                                    'type': fields[3],
                                    'message': fields[4],
                                    'severity': '6'
                                }
                                self.all_events.append(event_data)
                            elif len(fields) >= 4:
                                # Old format fallback: id|timestamp|event_type|message
                                event_data = {
                                    'id': fields[0],
                                    'timestamp': fields[1][:19],
                                    'source': 'N/A',
                                    'type': fields[2],
                                    'message': fields[3],
                                    'severity': '6'
                                }
                                self.all_events.append(event_data)
                except Exception as e:
                    self.log(f"Parse error: {e}")
                
                self._filter_events()
    
    def _filter_events(self):
        """Apply filters to events"""
        if not hasattr(self, 'events_table'):
            return
        
        search = self.event_search.text().lower()
        sev_idx = self.severity_filter.currentIndex()
        
        filtered = []
        for evt in self.all_events:
            # Search filter
            if search and search not in evt['message'].lower():
                continue
            
            # Severity filter
            if sev_idx > 0:
                target_sev = str(sev_idx - 1)
                if evt['severity'] != target_sev:
                    continue
            
            filtered.append(evt)
        
        # Populate table
        self.events_table.setSortingEnabled(False)
        self.events_table.setRowCount(len(filtered))
        
        severity_colors = {
            '0': '#ff1744', '1': '#ff5722', '2': '#ff9800', '3': '#ff6b6b',
            '4': '#ffeb3b', '5': '#4caf50', '6': '#2196f3', '7': '#9e9e9e'
        }
        
        for row, evt in enumerate(filtered):
            self.events_table.setItem(row, 0, QTableWidgetItem(evt['id']))
            self.events_table.setItem(row, 1, QTableWidgetItem(evt['timestamp']))
            self.events_table.setItem(row, 2, QTableWidgetItem(evt['source']))
            
            sev_item = QTableWidgetItem(evt['severity'])
            sev_item.setForeground(QColor(severity_colors.get(evt['severity'], '#ffffff')))
            self.events_table.setItem(row, 3, sev_item)
            
            self.events_table.setItem(row, 4, QTableWidgetItem(evt['type']))
            self.events_table.setItem(row, 5, QTableWidgetItem(evt['message'][:200]))
        
        self.events_table.setSortingEnabled(True)
        self.event_stats.setText(f"Showing {len(filtered)} of {len(self.all_events)} events")
    
    def _export_events(self):
        """Export events to CSV"""
        import csv
        from datetime import datetime
        filename = f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'Source', 'Severity', 'Type', 'Message'])
                
                for row in range(self.events_table.rowCount()):
                    row_data = [self.events_table.item(row, col).text() for col in range(6)]
                    writer.writerow(row_data)
            
            QMessageBox.information(self, "Export Success", f"Exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
    
    def _fetch_metrics(self):
        """Fetch dashboard metrics"""
        # 1. Events over time
        time_data = self._query_metric("events_over_time")
        # 2. Severity
        sev_data = self._query_metric("severity_dist")
        # 3. Top sources
        src_data = self._query_metric("top_sources")
        
        self._update_dashboard(time_data, sev_data, src_data)
    
    def _query_metric(self, metric_type):
        """Helper to query metrics"""
        data = []
        cmd = f"QUERY_METRICS {self.current_user} {metric_type}"
        if self.client.send(cmd):
            resp = self.client.receive()
            if resp.startswith("RESULTS"):
                try:
                    parts = resp.split(';', 1)
                    if len(parts) > 1:
                        items = parts[1].split(';')
                        for item in items:
                            if '|' in item:
                                data.append(item.split('|'))
                except: pass
        return data
    
    def _update_dashboard(self, time_data, sev_data, src_data):
        """Update dashboard charts"""
        # Update stat cards
        total = sum(int(x[1]) for x in time_data) if time_data else 0
        critical = sum(int(x[1]) for x in sev_data if int(x[0]) <= 2) if sev_data else 0
        sources = len(src_data)
        
        if hasattr(self, 'total_events_card'):
            self.total_events_card.findChild(QLabel, "value").setText(str(total))
            self.severity_high_card.findChild(QLabel, "value").setText(str(critical))
            self.sources_card.findChild(QLabel, "value").setText(str(sources))
        
        # Line chart
        self.ax_line.clear()
        self.ax_line.set_facecolor('#2d2d2d')
        self.ax_line.set_title("Events per Hour (Last 24h)", color='#e0e0e0')
        if time_data:
            hours = [x[0][11:13] for x in time_data]
            counts = [int(x[1]) for x in time_data]
            hours.reverse()
            counts.reverse()
            self.ax_line.plot(hours, counts, marker='o', color='#0078d4', linewidth=2)
            self.ax_line.grid(True, alpha=0.3)
        self.ax_line.tick_params(colors='#e0e0e0')
        self.canvas_line.draw()
        
        # Pie chart
        self.ax_pie.clear()
        self.ax_pie.set_facecolor('#2d2d2d')
        self.ax_pie.set_title("Severity Distribution", color='#e0e0e0')
        if sev_data:
            labels = [f"Sev {x[0]}" for x in sev_data]
            sizes = [int(x[1]) for x in sev_data]
            colors = ['#ff1744', '#ff5722', '#ff9800', '#ff6b6b', '#ffeb3b', '#4caf50', '#2196f3', '#9e9e9e']
            self.ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(sizes)], textprops={'color': '#e0e0e0'})
        self.canvas_pie.draw()
        
        # Bar chart
        self.ax_bar.clear()
        self.ax_bar.set_facecolor('#2d2d2d')
        self.ax_bar.set_title("Top Log Sources", color='#e0e0e0')
        if src_data:
            import numpy as np
            sources = [x[0][:15] for x in src_data]
            counts = [int(x[1]) for x in src_data]
            y_pos = np.arange(len(sources))
            self.ax_bar.barh(y_pos, counts, color='#4caf50')
            self.ax_bar.set_yticks(y_pos)
            self.ax_bar.set_yticklabels(sources)
            self.ax_bar.invert_yaxis()
        self.ax_bar.tick_params(colors='#e0e0e0')
        self.canvas_bar.draw()
    
    def disconnect_and_exit(self):
        """Clean disconnect and close"""
        self.refresh_timer.stop()
        self.client.disconnect()
        self.close()
    
    def closeEvent(self, event):
        """Cleanup on close"""
        self.refresh_timer.stop()
        self.client.disconnect()
        event.accept()


# ==============================================================================
# MAIN
# ==============================================================================
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
