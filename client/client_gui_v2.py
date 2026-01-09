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

# Local imports
from user_preferences import get_preferences, FilterPresets

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
        self.buffer_size = 65536  # Increased from 4096 to handle large responses

    def connect(self, ip: str, port: int) -> tuple[bool, str]:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect((ip, port))
            self.sock.settimeout(5)  # Keep timeout for receive
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
            # Receive data in a loop until we have complete response
            chunks = []
            total_received = 0
            max_size = 128 * 1024  # 128KB max
            
            self.sock.settimeout(2)  # Short timeout for subsequent chunks
            
            while total_received < max_size:
                try:
                    data = self.sock.recv(self.buffer_size)
                    if not data:
                        break
                    chunks.append(data)
                    total_received += len(data)
                    
                    # If we received less than buffer, likely end of message
                    if len(data) < self.buffer_size:
                        break
                except socket.timeout:
                    break  # No more data coming
                except:
                    break
            
            result = b''.join(chunks).decode('utf-8', errors='ignore').strip()
            return result
        except Exception as e:
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
        self.username_input.returnPressed.connect(self._focus_password)  # Enter → password
        form_layout.addRow("Username:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(35)
        self.password_input.returnPressed.connect(self.validate_and_accept)  # Enter → login
        form_layout.addRow("Password:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(35)
        self.login_btn.clicked.connect(self.validate_and_accept)
        self.login_btn.setDefault(True)  # Make Login the default button
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(35)
        self.cancel_btn.setStyleSheet("background-color: #3d3d3d;")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setAutoDefault(False)  # Prevent Enter from triggering Cancel
        
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
    
    def _focus_password(self):
        """Move focus to password field when Enter pressed in username"""
        self.password_input.setFocus()
    
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
        
        # Dashboard configuration
        self.dashboard_time_range = "24h"  # Default: Last 24 hours
        
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
            # Load saved filter preferences
            QTimer.singleShot(500, self._load_saved_preferences)
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
        self.tabs.addTab(self._create_network_tab(), "🌐 Network")
        self.tabs.addTab(self._create_console_tab(), "💻 Console")
        
        # Admin-only tab (added for all, visibility controlled by role)
        self.admin_tab = self._create_admin_tab()
        self.admin_tab_index = self.tabs.addTab(self.admin_tab, "⚙️ Admin")
        
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
        """Events table with advanced filtering"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Filter panel - Two rows for better organization
        filter_panel = QGroupBox("🔍 Filters")
        filter_panel.setStyleSheet("QGroupBox { font-weight: bold; padding-top: 10px; }")
        filter_vbox = QVBoxLayout()
        filter_panel.setLayout(filter_vbox)
        
        # Row 1: Search, Severity, Time Range
        row1 = QHBoxLayout()
        
        row1.addWidget(QLabel("Search:"))
        self.event_search = QLineEdit()
        self.event_search.setPlaceholderText("Search messages...")
        self.event_search.setFixedWidth(200)
        self.event_search.textChanged.connect(self._filter_events)
        row1.addWidget(self.event_search)
        
        row1.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "0-Emergency", "1-Alert", "2-Critical", "3-Error", "4-Warning", "5-Notice", "6-Info", "7-Debug"])
        self.severity_filter.currentIndexChanged.connect(self._filter_events)
        row1.addWidget(self.severity_filter)
        
        row1.addWidget(QLabel("Time Range:"))
        self.time_range_filter = QComboBox()
        self.time_range_filter.addItems(["All", "Last 1 Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"])
        self.time_range_filter.currentIndexChanged.connect(self._on_filter_changed)
        row1.addWidget(self.time_range_filter)
        
        row1.addStretch()
        filter_vbox.addLayout(row1)
        
        # Row 2: Source IP, Event Type, Limit, Actions
        row2 = QHBoxLayout()
        
        row2.addWidget(QLabel("Source IP:"))
        self.source_ip_filter = QLineEdit()
        self.source_ip_filter.setPlaceholderText("e.g. 192.168.1.1")
        self.source_ip_filter.setFixedWidth(150)
        self.source_ip_filter.textChanged.connect(self._filter_events)
        row2.addWidget(self.source_ip_filter)
        
        row2.addWidget(QLabel("Event Type:"))
        self.event_type_filter = QComboBox()
        self.event_type_filter.addItems(["All", "syslog", "auth", "network", "security"])
        self.event_type_filter.currentIndexChanged.connect(self._filter_events)
        row2.addWidget(self.event_type_filter)
        
        row2.addWidget(QLabel("Limit:"))
        self.event_limit = QSpinBox()
        self.event_limit.setRange(10, 500)
        self.event_limit.setValue(100)
        row2.addWidget(self.event_limit)
        
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self._fetch_events)
        row2.addWidget(refresh_btn)
        
        save_filter_btn = QPushButton("💾 Save Filters")
        save_filter_btn.setStyleSheet("background-color: #2d5d7d;")
        save_filter_btn.clicked.connect(self._save_event_filters)
        row2.addWidget(save_filter_btn)
        
        row2.addStretch()
        
        export_btn = QPushButton("📄 Export CSV")
        export_btn.setStyleSheet("background-color: #2d7d2d;")
        export_btn.clicked.connect(self._export_events)
        row2.addWidget(export_btn)
        
        filter_vbox.addLayout(row2)
        layout.addWidget(filter_panel)
        
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
        
        # ====== MODULAR CONTROLS ======
        controls_group = QGroupBox("⚙️ Dashboard Configuration")
        controls_layout = QHBoxLayout()
        controls_group.setLayout(controls_layout)
        
        # Time Range Selector
        controls_layout.addWidget(QLabel("📅 Time Range:"))
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems(["Last 1 Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "Last 30 Days"])
        self.time_range_combo.setCurrentIndex(2)  # Default: Last 24 Hours
        self.time_range_combo.currentIndexChanged.connect(self._on_time_range_changed)
        controls_layout.addWidget(self.time_range_combo)
        
        controls_layout.addSpacing(20)
        
        # Refresh Rate Selector
        controls_layout.addWidget(QLabel("🔄 Auto-Refresh:"))
        self.refresh_rate_combo = QComboBox()
        self.refresh_rate_combo.addItems(["Off", "5 seconds", "10 seconds", "30 seconds", "60 seconds"])
        self.refresh_rate_combo.setCurrentIndex(2)  # Default: 10 seconds
        self.refresh_rate_combo.currentIndexChanged.connect(self._on_refresh_rate_changed)
        controls_layout.addWidget(self.refresh_rate_combo)
        
        controls_layout.addSpacing(20)
        
        # Manual Refresh Button
        refresh_btn = QPushButton("🔃 Refresh Now")
        refresh_btn.clicked.connect(self._refresh_dashboard)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        layout.addWidget(controls_group)
        
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
        
        # Widget Configuration Panel (Phase 4)
        config_group = QGroupBox("📐 Dashboard Widgets")
        config_layout = QHBoxLayout()
        config_group.setLayout(config_layout)
        
        self.widget_line_check = self.widgets_checkbox("Events Timeline", True, self.canvas_line)
        config_layout.addWidget(self.widget_line_check)
        
        self.widget_pie_check = self.widgets_checkbox("Severity Chart", True, self.canvas_pie)
        config_layout.addWidget(self.widget_pie_check)
        
        self.widget_bar_check = self.widgets_checkbox("Top Sources", True, self.canvas_bar)
        config_layout.addWidget(self.widget_bar_check)
        
        save_layout_btn = QPushButton("💾 Save Layout")
        save_layout_btn.clicked.connect(self._save_dashboard_layout)
        config_layout.addWidget(save_layout_btn)
        
        config_layout.addStretch()
        layout.addWidget(config_group)
        
        return widget
    
    def widgets_checkbox(self, label: str, checked: bool, widget):
        """Create a checkbox that toggles widget visibility"""
        from PyQt6.QtWidgets import QCheckBox
        checkbox = QCheckBox(label)
        checkbox.setChecked(checked)
        checkbox.stateChanged.connect(lambda state: widget.setVisible(state == 2))
        return checkbox
    
    def _save_dashboard_layout(self):
        """Save dashboard widget visibility preferences"""
        prefs = get_preferences()
        layout_config = {
            "show_timeline": self.widget_line_check.isChecked(),
            "show_severity": self.widget_pie_check.isChecked(),
            "show_sources": self.widget_bar_check.isChecked()
        }
        prefs.set(self.current_user, "dashboard_layout", layout_config)
        self.log("✅ Dashboard layout saved")
    
    def _load_dashboard_layout(self):
        """Load saved dashboard widget preferences"""
        prefs = get_preferences()
        layout_config = prefs.get(self.current_user, "dashboard_layout", {})
        
        if layout_config:
            if "show_timeline" in layout_config:
                self.widget_line_check.setChecked(layout_config["show_timeline"])
                self.canvas_line.setVisible(layout_config["show_timeline"])
            if "show_severity" in layout_config:
                self.widget_pie_check.setChecked(layout_config["show_severity"])
                self.canvas_pie.setVisible(layout_config["show_severity"])
            if "show_sources" in layout_config:
                self.widget_bar_check.setChecked(layout_config["show_sources"])
                self.canvas_bar.setVisible(layout_config["show_sources"])
    
    def _on_time_range_changed(self, index):
        """Handle time range selection change"""
        ranges = {0: "1h", 1: "6h", 2: "24h", 3: "7d", 4: "30d"}
        self.dashboard_time_range = ranges.get(index, "24h")
        self.log(f"📅 Time range changed to: {self.time_range_combo.currentText()}")
        self._refresh_dashboard()
    
    def _on_refresh_rate_changed(self, index):
        """Handle refresh rate selection change"""
        rates = {0: 0, 1: 5000, 2: 10000, 3: 30000, 4: 60000}
        new_rate = rates.get(index, 10000)
        
        if new_rate == 0:
            self.refresh_timer.stop()
            self.log("🔄 Auto-refresh disabled")
        else:
            self.refresh_timer.setInterval(new_rate)
            if not self.refresh_timer.isActive():
                self.refresh_timer.start()
            self.log(f"🔄 Refresh rate: {self.refresh_rate_combo.currentText()}")
    
    def _refresh_dashboard(self):
        """Manual dashboard refresh"""
        self.log("🔃 Refreshing dashboard...")
        # Trigger metric fetching
        self._on_timer()
    
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
        try:
            if not self.client or not self.current_user:
                return
            
            cmd = f"QUERY_ALERTS {self.current_user} 100"
            if self.client.send(cmd):
                response = self.client.receive()
                if response and "RESULTS" in response:
                    self._populate_alerts_table(response)
        except Exception as e:
            print(f"Error fetching alerts: {e}")
    
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
    
    def _create_network_tab(self) -> QWidget:
        """Create Network Flow monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        widget.setLayout(layout)
        
        # Header
        header = QLabel("🌐 Network Flow Monitor")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #3498db;")
        layout.addWidget(header)
        
        # Stats cards row
        stats_row = QHBoxLayout()
        
        # TCP Count Card
        self.tcp_stat_card = self._create_stat_card("TCP", "0")
        stats_row.addWidget(self.tcp_stat_card)
        
        # UDP Count Card
        self.udp_stat_card = self._create_stat_card("UDP", "0")
        stats_row.addWidget(self.udp_stat_card)
        
        # Established Card
        self.estab_stat_card = self._create_stat_card("Established", "0")
        stats_row.addWidget(self.estab_stat_card)
        
        # Listening Card
        self.listen_stat_card = self._create_stat_card("Listening", "0")
        stats_row.addWidget(self.listen_stat_card)
        
        layout.addLayout(stats_row)
        
        # Toolbar with filters
        toolbar = QHBoxLayout()
        
        toolbar.addWidget(QLabel("Protocol:"))
        self.network_protocol_filter = QComboBox()
        self.network_protocol_filter.addItems(["All", "TCP", "UDP"])
        self.network_protocol_filter.currentTextChanged.connect(self._on_network_filter_changed)
        toolbar.addWidget(self.network_protocol_filter)
        
        toolbar.addWidget(QLabel("Port:"))
        self.network_port_filter = QLineEdit()
        self.network_port_filter.setPlaceholderText("e.g. 443")
        self.network_port_filter.setFixedWidth(80)
        self.network_port_filter.textChanged.connect(self._filter_network_table)
        toolbar.addWidget(self.network_port_filter)
        
        toolbar.addWidget(QLabel("Remote IP:"))
        self.network_ip_filter = QLineEdit()
        self.network_ip_filter.setPlaceholderText("e.g. 192.168")
        self.network_ip_filter.setFixedWidth(120)
        self.network_ip_filter.textChanged.connect(self._filter_network_table)
        toolbar.addWidget(self.network_ip_filter)
        
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self._fetch_network_flows)
        toolbar.addWidget(refresh_btn)
        
        toolbar.addStretch()
        self.network_stats_label = QLabel("0 flows")
        self.network_stats_label.setStyleSheet("font-weight: bold; color: #3498db;")
        toolbar.addWidget(self.network_stats_label)
        
        layout.addLayout(toolbar)
        
        # Network flows table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(8)
        self.network_table.setHorizontalHeaderLabels([
            "Time", "Host", "Protocol", "Local Address", "Port", 
            "Remote Address", "Port", "State"
        ])
        
        # Style
        self.network_table.setAlternatingRowColors(True)
        self.network_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.network_table.verticalHeader().setVisible(False)
        self.network_table.setStyleSheet("""
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
        header = self.network_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Host
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Local Address
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Local Port
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Remote Address
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Remote Port
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # State
        
        layout.addWidget(self.network_table)
        
        # Top remote IPs section
        top_ips_label = QLabel("🔝 Top Remote Connections")
        top_ips_label.setStyleSheet("font-size: 12pt; font-weight: bold; margin-top: 10px;")
        layout.addWidget(top_ips_label)
        
        self.top_remotes_text = QLabel("Waiting for data...")
        self.top_remotes_text.setStyleSheet("color: #95a5a6; padding: 10px; background-color: #34495e; border-radius: 5px;")
        layout.addWidget(self.top_remotes_text)
        
        return widget
    
    def _fetch_network_flows(self):
        """Fetch network flows from server"""
        if not self.client or not self.current_user:
            return
        
        protocol = self.network_protocol_filter.currentText()
        if protocol == "All":
            protocol = ""
        
        cmd = f"QUERY_NETWORK_FLOWS {self.current_user} 1000 {protocol}"
        if self.client.send(cmd):
            response = self.client.receive()
            if response:
                self._populate_network_table(response)
    
    def _populate_network_table(self, response: str):
        """Parse and display network flow data"""
        try:
            lines = response.strip().split('\n')
            if not lines or lines[0].startswith('ERR'):
                return
            
            self.network_table.setRowCount(0)
            
            tcp_count = 0
            udp_count = 0
            estab_count = 0
            listen_count = 0
            remote_ip_counts = {}  # Track remote IP frequencies
            
            for line in lines:
                if not line.strip() or line.startswith('OK'):
                    continue
                
                # Format: timestamp|source_host|protocol|local_addr|local_port|remote_addr|remote_port|state
                parts = line.split('|')
                if len(parts) >= 8:
                    row = self.network_table.rowCount()
                    self.network_table.insertRow(row)
                    
                    # Track remote IP (column 5)
                    remote_ip = parts[5].strip()
                    if remote_ip and remote_ip != "0.0.0.0":
                        remote_ip_counts[remote_ip] = remote_ip_counts.get(remote_ip, 0) + 1
                    
                    for col, val in enumerate(parts[:8]):
                        item = QTableWidgetItem(val.strip())
                        
                        # Color code by state
                        if col == 7:  # State column
                            state = val.strip()
                            if state == "ESTABLISHED":
                                item.setForeground(QColor("#2ecc71"))  # Green
                                estab_count += 1
                            elif state == "LISTEN":
                                item.setForeground(QColor("#3498db"))  # Blue
                                listen_count += 1
                            elif state in ["SYN_SENT", "SYN_RECV"]:
                                item.setForeground(QColor("#f39c12"))  # Orange
                            elif state in ["TIME_WAIT", "CLOSE_WAIT"]:
                                item.setForeground(QColor("#e74c3c"))  # Red
                        
                        # Color code by protocol
                        if col == 2:  # Protocol column
                            proto = val.strip()
                            if proto == "TCP":
                                item.setForeground(QColor("#9b59b6"))  # Purple
                                tcp_count += 1
                            elif proto == "UDP":
                                item.setForeground(QColor("#e67e22"))  # Orange
                                udp_count += 1
                        
                        self.network_table.setItem(row, col, item)
            
            # Update stats
            total = self.network_table.rowCount()
            self.network_stats_label.setText(f"{total} flows")
            
            # Update stat cards
            self._update_stat_card(self.tcp_stat_card, str(tcp_count))
            self._update_stat_card(self.udp_stat_card, str(udp_count))
            self._update_stat_card(self.estab_stat_card, str(estab_count))
            self._update_stat_card(self.listen_stat_card, str(listen_count))
            
            # Update top remote connections
            if remote_ip_counts:
                sorted_ips = sorted(remote_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                top_text = " | ".join([f"{ip}: {count}" for ip, count in sorted_ips])
                self.top_remotes_text.setText(f"📊 {top_text}")
            else:
                self.top_remotes_text.setText("No external connections detected")
            
        except Exception as e:
            print(f"Error populating network table: {e}")
    
    def _update_stat_card(self, card_widget, value: str):
        """Update the value in a stat card"""
        # Find the value label and update it
        for child in card_widget.findChildren(QLabel):
            if child.font().pointSize() >= 20:
                child.setText(value)
                break
    
    def _on_network_filter_changed(self, protocol: str):
        """Handle protocol filter change"""
        self._fetch_network_flows()

    def _filter_network_table(self):
        """Filter network table by port and IP (client-side)"""
        port_filter = self.network_port_filter.text().strip() if hasattr(self, 'network_port_filter') else ""
        ip_filter = self.network_ip_filter.text().strip() if hasattr(self, 'network_ip_filter') else ""
        
        visible_count = 0
        for row in range(self.network_table.rowCount()):
            show = True
            
            # Port filter (check columns 4 and 6 - local_port and remote_port)
            if port_filter:
                local_port = self.network_table.item(row, 4)
                remote_port = self.network_table.item(row, 6)
                local_match = local_port and port_filter in local_port.text()
                remote_match = remote_port and port_filter in remote_port.text()
                if not (local_match or remote_match):
                    show = False
            
            # IP filter (check column 5 - remote_addr)
            if ip_filter and show:
                remote_ip = self.network_table.item(row, 5)
                if not (remote_ip and ip_filter in remote_ip.text()):
                    show = False
            
            self.network_table.setRowHidden(row, not show)
            if show:
                visible_count += 1
        
        self.network_stats_label.setText(f"{visible_count} flows (filtered)")

    def _create_admin_tab(self) -> QWidget:
        """Admin panel for user and agent management"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Title
        title = QLabel("⚙️ Administration Panel")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # --- Users Section ---
        users_group = QGroupBox("👤 User Management")
        users_layout = QVBoxLayout()
        users_group.setLayout(users_layout)
        
        # Users toolbar
        users_toolbar = QHBoxLayout()
        self.users_count_label = QLabel("Users: 0")
        users_toolbar.addWidget(self.users_count_label)
        users_toolbar.addStretch()
        
        refresh_users_btn = QPushButton("↻ Refresh")
        refresh_users_btn.clicked.connect(self._fetch_users)
        users_toolbar.addWidget(refresh_users_btn)
        
        add_user_btn = QPushButton("➕ Add User")
        add_user_btn.setStyleSheet("background-color: #27ae60;")
        add_user_btn.clicked.connect(self._show_add_user_dialog)
        users_toolbar.addWidget(add_user_btn)
        
        users_layout.addLayout(users_toolbar)
        
        # Users table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(4)
        self.users_table.setHorizontalHeaderLabels(["Username", "Role", "Admin ID", "Actions"])
        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        users_layout.addWidget(self.users_table)
        
        layout.addWidget(users_group)
        
        # --- Agents Section ---
        agents_group = QGroupBox("🖥️ Registered Agents")
        agents_layout = QVBoxLayout()
        agents_group.setLayout(agents_layout)
        
        # Agents toolbar
        agents_toolbar = QHBoxLayout()
        self.agents_count_label = QLabel("Agents: 0")
        agents_toolbar.addWidget(self.agents_count_label)
        agents_toolbar.addStretch()
        
        refresh_agents_btn = QPushButton("↻ Refresh")
        refresh_agents_btn.clicked.connect(self._fetch_agents)
        agents_toolbar.addWidget(refresh_agents_btn)
        
        agents_layout.addLayout(agents_toolbar)
        
        # Agents table
        self.agents_table = QTableWidget()
        self.agents_table.setColumnCount(4)
        self.agents_table.setHorizontalHeaderLabels(["Hostname", "IP Address", "Last Seen", "Status"])
        header = self.agents_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        agents_layout.addWidget(self.agents_table)
        
        layout.addWidget(agents_group)
        
        return widget
    
    def _fetch_users(self):
        """Fetch users list from server"""
        if not self.client or not self.current_user:
            return
        
        cmd = f"LIST_USERS {self.current_user}"
        if self.client.send(cmd):
            response = self.client.receive()
            self.log(f"DEBUG LIST_USERS response: {response[:200] if response else 'None'}")
            if response and "RESULTS" in response:
                self._populate_users_table(response)
    
    def _populate_users_table(self, response: str):
        """Parse and display users data"""
        try:
            # Format: ACK RESULTS count=N;user|role|admin_id;...
            if "count=" not in response:
                return
            
            parts = response.split(";")
            self.users_table.setRowCount(0)
            
            for part in parts[1:]:  # Skip count= part
                if not part.strip() or "|" not in part:
                    continue
                fields = part.split("|")
                if len(fields) >= 3:
                    row = self.users_table.rowCount()
                    self.users_table.insertRow(row)
                    
                    self.users_table.setItem(row, 0, QTableWidgetItem(fields[0]))
                    
                    role_item = QTableWidgetItem(fields[1])
                    if fields[1] == "admin":
                        role_item.setForeground(QColor("#e74c3c"))
                    self.users_table.setItem(row, 1, role_item)
                    
                    self.users_table.setItem(row, 2, QTableWidgetItem(fields[2]))
                    
                    # Delete button (only for non-self users)
                    if fields[0] != self.current_user:
                        delete_btn = QPushButton("🗑️ Delete")
                        delete_btn.setStyleSheet("background-color: #c0392b; padding: 2px 8px;")
                        delete_btn.clicked.connect(lambda _, u=fields[0]: self._delete_user(u))
                        self.users_table.setCellWidget(row, 3, delete_btn)
                    else:
                        self.users_table.setItem(row, 3, QTableWidgetItem("(current)"))
            
            self.users_count_label.setText(f"Users: {self.users_table.rowCount()}")
        except Exception as e:
            self.log(f"Error parsing users: {e}")
    
    def _show_add_user_dialog(self):
        """Show dialog to add new user"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New User")
        dialog.setMinimumWidth(300)
        
        layout = QFormLayout(dialog)
        
        username_input = QLineEdit()
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        role_combo = QComboBox()
        role_combo.addItems(["user", "admin"])
        
        layout.addRow("Username:", username_input)
        layout.addRow("Password:", password_input)
        layout.addRow("Role:", role_combo)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            username = username_input.text().strip()
            password = password_input.text()
            role = role_combo.currentText()
            
            if username and password:
                self._create_user(username, password, role)
    
    def _create_user(self, username: str, password: str, role: str):
        """Create new user via server"""
        cmd = f"CREATE_USER {self.current_user} {username} {password} {role}"
        if self.client.send(cmd):
            response = self.client.receive()
            if "OK" in response:
                self.log(f"✅ User created: {username}")
                self._fetch_users()
            else:
                self.log(f"❌ Failed to create user: {response}")
    
    def _delete_user(self, username: str):
        """Delete user after confirmation"""
        reply = QMessageBox.question(self, "Confirm Delete",
                                     f"Delete user '{username}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            cmd = f"DELETE_USER {self.current_user} {username}"
            if self.client.send(cmd):
                response = self.client.receive()
                if "OK" in response:
                    self.log(f"✅ User deleted: {username}")
                    self._fetch_users()
                else:
                    self.log(f"❌ Failed to delete: {response}")
    
    def _fetch_agents(self):
        """Fetch agents list from server"""
        if not self.client or not self.current_user:
            return
        
        cmd = f"LIST_AGENTS {self.current_user}"
        if self.client.send(cmd):
            response = self.client.receive()
            self.log(f"DEBUG LIST_AGENTS response: {response[:200] if response else 'None'}")
            if response and "RESULTS" in response:
                self._populate_agents_table(response)
    
    def _populate_agents_table(self, response: str):
        """Parse and display agents data"""
        try:
            # Format: ACK RESULTS count=N;hostname|ip|last_seen|status;...
            if "count=" not in response:
                return
            
            parts = response.split(";")
            self.agents_table.setRowCount(0)
            
            for part in parts[1:]:
                if not part.strip() or "|" not in part:
                    continue
                fields = part.split("|")
                if len(fields) >= 4:
                    row = self.agents_table.rowCount()
                    self.agents_table.insertRow(row)
                    
                    self.agents_table.setItem(row, 0, QTableWidgetItem(fields[0]))
                    self.agents_table.setItem(row, 1, QTableWidgetItem(fields[1]))
                    self.agents_table.setItem(row, 2, QTableWidgetItem(fields[2]))
                    
                    status_item = QTableWidgetItem(fields[3])
                    if "online" in fields[3].lower():
                        status_item.setForeground(QColor("#27ae60"))
                    else:
                        status_item.setForeground(QColor("#e74c3c"))
                    self.agents_table.setItem(row, 3, status_item)
            
            self.agents_count_label.setText(f"Agents: {self.agents_table.rowCount()}")
        except Exception as e:
            self.log(f"Error parsing agents: {e}")

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
        elif current_tab == 3:  # Network tab
            self._fetch_network_flows()
    
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
    
    def _convert_to_local(self, utc_timestamp: str) -> str:
        """Convert UTC timestamp to Romania timezone (UTC+2)"""
        try:
            from datetime import datetime, timedelta
            # Parse UTC timestamp
            dt = datetime.strptime(utc_timestamp, '%Y-%m-%d %H:%M:%S')
            # Add 2 hours for Romania timezone
            local_dt = dt + timedelta(hours=2)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return utc_timestamp  # Return original if parsing fails
    
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
                                # Convert UTC to Romania timezone (UTC+2)
                                ts = self._convert_to_local(fields[1][:19])
                                event_data = {
                                    'id': fields[0],
                                    'timestamp': ts,
                                    'source': fields[2],
                                    'type': fields[3],
                                    'message': fields[4],
                                    'severity': '6'
                                }
                                self.all_events.append(event_data)
                            elif len(fields) >= 4:
                                # Old format fallback: id|timestamp|event_type|message
                                ts = self._convert_to_local(fields[1][:19])
                                event_data = {
                                    'id': fields[0],
                                    'timestamp': ts,
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
        source_ip = self.source_ip_filter.text().strip() if hasattr(self, 'source_ip_filter') else ""
        event_type = self.event_type_filter.currentText() if hasattr(self, 'event_type_filter') else "All"
        time_range = self.time_range_filter.currentText() if hasattr(self, 'time_range_filter') else "All"
        
        # Calculate time threshold based on time range
        from datetime import datetime, timedelta
        time_threshold = None
        if time_range == "Last 1 Hour":
            time_threshold = datetime.now() - timedelta(hours=1)
        elif time_range == "Last 24 Hours":
            time_threshold = datetime.now() - timedelta(hours=24)
        elif time_range == "Last 7 Days":
            time_threshold = datetime.now() - timedelta(days=7)
        elif time_range == "Last 30 Days":
            time_threshold = datetime.now() - timedelta(days=30)
        
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
            
            # Source IP filter
            if source_ip and source_ip not in evt.get('source', ''):
                continue
            
            # Event Type filter
            if event_type != "All" and evt.get('type', '') != event_type:
                continue
            
            # Time Range filter
            if time_threshold:
                try:
                    # Parse timestamp (format: 2026-01-07 20:04:06 or ISO format)
                    ts = evt.get('timestamp', '')
                    if 'T' in ts:
                        evt_time = datetime.fromisoformat(ts.split('+')[0].split('.')[0])
                    else:
                        evt_time = datetime.strptime(ts[:19], '%Y-%m-%d %H:%M:%S')
                    if evt_time < time_threshold:
                        continue
                except:
                    pass  # Keep event if timestamp parsing fails
            
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
    
    def _on_filter_changed(self):
        """Handle filter change - refresh from server if needed"""
        self._filter_events()
    
    def _save_event_filters(self):
        """Save current filter settings to preferences"""
        prefs = get_preferences()
        filters = {
            "severity": self.severity_filter.currentIndex(),
            "time_range": self.time_range_filter.currentText(),
            "source_ip": self.source_ip_filter.text(),
            "event_type": self.event_type_filter.currentText(),
            "limit": self.event_limit.value()
        }
        prefs.set(self.current_user, "event_filters", filters)
        self.log("✅ Filter settings saved")
    
    def _load_event_filters(self):
        """Load saved filter settings"""
        prefs = get_preferences()
        filters = prefs.get(self.current_user, "event_filters", {})
        
        if filters:
            if "severity" in filters:
                self.severity_filter.setCurrentIndex(filters["severity"])
            if "time_range" in filters and hasattr(self, 'time_range_filter'):
                idx = self.time_range_filter.findText(filters["time_range"])
                if idx >= 0:
                    self.time_range_filter.setCurrentIndex(idx)
            if "source_ip" in filters and hasattr(self, 'source_ip_filter'):
                self.source_ip_filter.setText(filters["source_ip"])
            if "event_type" in filters and hasattr(self, 'event_type_filter'):
                idx = self.event_type_filter.findText(filters["event_type"])
                if idx >= 0:
                    self.event_type_filter.setCurrentIndex(idx)
            if "limit" in filters:
                self.event_limit.setValue(filters["limit"])
    
    def _load_saved_preferences(self):
        """Load all saved preferences after login"""
        try:
            self._load_event_filters()
            if hasattr(self, 'widget_line_check'):
                self._load_dashboard_layout()
            self.log("✅ Loaded saved preferences")
        except Exception as e:
            self.log(f"⚠️ Could not load preferences: {e}")
    
    
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
        try:
            # 1. Events over time
            time_data = self._query_metric("events_over_time")
            # 2. Severity
            sev_data = self._query_metric("severity_dist")
            # 3. Top sources
            src_data = self._query_metric("top_sources")
            
            self._update_dashboard(time_data, sev_data, src_data)
        except Exception as e:
            print(f"Error fetching metrics: {e}")
    
    def _query_metric(self, metric_type):
        """Helper to query metrics"""
        data = []
        try:
            cmd = f"QUERY_METRICS {self.current_user} {metric_type}"
            if self.client.send(cmd):
                resp = self.client.receive()
                if resp and "RESULTS" in resp:  # Changed from startswith to 'in'
                    # Find the part after "RESULTS "
                    idx = resp.find("RESULTS ")
                    if idx != -1:
                        resp = resp[idx + 8:]  # Skip "RESULTS "
                    parts = resp.split(';', 1)
                    if len(parts) > 1:
                        items = parts[1].split(';')
                        for item in items:
                            if '|' in item:
                                data.append(item.split('|'))
        except Exception as e:
            pass
        return data
    
    def _update_dashboard(self, time_data, sev_data, src_data):
        """Update dashboard charts"""
        try:
            # Validate and filter data - ensure each item has 2 elements with valid numbers
            valid_time_data = []
            for x in time_data:
                if len(x) >= 2:
                    try:
                        int(x[1])
                        valid_time_data.append(x)
                    except ValueError:
                        pass
            
            valid_sev_data = []
            for x in sev_data:
                if len(x) >= 2:
                    try:
                        int(x[0])
                        int(x[1])
                        valid_sev_data.append(x)
                    except ValueError:
                        pass
            
            valid_src_data = []
            for x in src_data:
                if len(x) >= 2:
                    try:
                        int(x[1])
                        valid_src_data.append(x)
                    except ValueError:
                        pass
            
            # Update stat cards
            total = sum(int(x[1]) for x in valid_time_data) if valid_time_data else 0
            critical = sum(int(x[1]) for x in valid_sev_data if int(x[0]) <= 2) if valid_sev_data else 0
            sources = len(valid_src_data)
            
            if hasattr(self, 'total_events_card'):
                self.total_events_card.findChild(QLabel, "value").setText(str(total))
                self.severity_high_card.findChild(QLabel, "value").setText(str(critical))
                self.sources_card.findChild(QLabel, "value").setText(str(sources))
            
            # Line chart
            self.ax_line.clear()
            self.ax_line.set_facecolor('#2d2d2d')
            self.ax_line.set_title("Events per Hour (Last 24h)", color='#e0e0e0')
            if valid_time_data:
                hours = [x[0][11:13] if len(x[0]) > 13 else x[0] for x in valid_time_data]
                counts = [int(x[1]) for x in valid_time_data]
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
            if valid_sev_data:
                labels = [f"Sev {x[0]}" for x in valid_sev_data]
                sizes = [int(x[1]) for x in valid_sev_data]
                colors = ['#ff1744', '#ff5722', '#ff9800', '#ff6b6b', '#ffeb3b', '#4caf50', '#2196f3', '#9e9e9e']
                self.ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(sizes)], textprops={'color': '#e0e0e0'})
            self.canvas_pie.draw()
            
            # Bar chart
            self.ax_bar.clear()
            self.ax_bar.set_facecolor('#2d2d2d')
            self.ax_bar.set_title("Top Log Sources", color='#e0e0e0')
            if valid_src_data:
                import numpy as np
                sources = [x[0][:15] for x in valid_src_data]
                counts = [int(x[1]) for x in valid_src_data]
                y_pos = np.arange(len(sources))
                self.ax_bar.barh(y_pos, counts, color='#4caf50')
                self.ax_bar.set_yticks(y_pos)
                self.ax_bar.set_yticklabels(sources)
                self.ax_bar.invert_yaxis()
            self.ax_bar.tick_params(colors='#e0e0e0')
            self.canvas_bar.draw()
        except Exception as e:
            print(f"Dashboard update error: {e}")
    
    def disconnect_and_exit(self):
        """Disconnect and return to login (not exit)"""
        self.refresh_timer.stop()
        self.client.disconnect()
        self.hide()  # Hide main window instead of closing
        
        # Show login dialog again
        login = LoginDialog()
        if login.exec() == QDialog.DialogCode.Accepted:
            creds = login.get_credentials()
            # Reconnect with new credentials
            self.client = NetworkClient()
            success, msg = self.client.connect(creds['ip'], creds['port'])
            if success:
                self.client.send(f"LOGIN {creds['username']} {creds['password']}")
                resp = self.client.receive()
                if "Login successful" in resp:
                    self.current_user = creds['username']
                    self.refresh_timer.start()
                    self.show()
                    return
        # If login failed or cancelled, exit
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
