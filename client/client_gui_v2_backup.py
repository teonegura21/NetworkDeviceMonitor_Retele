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
        self.setFixedSize(400, 350)
        
        # Results
        self.credentials = None
        
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
        
        # Connection Group
        conn_group = QGroupBox("Server Connection")
        conn_layout = QFormLayout()
        
        self.ip_input = QLineEdit("127.0.0.1")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        
        conn_layout.addRow("Server IP:", self.ip_input)
        conn_layout.addRow("Port:", self.port_input)
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)
        
        # Credentials Group
        cred_group = QGroupBox("Authentication")
        cred_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        cred_layout.addRow("Username:", self.username_input)
        cred_layout.addRow("Password:", self.password_input)
        cred_group.setLayout(cred_layout)
        layout.addWidget(cred_group)
        
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
        
        # First show login
        if not self._show_login():
            sys.exit(0)
        
        # Build UI after successful login
        self._setup_ui()
        self._connect_server()
    
    def _show_login(self) -> bool:
        """Show login dialog and return True if successful"""
        dialog = LoginDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.credentials = dialog.credentials
            return True
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
        self.tabs.addTab(self._create_events_tab(), "📊 Events")
        self.tabs.addTab(self._create_dashboard_tab(), "📈 Dashboard")
        self.tabs.addTab(self._create_console_tab(), "🖥 Console")
        
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
        """Events table - will implement in next part"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        label = QLabel("Events Table - Coming in Part 2...")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        
        return widget
    
    def _create_dashboard_tab(self) -> QWidget:
        """Dashboard with metrics - will implement in next part"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        label = QLabel("Dashboard - Coming in Part 2...")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        
        return widget
    
    def _create_console_tab(self) -> QWidget:
        """Console/log output"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console)
        
        return widget
    
    def _connect_server(self):
        """Attempt to connect and login"""
        creds = self.credentials
        self.log(f"Connecting to {creds['ip']}:{creds['port']}...")
        
        success, msg = self.client.connect(creds['ip'], creds['port'])
        if not success:
            QMessageBox.critical(self, "Connection Error", msg)
            self.close()
            return
        
        self.log(msg)
        
        # Login
        login_cmd = f"LOGIN {creds['username']} {creds['password']}"
        if self.client.send(login_cmd):
            resp = self.client.receive()
            self.log(f"Login response: {resp}")
            
            if "OK" in resp:
                self.current_user = creds['username']
                self.connection_status.setText("🟢 Connected")
                self.connection_status.setStyleSheet("font-weight: bold; color: #4caf50;")
                self.statusBar().showMessage(f"Logged in as {self.current_user}")
                
                # Start refresh timer
                self.refresh_timer.start(5000)
                self.refresh_data()
            else:
                QMessageBox.critical(self, "Login Failed", "Invalid credentials")
                self.close()
    
    def log(self, message: str):
        """Add message to console"""
        timestamp = time.strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")
    
    def refresh_data(self):
        """Periodic data refresh - will implement fully later"""
        if not self.client.connected:
            return
        # Placeholder for now
        pass
    
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
