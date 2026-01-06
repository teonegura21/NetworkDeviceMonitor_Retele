#!/usr/bin/env python3
"""
Client GUI pentru Network Monitoring System
Incarca interfata din Qt Designer (.ui) si o conecteaza la logica de retea.
"""

import sys
import socket
import threading
import time
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6 import uic


class NetworkClient:
    """Clasa pentru comunicarea cu serverul C++"""
    
    def __init__(self):
        self.sock = None
        self.connected = False
        self.buffer_size = 4096

    def connect(self, ip: str, port: int) -> tuple[bool, str]:
        """Conectare la server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect((ip, port))
            self.sock.settimeout(None)
            self.connected = True
            welcome = self.sock.recv(self.buffer_size).decode('utf-8', errors='ignore')
            return True, f"Conectat! Server: {welcome.strip()}"
        except Exception as e:
            self.connected = False
            return False, f"Eroare: {e}"

    def send(self, message: str) -> bool:
        """Trimite un mesaj la server (cu newline)"""
        if not self.connected:
            return False
        try:
            self.sock.sendall((message + "\n").encode('utf-8'))
            return True
        except:
            self.connected = False
            return False

    def receive(self) -> str:
        """Primeste raspuns de la server"""
        if not self.connected:
            return ""
        try:
            data = self.sock.recv(self.buffer_size)
            return data.decode('utf-8', errors='ignore').strip() if data else ""
        except:
            return ""

    def disconnect(self):
        """Inchide conexiunea"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.connected = False




from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTabWidget, QGridLayout
import matplotlib
matplotlib.use('QtAgg') 
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np

# Dashboard Widget Class
class DashboardPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QGridLayout()
        self.setLayout(layout)
        
        # 1. Events Over Time (Line Chart)
        self.fig_line = Figure(figsize=(5, 3), dpi=100)
        self.canvas_line = FigureCanvas(self.fig_line)
        self.ax_line = self.fig_line.add_subplot(111)
        self.ax_line.set_title("Events per Hour (Last 24h)")
        layout.addWidget(self.canvas_line, 0, 0, 1, 2) # Span top row
        
        # 2. Severity Dist (Pie Chart)
        self.fig_pie = Figure(figsize=(4, 3), dpi=100)
        self.canvas_pie = FigureCanvas(self.fig_pie)
        self.ax_pie = self.fig_pie.add_subplot(111)
        self.ax_pie.set_title("Severity Distribution")
        layout.addWidget(self.canvas_pie, 1, 0)
        
        # 3. Top Sources (Bar Chart)
        self.fig_bar = Figure(figsize=(4, 3), dpi=100)
        self.canvas_bar = FigureCanvas(self.fig_bar)
        self.ax_bar = self.fig_bar.add_subplot(111)
        self.ax_bar.set_title("Top Log Sources")
        layout.addWidget(self.canvas_bar, 1, 1)
        
    def update_charts(self, time_data, sev_data, src_data):
        # 1. Line Chart
        self.ax_line.clear()
        self.ax_line.set_title("Events per Hour (Last 24h)")
        if time_data:
            hours = [x[0][11:13] for x in time_data] # Extract HH from "YYYY-MM-DD HH:00:00"
            counts = [int(x[1]) for x in time_data]
            # Reverse to show chronological order (query returns DESC)
            hours.reverse()
            counts.reverse()
            self.ax_line.plot(hours, counts, marker='o', linestyle='-', color='b')
            self.ax_line.grid(True)
        self.canvas_line.draw()
        
        # 2. Pie Chart
        self.ax_pie.clear()
        self.ax_pie.set_title("Severity Distribution")
        if sev_data:
            labels = [f"Sev {x[0]}" for x in sev_data]
            sizes = [int(x[1]) for x in sev_data]
            self.ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        self.canvas_pie.draw()
        
        # 3. Bar Chart
        self.ax_bar.clear()
        self.ax_bar.set_title("Top Log Sources")
        if src_data:
            sources = [x[0] for x in src_data]
            counts = [int(x[1]) for x in src_data]
            y_pos = np.arange(len(sources))
            self.ax_bar.barh(y_pos, counts, align='center', color='g')
            self.ax_bar.set_yticks(y_pos)
            self.ax_bar.set_yticklabels(sources)
            self.ax_bar.invert_yaxis()  # labels read top-to-bottom
        self.canvas_bar.draw()

class MainWindow(QMainWindow):
    """Fereastra principala - incarca UI din Designer"""
    
    def __init__(self):
        super().__init__()
        
        # Incarca fisierul .ui creat in Qt Designer
        ui_path = os.path.join(os.path.dirname(__file__), "mainwindows.ui")
        uic.loadUi(ui_path, self)
        
        self.setWindowTitle("NMS Client - PyQt6 (Viewer + Dashboard)")
        
        # REFACTOR: Use Tabs
        self.tabs = QTabWidget()
        self.old_central = self.centralWidget()
        if self.old_central:
            # Note: setCentralWidget ownership transfer is tricky in PySide/PyQt
            # But reparenting usually works.
            self.old_central.setParent(self.tabs)
            self.tabs.addTab(self.old_central, "Live Logging")
        
        self.dashboard = DashboardPanel()
        self.tabs.addTab(self.dashboard, "Dashboard")
        
        self.setCentralWidget(self.tabs)
        
        # Initializare client retea
        self.client = NetworkClient()
        self.current_user = ""
        
        # Timer pentru polling
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.last_event_id = 0
        
        # Conectare semnale la sloturi (butoane -> functii)
        # Widgeturile sunt accesate prin numele lor din Designer
        self.btn_connect.clicked.connect(self.on_connect)
        self.btn_register.clicked.connect(self.send_register)
        self.btn_heartbeat.clicked.connect(self.send_heartbeat)
        
        # Setam valori default pentru IP si Port
        self.lineEdit.setText("127.0.0.1")
        self.lineEdit_2.setText("8080")
        
        # Initial, butoanele de actiuni sunt dezactivate
        self.btn_register.setEnabled(False)
        self.btn_heartbeat.setEnabled(False)
        
        self.log("[INFO] Aplicatie pornita. Conecteaza-te la server.")
    
    def log(self, message: str):
        """Adauga mesaj in consola de loguri"""
        timestamp = time.strftime("%H:%M:%S")
        if hasattr(self, 'log_console'):
            self.log_console.append(f"[{timestamp}] {message}")
        else:
            print(f"[{timestamp}] {message}")
    
    def on_connect(self):
        """Handler pentru butonul CONNECT"""
        if not self.client.connected:
            ip = self.lineEdit.text()
            port = int(self.lineEdit_2.text())
            
            success, msg = self.client.connect(ip, port)
            if success:
                self.log(msg)
                
                # Trimitem comanda LOGIN cu credentialele din UI
                username = self.input_username.text()
                password = self.input_password.text()
                login_cmd = f"LOGIN {username} {password}"
                
                if self.client.send(login_cmd):
                    self.log(f"🔐 Trimit LOGIN pentru {username}...")
                    resp = self.client.receive()
                    self.log(f"📥 {resp}")
                    
                    if "OK" in resp:
                        # Autentificare reusita!
                        self.current_user = username
                        self.btn_connect.setText("DISCONNECT")
                        self.btn_register.setEnabled(True)
                        self.btn_heartbeat.setEnabled(True)
                        self.statusbar.showMessage(f"Autentificat ca {username} @ {ip}:{port}")
                        
                        # Pornim polling-ul (la fiecare 5 secunde)
                        self.refresh_timer.start(5000)
                        self.refresh_data() 
                    else:
                        # Autentificare esuata
                        QMessageBox.critical(self, "Eroare Login", "Username sau parola incorecta!")
                        self.client.disconnect()
            else:
                QMessageBox.critical(self, "Eroare", msg)
        else:
            # Deconectare
            self.refresh_timer.stop()
            self.client.disconnect()
            self.btn_connect.setText("CONNECT")
            self.btn_register.setEnabled(False)
            self.btn_heartbeat.setEnabled(False)
            self.statusbar.showMessage("Deconectat")
            self.log("[INFO] Deconectat de la server.")
            
    def refresh_data(self):
        """Fetch logs logic + metrics if on dashboard"""
        if not self.client.connected: return
        
        # 1. Fetch Logs (always, or only if on logs tab?)
        # Let's simple fetch logs always to keep console updated
        self.fetch_logs()
        
        # 2. Fetch Metrics (only if on dashboard tab to save load)
        if self.tabs.currentWidget() == self.dashboard:
            self.fetch_metrics()

    def fetch_logs(self):
        """Cere ultimele evenimente de la server"""
        cmd = f"QUERY_EVENTS {self.current_user} 10"
        if self.client.send(cmd):
            resp = self.client.receive()
            if resp.startswith("RESULTS"):
                try:
                    parts = resp.split(';', 1)
                    if len(parts) > 1:
                        events_str = parts[1]
                        events = events_str.split(';')
                        for evt in events:
                            if not evt: continue
                            fields = evt.split('|')
                            if len(fields) >= 4:
                                evt_id = int(fields[0])
                                # Simple log to console
                                # Note: In real app, avoid spamming duplicates.
                                # Here we just log to show it works.
                                # self.log(f"EVENT #{evt_id}: {fields[3][:50]}...")
                                pass
                except Exception as e:
                    print(f"Parse error: {e}")

    def fetch_metrics(self):
        """Cere metrics si updateaza dashboardul"""
        # 1. Events over time
        time_data = self._query_metric("events_over_time")
        # 2. Severity
        sev_data = self._query_metric("severity_dist")
        # 3. Top Sources
        src_data = self._query_metric("top_sources")
        
        self.dashboard.update_charts(time_data, sev_data, src_data)

    def _query_metric(self, metric_type):
        """Helper to query a specific metric"""
        data = []
        cmd = f"QUERY_METRICS {self.current_user} {metric_type}"
        if self.client.send(cmd):
            resp = self.client.receive()
            # Format: RESULTS count=N;val1;val2;...
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

    def send_register(self):
        """Trimite comanda REGISTER"""
        cmd = f"REGISTER {self.current_user} 1.0 PyQt6-Client Linux"
        if self.client.send(cmd):
            self.log(f"📤 {cmd}")
            resp = self.client.receive()
            if resp:
                self.log(f"📥 {resp}")
    
    def send_heartbeat(self):
        """Trimite comanda HEARTBEAT"""
        # Aceasta era pentru agent, dar acum clientul poate trimite heartbeat ca "alive session"
        cmd = f"HEARTBEAT {self.current_user} 3600"
        if self.client.send(cmd):
            self.log(f"📤 {cmd}")
            resp = self.client.receive()
            if resp:
                self.log(f"📥 {resp}")
    
    def closeEvent(self, event):
        """Cleanup la inchidere"""
        self.refresh_timer.stop()
        self.client.disconnect()
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


