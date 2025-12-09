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


class LogMonitorThread(QThread):
    """Thread pentru monitorizarea fisierului de log"""
    log_signal = pyqtSignal(str)
    
    def __init__(self, client: NetworkClient, log_path: str = "/var/log/syslog"):
        super().__init__()
        self.client = client
        self.log_path = log_path
        self.running = True
    
    def run(self):
        if not os.access(self.log_path, os.R_OK):
            self.log_signal.emit(f"[WARN] Nu pot citi {self.log_path}")
            return
        
        self.log_signal.emit(f"[INFO] Monitorizare: {self.log_path}")
        
        try:
            with open(self.log_path, 'r') as f:
                f.seek(0, 2)
                while self.running and self.client.connected:
                    line = f.readline()
                    if line:
                        clean = line.strip()
                        if clean:
                            # Trimitem la server
                            self.client.send(f"BATCH_EVENT {clean}")
                            # Afisam si in UI (trimitem doar ultimele 80 caractere pentru lizibilitate)
                            display_text = clean[:80] + "..." if len(clean) > 80 else clean
                            self.log_signal.emit(f"📡 {display_text}")
                    else:
                        time.sleep(0.5)
        except Exception as e:
            self.log_signal.emit(f"[ERROR] {e}")
    
    def stop(self):
        self.running = False


class MainWindow(QMainWindow):
    """Fereastra principala - incarca UI din Designer"""
    
    def __init__(self):
        super().__init__()
        
        # Incarca fisierul .ui creat in Qt Designer
        ui_path = os.path.join(os.path.dirname(__file__), "mainwindows.ui")
        uic.loadUi(ui_path, self)
        
        self.setWindowTitle("NMS Client - PyQt6")
        
        # Initializare client retea
        self.client = NetworkClient()
        self.monitor_thread = None
        
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
        self.log_console.append(f"[{timestamp}] {message}")
    
    def on_connect(self):
        """Handler pentru butonul CONNECT"""
        if not self.client.connected:
            ip = self.lineEdit.text()
            port = int(self.lineEdit_2.text())
            
            success, msg = self.client.connect(ip, port)
            if success:
                self.log(msg)
                self.btn_connect.setText("DISCONNECT")
                self.btn_register.setEnabled(True)
                self.btn_heartbeat.setEnabled(True)
                self.statusbar.showMessage(f"Conectat la {ip}:{port}")
                
                # Pornim monitorizarea logurilor
                self.monitor_thread = LogMonitorThread(self.client)
                self.monitor_thread.log_signal.connect(self.log)
                self.monitor_thread.start()
            else:
                QMessageBox.critical(self, "Eroare", msg)
        else:
            # Deconectare
            if self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread.wait()
            self.client.disconnect()
            self.btn_connect.setText("CONNECT")
            self.btn_register.setEnabled(False)
            self.btn_heartbeat.setEnabled(False)
            self.statusbar.showMessage("Deconectat")
            self.log("[INFO] Deconectat de la server.")
    
    def send_register(self):
        """Trimite comanda REGISTER"""
        cmd = "REGISTER 1.0 PyQt6-Client Linux"
        if self.client.send(cmd):
            self.log(f"📤 {cmd}")
            resp = self.client.receive()
            if resp:
                self.log(f"📥 {resp}")
    
    def send_heartbeat(self):
        """Trimite comanda HEARTBEAT"""
        cmd = "HEARTBEAT 3600"
        if self.client.send(cmd):
            self.log(f"📤 {cmd}")
            resp = self.client.receive()
            if resp:
                self.log(f"📥 {resp}")
    
    def closeEvent(self, event):
        """Cleanup la inchidere"""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait()
        self.client.disconnect()
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
