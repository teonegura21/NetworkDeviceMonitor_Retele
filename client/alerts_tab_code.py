# Add this to client_gui_v2.py MainWindow class

# 1. In __init__, add Alerts tab after Dashboard:
#    self.tabs.addTab(self._create_alerts_tab(), "🚨 Alerts")

# 2. Add these methods to MainWindow class:

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
    
    state_filter = QComboBox()
    state_filter.addItems(["All", "Open", "Acknowledged", "Closed"])
    state_filter.currentTextChanged.connect(self._on_alert_filter_changed)
    toolbar.addWidget(QLabel("State:"))
    toolbar.addWidget(state_filter)
    
    refresh_btn = QPushButton("↻ Refresh")
    refresh_btn.clicked.connect(self._fetch_alerts)
    toolbar.addWidget(refresh_btn)
    
    toolbar.addStretch()
    self.alerts_stats_label = QLabel("0 alerts")
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
            if len(fields) <8:
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

# 3. In _setup_timer, add:
#    if self.tabs.currentIndex() == 3:  # Alerts tab
#        self._fetch_alerts()
