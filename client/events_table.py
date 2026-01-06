# Add this near the top after imports, before LoginDialog class

# ==============================================================================
# EVENTS TABLE WIDGET - Filterable event display
# ==============================================================================
class EventsTableWidget(QWidget):
    """Professional events table with filtering and color coding"""
    
    def __init__(self, client, current_user):
        super().__init__()
        self.client = client
        self.current_user = current_user
        self.events_cache = []
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Filter toolbar
        filter_widget = self._create_filter_toolbar()
        layout.addWidget(filter_widget)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Source IP", "Severity", "Type", "Message"
        ])
        
        # Column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        # Enable sorting
        self.table.setSortingEnabled(True)
        
        layout.addWidget(self.table)
        
        # Stats bar
        self.stats_label = QLabel("Total Events: 0")
        self.stats_label.setStyleSheet("color: #a0a0a0; padding: 5px;")
        layout.addWidget(self.stats_label)
    
    def _create_filter_toolbar(self) -> QWidget:
        """Create filter controls"""
        widget = QWidget()
        widget.setFixedHeight(60)
        layout = QHBoxLayout()
        widget.setLayout(layout)
        
        # Search box
        layout.addWidget(QLabel("🔍 Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in messages...")
        self.search_input.setFixedWidth(250)
        self.search_input.textChanged.connect(self.apply_filters)
        layout.addWidget(self.search_input)
        
        # Severity filter
        layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems([
            "All", "Emergency (0)", "Alert (1)", "Critical (2)", 
            "Error (3)", "Warning (4)", "Notice (5)", "Info (6)", "Debug (7)"
        ])
        self.severity_filter.currentIndexChanged.connect(self.apply_filters)
        layout.addWidget(self.severity_filter)
        
        # Limit
        layout.addWidget(QLabel("Limit:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 1000)
        self.limit_spin.setValue(100)
        self.limit_spin.setSingleStep(10)
        layout.addWidget(self.limit_spin)
        
        # Refresh button
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self.fetch_events)
        layout.addWidget(refresh_btn)
        
        layout.addStretch()
        
        # Export button
        export_btn = QPushButton("📥 Export CSV")
        export_btn.setStyleSheet("background-color: #2d7d2d;")
        export_btn.clicked.connect(self.export_to_csv)
        layout.addWidget(export_btn)
        
        return widget
    
    def fetch_events(self):
        """Fetch events from server"""
        limit = self.limit_spin.value()
        cmd = f"QUERY_EVENTS {self.current_user} {limit}"
        
        if self.client.send(cmd):
            resp = self.client.receive()
            if resp.startswith("RESULTS"):
                self.events_cache = []
                try:
                    parts = resp.split(';', 1)
                    if len(parts) > 1:
                        events_str = parts[1]
                        events = events_str.split(';')
                        for evt in events:
                            if not evt: continue
                            fields = evt.split('|')
                            if len(fields) >= 4:
                                # Parse: id|timestamp|type|message
                                # We need to enhance server response to include src_ip and severity
                                # For now, use placeholder
                                event_data = {
                                    'id': fields[0],
                                    'timestamp': fields[1][:19],  # Trim to datetime
                                    'source': 'unknown',  # TODO: enhance server
                                    'severity': '6',  # Default to Info
                                    'type': fields[2] if len(fields) > 2 else 'event',
                                    'message': fields[3] if len(fields) > 3 else ''
                                }
                                self.events_cache.append(event_data)
                except Exception as e:
                    print(f"Parse error: {e}")
        
        self.apply_filters()
    
    def apply_filters(self):
        """Apply search and severity filters to cached events"""
        search_text = self.search_input.text().lower()
        severity_idx = self.severity_filter.currentIndex()
        
        filtered = []
        for event in self.events_cache:
            # Search filter
            if search_text and search_text not in event['message'].lower():
                continue
            
            # Severity filter
            if severity_idx > 0:  # 0 = "All"
                target_sev = str(severity_idx - 1)
                if event['severity'] != target_sev:
                    continue
            
            filtered.append(event)
        
        self.populate_table(filtered)
    
    def populate_table(self, events):
        """Fill table with events"""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(events))
        
        for row, event in enumerate(events):
            # ID
            self.table.setItem(row, 0, QTableWidgetItem(event['id']))
            
            # Timestamp
            self.table.setItem(row, 1, QTableWidgetItem(event['timestamp']))
            
            # Source
            self.table.setItem(row, 2, QTableWidgetItem(event['source']))
            
            # Severity with color
            sev_item = QTableWidgetItem(f"{event['severity']}")
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Color code by severity
            sev_colors = {
                '0': '#ff1744',  # Emergency - Red
                '1': '#ff5722',  # Alert - Deep Orange
                '2': '#ff9800',  # Critical - Orange
                '3': '#ff6b6b',  # Error - Light Red
                '4': '#ffeb3b',  # Warning - Yellow
                '5': '#4caf50',  # Notice - Green
                '6': '#2196f3',  # Info - Blue
                '7': '#9e9e9e',  # Debug - Gray
            }
            color = sev_colors.get(event['severity'], '#ffffff')
            sev_item.setForeground(QColor(color))
            self.table.setItem(row, 3, sev_item)
            
            # Type
            self.table.setItem(row, 4, QTableWidgetItem(event['type']))
            
            # Message
            msg_item = QTableWidgetItem(event['message'][:200])  # Truncate long messages
            self.table.setItem(row, 5, msg_item)
        
        self.table.setSortingEnabled(True)
        self.stats_label.setText(f"Showing {len(events)} of {len(self.events_cache)} events")
    
    def export_to_csv(self):
        """Export visible events to CSV"""
        import csv
        from datetime import datetime
        
        filename = f"nms_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'Source', 'Severity', 'Type', 'Message'])
                
                for row in range(self.table.rowCount()):
                    row_data = [
                        self.table.item(row, col).text() if self.table.item(row, col) else ''
                        for col in range(6)
                    ]
                    writer.writerow(row_data)
            
            QMessageBox.information(self, "Export Success", 
                                    f"Exported {self.table.rowCount()} events to:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
