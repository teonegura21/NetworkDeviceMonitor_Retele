"""
User Preferences Module
Stores persistent user preferences (filters, dashboard config) in local SQLite
"""

import sqlite3
import os
import json
from typing import Optional, Dict, Any

class UserPreferences:
    """Manages persistent user preferences in local SQLite database"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Store in user's config directory
            config_dir = os.path.expanduser("~/.config/nms_client")
            os.makedirs(config_dir, exist_ok=True)
            db_path = os.path.join(config_dir, "preferences.db")
        
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Create preferences table if it doesn't exist"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS preferences (
                    username TEXT,
                    key TEXT,
                    value TEXT,
                    PRIMARY KEY (username, key)
                )
            """)
            conn.commit()
    
    def get(self, username: str, key: str, default: Any = None) -> Any:
        """Get a preference value"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT value FROM preferences WHERE username = ? AND key = ?",
                    (username, key)
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
                return default
        except:
            return default
    
    def set(self, username: str, key: str, value: Any):
        """Set a preference value"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO preferences (username, key, value)
                    VALUES (?, ?, ?)
                """, (username, key, json.dumps(value)))
                conn.commit()
        except Exception as e:
            print(f"Error saving preference: {e}")
    
    def get_all(self, username: str) -> Dict[str, Any]:
        """Get all preferences for a user"""
        prefs = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT key, value FROM preferences WHERE username = ?",
                    (username,)
                )
                for key, value in cursor.fetchall():
                    prefs[key] = json.loads(value)
        except:
            pass
        return prefs
    
    def delete(self, username: str, key: str):
        """Delete a preference"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM preferences WHERE username = ? AND key = ?",
                    (username, key)
                )
                conn.commit()
        except:
            pass


# Filter presets for easy access
class FilterPresets:
    """Common filter combinations"""
    
    EVENTS_DEFAULTS = {
        "time_range": "24h",
        "severity": "All",
        "source_ip": "",
        "event_type": "All",
        "limit": 100
    }
    
    NETWORK_DEFAULTS = {
        "protocol": "All",
        "port": "",
        "remote_ip": "",
        "state": "All"
    }
    
    ALERTS_DEFAULTS = {
        "state": "All",
        "severity": "All",
        "time_range": "24h"
    }


# Singleton instance for easy access
_prefs_instance: Optional[UserPreferences] = None

def get_preferences() -> UserPreferences:
    """Get the global preferences instance"""
    global _prefs_instance
    if _prefs_instance is None:
        _prefs_instance = UserPreferences()
    return _prefs_instance
