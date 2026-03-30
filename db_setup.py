#!/usr/bin/env python3
"""
MySQL Database Auto-Setup Script
Creates database and all tables automatically
"""

from database import DatabaseManager

if __name__ == "__main__":
    print("🛠️  Setting up Threat Detection Database...")
    
    db = DatabaseManager()
    db.create_database_and_tables()
    
    print("✅ Database 'threat_detection_db' ready!")
    print("✅ All 5 tables created:")
    print("   threat_logs, prediction_logs, blocked_ips")
    print("   system_metrics, model_performance")
    print("\n🚀 Ready for: python train_model.py")

