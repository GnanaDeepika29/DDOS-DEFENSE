"""
DDoS Detection System Configuration
Centralized configuration for all modules
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base directories
BASE_DIR = Path(__file__).parent.parent
DATASET_DIR = Path("D:/01-12")
MODELS_DIR = BASE_DIR / 'models'
DATA_DIR = BASE_DIR / 'data'
LOGS_DIR = BASE_DIR / 'logs'
CONFIG_DIR = BASE_DIR / 'config'

# Ensure directories exist
for dir_path in [MODELS_DIR, DATA_DIR, LOGS_DIR, CONFIG_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Dataset configuration
DATASET_FILES = [
    'DrDoS_DNS.csv', 'DrDoS_LDAP.csv', 'DrDoS_MSSQL.csv',
    'DrDoS_NetBIOS.csv', 'DrDoS_NTP.csv', 'DrDoS_SNMP.csv',
    'DrDoS_SSDP.csv', 'DrDoS_UDP.csv', 'LDAP.csv',
    'MSSQL.csv', 'NetBIOS.csv', 'Portmap.csv',
    'Syn.csv', 'TFTP.csv', 'UDP.csv', 'UDPLag.csv'
]

# Feature columns (excluding metadata and label)
DROP_COLUMNS = ['Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
TARGET_COLUMN = 'Label'

# Active model artefact (stem under MODELS_DIR)
ACTIVE_MODEL = 'xgboost'

# Model configuration
MODEL_CONFIG = {
    'random_forest': {
        'n_estimators': 100,
        'max_depth': 20,
        'random_state': 42,
        'n_jobs': -1
    },
    'xgboost': {
        'n_estimators': 100,
               'max_depth': 6,
        'learning_rate': 0.1,
        'random_state': 42,
        'n_jobs': -1
    }
}

# Detection thresholds
DETECTION_THRESHOLD = float(os.getenv('DETECTION_THRESHOLD', 0.7))
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', 0.8))

# Real-time capture configuration
CAPTURE_INTERFACE = os.getenv('CAPTURE_INTERFACE', 'Ethernet')
CAPTURE_TIMEOUT = int(os.getenv('CAPTURE_TIMEOUT', 10))
FEATURE_WINDOW_SIZE = int(os.getenv('FEATURE_WINDOW_SIZE', 50))
CAPTURE_FILTER = os.getenv('CAPTURE_FILTER', 'ip')
FLOW_TIMEOUT = float(os.getenv('FLOW_TIMEOUT', 120.0))
FLOW_ACTIVITY_TIMEOUT = float(os.getenv('FLOW_ACTIVITY_TIMEOUT', 30.0))

# Mitigation configuration
AUTO_BLOCK_ENABLED = os.getenv('AUTO_BLOCK_ENABLED', 'True').lower() == 'true'
BLOCK_DURATION = int(os.getenv('BLOCK_DURATION', 3600))
RATE_LIMIT_THRESHOLD = int(os.getenv('RATE_LIMIT_THRESHOLD', 1000))
MAX_CONNECTIONS_PER_IP = int(os.getenv('MAX_CONNECTIONS_PER_IP', 100))

# Alert configuration
ALERT_LOG_FILE = LOGS_DIR / 'alerts.log'
EMAIL_ENABLED = os.getenv('EMAIL_ENABLED', 'True').lower() == 'true'
WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'False').lower() == 'true'
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')

# Email configuration (default: gnanadeepika2982004@gmail.com)
EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', 587))
EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', 'gnanadeepika2982004@gmail.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'bhrekqedlgpivpcy')
EMAIL_RECIPIENTS = os.getenv('EMAIL_RECIPIENTS', 'gnanadeepika2982004@gmail.com').split(',') if os.getenv('EMAIL_RECIPIENTS') else ['gnanadeepika2982004@gmail.com']
EMAIL_FROM = os.getenv('EMAIL_FROM', 'gnanadeepika2982004@gmail.com')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'

# API Server configuration (dashboard at http://localhost:8000/dashboard)
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', 8000))

# Dashboard configuration (served from same API server)
DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', API_HOST)
DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', API_PORT))

# Database
DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{BASE_DIR}/data/ddos.db')

# Redis (for real-time message queue)
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', 10485760))
LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 5))

# CORS (Cross-Origin Resource Sharing) for API server
CORS_ALLOW_ORIGINS_STR = os.getenv('CORS_ALLOW_ORIGINS', '*')
CORS_ALLOW_ORIGINS = [o.strip() for o in CORS_ALLOW_ORIGINS_STR.split(',')] if CORS_ALLOW_ORIGINS_STR else ['*']

# Whitelist (IPs/networks to never block)
WHITELIST = [
    '127.0.0.1',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12'
]

# Malicious IP storage
BLOCKED_IPS_FILE = DATA_DIR / 'blocked_ips.json'
