#!/usr/bin/env python3
# AI Firewall для Ubuntu

import subprocess
import json
import time
from scapy.all import *
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
import logging
from datetime import datetime

# Конфигурация для Ubuntu
CONFIG = {
    "interface": "ens33",  # Типичное имя интерфейса в Ubuntu
    "threshold": 0.65,
    "update_interval": 3600,
    "log_file": "/var/log/ai_firewall_ubuntu.log",
    "rules_file": "/etc/ai_firewall/rules.json"
}

class AIFirewall:
    def __init__(self):
        self.model = None
        self.logger = self.setup_logger()
        self.load_rules()
        self.train_initial_model()
        self.init_firewall()

    def init_firewall(self):
        # Остановка UFW если активен
        subprocess.run("sudo ufw disable", shell=True)
        
        # Базовая настройка iptables
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT", shell=True)
        subprocess.run("sudo iptables -A INPUT -i lo -j ACCEPT", shell=True)
        subprocess.run("sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True)

    def setup_logger(self):
        logging.basicConfig(
            filename=CONFIG['log_file'],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger()

    # Остальные методы класса остаются без изменений
    # (packet_handler, extract_features, detect_anomaly и т.д.)

if __name__ == "__main__":
    try:
        fw = AIFirewall()
        fw.run()
    except KeyboardInterrupt:
        print("\nFirewall stopped.")
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo ufw --force enable", shell=True)
