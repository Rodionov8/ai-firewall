#!/usr/bin/env python3
# AI Firewall для Ubuntu (без scapy)

import subprocess
import json
import time
import sys
import signal
import logging
import os
import random
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd

# Конфигурация
CONFIG = {
    "interface": "ens33",
    "threshold": 0.65,
    "update_interval": 3600,
    "log_file": "/var/log/ai_firewall_ubuntu.log",
    "rules_file": "/etc/ai_firewall/rules.json",
    "default_policy": "DROP",
    "simulation": True  # Режим симуляции сети
}

class AIFirewall:
    def __init__(self):
        self.running = True
        self.logger = self.setup_logger()
        self.check_environment()
        self.init_firewall()
        self.load_rules()
        self.train_initial_model()
        signal.signal(signal.SIGTERM, self.signal_handler)

    def check_environment(self):
        required_dirs = ['/etc/ai_firewall', '/var/log']
        for d in required_dirs:
            if not os.path.exists(d):
                os.makedirs(d)
            if not os.access(d, os.W_OK):
                raise PermissionError(f"No write access to {d}")

    def setup_logger(self):
        logger = logging.getLogger("AIFirewall")
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(CONFIG['log_file'])
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def init_firewall(self):
        try:
            subprocess.run("sudo ufw disable", shell=True, check=True)
            
            subprocess.run("sudo iptables -F", shell=True, check=True)
            subprocess.run(f"sudo iptables -P INPUT {CONFIG['default_policy']}", 
                         shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT", 
                         shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT", 
                         shell=True, check=True)
            
            self.logger.info("Firewall initialized")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Firewall init error: {str(e)}")
            sys.exit(1)

    def generate_simulated_packet(self):
        """Генерация синтетических данных пакета"""
        return {
            'src_ip': f"192.168.1.{random.randint(1,255)}",
            'length': random.randint(64, 1500),
            'ttl': random.choice([32, 64, 128]),
            'timestamp': datetime.now().timestamp() % 86400
        }

    def packet_handler(self):
        """Обработчик симулированных пакетов"""
        packet = self.generate_simulated_packet()
        features = self.extract_features(packet)
        anomaly_score = self.detect_anomaly(features)
        
        if anomaly_score > CONFIG['threshold']:
            self.block_ip(packet['src_ip'])
            self.logger.info(f"Blocked {packet['src_ip']} (score: {anomaly_score:.2f})")

    def extract_features(self, packet):
        features = [
            packet['length'],
            packet['ttl'],
            packet['timestamp'],
            random.random()  # Заглушка для payload
        ]
        return np.array(features).reshape(1, -1)

    def detect_anomaly(self, features):
        return 1 - self.model.decision_function(features)[0]

    def block_ip(self, ip):
        try:
            subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", 
                          shell=True, check=True)
            self.update_rules_file(ip)
            self.logger.info(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Block IP failed: {str(e)}")

    def update_rules_file(self, ip):
        try:
            with open(CONFIG['rules_file'], 'r+') as f:
                try:
                    rules = json.load(f)
                except json.JSONDecodeError:
                    rules = {"blocked_ips": []}
                
                if ip not in rules['blocked_ips']:
                    rules['blocked_ips'].append(ip)
                    f.seek(0)
                    json.dump(rules, f)
                    f.truncate()
        except IOError as e:
            self.logger.error(f"Rules file error: {str(e)}")

    def train_initial_model(self):
        try:
            X_train = np.random.normal(size=(1000, 4))
            self.model = IsolationForest(n_estimators=100, contamination=0.1)
            self.model.fit(X_train)
            self.logger.info("Initial model trained")
        except Exception as e:
            self.logger.error(f"Model training error: {str(e)}")
            sys.exit(1)

    def load_rules(self):
        try:
            with open(CONFIG['rules_file'], 'r') as f:
                rules = json.load(f)
                for ip in rules.get('blocked_ips', []):
                    subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", 
                                 shell=True, check=True)
            self.logger.info("Loaded existing rules")
        except (FileNotFoundError, json.JSONDecodeError):
            self.logger.warning("No rules file found, starting fresh")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Rule loading failed: {str(e)}")

    def signal_handler(self, signum, frame):
        self.logger.info("Received shutdown signal")
        self.running = False
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo ufw --force enable", shell=True)
        sys.exit(0)

    def run(self):
        self.logger.info("Starting simulation mode")
        try:
            while self.running:
                self.packet_handler()
                time.sleep(0.1)  # Задержка для симуляции
        except Exception as e:
            self.logger.error(f"Main loop error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        firewall = AIFirewall()
        firewall.run()
    except KeyboardInterrupt:
        print("\nShutting down firewall...")
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo ufw --force enable", shell=True)
        sys.exit(0)
