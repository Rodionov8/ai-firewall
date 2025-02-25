!/usr/bin/env python3
# AI Firewall для Ubuntu (курсовая работа)

import subprocess
import json
import time
import sys
import signal
import logging
import os
import random
from datetime import datetime
import numpy as np

# Конфигурация системы
CONFIG = {
    "interface": "ens33",  # Сетевой интерфейс
    "threshold": 3.0,      # Порог для Z-оценки (обычно 3.0 для аномалий)
    "update_interval": 3600,  # Интервал обновления модели (в секундах)
    "log_file": "/var/log/ai_firewall_ubuntu.log",  # Файл для логирования
    "rules_file": "/etc/ai_firewall/rules.json",    # Файл с правилами
    "default_policy": "DROP",  # Политика по умолчанию для iptables
    "simulation": True         # Режим симуляции трафика
}

class AIFirewall:
    def __init__(self):
        """Инициализация системы."""
        self.running = True
        self.logger = self.setup_logger()
        try:
            self.check_environment()
            self.init_firewall()
            self.load_rules()
            self.train_initial_model()
            signal.signal(signal.SIGTERM, self.signal_handler)
            self.logger.info("Система AI Firewall инициализирована.")
        except Exception as e:
            self.logger.critical(f"Ошибка инициализации: {str(e)}", exc_info=True)
            sys.exit(1)

    def setup_logger(self):
        """Настройка системы логирования."""
        logger = logging.getLogger("AIFirewall")
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(CONFIG['log_file'])
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def check_environment(self):
        """Проверка окружения."""
        required_dirs = ['/etc/ai_firewall', '/var/log']
        for d in required_dirs:
            if not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            if not os.access(d, os.W_OK):
                raise PermissionError(f"Нет доступа к {d}")

    def init_firewall(self):
        """Настройка базовых правил iptables."""
        try:
            subprocess.run("sudo ufw disable", shell=True, check=True)
            subprocess.run("sudo iptables -F", shell=True, check=True)
            subprocess.run(f"sudo iptables -P INPUT {CONFIG['default_policy']}", shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True, check=True)
            self.logger.info("Настройка iptables завершена.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ошибка настройки iptables: {str(e)}")
            sys.exit(1)

    def generate_simulated_packet(self):
        """Генерация синтетического пакета."""
        return {
            'src_ip': f"192.168.1.{random.randint(1, 255)}",
            'length': random.randint(64, 1500),
            'ttl': random.choice([32, 64, 128]),
            'timestamp': datetime.now().timestamp() % 86400
        }

    def extract_features(self, packet):
        """Извлечение признаков из пакета."""
        return np.array([
            packet['length'],
            packet['ttl'],
            packet['timestamp'],
            random.random()  # Заглушка для payload
        ])

    def train_initial_model(self):
        """Инициализация статистической модели."""
        try:
            # Генерация синтетических данных для инициализации
            self.mean = np.zeros(4)  # Средние значения признаков
            self.std = np.ones(4)    # Стандартные отклонения
            self.logger.info("Статистическая модель инициализирована.")
        except Exception as e:
            self.logger.error(f"Ошибка инициализации модели: {str(e)}")
            sys.exit(1)

    def detect_anomaly(self, features):
        """Обнаружение аномалий с помощью Z-оценки."""
        z_scores = np.abs((features - self.mean) / self.std)
        return np.max(z_scores)  # Возвращаем максимальное отклонение

    def block_ip(self, ip):
        """Блокировка IP-адреса."""
        try:
            subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            self.update_rules_file(ip)
            self.logger.info(f"Заблокирован IP: {ip}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ошибка блокировки IP: {str(e)}")

    def update_rules_file(self, ip):
        """Обновление файла с правилами."""
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
            self.logger.error(f"Ошибка обновления файла правил: {str(e)}")

    def load_rules(self):
        """Загрузка правил из файла."""
        try:
            with open(CONFIG['rules_file'], 'r') as f:
                rules = json.load(f)
                for ip in rules.get('blocked_ips', []):
                    subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            self.logger.info("Загружены существующие правила.")
        except (FileNotFoundError, json.JSONDecodeError):
            self.logger.warning("Файл правил не найден, начинаем с нуля.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ошибка загрузки правил: {str(e)}")

    def signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown."""
        self.logger.info("Получен сигнал завершения.")
        self.running = False
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo ufw --force enable", shell=True)
        sys.exit(0)

    def run(self):
        """Основной цикл работы системы."""
        self.logger.info("Запуск системы AI Firewall.")
        while self.running:
            try:
                packet = self.generate_simulated_packet()
                features = self.extract_features(packet)
                anomaly_score = self.detect_anomaly(features)
                if anomaly_score > CONFIG['threshold']:
                    self.block_ip(packet['src_ip'])
                time.sleep(1)  # Задержка для симуляции
            except Exception as e:
                self.logger.error(f"Ошибка в основном цикле: {str(e)}")
                time.sleep(5)

if __name__ == "__main__":
    try:
        firewall = AIFirewall()
        firewall.run()
    except KeyboardInterrupt:
        print("\nЗавершение работы системы...")
        subprocess.run("sudo iptables -F", shell=True)
        subprocess.run("sudo ufw --force enable", shell=True)
        sys.exit(0)
