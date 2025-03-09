import subprocess
import re
from collections import defaultdict
import time
import os
import threading
from scapy.all import sniff, IP, TCP
from datetime import datetime

# Настройки фаервола
REQUEST_LIMIT = 100
TIME_WINDOW = 60
BLOCK_TIME = 3600

ip_request_count = defaultdict(int)

def unblock_ip_after_delay(ip, log_entry):
    """Разблокирует IP через BLOCK_TIME секунд и логирует событие."""
    time.sleep(BLOCK_TIME)
    subprocess.call(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    print(f"[Фаервол] IP-адрес {ip} разблокирован.")
    
    # Логирование разблокировки
    log_entry["action"] = "UNBLOCK"
    log_entry["unblock_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("/var/log/firewall_blocked_ips.log", "a", encoding="utf-8") as log_file:
        log_file.write(f"{log_entry}\n")
    
    ip_request_count[ip] = 0  # Сброс счетчика

def block_ip(ip, reason, packet=None):
    """Блокирует IP и запускает таймер для разблокировки."""
    subprocess.call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    print(f"[Фаервол] IP-адрес {ip} заблокирован. Причина: {reason}.")

    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "reason": reason,
        "request_count": ip_request_count[ip],
        "action": "BLOCK"
    }

    if packet:
        if packet.haslayer(IP):
            log_entry["src_ip"] = packet[IP].src
            log_entry["dst_ip"] = packet[IP].dst
            log_entry["protocol"] = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        if packet.haslayer(TCP):
            log_entry["src_port"] = packet[TCP].sport
            log_entry["dst_port"] = packet[TCP].dport
            log_entry["tcp_flags"] = str(packet[TCP].flags)  # Преобразуем флаги в строку

    # Запись блокировки в лог
    log_path = "/var/log/firewall_blocked_ips.log"
    if not os.path.exists(log_path):
        open(log_path, "w").close()
        os.chmod(log_path, 0o644)
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"{log_entry}\n")

    # Запуск разблокировки в отдельном потоке
    threading.Thread(
        target=unblock_ip_after_delay,
        args=(ip, log_entry)
    ).start()

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_request_count[ip_src] += 1

        if ip_request_count[ip_src] > REQUEST_LIMIT:
            reason = f"Слишком много запросов ({ip_request_count[ip_src]} за {TIME_WINDOW} сек)"
            block_ip(ip_src, reason, packet)

        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 0:
                block_ip(ip_src, "NULL-пакет", packet)
            elif tcp_flags == 1:
                block_ip(ip_src, "FIN-пакет", packet)

def monitor_traffic():
    print("[Фаервол] Запуск мониторинга...")
    sniff(prn=analyze_packet, filter="ip")

if __name__ == "__main__":
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("[Фаервол] Остановлен.")
