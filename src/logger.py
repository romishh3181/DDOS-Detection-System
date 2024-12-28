import csv
import os
from datetime import datetime


LOG_DIR = "D:\DDOS_Detection\Logs"
LOG_FILE = os.path.join(LOG_DIR, "ddos_logs.csv")

os.makedirs(LOG_DIR, exist_ok=True)

if not os.path.isfile(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Source_IP", "Destination_IP", "Attack_Status", "Action_Taken"])

def log_ddos_event(source_ip, destination_ip, attack_status, action_taken):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, source_ip, destination_ip, attack_status, action_taken])

    print(f"[LOGGED] {timestamp} - {attack_status} from {source_ip} to {destination_ip} ({action_taken})")
