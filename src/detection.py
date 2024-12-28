import pyshark
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
import time
import os
import platform
from  logger import log_ddos_event
import subprocess


model = tf.keras.models.load_model(r'D:\DDOS_Detection\models\ddos_detection_model.h5')
scaler = pd.read_pickle(r'D:\DDOS_Detection\models\scaler.pkl')
label_encoder = pd.read_pickle(r'D:\DDOS_Detection\models\label_encoder.pkl')  


CAPTURE_INTERFACE = 'Wi-Fi'
ALERT_THRESHOLD = 0.8
def block_ip_win(ip_address):
    try:
        print(f"[INFO] Blocking IP on Windows: {ip_address}")
        command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        subprocess.run(command, shell=True, check=True)
        print(f"[SUCCESS] IP {ip_address} blocked on Windows firewall.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip_address} on Windows: {e}")
def block_ip_lin(ip_address):
    try:
        print(f"[INFO] Blocking IP on Linux: {ip_address}")
        command = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
        subprocess.run(command, shell=True, check=True)
        print(f"[SUCCESS] IP {ip_address} blocked on Linux firewall.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip_address} on Linux: {e}")
def detect_ddos(source_ip, destination_ip, is_attack):
    if is_attack:
        action_taken = "Blocked"
        attack_status = "DDoS Attack Detected"
    else:
        action_taken = "Allowed"
        attack_status = "Normal Traffic"
    
    log_ddos_event(source_ip, destination_ip, attack_status, action_taken)
def trigger_alert(src_ip, dest_ip):
    if src_ip == '0.0.0.0':
        print("[WARNING] Invalid Source IP detected, skipping mitigation.")
        return
    print(f"[ALERT] 🚨 DDoS Attack Detected!")
    print(f"Source IP: {src_ip}, Destination IP: {dest_ip}")
    system_pf=platform.system()
    if system_pf=='Windows':
        block_ip_win(src_ip)
    elif system_pf=='Linux':
        block_ip_lin(src_ip)
    else:
        print(f"Error occurred!!! Unsupported OS: {system_pf}. Cannot perform mitigation")          


def map_protocol(protocol):
    protocol_mapping = {
        'TCP': 6,
        'UDP': 17
    }
    return protocol_mapping.get(protocol, 0)


def extract_features(packet):
    try:
        features = {
            'Flow Duration': float(getattr(packet.frame_info, 'time_delta', 0) or 0),
            'Total Fwd Packets': 1 if hasattr(packet, 'tcp') else 0,
            'Total Backward Packets': 1 if hasattr(packet, 'udp') else 0,
            'Flow Bytes/s': float(getattr(packet, 'length', 0) or 0),
            'Flow Packets/s': 1.0,
            'Packet Length Mean': float(getattr(packet, 'length', 0) or 0),
            'Packet Length Std': 0.0,
            'SYN Flag Count': int('SYN' in getattr(packet.tcp, 'flags', '')) if hasattr(packet, 'tcp') else 0,
            'ACK Flag Count': int('ACK' in getattr(packet.tcp, 'flags', '')) if hasattr(packet, 'tcp') else 0,
            'FIN Flag Count': int('FIN' in getattr(packet.tcp, 'flags', '')) if hasattr(packet, 'tcp') else 0,
            'RST Flag Count': int('RST' in getattr(packet.tcp, 'flags', '')) if hasattr(packet, 'tcp') else 0,
            'Flow IAT Mean': float(getattr(packet.tcp, 'time_delta', 0) or 0) if hasattr(packet, 'tcp') else 0,
            'Flow IAT Std': 0.0,
            'Protocol': map_protocol(getattr(packet, 'transport_layer', '') or ''),
            'Source IP': getattr(packet.ip, 'src', '0.0.0.0') if hasattr(packet, 'ip') else '0.0.0.0',
            'Source Port': int(getattr(packet[packet.transport_layer], 'srcport', 0) or 0) if hasattr(packet, 'transport_layer') else 0,
            'Destination IP': getattr(packet.ip, 'dst', '0.0.0.0') if hasattr(packet, 'ip') else '0.0.0.0',
            'Destination Port': int(getattr(packet[packet.transport_layer], 'dstport', 0) or 0) if hasattr(packet, 'transport_layer') else 0,
            'Timestamp': getattr(packet, 'sniff_time', pd.Timestamp.now())
        }
        return features
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        return None


def start_realtime_detection():
    capture = pyshark.LiveCapture(interface=CAPTURE_INTERFACE,tshark_path=r"D:\Wireshark\tshark.exe")
    print("[INFO] Starting Real-Time DDoS Detection...")

    for packet in capture.sniff_continuously(packet_count=100):
        features = extract_features(packet)
        
        if features:
            data = pd.DataFrame([features])
            data['Timestamp'] = pd.to_datetime(data['Timestamp'])
            data['Hour'] = data['Timestamp'].dt.hour
            data['DayOfWeek'] = data['Timestamp'].dt.day_of_week
            data['Minute'] = data['Timestamp'].dt.minute
            data = data.drop(columns=['Source IP', 'Destination IP', 'Timestamp'])
            def categorize_port(port):
                if 0 <= port <= 1023:
                    return 'Well-known Port'
                elif 1024 <= port <= 49151:
                    return 'Registered Port'
                elif 49152 <= port <= 65535:
                    return 'Dynamic Port'
                else:
                    return 'Unknown Port'
            data['Source Port Category'] = data['Source Port'].apply(categorize_port)
            data['Destination Port Category'] =data['Destination Port'].apply(categorize_port)
            data = data.drop(columns=['Source Port', 'Destination Port'])
            data['Protocol'] = data['Protocol'].astype(int)
            if(data['Protocol']==6).any():
                data['Protocol_6']=True 
            else:
                data['Protocol_6']=False
            if(data['Protocol']==17).any():
                data['Protocol_17']=True 
            else:
                data['Protocol_17']=False
            if(data['Source Port Category']=='Registered Port').any():
                data['Source Port Category_Registered Port']=True
            else:
                data['Source Port Category_Registered Port']=False       
            if(data['Source Port Category']=='Well-known Port').any():
                data['Source Port Category_Well-known Port']=True
            else:
                data['Source Port Category_Well-known Port']=False
            if(data['Destination Port Category']=='Registered Port').any():
                data['Destination Port Category_Registered Port']=True
            else:
                data['Destination Port Category_Registered Port']=False       
            if(data['Destination Port Category']=='Well-known Port').any():
                data['Destination Port Category_Well-known Port']=True
            else:
                data['Destination Port Category_Well-known Port']=False       
            data = data.drop(columns=['Source Port Category', 'Destination Port Category','Protocol'])
            num_cols = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
                        'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean', 
                        'Packet Length Std', 'SYN Flag Count', 'ACK Flag Count', 
                        'FIN Flag Count', 'RST Flag Count', 'Flow IAT Mean', 'Flow IAT Std']
            
            data[num_cols] = scaler.transform(data[num_cols])
            
           
            prediction = model.predict(data)
            prediction_class = (prediction > ALERT_THRESHOLD).astype(int)
            
            if prediction_class[0][0] == 0: 
                trigger_alert(features['Source IP'], features['Destination IP'])
                detect_ddos(features['Source IP'], features['Destination IP'],True)
            else:
                print(f"[INFO] Normal Traffic Detected: {features['Source IP']} -> {features['Destination IP']}")
                detect_ddos(features['Source IP'], features['Destination IP'],False)
        time.sleep(0.1) 

if __name__ == '__main__':
    start_realtime_detection()
