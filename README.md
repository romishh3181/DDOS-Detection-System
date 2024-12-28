# 📊 **DDoS Detection System**

## 🚀 **Overview**
The **DDoS Detection System** is a real-time network traffic monitoring and mitigation tool designed to detect Distributed Denial of Service (DDoS) attacks. It uses machine learning models to identify suspicious traffic patterns and trigger appropriate mitigation measures. This system supports both **Windows** and **Linux** environments.

---

## 🛠️ **Features**
- ✅ **Real-time Packet Sniffing**: Monitors network traffic using PyShark.
- ✅ **Machine Learning-Based Detection**: Predicts DDoS attacks using a pre-trained TensorFlow model.
- ✅ **Automatic Mitigation**: Blocks malicious IP addresses using firewall rules.
- ✅ **Cross-Platform Support**: Works on both **Windows** and **Linux**.
- ✅ **Logging Mechanism**: Stores detection logs in a CSV file.

---

## 📂 **Project Structure**
```
DDoS_Detection/
├── models/         # Pre-trained model and scaler files
├── notebooks/      # Jupyter notebooks for data analysis and training
├── src/            # Python scripts for detection and mitigation
├── requirements.txt  # Python dependencies
└── README.md       # Documentation
```

---

## 🧠 **How It Works**
1. **Packet Capture:** Captures live network traffic using PyShark.
2. **Feature Extraction:** Extracts essential network features from each packet.
3. **Prediction:** Uses a TensorFlow model to classify traffic as normal or DDoS.
4. **Mitigation:** If an attack is detected, it blocks the attacker's IP using firewall rules.
5. **Logging:** All activities are logged into a CSV file.

---

## 💻 **Setup and Installation**

### Prerequisites
- Python 3.8+
- Virtual Environment
- Wireshark
- Tshark

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DDOS-Detection-System.git
   cd DDOS-Detection-System
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Update `src/detection.py` with your network interface.

5. Run the detection script:
   ```bash
   python src/detection.py
   ```

---

## 📝 **Usage**
- Ensure Wireshark and Tshark are installed.
- Run the script as an administrator.
- Monitor real-time detection logs in the `logs/` folder.
- View blocked IP addresses via firewall rules.

---

## 📊 **Logging**
Logs are saved in a CSV file located at:
```
Logs/ddos_logs.csv
```
Each log entry includes:
- Timestamp
- Source IP
- Destination IP
- Attack Status (Normal/Detected)

---

## 🛡️ **Mitigation**
- **Windows:** Firewall rules block malicious IPs.
- **Linux:** `iptables` rules block malicious IPs.
- To unblock an IP:
   ```bash
   netsh advfirewall firewall delete rule name="Block <IP>"  # Windows
   sudo iptables -D INPUT -s <IP> -j DROP  # Linux
   ```

---

## 📑 **License**
This project is licensed under the **MIT License**.

---

## 🤝 **Contribution**
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-new-feature
   ```
3. Commit your changes.
4. Push to your branch and create a Pull Request.

---

## 📬 **Contact**
- **Author:** Rohan Mishra
- **Email:** mavrohan2004@gmail.com
- **GitHub:** [romishh3181](https://github.com/romishh3181)

---

⭐ If you find this project helpful, give it a star!
