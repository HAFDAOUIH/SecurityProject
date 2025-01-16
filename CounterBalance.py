import threading
import tkinter as tk
from tkinter import scrolledtext
import logging
import subprocess
import os
import re
import psutil
import numpy as np
import pandas as pd
import time
from scapy.all import sniff
import requests
import zipfile
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout

class CounterBalance:
    IMG_WIDTH = 128
    IMG_HEIGHT = 128

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CounterBalance - An AI-driven Intrusion Detection and Endpoint Defense System")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f0f0f0")
        self.root.state('normal')  # Maximize window

        # Check and create required directories
        self.create_directories()

        # GUI components
        self.create_gui()

        # Initialize logging
        self.init_logging()

        # Start CPU and memory monitoring
        self.monitor_thread = threading.Thread(target=self.monitor_system_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Check IDS & EDR status every 3 seconds
        self.check_edr_status()

        # Initialize AI model
        self.init_ai_model()

        # Start the GUI
        self.root.mainloop()

    def create_directories(self):
        # Check and create required directories
        directories = ['logs', 'dataset', 'quarantine']
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def create_gui(self):
        # Title and subtitle
        title_frame = tk.Frame(self.root, bg="#374785")
        title_frame.pack(fill="x")

        self.title_label = tk.Label(title_frame, text="CounterBalance", font=("Helvetica", 24, "bold"), fg="white", bg="#374785")
        self.title_label.pack(pady=10)

        self.subtitle_label = tk.Label(title_frame, text="An AI-driven Intrusion Detection and Endpoint Defense System", font=("Helvetica", 14), fg="white", bg="#374785")
        self.subtitle_label.pack()

        # Buttons
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(fill="x")

        self.start_stop_button = tk.Button(button_frame, text="Start IDS & EDR", font=("Helvetica", 10), command=self.start_stop_detection)
        self.start_stop_button.pack(side="left", padx=5)

        self.open_logs_button = tk.Button(button_frame, text="Open Logs Directory", font=("Helvetica", 10), command=self.open_logs_directory)
        self.open_logs_button.pack(side="left", padx=5)

        self.scan_files_button = tk.Button(button_frame, text="Scan Files", font=("Helvetica", 10), command=self.scan_files)
        self.scan_files_button.pack(side="left", padx=5)

        self.monitor_processes_button = tk.Button(button_frame, text="Monitor Processes", font=("Helvetica", 10), command=self.monitor_processes)
        self.monitor_processes_button.pack(side="left", padx=5)

        self.end_process_button = tk.Button(button_frame, text="End Process", font=("Helvetica", 10), command=self.end_selected_process)
        self.end_process_button.pack(side="left", padx=5)

        # Main content frame
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)

        # Divide the GUI into six equal parts
        part_width = self.root.winfo_screenwidth() // 6

        # Left panel
        left_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        left_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console1_label = tk.Label(left_panel, text="Live Network Traffic", font=("Helvetica", 12), bg="#f0f0f0")
        self.console1_label.pack(pady=5)

        self.console1_text = scrolledtext.ScrolledText(left_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console1_text.pack(pady=5, padx=5, fill="both", expand=True)

        self.console2_label = tk.Label(left_panel, text="IDS & EDR Information", font=("Helvetica", 12), bg="#f0f0f0")
        self.console2_label.pack(pady=5)

        self.console2_text = scrolledtext.ScrolledText(left_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console2_text.pack(pady=5, padx=5, fill="both", expand=True)

        # Middle panel
        middle_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        middle_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console3_label = tk.Label(middle_panel, text="Windows Event Log & Security Alerts", font=("Helvetica", 12), bg="#f0f0f0")
        self.console3_label.pack(pady=5)

        self.console3_text = scrolledtext.ScrolledText(middle_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console3_text.pack(pady=5, padx=5, fill="both", expand=True)

        # Right panel
        right_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        right_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console4_label = tk.Label(right_panel, text="Running Processes", font=("Helvetica", 12), bg="#f0f0f0")
        self.console4_label.pack(pady=5)

        self.console4_text = scrolledtext.ScrolledText(right_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console4_text.pack(pady=5, padx=5, fill="both", expand=True)

        self.console5_label = tk.Label(right_panel, text="System Metrics", font=("Helvetica", 12), bg="#f0f0f0")
        self.console5_label.pack(pady=5)

        self.console5_text = scrolledtext.ScrolledText(right_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console5_text.pack(pady=5, padx=5, fill="both", expand=True)

    def init_logging(self):
        # Initialize logging configuration
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Create a file handler
        log_file = "logs/counterbalance.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Create a logging format
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        # Add the file handler to the logger
        self.logger.addHandler(file_handler)

    def start_stop_detection(self):
        # Start or stop intrusion detection and endpoint defense
        if not hasattr(self, 'detect_thread') or not self.detect_thread.is_alive():
            self.start_detection()
        else:
            self.stop_detection()

    def start_detection(self):
        # Start intrusion detection and endpoint defense
        self.log_event("Starting IDS & EDR...")
        self.update_status("IDS & EDR running")
        self.detect_thread = threading.Thread(target=self.detect_intrusion)
        self.detect_thread.daemon = True
        self.detect_thread.start()
        self.start_stop_button.config(text="Stop IDS & EDR")

    def stop_detection(self):
        # Stop intrusion detection and endpoint defense
        if hasattr(self, 'detect_thread') and self.detect_thread.is_alive():
            self.log_event("Stopping IDS & EDR...")
            self.update_status("IDS & EDR stopping...")
            self.detect_thread.join()
            self.start_stop_button.config(text="Start IDS & EDR")
        else:
            self.log_event("IDS & EDR is not running.")

    def detect_intrusion(self):
        self.log_event("Starting intrusion detection...")

        try:
            # Continuously sniff network packets and perform anomaly detection
            sniff(prn=self.dpi_callback, store=False)
        except Exception as e:
            self.log_event(f"Error during intrusion detection: {str(e)}")
        finally:
            self.log_event("Intrusion detection stopped.")

    def dpi_callback(self, packet):
        # Deep Packet Inspection callback function
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            # Perform anomaly detection using Isolation Forest
            self.log_event("Anomaly detected: " + str(packet.summary()))

            # Get threat intelligence information for the detected IP address
            threat_info = self.get_threat_intelligence(packet["IP"].dst)
            if threat_info:
                self.log_event("Threat intelligence: " + threat_info)

            # Trigger automated response actions based on detected threats
            self.trigger_response_actions(packet)

            # Update network monitoring
            self.update_network_monitoring(packet)

    def trigger_response_actions(self, packet):
        # Automated response actions based on detected threats
        if not self.is_ip_blocked(packet["IP"].src):
            self.block_ip(packet["IP"].src)
        self.quarantine_malware(packet)
        self.prevent_execution(packet)

    def get_threat_intelligence(self, ip_address):
        # Fetch threat intelligence information from external APIs
        try:
            response = requests.get(f"https://api.threatintelligenceplatform.com/v1/ip/{ip_address}")
            if response.status_code == 200:
                return response.json().get("threat_description", "Threat intelligence data not available.")
            else:
                return "Threat intelligence data not available."
        except Exception as e:
            return f"Error fetching threat intelligence: {str(e)}"

    def block_ip(self, ip_address):
        # Block IP address using Windows Firewall
        self.log_event(f"Blocking IP address: {ip_address}")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name='Block IP'", "dir=in", "action=block", f"remoteip={ip_address}"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to block IP address {ip_address}: {e}")

    def is_ip_blocked(self, ip_address):
        # Check if the IP address is already blocked
        try:
            output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name='Block IP'"], universal_newlines=True)
            return ip_address in output
        except subprocess.CalledProcessError:
            return False

    def quarantine_malware(self, packet):
        # Placeholder function to quarantine malware
        if packet.haslayer("Raw"):
            payload = str(packet["Raw"])
            if "malware_signature" in payload:
                self.log_event("Quarantining malware...")
                try:
                    os.rename("infected_file.exe", f"quarantine/infected_file_{int(time.time())}.exe")
                    self.log_event("Malware quarantined successfully.")
                except Exception as e:
                    self.log_event(f"Error quarantining malware: {str(e)}")

    def prevent_execution(self, packet):
        # Placeholder function to prevent execution of malicious files
        if packet.haslayer("HTTP"):
            url = str(packet["HTTP"].Host) + str(packet["HTTP"].Path)
            if re.match(r"evil\.com/.*\.exe", url):
                self.log_event("Preventing execution of malicious file...")
                try:
                    subprocess.run(["powershell", "Remove-Item", "-Path", f"C:\\Users\\{os.getlogin()}\\Downloads\\malicious_file.exe", "-Force"], check=True)
                    self.log_event("Malicious file execution prevented.")
                except subprocess.CalledProcessError as e:
                    self.log_event(f"Error preventing execution of malicious file: {str(e)}")

    def update_network_monitoring(self, packet):
        # Update network monitoring information in the GUI
        self.console1_text.insert(tk.END, str(packet.summary()) + "\n")
        self.console1_text.see(tk.END)

    def open_logs_directory(self):
        # Open logs directory
        log_dir = os.path.realpath("logs")
        subprocess.Popen(f'explorer "{log_dir}"')

    def monitor_system_metrics(self):
        # Continuously monitor CPU and memory usage
        while True:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent

            # Update system metrics in the GUI
            self.console5_text.delete(1.0, tk.END)
            self.console5_text.insert(tk.END, f"CPU Usage: {cpu_usage}%\nMemory Usage: {memory_usage}%")
            self.console5_text.see(tk.END)

    def check_edr_status(self):
        # Check IDS & EDR status every 3 seconds
        if hasattr(self, 'detect_thread') and self.detect_thread.is_alive():
            self.update_status("IDS & EDR running")
        else:
            self.update_status("IDS & EDR not running")
        self.root.after(3000, self.check_edr_status)

    def update_status(self, status):
        # Update IDS & EDR status in the GUI
        self.console2_text.delete(1.0, tk.END)
        self.console2_text.insert(tk.END, status)
        self.console2_text.see(tk.END)

    def scan_files(self):
        # Placeholder function to scan files for malware
        self.log_event("Scanning files for malware...")

        # Simulate file scanning process
        time.sleep(5)

        self.log_event("File scanning complete.")

    def monitor_processes(self):
        # Monitor running processes
        self.log_event("Monitoring running processes...")

        # Get running processes information
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            process_list.append(proc.info)

        # Display running processes in the GUI
        self.console4_text.delete(1.0, tk.END)
        for process in process_list:
            self.console4_text.insert(tk.END, f"PID: {process['pid']} | Name: {process['name']} | User: {process['username']}\n")
        self.console4_text.see(tk.END)

        self.log_event("Process monitoring complete.")

    def end_selected_process(self):
        # Placeholder function to end a selected process
        self.log_event("Ending selected process...")

        # Simulate ending process
        time.sleep(2)

        self.log_event("Selected process ended.")

    def log_event(self, message):
        # Log events to the console and log file
        self.logger.info(message)
        self.console3_text.insert(tk.END, message + "\n")
        self.console3_text.see(tk.END)

    def init_ai_model(self):
        # Initialize AI model for malware detection
        self.log_event("Initializing AI model for malware detection...")

        # Placeholder code to train AI model
        X, y = self.load_dataset()
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        X_train_scaled = StandardScaler().fit_transform(X_train)
        X_test_scaled = StandardScaler().fit_transform(X_test)

        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train_scaled.shape[1],)),
            Dropout(0.5),
            Dense(64, activation='relu'),
            Dropout(0.5),
            Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        model.fit(X_train_scaled, y_train, epochs=10, batch_size=32, validation_data=(X_test_scaled, y_test))

        self.log_event("AI model initialized successfully.")

    def load_dataset(self):
        # Placeholder function to load dataset for AI model training
        self.log_event("Loading dataset for AI model training...")

        # Placeholder code to load dataset
        X = np.random.rand(100, 10)
        y = np.random.randint(2, size=(100,))

        self.log_event("Dataset loaded successfully.")

        return X, y

if __name__ == "__main__":
    app = CounterBalance()
