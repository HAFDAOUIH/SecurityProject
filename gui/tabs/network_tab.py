import logging
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff
import threading
import time
from utils.network_processor import NetworkProcessor
from utils.packet_analyzer import PacketAnalyzer


class NetworkTab(ttk.Frame):
    def __init__(self, parent, threats_tab=None):
        super().__init__(parent)
        self.threats_tab = threats_tab
        if not self.threats_tab:
            logging.warning("NetworkTab initialized without threats_tab")
        self.network_processor = NetworkProcessor()
        self.packet_analyzer = PacketAnalyzer(self.network_processor, self.threats_tab)
        self.create_widgets()
        self.is_capturing = False

    def create_widgets(self):
        # Network Traffic Monitor
        monitor_frame = ttk.LabelFrame(self, text="Network Traffic", padding=10)
        monitor_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.traffic_text = scrolledtext.ScrolledText(monitor_frame)
        self.traffic_text.pack(fill="both", expand=True)

        # Statistics
        stats_frame = ttk.LabelFrame(self, text="Network Statistics", padding=10)
        stats_frame.pack(fill="x", padx=5, pady=5)

        self.packets_label = ttk.Label(stats_frame, text="Packets Captured: 0")
        self.packets_label.pack(side="left", padx=10)

        self.threats_label = ttk.Label(stats_frame, text="Threats Detected: 0")
        self.threats_label.pack(side="left", padx=10)

        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)

        self.capture_button = ttk.Button(control_frame, text="Start Capture",
                                       command=self.toggle_capture)
        self.capture_button.pack(side="left", padx=5)

        ttk.Button(control_frame, text="Clear Log",
                  command=self.clear_log).pack(side="left", padx=5)

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        self.is_capturing = True
        self.capture_button.config(text="Stop Capture")
        self.packet_analyzer.start_capture()
        self.log_message("Network capture started")

    def stop_capture(self):
        self.is_capturing = False
        self.capture_button.config(text="Start Capture")
        self.packet_analyzer.stop_capture()
        self.log_message("Network capture stopped")

    def clear_log(self):
        self.traffic_text.delete(1.0, tk.END)

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.traffic_text.see(tk.END)