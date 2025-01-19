# gui/tabs/network_tab.py
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from utils.network_processor import NetworkProcessor
from utils.packet_analyzer import PacketAnalyzer
from scapy.all import get_if_list
import platform

class NetworkTab(ttk.Frame):
    def __init__(self, parent, threats_tab=None, packet_analyzer=None):
        super().__init__(parent)
        self.threats_tab = threats_tab
        if not self.threats_tab:
            logging.warning("NetworkTab initialized without threats_tab")

        self.packet_analyzer = packet_analyzer
        if not self.packet_analyzer:
            logging.warning("NetworkTab initialized without packet_analyzer")

        self.is_capturing = False
        self.interfaces = self.get_network_interfaces()
        self.create_widgets()

    def get_network_interfaces(self):
        """Get list of available network interfaces based on OS"""
        try:
            if platform.system() == "Windows":
                # Get Windows interfaces
                interfaces = print('Windows trash')
                return [iface.get('name', '') for iface in interfaces if iface.get('name')]
            else:
                # Get Linux/Unix interfaces
                return get_if_list()
        except Exception as e:
            logging.error(f"Error getting network interfaces: {str(e)}")
            return ["Error loading interfaces"]

    def create_widgets(self):
        # Interface Selection
        interface_frame = ttk.LabelFrame(self, text="Network Interface", padding=10)
        interface_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(interface_frame, text="Select Interface:").pack(side="left", padx=5)

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            interface_frame,
            textvariable=self.interface_var,
            values=self.interfaces,
            state="readonly",
            width=30
        )
        if self.interfaces:
            self.interface_combo.set(self.interfaces[0])
        self.interface_combo.pack(side="left", padx=5)

        ttk.Button(
            interface_frame,
            text="Refresh Interfaces",
            command=self.refresh_interfaces
        ).pack(side="left", padx=5)

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

        self.capture_button = ttk.Button(
            control_frame,
            text="Start Capture",
            command=self.toggle_capture
        )
        self.capture_button.pack(side="left", padx=5)

        ttk.Button(
            control_frame,
            text="Clear Log",
            command=self.clear_log
        ).pack(side="left", padx=5)

    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        self.interfaces = self.get_network_interfaces()
        self.interface_combo['values'] = self.interfaces
        if self.interfaces:
            self.interface_combo.set(self.interfaces[0])

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        if not self.packet_analyzer:
            self.log_message("Error: Packet analyzer not initialized")
            return

        selected_interface = self.interface_var.get()
        if not selected_interface:
            self.log_message("Error: Please select a network interface")
            return

        try:
            self.is_capturing = True
            self.capture_button.config(text="Stop Capture")
            self.interface_combo.config(state="disabled")

            # Set the selected interface in the packet analyzer
            self.packet_analyzer.set_interface(selected_interface)
            self.packet_analyzer.start_capture()

            self.log_message(f"Network capture started on interface: {selected_interface}")
        except Exception as e:
            self.log_message(f"Error starting capture: {str(e)}")
            self.stop_capture()

    def stop_capture(self):
        if self.packet_analyzer:
            self.is_capturing = False
            self.capture_button.config(text="Start Capture")
            self.interface_combo.config(state="readonly")
            self.packet_analyzer.stop_capture()
            self.log_message("Network capture stopped")

    def clear_log(self):
        self.traffic_text.delete(1.0, tk.END)

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.traffic_text.see(tk.END)

    def update_statistics(self, packets_count, threats_count):
        """Update the statistics labels"""
        self.packets_label.config(text=f"Packets Captured: {packets_count}")
        self.threats_label.config(text=f"Threats Detected: {threats_count}")
        logging.info(f"Updated statistics: Packets={packets_count}, Threats={threats_count}")
