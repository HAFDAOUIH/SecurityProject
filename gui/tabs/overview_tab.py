import tkinter as tk
from tkinter import ttk, scrolledtext
import psutil
import threading
import time


class OverviewTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
        self.start_monitoring()

    def create_widgets(self):
        # System Information
        info_frame = ttk.LabelFrame(self, text="System Information", padding=10)
        info_frame.pack(fill="x", padx=5, pady=5)

        self.cpu_label = ttk.Label(info_frame, text="CPU Usage: 0%")
        self.cpu_label.pack(anchor="w")

        self.memory_label = ttk.Label(info_frame, text="Memory Usage: 0%")
        self.memory_label.pack(anchor="w")

        # Status Log
        log_frame = ttk.LabelFrame(self, text="System Status", padding=10)
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True)

        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)

    def start_monitoring(self):
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.log_message("System monitoring started")

    def stop_monitoring(self):
        self.monitoring = False
        self.log_message("System monitoring stopped")

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def _monitor_system(self):
        while self.monitoring:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent

            self.cpu_label.config(text=f"CPU Usage: {cpu_percent}%")
            self.memory_label.config(text=f"Memory Usage: {memory_percent}%")

            time.sleep(1)

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)