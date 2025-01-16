import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time


class ProcessTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
        self.monitoring = False
        self.start_monitoring()

    def create_widgets(self):
        # Process List
        columns = ("PID", "Name", "CPU", "Memory", "Status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        # Configure columns
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Process Name")
        self.tree.heading("CPU", text="CPU %")
        self.tree.heading("Memory", text="Memory %")
        self.tree.heading("Status", text="Status")

        # Set column widths
        self.tree.column("PID", width=100)
        self.tree.column("Name", width=200)
        self.tree.column("CPU", width=100)
        self.tree.column("Memory", width=100)
        self.tree.column("Status", width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack widgets
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(control_frame, text="Refresh", command=self.refresh_processes).pack(side="left", padx=5)
        ttk.Button(control_frame, text="End Process", command=self.end_process).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Process Details", command=self.show_process_details).pack(side="left", padx=5)

    def start_monitoring(self):
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_processes)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False

    def _monitor_processes(self):
        while self.monitoring:
            self.refresh_processes()
            time.sleep(2)

    def refresh_processes(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Get process list
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                self.tree.insert("", "end", values=(
                    proc.info['pid'],
                    proc.info['name'],
                    f"{proc.info['cpu_percent']:.1f}",
                    f"{proc.info['memory_percent']:.1f}",
                    proc.info['status']
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def end_process(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process to end")
            return

        pid = self.tree.item(selected[0])['values'][0]
        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("Success", f"Process {pid} has been terminated")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")

    def show_process_details(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process to view details")
            return

        pid = self.tree.item(selected[0])['values'][0]
        try:
            proc = psutil.Process(pid)
            details = f"""
            Process Details:
            PID: {proc.pid}
            Name: {proc.name()}
            Status: {proc.status()}
            CPU Usage: {proc.cpu_percent()}%
            Memory Usage: {proc.memory_percent():.1f}%
            Created: {time.ctime(proc.create_time())}
            User: {proc.username()}
            """
            messagebox.showinfo("Process Details", details)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")