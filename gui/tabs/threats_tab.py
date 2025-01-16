import logging
import tkinter as tk
from tkinter import ttk, messagebox
import time


'''class ThreatsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()

    def create_widgets(self):
        # Threat List
        columns = ("Time", "Type", "Source", "Destination", "Risk", "Status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        # Configure columns
        self.tree.heading("Time", text="Time")
        self.tree.heading("Type", text="Threat Type")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Risk", text="Risk Level")
        self.tree.heading("Status", text="Status")

        # Set column widths
        self.tree.column("Time", width=150)
        self.tree.column("Type", width=150)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Risk", width=100)
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

        ttk.Button(control_frame, text="Block Threat", command=self.block_threat).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Quarantine", command=self.quarantine_threat).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear History", command=self.clear_history).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Export Report", command=self.export_report).pack(side="left", padx=5)

    def add_threat(self, threat_type, source, destination, risk_level):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", "end", values=(
            timestamp,
            threat_type,
            source,
            destination,
            risk_level,
            "Detected"
        ))

    def block_threat(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to block")
            return

        # Add blocking logic here
        item = self.tree.item(selected[0])
        self.tree.set(selected[0], "Status", "Blocked")

    def quarantine_threat(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to quarantine")
            return

        # Add quarantine logic here
        item = self.tree.item(selected[0])
        self.tree.set(selected[0], "Status", "Quarantined")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the threat history?"):
            for item in self.tree.get_children():
                self.tree.delete(item)

    def export_report(self):
        # Add export functionality
        pass'''

import tkinter as tk
from tkinter import ttk
from datetime import datetime
import csv
import os


class ThreatsTab(ttk.Frame):
    def __init__(self, parent, config=None):
        super().__init__(parent)
        self.config = config
        self.threats = []
        self.create_widgets()

    def create_widgets(self):
        # Create treeview for threats
        columns = ("Time", "Type", "Source", "Destination", "Risk", "Status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        # Configure columns
        column_widths = {
            "Time": 150,
            "Type": 150,
            "Source": 150,
            "Destination": 150,
            "Risk": 100,
            "Status": 100
        }

        for col in columns:
            self.tree.heading(col, text=col.replace("Type", "Threat Type"))
            self.tree.column(col, width=column_widths.get(col, 100))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack widgets
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)

        # Add buttons
        buttons = [
            ("Block Threat", self.block_threat),
            ("Quarantine", self.quarantine_threat),
            ("Clear History", self.clear_history),
            ("Export Report", self.export_report)
        ]

        for text, command in buttons:
            ttk.Button(control_frame, text=text, command=command).pack(
                side="left", padx=5
            )

    def add_threat(self, threat_type, source, destination, risk_level, timestamp=None, status="Detected"):
        """Add a new threat/packet to the treeview"""
        if timestamp is None:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamp, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

        item_id = self.tree.insert("", "end", values=(
            timestamp,
            threat_type,
            source,
            destination,
            risk_level,
            status
        ))

        # Add visual distinction between normal and attack traffic
        if "NORMAL" in threat_type.upper():
            self.tree.item(item_id, tags=('normal',))
        else:
            self.tree.item(item_id, tags=('attack',))

        # Configure tag colors
        self.tree.tag_configure('normal', foreground='green')
        self.tree.tag_configure('attack', foreground='red')

        self.threats.append((timestamp, threat_type, source, destination, risk_level, status))

    def block_threat(self):
        """Block the selected threat"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to block")
            return

        for item in selected:
            values = self.tree.item(item)['values']
            self.tree.set(item, "Status", "Blocked")
            # Here you would implement actual blocking logic

    def quarantine_threat(self):
        """Quarantine the selected threat"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to quarantine")
            return

        for item in selected:
            values = self.tree.item(item)['values']
            self.tree.set(item, "Status", "Quarantined")
            # Here you would implement actual quarantine logic

    def clear_history(self):
        """Clear all threats from the treeview"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the threat history?"):
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.threats = []

    def export_report(self):
        """Export threats to a CSV file"""
        try:
            if not self.tree.get_children():
                messagebox.showinfo("Info", "No threats to export")
                return

            # Get the save location
            filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            if self.config and 'DIRECTORIES' in self.config:
                save_dir = self.config['DIRECTORIES'].get('LOGS', '')
                filename = os.path.join(save_dir, filename)

            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write headers
                writer.writerow(['Time', 'Threat Type', 'Source', 'Destination',
                                 'Risk Level', 'Status'])
                # Write threats
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    writer.writerow(values)

            messagebox.showinfo("Success", f"Report exported to {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")