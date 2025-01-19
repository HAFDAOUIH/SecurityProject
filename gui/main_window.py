# gui/main_window.py
import os
import tkinter as tk
from tkinter import ttk, scrolledtext

from utils.config import ApplicationConfig
from utils.network_processor import NetworkProcessor
from utils.packet_analyzer import PacketAnalyzer
from .tabs.overview_tab import OverviewTab
from .tabs.network_tab import NetworkTab
from .tabs.process_tab import ProcessTab
from .tabs.threats_tab import ThreatsTab
import logging

class MainWindow(tk.Tk):
    def __init__(self, config: ApplicationConfig):
        super().__init__()
        self.configuration = config
        self.setup_window()
        self.create_menu()
        self.create_notebook()
        self.setup_logging()

    def setup_window(self):
        self.title("CounterBalance - AI-driven IDS")
        self.state('normal')
        self.configure(bg='#f0f0f0')

    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Settings", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Export Logs", command=self.export_logs)
        tools_menu.add_command(label="View Reports", command=self.view_reports)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        # Create threats_tab first since others depend on it
        self.threats_tab = ThreatsTab(self.notebook, config=self.configuration)

        # Initialize NetworkProcessor
        network_processor = NetworkProcessor()

        # Create PacketAnalyzer with proper configuration
        packet_analyzer = PacketAnalyzer(
            network_processor=network_processor,
            threats_tab=self.threats_tab,
            config=self.configuration
        )

        # Pass packet_analyzer to NetworkTab
        self.network_tab = NetworkTab(
            self.notebook,
            threats_tab=self.threats_tab,
            packet_analyzer=packet_analyzer
        )

        self.overview_tab = OverviewTab(self.notebook)
        self.process_tab = ProcessTab(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.network_tab, text="Network")
        self.notebook.add(self.process_tab, text="Processes")
        self.notebook.add(self.threats_tab, text="Threats")

    def setup_logging(self):
        """Set up logging configuration"""
        os.makedirs(self.configuration.logs_dir, exist_ok=True)
        log_file = os.path.join(self.configuration.logs_dir, 'main.log')

        logging.basicConfig(
            level=self.configuration.log_level,
            format=self.configuration.log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def show_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        # Add settings controls here

    def export_logs(self):
        # Add log export functionality
        pass

    def view_reports(self):
        # Add report viewing functionality
        pass