# utils/packet_analyzer.py
from scapy.all import IP, sniff, conf
import threading
import logging
from tkinter import ttk, messagebox
from typing import Optional
from .model_handler import ModelHandler
from .network_processor import NetworkProcessor

class PacketAnalyzer:
    def __init__(self, network_processor: NetworkProcessor, threats_tab, config=None):
        self.network_processor = network_processor
        self.threats_tab = threats_tab
        self.config = config
        self.model_handler = ModelHandler(config)
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.interface = None
        self.packets_processed = 0
        self.threats_detected = 0

        logging.info("PacketAnalyzer initialized")


        if self.threats_tab:
            logging.info("ThreatsTab is successfully passed to PacketAnalyzer")
        else:
            logging.error("ThreatsTab is not initialized in PacketAnalyzer")

    def set_interface(self, interface: str):
        """Set the network interface to capture packets from"""
        self.interface = interface
        logging.info(f"Network interface set to: {interface}")

    def start_capture(self):
        """Start packet capture and analysis"""
        if not self.interface:
            raise ValueError("No network interface selected")

        if not self.is_capturing:
            try:
                self.is_capturing = True
                self.capture_thread = threading.Thread(target=self._capture_packets)
                self.capture_thread.daemon = True
                self.capture_thread.start()
                logging.info(f"Packet capture started on interface: {self.interface}")
            except Exception as e:
                logging.error(f"Failed to start packet capture: {str(e)}")
                self.is_capturing = False
                raise

    def stop_capture(self):
        """Stop packet capture"""
        try:
            self.is_capturing = False
            if self.capture_thread:
                self.capture_thread.join(timeout=1.0)
            logging.info("Packet capture stopped")
        except Exception as e:
            logging.error(f"Error stopping packet capture: {str(e)}")

    def _capture_packets(self):
        """Capture and analyze network packets"""
        try:
            # Configure Scapy to use the selected interface
            conf.iface = self.interface

            sniff(
                iface=self.interface,
                prn=self._analyze_packet,
                store=0,
                stop_filter=lambda _: not self.is_capturing
            )
        except Exception as e:
            logging.error(f"Error in packet capture: {str(e)}")
            self.is_capturing = False

    def _analyze_packet(self, packet):
        """Analyze a single packet"""
        try:
            if IP not in packet:
                return

            # Extract features
            features = self.network_processor.process_packet(packet)

            # Skip if feature extraction failed
            if not features:
                logging.warning("No features extracted from packet.")
                return

            # Update packet count
            self.packets_processed += 1

            # Preprocess features
            preprocessed_features = self.model_handler.preprocess_packet(features)

            # Make prediction
            prediction, confidence = self.model_handler.predict(preprocessed_features)

            # Determine risk level
            risk_level = self._calculate_risk_level(prediction, confidence)

            logging.info(f"Prediction: {prediction}, Confidence: {confidence}, Risk Level: {risk_level}")

            # Add to threats tab only if actually suspicious
            self.threats_detected += 1
            self.threats_tab.add_threat(
                threat_type=prediction,
                source=packet[IP].src,
                destination=packet[IP].dst,
                risk_level=risk_level,
                status="Detected"
            )

            # Update statistics in the Network Tab
            if hasattr(self.threats_tab, 'update_statistics'):
                self.threats_tab.update_statistics(self.packets_processed, self.threats_detected)

        except Exception as e:
            logging.error(f"Error analyzing packet: {str(e)}")
            logging.exception("Full traceback:")


    def _calculate_risk_level(self, prediction: str, confidence: float) -> str:
        """Calculate risk level based on prediction and confidence"""
        # If it's normal traffic, base risk on confidence inversely
        if prediction.lower() == "normal":
            if confidence >= 0.8:
                return "Low"
            elif confidence >= 0.6:
                return "Medium"
            else:
                return "High"

        # For attack traffic, use confidence directly
        if confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"