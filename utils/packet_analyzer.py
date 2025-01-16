# utils/packet_analyzer.py
from scapy.all import sniff
import threading
import queue
import logging


class PacketAnalyzer:
    def __init__(self, network_processor, threats_tab=None, network_tab=None):
        self.network_processor = network_processor
        self.threats_tab = threats_tab
        self.network_tab = network_tab
        if not self.threats_tab:
            logging.warning("PacketAnalyzer initialized without threats_tab")
        self.packet_queue = queue.Queue()
        self.is_running = False
        self.processing_thread = None

    def start_capture(self):
        """Start packet capture and analysis"""
        self.is_running = True
        self.processing_thread = threading.Thread(target=self._process_packets)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        try:
            sniff(prn=self._packet_callback, store=0)
        except Exception as e:
            logging.error(f"Error in packet capture: {str(e)}")
            self.stop_capture()

    def stop_capture(self):
        """Stop packet capture and analysis"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join()

    def _packet_callback(self, packet):
        """Callback function for packet capture"""
        if self.is_running:
            self.packet_queue.put(packet)

    def _process_packets(self):
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                result, original_packet = self.network_processor.process_packet(packet)

                if result and self.threats_tab:
                    try:
                        # Display all packets, not just attacks
                        self.threats_tab.add_threat(
                            threat_type=f"{result['protocol'].upper()} {result['prediction']}",
                            source=result['source'],
                            destination=result['destination'],
                            risk_level=result['risk_level'] if result['prediction'] == 'Attack' else 'None'
                        )
                    except Exception as e:
                        logging.error(f"Error adding packet to display: {str(e)}")

            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error processing packet: {str(e)}")