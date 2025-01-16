# utils/network_processor.py
import logging

import joblib
import numpy as np
from scapy.all import IP
import pandas as pd
from collections import defaultdict
import time


class NetworkProcessor:
    def __init__(self, model_path='models/best_model_XGB.pkl', scaler_path='models/scaler.pkl'):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.packet_stats = defaultdict(int)
        self.connection_stats = defaultdict(lambda: defaultdict(int))
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised',
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate'
        ]

        # Define mappings for categorical features
        self.protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        self.service_map = self._create_service_map()
        self.flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4,
                         'SH': 5, 'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9,
                         'OTH': 10}

    def _create_service_map(self):
        # Common network services mapping
        services = ['http', 'smtp', 'domain', 'ftp', 'ssh', 'telnet', 'pop3',
                    'imap', 'ssl', 'dns', 'other']
        return {service: idx for idx, service in enumerate(services)}

    def _extract_features(self, packet):
        if not packet.haslayer(IP):
            return None

        # Extract basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)

        # Update statistics
        self.packet_stats['total'] += 1
        conn_key = f"{src_ip}:{dst_ip}"
        self.connection_stats[conn_key]['count'] += 1
        self.connection_stats[conn_key]['bytes'] += length

        # Calculate features
        duration = time.time() - self.connection_stats[conn_key].get('start_time', time.time())
        if 'start_time' not in self.connection_stats[conn_key]:
            self.connection_stats[conn_key]['start_time'] = time.time()

        protocol_type = self.protocol_map.get(self._get_protocol_name(protocol), 2)
        service = self.service_map.get(self._get_service_name(packet), 10)
        flag = self.flag_map.get(self._get_tcp_flag(packet), 10)

        # Create feature vector
        features = {
            'duration': duration,
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': self.connection_stats[conn_key]['bytes'],
            'dst_bytes': length,
            'wrong_fragment': int(bool(packet.getfieldval('flags') & 0x1)),
            'hot': 0,  # Placeholder - could be implemented based on specific patterns
            'logged_in': 0,  # Placeholder - could be implemented based on session tracking
            'num_compromised': 0,  # Placeholder - could be implemented based on threat intel
            'count': self.connection_stats[conn_key]['count'],
            'srv_count': sum(1 for k in self.connection_stats if k.startswith(src_ip)),
            'serror_rate': self._calculate_error_rate(src_ip),
            'srv_serror_rate': self._calculate_service_error_rate(src_ip),
            'rerror_rate': self._calculate_reject_rate(src_ip)
        }



        return features

    def _get_protocol_name(self, protocol):
        protocol_names = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        return protocol_names.get(protocol, 'other')

    def _get_service_name(self, packet):
        common_ports = {
            80: 'http', 443: 'ssl', 21: 'ftp', 22: 'ssh',
            23: 'telnet', 25: 'smtp', 53: 'domain'
        }
        try:
            dport = packet.dport
            return common_ports.get(dport, 'other')
        except:
            return 'other'

    def _get_tcp_flag(self, packet):
        try:
            if packet.haslayer('TCP'):
                flags = packet['TCP'].flags
                if flags & 0x02 and flags & 0x10:  # SYN-ACK
                    return 'SF'
                elif flags & 0x02:  # SYN
                    return 'S0'
                elif flags & 0x14:  # RST-ACK
                    return 'RSTR'
            return 'OTH'
        except:
            return 'OTH'

    def _calculate_error_rate(self, ip):
        total = sum(1 for k in self.connection_stats if k.startswith(ip))
        errors = sum(1 for k in self.connection_stats if k.startswith(ip) and
                     self.connection_stats[k].get('errors', 0) > 0)
        return errors / total if total > 0 else 0

    def _calculate_service_error_rate(self, ip):
        return self._calculate_error_rate(ip)  # Simplified implementation

    def _calculate_reject_rate(self, ip):
        return self._calculate_error_rate(ip)  # Simplified implementation

    def process_packet(self, packet):
        features = self._extract_features(packet)
        if features is None:
            return None, None

        # Convert features to DataFrame
        df = pd.DataFrame([features])

        # Scale features
        scaled_features = self.scaler.transform(df)

        # Make prediction
        prediction = self.model.predict(scaled_features)[0]
        prediction_proba = self.model.predict_proba(scaled_features)[0]

        # Determine risk level based on probability
        risk_level = self._calculate_risk_level(prediction_proba[1]) if prediction == 1 else "None"

        result = {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'confidence': prediction_proba.max(),
            'risk_level': risk_level,
            'source': packet[IP].src,
            'destination': packet[IP].dst,
            'protocol': self._get_protocol_name(packet[IP].proto)
        }

        return result, packet
    def _calculate_risk_level(self, attack_probability):
        # Increase the thresholds to reduce false positives
        if attack_probability > 0.95:  # More strict threshold
            return "Critical"
        elif attack_probability > 0.85:
            return "High"
        elif attack_probability > 0.75:
            return "Medium"
        else:
            return "Low"