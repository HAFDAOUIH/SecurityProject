# utils/network_processor.py
from scapy.all import IP, TCP, UDP, ICMP
import logging
from typing import Dict, Any

class NetworkProcessor:
    def __init__(self):
        self.current_connections = {}
        self.packet_count = 0
        logging.info("NetworkProcessor initialized")

    def process_packet(self, packet) -> Dict[str, Any]:
        """Process a network packet and extract relevant features"""
        try:
            if IP not in packet:
                return None

            self.packet_count += 1
            features = {}

            # Extract IP features
            ip_features = self._extract_ip_features(packet[IP])
            features.update(ip_features)

            # Extract protocol-specific features
            if TCP in packet:
                features.update(self._extract_tcp_features(packet[TCP]))
            elif UDP in packet:
                features.update(self._extract_udp_features(packet[UDP]))
            elif ICMP in packet:
                features.update(self._extract_icmp_features(packet[ICMP]))
            else:
                features.update({
                    'service': 'other',
                    'flag': 'OTH'
                })

            # Add connection-based features
            conn_key = self._get_connection_key(packet)
            features.update(self._get_connection_features(conn_key))

            return self._normalize_features(features)

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            return None

    def _extract_ip_features(self, ip) -> Dict[str, Any]:
        """Extract features from IP layer"""
        return {
            'protocol_type': ip.proto,
            'src_bytes': len(ip),
            'dst_bytes': 0,  # Will be updated with response
            'land': 1 if ip.src == ip.dst else 0,
            'wrong_fragment': ip.frag,
            'urgent': 0  # Will be updated for TCP
        }

    def _extract_tcp_features(self, tcp) -> Dict[str, Any]:
        """Extract features from TCP layer"""
        flags = str(tcp.flags)
        return {
            'service': tcp.dport,
            'flag': self._get_tcp_flag(flags),
            'urgent': tcp.urgptr if tcp.urgptr else 0
        }

    def _extract_udp_features(self, udp) -> Dict[str, Any]:
        """Extract features from UDP layer"""
        return {
            'service': udp.dport,
            'flag': 'UDP'
        }

    def _extract_icmp_features(self, icmp) -> Dict[str, Any]:
        """Extract features from ICMP layer"""
        return {
            'service': 'icmp',
            'flag': 'ICMP'
        }

    def _get_connection_key(self, packet) -> str:
        """Generate unique connection key"""
        ip = packet[IP]
        if TCP in packet:
            proto = 'TCP'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = 'UDP'
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = 'ICMP'
            sport = 0
            dport = 0

        return f"{ip.src}:{sport}-{ip.dst}:{dport}-{proto}"

    def _get_connection_features(self, conn_key: str) -> Dict[str, Any]:
        """Get connection-based features"""
        conn = self.current_connections.get(conn_key, {
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,

        })

        conn['count'] += 1
        self.current_connections[conn_key] = conn

        return conn

    def _normalize_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize features to match training data format"""
        # Start with default values for all base features
        default_features = {
            'duration': 0,
            'protocol_type': 0,
            'service': 0,
            'flag': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0,
            # Add frequency encoding features
            'protocol_type_freq': 0,
            'service_freq': 0,
            'flag_freq': 0
        }

        return {**default_features, **features}

    def _get_tcp_flag(self, flags: str) -> str:
        """Convert TCP flags to categorical value"""
        flag_map = {
            'S': 'SYN',
            'SA': 'SYNACK',
            'A': 'ACK',
            'FA': 'FINACK',
            'R': 'RST',
            'P': 'PUSH',
            'F': 'FIN'
        }
        return flag_map.get(flags, 'OTH')