# utils/config.py
import os
import logging
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class ApplicationConfig:
    """Application configuration class"""
    base_dir: str
    models_dir: str
    logs_dir: str
    quarantine_dir: str
    model_path: str
    scaler_path: str
    encoders_path: Dict[str, str]
    log_level: int
    log_format: str
    network_interface: str
    packet_buffer_size: int
    threat_detection_threshold: float

    @classmethod
    def create_default(cls, base_dir: str) -> 'ApplicationConfig':
        """Create default configuration"""
        models_dir = os.path.join(base_dir, 'model_components')

        return cls(
            base_dir=base_dir,
            models_dir=models_dir,
            logs_dir=os.path.join(base_dir, 'logs'),
            quarantine_dir=os.path.join(base_dir, 'quarantine'),
            model_path=os.path.join(models_dir, 'xgboost_model.pkl'),
            scaler_path=os.path.join(models_dir, 'scaler.pkl'),
            encoders_path={
                'protocol_type': os.path.join(models_dir, 'protocol_type_encoder.pkl'),
                'service': os.path.join(models_dir, 'service_encoder.pkl'),
                'flag': os.path.join(models_dir, 'flag_encoder.pkl'),
                'attack_label': os.path.join(models_dir, 'attack_label_encoder.pkl')
            },
            log_level=logging.INFO,
            log_format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            network_interface='any',  # Default network interface
            packet_buffer_size=1024,
            threat_detection_threshold=0.7
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'BASE_DIR': self.base_dir,
            'DIRECTORIES': {
                'MODELS': self.models_dir,
                'LOGS': self.logs_dir,
                'QUARANTINE': self.quarantine_dir
            },
            'MODEL_FILES': {
                'MODEL': self.model_path,
                'SCALER': self.scaler_path,
                'ENCODERS': self.encoders_path
            },
            'LOGGING': {
                'LEVEL': self.log_level,
                'FORMAT': self.log_format
            },
            'NETWORK': {
                'INTERFACE': self.network_interface,
                'BUFFER_SIZE': self.packet_buffer_size
            },
            'DETECTION': {
                'THRESHOLD': self.threat_detection_threshold
            }
        }