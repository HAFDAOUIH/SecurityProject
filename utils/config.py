# utils/config.py
import os
import logging
from dataclasses import dataclass


@dataclass
class ModelConfig:
    feature_names: list = None
    categorical_features: list = None
    numerical_features: list = None
    label_encoders: dict = None


@dataclass
class NetworkConfig:
    interface: str = None
    capture_timeout: int = 1
    batch_size: int = 100
    max_queue_size: int = 1000


@dataclass
class ApplicationConfig:
    """Configuration class for the application"""
    base_dir: str
    models_dir: str
    logs_dir: str
    quarantine_dir: str
    model_path: str
    scaler_path: str
    model_config: ModelConfig
    network_config: NetworkConfig
    log_level: int
    log_format: str

    @classmethod
    def create_default(cls, base_dir):
        return cls(
            base_dir=base_dir,
            models_dir=os.path.join(base_dir, 'models'),
            logs_dir=os.path.join(base_dir, 'logs'),
            quarantine_dir=os.path.join(base_dir, 'quarantine'),
            model_path=os.path.join(base_dir, 'models', 'best_model_XGB.pkl'),
            scaler_path=os.path.join(base_dir, 'models', 'scaler.pkl'),
            model_config=ModelConfig(
                feature_names=[
                    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                    'dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised',
                    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate'
                ],
                categorical_features=['protocol_type', 'service', 'flag'],
                numerical_features=[
                    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment',
                    'hot', 'logged_in', 'num_compromised', 'count', 'srv_count',
                    'serror_rate', 'srv_serror_rate', 'rerror_rate'
                ]
            ),
            network_config=NetworkConfig(),
            log_level=logging.INFO,
            log_format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )


def init_directories(config):
    """Initialize required directories"""
    directories = [
        config.models_dir,
        config.logs_dir,
        config.quarantine_dir
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Initialized directory: {directory}")