# utils/model_handler.py
import joblib
import logging
import numpy as np
import pandas as pd
from typing import Dict, Tuple, List, Any
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

class ModelHandler:
    def __init__(self, config):
        self.config = config
        self.model = None
        self.scaler = None
        self.encoders = {}
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            'bytes_ratio', 'packet_rate', 'login_attempt_ratio',
            'root_access_ratio', 'file_operation_intensity',
            'error_rate_ratio', 'host_error_rate_ratio',
            'service_diversity_score', 'privilege_escalation_risk',
            'remote_access_risk', 'protocol_type_freq', 'service_freq',
            'flag_freq'
        ]
        self.load_components()

    def load_components(self):
        """Load all model components and verify feature names"""
        try:
            # Load model and scaler
            self.model = joblib.load(self.config.model_path)
            self.scaler = joblib.load(self.config.scaler_path)

            # Get feature names from scaler if available
            scaler_features = None
            if hasattr(self.scaler, 'feature_names_in_'):
                scaler_features = self.scaler.feature_names_in_.tolist()
                logging.info("Scaler feature names found:")
                logging.info(f"Number of scaler features: {len(scaler_features)}")
                logging.info(f"Scaler features: {scaler_features}")

                logging.info(f"Number of current features: {len(self.feature_names)}")
                logging.info(f"Current features: {self.feature_names}")

                # Compare features
                if set(scaler_features) != set(self.feature_names):
                    missing_in_current = set(scaler_features) - set(self.feature_names)
                    missing_in_scaler = set(self.feature_names) - set(scaler_features)

                    if missing_in_current:
                        logging.error(f"Features in scaler but missing in current: {missing_in_current}")
                    if missing_in_scaler:
                        logging.error(f"Features in current but missing in scaler: {missing_in_scaler}")

                # Update feature names to match scaler if different
                if scaler_features:
                    self.feature_names = scaler_features
                    logging.info("Updated feature names to match scaler")

            # Load encoders
            for name, path in self.config.encoders_path.items():
                self.encoders[name] = joblib.load(path)
                logging.info(f"Loaded {name} encoder successfully")

        except Exception as e:
            logging.error(f"Error loading model components: {str(e)}")
            raise

    def preprocess_packet(self, packet_data: Dict[str, Any]) -> np.ndarray:
        """Preprocess a single packet's data"""
        try:
            # Handle categorical features
            for feature, encoder in self.encoders.items():
                if feature in packet_data and feature != 'attack_label':
                    try:
                        value = packet_data[feature]
                        if value in encoder.classes_:
                            packet_data[feature] = encoder.transform([value])[0]
                        else:
                            packet_data[feature] = encoder.transform([encoder.classes_[0]])[0]
                    except Exception as e:
                        logging.warning(f"Error encoding {feature}: {str(e)}")
                        packet_data[feature] = 0

            # Create engineered features
            self._add_engineered_features(packet_data)

            # Create DataFrame with exact feature order
            feature_vector = []
            for feature in self.feature_names:
                if feature not in packet_data:
                    logging.warning(f"Missing feature during preprocessing: {feature}")
                feature_vector.append(float(packet_data.get(feature, 0)))

            feature_df = pd.DataFrame([feature_vector], columns=self.feature_names)

            # Debug info before scaling
            logging.info(f"Features before scaling: {feature_df.columns.tolist()}")

            # Scale features
            try:
                scaled_features = self.scaler.transform(feature_df)
                return scaled_features[0]
            except Exception as e:
                logging.error(f"Error during scaling: {str(e)}")
                logging.error(f"DataFrame shape: {feature_df.shape}")
                logging.error(f"DataFrame columns: {feature_df.columns.tolist()}")
                raise

        except Exception as e:
            logging.error(f"Error preprocessing packet: {str(e)}")
            raise

    def _add_engineered_features(self, data: Dict[str, Any]):
        """Add engineered features in consistent order"""
        # Calculate bytes_ratio
        data['bytes_ratio'] = np.log1p(data.get('src_bytes', 0)) / (np.log1p(data.get('dst_bytes', 0)) + 1)

        # Calculate packet_rate
        data['packet_rate'] = (data.get('count', 0) ** 2) / (data.get('duration', 1) + 1)

        # Calculate login_attempt_ratio
        data['login_attempt_ratio'] = data.get('num_failed_logins', 0) / (data.get('count', 0) + 1)

        # Calculate root_access_ratio
        data['root_access_ratio'] = (data.get('root_shell', 0) + data.get('su_attempted', 0)) / (data.get('count', 0) + 1)

        # Calculate file_operation_intensity
        data['file_operation_intensity'] = (
                                                   data.get('num_file_creations', 0) +
                                                   data.get('num_shells', 0) +
                                                   data.get('num_access_files', 0)
                                           ) / (data.get('count', 0) + 1)

        # Calculate error_rate_ratio
        data['error_rate_ratio'] = (
                data.get('serror_rate', 0) + data.get('srv_serror_rate', 0) +
                data.get('rerror_rate', 0) + data.get('srv_rerror_rate', 0)
        )

        # Calculate host_error_rate_ratio
        data['host_error_rate_ratio'] = (
                                                data.get('dst_host_serror_rate', 0) + data.get('dst_host_srv_serror_rate', 0)
                                        ) / (data.get('dst_host_rerror_rate', 0) + data.get('dst_host_srv_rerror_rate', 0) + 1)

        # Calculate service_diversity_score
        data['service_diversity_score'] = (
                data.get('diff_srv_rate', 0) * data.get('srv_diff_host_rate', 0) *
                data.get('dst_host_diff_srv_rate', 0) * data.get('dst_host_srv_diff_host_rate', 0)
        )

        # Calculate privilege_escalation_risk
        data['privilege_escalation_risk'] = (
                                                    data.get('root_shell', 0) * 4 +
                                                    data.get('su_attempted', 0) * 3 +
                                                    data.get('num_root', 0) * 3 +
                                                    data.get('num_file_creations', 0) * 2+
                                                    data.get('num_shells', 0) * 3
                                            ) / (data.get('count', 0) + 1)

        # Calculate remote_access_risk
        data['remote_access_risk'] = (
                                             data.get('num_failed_logins', 0) * 2 +
                                             data.get('logged_in', 0) +
                                             data.get('is_guest_login', 0) * 2 +
                                             data.get('num_compromised', 0)
                                     ) / (data.get('count', 0) + 1)


        data['flood_score'] = (
                data.get('count', 0) * data.get('packet_rate', 0) *
                (1 + data.get('serror_rate', 0))
        )

    def predict(self, features: np.ndarray) -> Tuple[str, float]:
        """Make prediction on preprocessed features"""
        try:
            probas = self.model.predict_proba([features])[0]
            pred_idx = np.argmax(probas)
            confidence = probas[pred_idx]

            pred_label = self.encoders['attack_label'].inverse_transform([pred_idx])[0]

            return pred_label, confidence

        except Exception as e:
            logging.error(f"Error making prediction: {str(e)}")
            raise