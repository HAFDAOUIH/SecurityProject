import threading

import pandas as pd
import tensorflow as tf
import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle
import logging
import os


'''class ModelHandler:
    def __init__(self, config):
        self.config = config
        self.load_models()

    def load_models(self):
        try:
            # Load LSTM model
            self.lstm_model = tf.keras.models.load_model(
                os.path.join(self.config['DIRECTORIES']['MODELS'], 'lstm.h5')
            )

            # Load scaler
            with open(os.path.join(self.config['DIRECTORIES']['MODELS'], 'scaler.pkl'), 'rb') as f:
                self.scaler = pickle.load(f)

            logging.info("Models loaded successfully")
        except Exception as e:
            logging.error(f"Error loading models: {str(e)}")
            raise

    def preprocess_features(self, features):
        """Preprocess features for model input"""
        try:
            if isinstance(features, pd.DataFrame):
                features = features.values  # Convert DataFrame to ndarray

            if len(features.shape) == 1:
                features = features.reshape(1, -1)  # Reshape to 2D

            scaled_features = self.scaler.transform(features)
            return scaled_features
        except Exception as e:
            logging.error(f"Error preprocessing features: {str(e)}")
            return None

    def predict(self, features):
        """Make predictions using the LSTM model"""
        try:
            # Ensure features is a 2D array
            if isinstance(features, pd.DataFrame):
                features = features.values  # Convert DataFrame to ndarray

            if len(features.shape) == 1:
                features = features.reshape(1, -1)  # Reshape 1D array to 2D

            # Preprocess features
            processed_features = self.preprocess_features(features)
            if processed_features is None:
                return None

            # Reshape for LSTM (batch_size, timesteps, features)
            reshaped_features = processed_features.reshape(
                (1, processed_features.shape[0], processed_features.shape[1])
            )

            # Make predictions
            predictions = self.lstm_model.predict(reshaped_features)
            return predictions
        except Exception as e:
            logging.error(f"Error making predictions: {str(e)}")
            return None'''

import pandas as pd
import tensorflow as tf
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle
import logging
import os


class ModelHandler:
    def __init__(self, config):
        self.config = config
        self.feature_cols = config['MODEL']['FEATURE_COLS']
        self.encoders = {}
        self.prediction_lock = threading.Lock()

        # Configure TensorFlow for better memory management
        gpus = tf.config.experimental.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
            except RuntimeError as e:
                logging.error(f"GPU configuration error: {e}")

        self.load_models()
        self.initialize_encoders()

    def initialize_encoders(self):
        """Initialize label encoders for categorical features with default values"""
        try:
            # Initialize encoders with basic categories to prevent the 'classes_' error
            self.encoders['protocol_type'] = LabelEncoder()
            self.encoders['protocol_type'].fit(['tcp', 'udp', 'icmp', 'unknown'])

            self.encoders['service'] = LabelEncoder()
            default_services = ['http', 'https', 'dns', 'smtp', 'ssh', 'ftp', 'telnet', 'other']
            self.encoders['service'].fit(default_services)

            self.encoders['flag'] = LabelEncoder()
            default_flags = ['SYN', 'ACK', 'PSH', 'RST', 'FIN', 'URG', 'OTH' , 'oth']
            self.encoders['flag'].fit(default_flags)

            logging.info("Encoders initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing encoders: {str(e)}")
            raise

    def load_models(self):
        """Load models with improved error handling"""
        try:
            model_path = os.path.join(self.config['DIRECTORIES']['MODELS'], 'lstm.h5')
            scaler_path = os.path.join(self.config['DIRECTORIES']['MODELS'], 'scaler.pkl')

            if not os.path.exists(model_path) or not os.path.exists(scaler_path):
                raise FileNotFoundError("Model files not found")

            # Load model with memory management settings
            tf.keras.backend.clear_session()
            self.lstm_model = tf.keras.models.load_model(model_path, compile=False)
            self.lstm_model.compile(optimizer='adam', loss='binary_crossentropy')

            # Load and initialize scaler with feature names
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

            # Ensure scaler has feature names
            if not hasattr(self.scaler, 'feature_names_in_'):
                self.scaler.feature_names_in_ = np.array(self.feature_cols)

        except Exception as e:
            logging.error(f"Error loading models: {str(e)}")
            raise

    def preprocess_features(self, features):
        """Preprocess features with proper feature name handling"""
        try:
            # Convert to DataFrame if not already
            if not isinstance(features, pd.DataFrame):
                features = pd.DataFrame([features], columns=self.feature_cols)

            # Create a copy to avoid modifying the original
            processed_features = features.copy()

            # Handle categorical features
            categorical_features = ['protocol_type', 'service', 'flag']
            for feature in categorical_features:
                if feature in processed_features.columns:
                    if feature not in self.encoders:
                        self.encoders[feature] = LabelEncoder()
                        # Initialize with default values
                        default_values = {
                            'protocol_type': ['tcp', 'udp', 'icmp', 'unknown'],
                            'service': ['http', 'https', 'dns', 'smtp', 'ssh', 'ftp', 'telnet', 'other'],
                            'flag': ['SYN', 'ACK', 'PSH', 'RST', 'FIN', 'URG', 'OTH']
                        }
                        self.encoders[feature].fit(default_values[feature])

                    processed_features[feature] = processed_features[feature].apply(
                        lambda x: self.encoders[feature].transform([str(x).lower()])[0]
                        if str(x).lower() in self.encoders[feature].classes_
                        else self.encoders[feature].transform(['unknown' if feature == 'protocol_type' else 'other'])[0]
                    )

            # Ensure all numeric columns are float
            numeric_cols = processed_features.select_dtypes(include=[np.number]).columns
            processed_features[numeric_cols] = processed_features[numeric_cols].astype(float)

            # Scale features using feature names
            scaled_features = pd.DataFrame(
                self.scaler.transform(processed_features),
                columns=self.feature_cols
            )

            return scaled_features.values

        except Exception as e:
            logging.error(f"Error preprocessing features: {str(e)}")
            return None

    def predict(self, features):
        """Thread-safe prediction with proper shape handling"""
        try:
            with self.prediction_lock:
                # Preprocess features
                processed_features = self.preprocess_features(features)
                if processed_features is None:
                    return None

                # Reshape for LSTM (samples, timesteps, features)
                lstm_input = processed_features.reshape(
                    processed_features.shape[0], 1, processed_features.shape[1]
                )

                # Make prediction
                with tf.device('/CPU:0'):
                    predictions = self.lstm_model.predict(
                        lstm_input,
                        batch_size=1,
                        verbose=0
                    )

                return predictions.squeeze()

        except Exception as e:
            logging.error(f"Prediction error: {str(e)}", exc_info=True)
            return None
