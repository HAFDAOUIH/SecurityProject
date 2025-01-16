import os
import sys
import logging
import joblib
from datetime import datetime
from gui.main_window import MainWindow
from utils.config import ApplicationConfig

def setup_logging(config):
    """Set up logging configuration"""
    os.makedirs(config.logs_dir, exist_ok=True)

    log_file = os.path.join(
        config.logs_dir,
        f'counterbalance_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )

    logging.basicConfig(
        level=config.log_level,
        format=config.log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
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

def check_model_files(config):
    """Check if required model files exist"""
    required_files = [
        (config.model_path, "XGBoost model"),
        (config.scaler_path, "StandardScaler")
    ]

    for file_path, description in required_files:
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Required {description} file not found at: {file_path}"
            )
        try:
            joblib.load(file_path)
            logging.info(f"Successfully loaded {description}")
        except Exception as e:
            raise Exception(f"Error loading {description}: {str(e)}")

def main():
    try:
        # Initialize configuration
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config = ApplicationConfig.create_default(base_dir)

        # Setup logging
        setup_logging(config)
        logging.info("Starting CounterBalance IDS...")

        # Initialize directories
        init_directories(config)

        # Check model files
        try:
            check_model_files(config)
        except Exception as e:
            logging.error(f"Model file check failed: {str(e)}")
            raise

        # Initialize GUI
        try:
            app = MainWindow(config)
            logging.info("Main window created successfully")

            # Start GUI main loop
            logging.info("Starting main event loop...")
            app.mainloop()

        except Exception as e:
            logging.error(f"Error in GUI initialization/execution: {str(e)}")
            raise

    except Exception as e:
        logging.critical(f"Critical error in main: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("CounterBalance IDS shutting down...")

if __name__ == "__main__":
    main()
