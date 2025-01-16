# CounterBalance
AI driven windows IDS and EDR all in one

CounterBalance is an AI-driven Intrusion Detection and Endpoint Defense System designed to protect Windows machines from various cyber threats. It combines anomaly detection using machine learning with automated response actions to defend against potential attacks.

CounterBalance - It's time to tip the digital scales.


![CounterBalance Logo](https://github.com/HelloSecurityDev/CounterBalance/blob/main/CounterBalance%20Logo.png)

## Features

 **Real-time Intrusion Detection:**
   - Utilizes deep packet inspection to analyze network traffic and detect anomalies.
   
 **Automated Response Actions:**
   - Automatically triggers response actions like blocking IP addresses and quarantining malware based on detected threats.
   
 **AI Model Integration:**
   - Incorporates machine learning models for malware detection and classification.
   
 **Graphical User Interface (GUI):**
   - Provides a user-friendly interface for monitoring system metrics, running processes, and viewing logs.
   - GUI divided into panels for live network traffic, IDS & EDR information, event logs, running processes, and system metrics.
   - Buttons for starting/stopping IDS & EDR, scanning files, monitoring processes, and ending processes.

 **Logging and Event Management:**
   - Enhanced logging with log file rotation, improved log formatting, and customizable log levels.
   - Logs events to the console and log file, providing detailed information about system activities.

 **Threat Intelligence Integration:**
   - Fetches threat intelligence information from external APIs to enhance threat detection capabilities.
   
 **Performance Optimization:**
   - Utilizes multithreading for CPU and memory monitoring to ensure minimal performance overhead.
   - Batch processing for AI model training to optimize training time and resource utilization.

 **Dependency Management:**
   - Includes a `requirements.txt` file listing all required Python packages for easy installation using `pip`.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/HelloSecurityDev/CounterBalance.git
   ```
2. Navigate to the project directory:

   ```bash
   cd CounterBalance
   ```
3. Install The Required Dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Run the Program:

   ```bash
   python CounterBalance.py
   ```

## Requirements

Python 3.6+
Required Python packages are listed below.

```bash
  - `tkinter`
  - `scapy`
  - `requests`
  - `psutil`
  - `numpy`
  - `pandas`
  - `scikit-learn`
  - `tensorflow`
```
   
## V4 UPDATE

The Version 4 update that has been pushed provides the following additions, updates, and changes to the CounterBalance program.

## Changes

1. **GUI Enhancements:**
   - **Old Version:** Basic GUI layout with limited functionality.
   - **New Version:** Improved GUI design with multiple panels for live network traffic, IDS & EDR information, event logs, running processes, and system metrics. Buttons for starting/stopping IDS & EDR, scanning files, monitoring processes, and ending processes have been added.

2. **Logging Improvements:**
   - **Old Version:** Basic logging setup with minimal configuration.
   - **New Version:** Enhanced logging with log file rotation, improved log formatting, and customizable log levels.

3. **Functionality Additions:**
   - **Old Version:** Limited functionality for packet sniffing and response actions.
   - **New Version:** Added functionality for malware detection using AI models, automated response actions such as IP blocking and malware quarantine, and preventing execution of malicious files.

4. **Dependency Management:**
   - **Old Version:** No explicit requirement specification.
   - **New Version:** Included a `requirements.txt` file listing all required Python packages for easy installation using `pip`.

5. **Documentation:**
   - **Old Version:** No documentation provided.
   - **New Version:** Added a comprehensive README.md file explaining the project, its features, prerequisites, usage instructions, configuration options, license, and acknowledgments.

6. **Code Refactoring:**
   - **Old Version:** Code structure lacking modularity and clarity.
   - **New Version:** Refactored code into classes and methods for better organization and readability. Improved variable names, added comments, and structured code blocks logically.

7. **API Integration:**
   - **Old Version:** No integration with external APIs for threat intelligence.
   - **New Version:** Integrated with external threat intelligence API to fetch information about detected threats.

8. **Error Handling:**
   - **Old Version:** Limited error handling, with potential for crashes.
   - **New Version:** Implemented robust error handling mechanisms to gracefully handle exceptions and prevent crashes.

9. **Performance Optimization:**
   - **Old Version:** No optimization measures implemented.
   - **New Version:** Introduced performance optimizations such as multithreading for CPU and memory monitoring, and batch processing for AI model training.

*There is currently no .exe executable download for V4 as of yet. I am working on producing it as quick as possible but as of now, downloading CounterBalance.exe from dropbox will only provide v1 not v4.*

## V4 Training Results

## Epoch 1/10
- Training accuracy: 53.44%
- Training loss: 0.7178
- Validation accuracy: 60.00%
- Validation loss: 0.6667

## Epoch 2/10
- Training accuracy: 45.08%
- Training loss: 0.7019
- Validation accuracy: 60.00%
- Validation loss: 0.6624

## Epoch 3/10
- Training accuracy: 59.61%
- Training loss: 0.6645
- Validation accuracy: 60.00%
- Validation loss: 0.6608

## Epoch 4/10
- Training accuracy: 55.39%
- Training loss: 0.7058
- Validation accuracy: 60.00%
- Validation loss: 0.6602

## Epoch 5/10
- Training accuracy: 51.02%
- Training loss: 0.7184
- Validation accuracy: 65.00%
- Validation loss: 0.6606

## Epoch 6/10
- Training accuracy: 48.67%
- Training loss: 0.6862
- Validation accuracy: 60.00%
- Validation loss: 0.6609

## Epoch 7/10
- Training accuracy: 46.95%
- Training loss: 0.7151
- Validation accuracy: 60.00%
- Validation loss: 0.6619

## Epoch 8/10
- Training accuracy: 51.33%
- Training loss: 0.7173
- Validation accuracy: 55.00%
- Validation loss: 0.6630

## Epoch 9/10
- Training accuracy: 59.06%
- Training loss: 0.6902
- Validation accuracy: 60.00%
- Validation loss: 0.6629

## Epoch 10/10
- Training accuracy: 55.23%
- Training loss: 0.6836
- Validation accuracy: 60.00%
- Validation loss: 0.6631

## Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.

## Created by

CounterBalance is created by [Hello Security LLC](https://hellosecurityllc.github.io) and [Adam Rivers](https://www.linkedin.com/in/adam-rivers-abtzpro23).

## Disclaimer

CounterBalance is still a work in progress and may contain bugs and quirks. There are many additions planned for future development to make it a fully featured and robust security solution.
