# IoT DDoS Intrusion Detection System

## Table of Contents
- [Project Overview](#project-overview)
- [System Architecture](#system-architecture)
- [Features](#features)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Contributors](#contributors)
- [License](#license)
  
## Project Overview
This project aims to develop an Intrusion Detection System (IDS) specifically designed for detecting and mitigating DDoS attacks in IoT networks. The system uses machine learning to identify DDoS attack patterns and automatically responds by blocking malicious traffic. The key components of the project include virtual machines simulating IoT devices, Docker containers, an MQTT broker for communication, and an automated response system.

## System Architecture
- Virtual Machines (VMs): Ubuntu VMs simulate a central server and IoT devices.
- Docker Containers: The IoT devices are simulated using Docker containers, each representing different types of IoT devices (e.g., sensors, smart appliances).
- Mosquitto MQTT Broker: Handles communication between IoT devices, generating realistic traffic and allowing for attack simulation.
- Machine Learning IDS: A Random Forest Classifier trained on the Bot-IoT dataset to detect DDoS attacks.
- Automated Mitigation: The system automatically blocks malicious IPs and throttles traffic to protect critical IoT devices during an attack.

## Features
- Real-time DDoS Detection: Identifies DDoS attacks using a machine learning model trained on IoT traffic.
- Automated Response: Automatically updates firewall rules (iptables) to block malicious traffic.
- Resource-Constrained Mitigation: Adaptive throttling and prioritization of high-priority IoT devices during attacks.

## Installation & Setup
### Pre-requisites

## Usage

## Contributors

## License
This project is licensed under the **GNU General Public License v3.0**. You are free to modify, distribute, and use this project as long as the same license applies to any derivative work.

For more details, see the [LICENSE](LICENSE) file.

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
