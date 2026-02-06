# BTR-SDN Simulation Framework

This repository contains the source code and simulation artifacts for the paper: **"BTR-SDN: A Blockchain-enabled Trusted Routing Scheme for SDN Interdomain"**.

## 📌 Overview
This project simulates a multi-domain SDN environment to evaluate the **BTR-SDN** trust model. It implements:
1.  **FAHP-based Trust Evaluation**: Multidimensional assessment of node behavior.
2.  **Dynamic Reputation Recovery**: A mechanism to restore trust for recovered nodes (implementing Equations 15-17 in the revised manuscript).
3.  **Secure Routing**: Trust-aware path calculation and pruning.
4.  **Blockchain Integration**: Simulation of ledger-based state synchronization.

## 🛠️ Key Features & Implementation
The simulation logic corresponds directly to the mathematical models in the paper:

| Feature | Paper Section | Code Location |
| :--- | :--- | :--- |
| **Trust Calculation** | Sec 3.1 (Eq 13) | `TrustManager.calculate_fahp_score` |
| **Decay Function** | Sec 3.1 (Eq 15) | `TrustManager.update` (Time decay logic) |
| **Recovery Window** | Sec 3.1 (Eq 16) | `TrustManager.update` (Compliance sum) |
| **Probation Penalty** | Sec 3.1 (Eq 17) | `TrustManager.update` (Probation logic) |
| **Route Pruning** | Sec 3.2 | `NetworkEnvironment.find_trusted_path` |

##  How to Run
### Prerequisites
* Python 3.8+
* Dependencies: `networkx`, `numpy`, `matplotlib`

### Installation
```bash
pip install networkx numpy matplotlib
