# Mini-SOC – Zero Trust Enterprise Network

## 1. Project Overview

This project focuses on implementing a Mini Security Operations Center (SOC) for an enterprise network segmented according to Zero Trust principles.

The main objectives are:
- Secure network communications.
- Segment the enterprise network using VLANs.
- Control access between network zones.
- Detect and prevent cyberattacks.
- Centralize and analyze security events.
- Classify network traffic using Machine Learning.

## 2. Network Architecture

The project uses two independent environments:

- **Cisco Packet Tracer:** Logical network design and VLAN configuration.
- **VMware Workstation:** Functional implementation using virtual machines.

The VMware environment includes pfSense, Suricata, Wazuh and Kali Linux.

## 3. VLAN Segmentation

| VLAN | Name | Subnet |
|---|---|---|
| 10 | METIER1 | 10.10.10.0/24 |
| 20 | METIER2 | 10.10.20.0/24 |
| 30 | SERVEURS | 10.10.30.0/24 |
| 40 | DMZ | 10.10.40.0/24 |
| 66 | KALI | 10.10.66.0/24 |

Network segmentation isolates enterprise departments, internal servers, the DMZ and the attack-testing environment.

## 4. Tools and Technologies

| Tool | Purpose |
|---|---|
| Cisco Packet Tracer | Network simulation |
| VMware Workstation | Virtualization |
| pfSense | Firewall and routing |
| Suricata | IDS/IPS |
| Wazuh | Security monitoring and log analysis |
| Kali Linux | Controlled attack simulation |
| Python | Machine Learning development |
| Scikit-learn | Machine Learning algorithms |
| CICIDS2017 | Network traffic dataset |

## 5. IDS/IPS and SIEM

Suricata is used to inspect network traffic and detect suspicious activities through security signatures.

Wazuh is used to:
- Collect and analyze security logs.
- Decode pfSense events.
- Apply custom detection and correlation rules.
- Generate security alerts.
- Associate detected activities with MITRE ATT&CK techniques.

## 6. Machine Learning

A Machine Learning module was developed using Python and Random Forest.

**Dataset:** CICIDS2017

**Classification categories:**
- Normal
- PortScan
- BruteForce
- DoS
- WebAttack

The model achieved 99.9% accuracy on the public test dataset. This result should not be interpreted as guaranteed accuracy on real laboratory traffic.

A second model uses the network features actually available in the laboratory to provide a more realistic evaluation.

See `mini-soc-ml/README.md` for implementation details.

## 7. Attack Scenarios

The architecture was tested using controlled attack simulations from Kali Linux:

1. Port Scanning
2. SSH Brute Force
3. Denial of Service (DoS)
4. ARP Spoofing

These scenarios were used to evaluate firewall filtering, intrusion detection and security monitoring.

## 8. Installation and Requirements

### Machine Learning Module

1. Install Python.
2. Open the `mini-soc-ml` directory.
3. Create a virtual environment:

```bash
python -m venv .venv
```

4. Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Follow the instructions in `mini-soc-ml/README.md` to prepare the dataset and run the scripts.

### Network Environment

The network infrastructure requires VMware Workstation and the corresponding virtual machines and configurations.

## 9. Project Structure

```text
mini-soc/
├── README.md
├── .gitignore
├── Guide_Soutenance_mini-SOC.docx
├── Soutenance_MiniSOC_Khadija_final.pptx
└── mini-soc-ml/
    ├── data/
    ├── sorties/
    ├── src/
    ├── notebooks/
    ├── requirements.txt
    ├── README.md
    └── *.py
```

## 10. Future Improvements

- Deploy Wazuh agents on additional machines.
- Validate Machine Learning models using real network traffic.
- Implement network micro-segmentation.
- Strengthen Zero Trust access controls.

## Disclaimer

This project was developed for educational and cybersecurity laboratory purposes only.

All attack simulations were conducted in a controlled environment.