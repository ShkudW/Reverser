# Reverser Tool
Reverser is a Python-based tool designed to generate reverse shell payloads with SSL encryption. The tool provides the ability to create either a PowerShell script (.ps1) or an executable file (.exe) that establishes a secure reverse shell connection to a specified IP address and port.

# Features
** SSL Encryption: The tool generates an SSL certificate and key to encrypt the reverse shell communication, enhancing security and bypassing basic network security measures.

** Payload Generation: Users can generate either a PowerShell script or an executable file. The payload is obfuscated to avoid detection by antivirus software.

** Randomized Obfuscation: The tool can randomize the obfuscation of the payload to further reduce the chance of detection by static analysis tools.

** Hidden Execution: Both the PowerShell script and the executable are designed to run in a hidden window, minimizing the likelihood of detection by the target user.

** Auto-generated Files: The executable file, when run, generates the PowerShell script on disk, hides it, and executes it to establish the reverse shell connection.

** Customizable: The IP address, port, and output file names can be customized through command-line arguments.

# Usage

Generating an SSL Certificate:
The tool automatically generates an SSL certificate and key that will be used to encrypt the reverse shell communication.

Generating a Payload with obfuscation:
```
python3 Reverser.py -ip <listener_ip_address> -port <listener_port> -type <exe | ps1>
```
Generating a Payload with random obfuscation:
```
python3 Reverser.py -ip <listener_ip_address> -port <listener_port> -type <exe | ps1> -random
```



