#!/usr/bin/env python3

import sys
import platform
import urllib.parse
import subprocess
import time
import webbrowser

def create_html_file(url):
    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.hostname
    filename = host + ".html"
    with open(filename, "w") as f:
        f.write("<html>\n")
        f.write("<body>\n")
        f.write("<h1><b>If you see the website content below, it indicates a potential clickjacking vulnerability.</b></h1>\n")
        f.write("<p><b>Clickjacking is a technique where an attacker tricks a user into clicking on a malicious element on a webpage, while the user perceives it as clicking on a different element.</b></p>\n")
        f.write("<iframe src='" + url + "' height='100%' width='100%'></iframe>\n")
        f.write("</body>\n")
        f.write("</html>\n")
    return filename

def start_web_server(port):
    try:
        if platform.system() == "Windows":
            subprocess.Popen(["python", "-m", "http.server", str(port)])
        else:
            subprocess.Popen(["python3", "-m", "http.server", str(port)])
        print(f"Web server started on port {port}")
        print("Press Ctrl+C to stop the server.")
    except OSError as e:
        print(f"Error: {e}")
        sys.exit(1)

def main():
    print("Clickjacking POC")
    print("-----------------")

    # Prompt for target URL
    url = input("Enter the target URL: ")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Prompt for server port
    port = int(input("Enter the server port: "))

    # Create HTML file
    filename = create_html_file(url)
    print("HTML file created successfully!")

    # Start the web server
    start_web_server(port)

    # Open HTML file in default web browser
    webbrowser.open(f"http://127.0.0.1:{port}/{filename}")

    try:
        # Wait for user to stop the server
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nWeb server stopped.")

if __name__ == '__main__':
    main()
