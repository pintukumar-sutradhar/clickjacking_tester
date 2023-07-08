# clickjacking_tester
Clickjacking Tester: A Python script to test for clickjacking vulnerabilities in web applications.
## Introduction
Clickjacking Tester is a Python script designed to detect potential clickjacking vulnerabilities in web applications. Clickjacking is a technique where an attacker tricks a user into clicking on a malicious element on a webpage, while the user perceives it as clicking on a different element. This script creates a test scenario by embedding the target web application within an HTML iframe, allowing you to visually inspect if the website is vulnerable to clickjacking.

## Features
- Simple and easy-to-use interface
- Generates an HTML file with an embedded iframe for testing
- Provides visual confirmation of potential clickjacking vulnerability

## Getting Started
To use Clickjacking Tester, follow these steps:

### Prerequisites
- Python 3.x installed on your system

### Installation
1. Clone the repository: 
2. Install the required dependencies:
3. pip install -r requirements.txt

## Usage
1. Run the script:
python clickjacking_tester.py
2. Enter the target URL when prompted.
3. Specify the server port.
4. Follow the instructions on the console to proceed with the test.
5. A web browser will automatically open, displaying the test scenario. If the target website is vulnerable to clickjacking, you will see its content rendered within the iframe.

## Contributing
Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

