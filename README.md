# Apacheck

## Description
Apacheck is a linting tool designed to analyze Apache configuration files for potential misconfigurations and security vulnerabilities. By scanning your Apache configuration files, Apacheck helps you ensure that your web server is properly configured and secure.

## Features:
- Identifies insecure SSL/TLS configurations.
- Checks for directory listing enabled.
- Detects outdated Apache versions and modules.
- Flags insecure file permissions on sensitive files.
- Scans for potential security risks like TRACE method enabled and insecure server-status configuration.

## Installation
1. Clone the repository:
```bash
git clone https://github.com/InfoSecMastermind/apacheck.git
```
4. Navigate to the project directory:
```bash
cd apacheck
```
6. Install dependencies:
```bash
pip install -r requirements.txt
```
## Usage:
To use Apacheck, simply provide the path to your Apache configuration file or directory containing configuration files as a command-line argument.

## Example usage:

```bash
python apacheck.py -f /path/to/your/apache/configuration
```
Run the script:
```bash
python apacheck.py -f /etc/apache2/apache2.conf
```
## Contributing:
Please contribute and make this better, its well needed.
