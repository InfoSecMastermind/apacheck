# Apacheck

## Description
Apacheck is a comprehensive linting tool designed to analyze Apache configuration files for potential misconfigurations and security vulnerabilities. By scanning your Apache configuration files, Apacheck helps you ensure that your web server is securely configured and up to recommended standards, reducing potential risks.

## Features:
- Identifies insecure SSL/TLS protocols (e.g., SSLv2, SSLv3).
- Checks for directory listing settings that could expose sensitive content.
- Flags outdated Apache versions and modules, highlighting known vulnerabilities.
- Validates secure file permissions on sensitive files like .htaccess and .htpasswd.
- Detects potential security risks, such as enabled TRACE method and insecure server-status configuration.
- Ensures critical HTTP security headers are set (e.g., X-Content-Type-Options, X-Frame-Options).
- Checks for potentially unused or unnecessary Apache modules.
- Analyzes HTTP methods to suggest limiting to essential methods.
- Warns if AllowOverride is set to All, which can expose server settings through .htaccess files.

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
Contributions are welcome to enhance Apacheck’s capabilities! Please help by adding new features, improving existing ones, or updating documentation where needed.
