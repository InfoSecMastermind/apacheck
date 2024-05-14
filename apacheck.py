import re
import os
import argparse

class ApacheMisconfigAnalyzer:
    def __init__(self):
        pass

    def analyze_apache_config(self, config_file):
        # Print message indicating the start of analysis for a specific configuration file
        print("Analyzing Apache configuration:", config_file)

        # Check if ServerTokens directive is set to Full
        with open(config_file, 'r') as f:
            config_content = f.read()
            # Search for ServerTokens directive and check if it's set to Full
            if re.search(r'ServerTokens\s+Full', config_content):
                print("[!] ServerTokens directive set to Full (may expose server version)")

            # Check if Directory listing is enabled
            if re.search(r'DirectoryIndex\s+\S*?\s+.*?(\+Indexes|\bIndexes\b)', config_content):
                print("[!] Directory listing is enabled")

            # Check for insecure SSL/TLS configurations
            if re.search(r'SSLProtocol\s+.*?(SSLv2|SSLv3)', config_content):
                print("[!] Insecure SSL/TLS protocols (SSLv2 or SSLv3) are enabled")

            # Check for insecure permissions on sensitive files
            sensitive_files = ['htpasswd', 'htaccess']
            for file in sensitive_files:
                file_path = os.path.join(os.path.dirname(config_file), file)
                if os.path.exists(file_path):
                    file_permissions = oct(os.stat(file_path).st_mode & 0o777)
                    if file_permissions != '0o600':
                        print("[!] Insecure permissions set for {} file".format(file))

            # Add more checks for other misconfigurations as needed
            # Check for outdated Apache version (exposing known vulnerabilities)
            if re.search(r'ServerTokens\s+.*?(\bProd\b|\bMajor\b)', config_content):
                print("[!] ServerTokens directive is set to 'Prod' or 'Major' (may expose server version)")

            # Check for TRACE method enabled (potential security risk)
            if re.search(r'TraceEnable\s+On', config_content):
                print("[!] TRACE method is enabled (potential security risk)")

            # Check for outdated Apache modules (may contain known vulnerabilities)
            if re.search(r'ModSecurity\s+\d+\.\d+', config_content):
                mod_security_version = re.search(r'ModSecurity\s+(\d+\.\d+)', config_content).group(1)
                if float(mod_security_version) < 2.6:
                    print("[!] ModSecurity version {} is outdated (contains known vulnerabilities)".format(mod_security_version))

            # Check for insecure server-status configuration (may expose sensitive information)
            if re.search(r'<Location\s+/server-status>', config_content):
                if not re.search(r'Allow\s+from\s+127\.0\.0\.1', config_content):
                    print("[!] Insecure server-status configuration (may expose sensitive information)")

    def main(self):
        # Parse command-line arguments
        parser = argparse.ArgumentParser(description="Apache Misconfiguration Analyzer")
        parser.add_argument("-f", "--file", help="Apache configuration file or directory", required=True)
        args = parser.parse_args()

        # Check if the specified file or directory exists
        if os.path.exists(args.file):
            # If a directory is provided, analyze all .conf files inside it
            if os.path.isdir(args.file):
                for file_name in os.listdir(args.file):
                    if file_name.endswith(".conf"):
                        config_file = os.path.join(args.file, file_name)
                        # Analyze each configuration file
                        self.analyze_apache_config(config_file)
            else:
                # If a single file is provided, analyze it
                self.analyze_apache_config(args.file)
        else:
            print("Error: Specified file or directory does not exist.")

if __name__ == "__main__":
    analyzer = ApacheMisconfigAnalyzer()
    analyzer.main()
