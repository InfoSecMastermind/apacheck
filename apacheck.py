import re
import os
import argparse
import logging

class ApacheMisconfigAnalyzer:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    def analyze_apache_config(self, config_file):
        logging.info("Analyzing Apache configuration: %s", config_file)

        try:
            with open(config_file, 'r') as f:
                config_content = f.read()

            self.check_servertokens(config_content)
            self.check_directory_listing(config_content)
            self.check_ssl_protocols(config_content)
            self.check_sensitive_file_permissions(config_file)
            self.check_mod_security_version(config_content)
            self.check_trace_method(config_content)
            self.check_server_status(config_content)
            self.check_allow_override(config_content)
            self.check_htaccess_files(config_file)
            self.check_http_methods(config_content)
            self.check_security_headers(config_content)
            self.check_unused_modules(config_content)

        except Exception as e:
            logging.error("Error reading file %s: %s", config_file, str(e))

    def check_servertokens(self, config_content):
        if re.search(r'ServerTokens\s+Full', config_content):
            logging.warning("[!] ServerTokens directive set to Full (may expose server version)")
        if re.search(r'ServerTokens\s+.*?(\bProd\b|\bMajor\b)', config_content):
            logging.warning("[!] ServerTokens directive is set to 'Prod' or 'Major' (may expose server version)")

    def check_directory_listing(self, config_content):
        if re.search(r'DirectoryIndex\s+\S*?\s+.*?(\+Indexes|\bIndexes\b)', config_content):
            logging.warning("[!] Directory listing is enabled")

    def check_ssl_protocols(self, config_content):
        if re.search(r'SSLProtocol\s+.*?(SSLv2|SSLv3)', config_content):
            logging.warning("[!] Insecure SSL/TLS protocols (SSLv2 or SSLv3) are enabled")

    def check_sensitive_file_permissions(self, config_file):
        sensitive_files = ['htpasswd', 'htaccess']
        for file in sensitive_files:
            file_path = os.path.join(os.path.dirname(config_file), file)
            if os.path.exists(file_path):
                file_permissions = oct(os.stat(file_path).st_mode & 0o777)
                if file_permissions != '0o600':
                    logging.warning("[!] Insecure permissions set for %s file", file)

    def check_mod_security_version(self, config_content):
        if re.search(r'ModSecurity\s+\d+\.\d+', config_content):
            mod_security_version = re.search(r'ModSecurity\s+(\d+\.\d+)', config_content).group(1)
            if float(mod_security_version) < 2.6:
                logging.warning("[!] ModSecurity version %s is outdated (contains known vulnerabilities)", mod_security_version)

    def check_trace_method(self, config_content):
        if re.search(r'TraceEnable\s+On', config_content):
            logging.warning("[!] TRACE method is enabled (potential security risk)")

    def check_server_status(self, config_content):
        if re.search(r'<Location\s+/server-status>', config_content):
            if not re.search(r'Allow\s+from\s+127\.0\.0\.1', config_content):
                logging.warning("[!] Insecure server-status configuration (may expose sensitive information)")

    def check_allow_override(self, config_content):
        if re.search(r'AllowOverride\s+All', config_content):
            logging.warning("[!] AllowOverride set to 'All' (may expose sensitive information)")

    def check_htaccess_files(self, config_file):
        htaccess_path = os.path.join(os.path.dirname(config_file), '.htaccess')
        if os.path.exists(htaccess_path):
            logging.warning("[!] .htaccess file found (ensure it is secured)")

    def check_http_methods(self, config_content):
        if re.search(r'Limit\s+.*?(GET|POST|PUT|DELETE)', config_content):
            logging.warning("[!] Check allowed HTTP methods - consider limiting methods")

    def check_security_headers(self, config_content):
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
        for header in security_headers:
            if not re.search(r'Header\s+always\s+set\s+' + re.escape(header), config_content):
                logging.warning("[!] Missing security header: %s", header)

    def check_unused_modules(self, config_content):
        unused_modules = ['mod_info', 'mod_status', 'mod_userdir']  # Add more as necessary
        for module in unused_modules:
            if re.search(r'LoadModule\s+' + re.escape(module), config_content):
                logging.warning("[!] Potentially unused module enabled: %s", module)

    def main(self):
        parser = argparse.ArgumentParser(description="Apache Misconfiguration Analyzer")
        parser.add_argument("-f", "--file", help="Apache configuration file or directory", required=True)
        args = parser.parse_args()

        if os.path.exists(args.file):
            if os.path.isdir(args.file):
                for file_name in os.listdir(args.file):
                    if file_name.endswith(".conf"):
                        config_file = os.path.join(args.file, file_name)
                        self.analyze_apache_config(config_file)
            else:
                self.analyze_apache_config(args.file)
        else:
            logging.error("Error: Specified file or directory does not exist.")

if __name__ == "__main__":
    analyzer = ApacheMisconfigAnalyzer()
    analyzer.main()
