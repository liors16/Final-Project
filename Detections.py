import json
from concurrent.futures import ThreadPoolExecutor
import requests
import time

class Detections:
    def __init__(self, header_parser, api_key):
        self.header_parser = header_parser
        self.api_key = api_key

# -------------------------------- SPF, DKIM, DMARC detections -------------------------------- #
    def check_record(self, header_name, record_name):
        check = self.check_record_by_name(header_name, record_name)
        return check

    def check_SPF_record(self):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check_record, ["Authentication-Results", "ARC-Authentication-Results"], ["spf", "spf"]))
        return all(results)

    def check_DKIM_record(self):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check_record, ["Authentication-Results", "ARC-Authentication-Results"], ["dkim", "dkim"]))
        return all(results)

    def check_DMARC_record(self):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check_record, ["Authentication-Results", "ARC-Authentication-Results"], ["dmarc", "dmarc"]))
        return all(results)

    def get_header_by_name(self, header_name):
        # Access the record header from ParseHeaders instance
        self.header = self.header_parser.headers.get(header_name, '')
        return self.header

    def check_record_by_name(self, header_name, record_name):
        # Gets the header content
        dkim_header = self.get_header_by_name(header_name)
        record_name = record_name + "="

        # Split the header into lines
        header_lines = dkim_header.split('\n')

        for line in header_lines:
            if record_name in line:
                found = line.split(record_name)

                # Checks if there is more records of DKIM/SPF/DMARC, and validate that they're "pass"
                if len(found) > 1 and found[1].split(None, 1)[0].lower() != "pass":
                    return False

        # If all the record checks = "pass"
        return True

    def perform_detections(self):
        spf_result = self.check_SPF_record()
        dkim_result = self.check_DKIM_record()
        dmarc_result = self.check_DMARC_record()

        return spf_result, dkim_result, dmarc_result

# -------------------------------- Attached URLs detections -------------------------------- #

    def check_attached_link(self, url):
        url_analysis_endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': self.api_key, 'resource': url}

        try:
            response = requests.get(url_analysis_endpoint, params=params)
            if response.status_code == 200:
                return response.json()

            else:
                print(f"THE CODE OF ERROR IS: {url} {response.status_code}")

        except requests.RequestException as e:
            print(f"There is an error while scanning {url} with VirusTotal: {e}")
            return None

# -------------------------------- IP Addresses detections -------------------------------- #

    def check_ip_address(self, ip_addr):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip_addr,
            'maxAgeInDays': '365'
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        try:
            response = requests.get(url, headers=headers, params=querystring)
            response.raise_for_status()  # Exception for bad status codes

            # Check if response content is JSON
            try:
                decoded_response = response.json()
                return decoded_response
            except json.JSONDecodeError as je:
                print(f"Error decoding JSON response for IP {ip_addr}: {je}")
                return None
        except requests.RequestException as e:
            print(f"An error occurred while checking IP {ip_addr} with AbuseIPDB: {e}")
            return None

    def check_ip_addresses_multithreaded(self, ip_addresses):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check_ip_address, ip_addresses))
        return results

# -------------------------------- The HTML content of message detections -------------------------------- #
    def get_html_content(self, link):
        try:
            # print("The link address is: " + link)
            response = requests.get(link)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to retrieve HTML content from {link}. Status code: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching HTML content from {link}: {e}")
            return None

# -------------------------------- The attached files scanning -------------------------------- #
    def scan_file(self, file_path):
        url_scan_endpoint = "https://www.virustotal.com/vtapi/v2/file/scan"
        url_report_endpoint = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {'apikey': self.api_key}

        try:
            with open(file_path, 'rb') as file:
                files = {'file': file}
                # Step 1: Submit file for scanning
                response = requests.post(url_scan_endpoint, params=params, files=files)
                if response.status_code == 200:
                    result = response.json()
                    scan_id = result.get('scan_id', '')
                    resource = result.get('resource', '')
                    if not scan_id or not resource:
                        print(f"Failed to get scan ID or resource for {file_path}")
                        return None

                    # Step 2: Poll for scan results using scan_id
                    params['resource'] = resource
                    params['scan_id'] = scan_id
                    retry_count = 0
                    while retry_count < 5:  # Retry 5 times with a delay
                        retry_count += 1
                        response = requests.get(url_report_endpoint, params=params)
                        if response.status_code == 200:
                            report = response.json()
                            if report.get('response_code') == 1:
                                return report  # Return full scan report
                            elif report.get('response_code') == -2:
                                print(f"Scan still queued for {file_path}. Waiting for results...")
                                time.sleep(60)  # Wait for 60 seconds before retrying
                            else:
                                print(f"No scan results found for {file_path}")
                                return None
                        else:
                            print(f"Failed to retrieve scan report for {file_path}. Status code: {response.status_code}")
                            return None

                    print(f"Exceeded retry limit for {file_path}. No scan results found.")
                    return None
                else:
                    print(f"Failed to scan {file_path}. Status code: {response.status_code}")
                    return None
        except IOError as e:
            print(f"Error reading file {file_path}: {e}")
            return None

# -------------------------------- The sender domain name scanning -------------------------------- #
    def check_domain(self, domain):
        url_domain_report_endpoint = "https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': self.api_key, 'domain': domain}

        try:
            response = requests.get(url_domain_report_endpoint, params=params)
            if response.status_code == 200:
                analysis_result = response.json()
                positives = 0
                total = 0

                # Sum up positives and total from different sections of the response
                if 'undetected_referrer_samples' in analysis_result:
                    for sample in analysis_result['undetected_referrer_samples']:
                        positives += sample['positives']
                        total += sample['total']
                if 'detected_downloaded_samples' in analysis_result:
                    for sample in analysis_result['detected_downloaded_samples']:
                        positives += sample['positives']
                        total += sample['total']
                if 'undetected_downloaded_samples' in analysis_result:
                    for sample in analysis_result['undetected_downloaded_samples']:
                        positives += sample['positives']
                        total += sample['total']

                return {'positives': positives, 'total': total}
        except requests.RequestException as e:
            print(f"An error occurred while scanning domain {domain} with VirusTotal: {e}")
            return None

