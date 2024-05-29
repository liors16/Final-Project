import json
from concurrent.futures import ThreadPoolExecutor
import requests

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

        # Print results of SPF, DKIM, DMARC
        print(f"SPF Record Result: {spf_result}")
        print(f"DKIM Record Result: {dkim_result}")
        print(f"DMARC Record Result: {dmarc_result}")

        return spf_result, dkim_result, dmarc_result

# -------------------------------- Attached URLs detections -------------------------------- #

    def check_attached_link(self, url):
        url_analysis_endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': self.api_key, 'resource': url}

        try:
            response = requests.get(url_analysis_endpoint, params=params)
            if response.status_code == 200:
                analysis_result = response.json()
                print("Positives:", analysis_result['positives'])
                print("Total Scans:", analysis_result['total'])

                # for scanner, result in analysis_result['scans'].items():
                #     print(f"- {scanner}: {result['result']}")
                # print(response.json())
                return response.json()

        except requests.RequestException as e:
            print(f"An error occurred while scanning {url} with VirusTotal: {e}")
            return None

# -------------------------------- IP Addresses detections -------------------------------- #
    def check_ip_address(self, ip_addr):
        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip_addr,
            'maxAgeInDays': '365'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        # Formatted output
        decoded_response = json.loads(response.text)
        print(json.dumps(decoded_response, sort_keys=True, indent=4))

    def check_ip_addresses_multithreaded(self, ip_addresses):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check_ip_address, ip_addresses))
        return results

# -------------------------------- The HTML content of message detections -------------------------------- #
    def get_html_content(self, link):
        try:
            print("The link address is: " + link)
            response = requests.get(link)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to retrieve HTML content from {link}. Status code: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching HTML content from {link}: {e}")
            return None


