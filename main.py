from EmailHeaderExtractor import ParseHeaders
from Detections import Detections
import os
import json

API_KEY_VIRUSTOTAL = os.environ.get('API_KEY_VIRUSTOTAL')
API_KEY_ABUSEIPDB = os.environ.get('API_KEY_ABUSEIPDB')

def main():

    # EML file path, it's just file name for now (temporary)
    eml_file_path = 'message1.eml'

    # Contains the dictionary of the message headers and message content
    header_parser = ParseHeaders(eml_file_path)
    detections_instance = Detections(header_parser, API_KEY_VIRUSTOTAL)  # For VirusTotal API
    detections_instance2 = Detections(header_parser, API_KEY_ABUSEIPDB)  # For AbuseIPDB API

    # Parse headers
    headers_dict, message_content = header_parser.parse_headers()

    print("Parsed Headers:")
    for header_name, header_value in headers_dict.items():
        print(f"{header_name}: {header_value}")

    # Print the message content
    print("\nMessage Content:")
    print(message_content)

    # Checks the SPF, DKIM, DMARC records considering all the email servers that the message passes through on the way
    detections_instance.perform_detections()

    # Extract links from the message content
    links = header_parser.extract_links_from_message(message_content)

    # Get the first links HTML content
    # first_link = links[4]
    # first_link_content = detections_instance.get_html_content(first_link)

    # detections_instance.check_attached_link(first_link)

    print()

    # Extract and print IP addresses from "Received" headers
    ip_addresses = header_parser.extract_ip_addresses_from_received_headers()

    # ip_addr = '54.240.14.170'
    detections_instance2.check_ip_addresses_multithreaded(ip_addresses)

    # Extract domain names from message content
    domains = header_parser.extract_domain_names_from_message(message_content)




    # Print the extracted links
    print("\nExtracted Links:")
    for link in links:
        print(link)

    first_four_links = links[3:8]

    # VirusTotal gives just 4 requests in a minute for free
    print("\nLink Tests:")
    for link in links:
        print(f"Results for the link: {link}")
        detections_instance.check_attached_link(link)

    print("\nExtracted Domain Names:")
    for domain in domains:
        print(domain)

    print("\nIP addresses from Received headers:", ip_addresses)


if __name__ == "__main__":
    main()
