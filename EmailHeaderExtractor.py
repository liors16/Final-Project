from email import message_from_file
import re

class ParseHeaders:
    def __init__(self, eml_file_path):
        self.eml_file_path = eml_file_path
        self.headers = {}
        self.msg_content = None

    # Parses the headers and the message content
    def parse_headers(self):
        with open(self.eml_file_path, 'r') as file:
            msg = message_from_file(file)

            # Extract and store each header in a dictionary
            for header_name, header_value in msg.items():
                self.headers[header_name] = header_value

            # Extract and store the content of the email message
            self.msg_content = self.extract_msg_content(msg)

        return self.headers, self.msg_content

    # Extract the content of the email message (body)
    def extract_msg_content(self, msg):
        if msg.is_multipart():
            # For multipart messages, concatenate all parts
            # The headers and the body are separated by "\n\n"
            # So when calling to "join" function - it identify the "\n\n"
            # And knows to ignore the headers from the final string
            # That will contain just the body
            content = ''.join(part.get_payload(decode=True).decode('utf-8', 'ignore') for part in msg.get_payload())
        else:
            # For non-multipart messages, use the payload directly
            content = msg.get_payload(decode=True).decode('utf-8', 'ignore')

        return content

    # Extracts all the links that are in the message
    def extract_links_from_message(self, message_content):
        # Regular expression pattern to match URLs
        url_pattern = r'(?i)\b((?:https?|ftp|file):\/\/\S+|www\.\S+)\b'

        # Find all URLs in the message content
        links = re.findall(url_pattern, message_content)
        for i, link in enumerate(links):
            if '"' in link:
                # Find the index of the first occurrence of the char: "
                idx = link.find('"')
                # Save the substring up to the char: "
                saved_string = link[:idx]
                links[i] = saved_string

        return links

    def extract_domain_names_from_message(self, message_content):
        # Regular expression pattern to match URLs
        url_pattern = r'(?i)\b((?:https?|ftp|file):\/\/\S+|www\.\S+)\b'

        # Find all URLs in the message content
        links = re.findall(url_pattern, message_content)
        domains = set() # I'm using set store only once each domain name
        for link in links:
            if '"' in link:
                idx = link.find('"')
                link = link[:idx]  # Removes any trailing characters after the URL
            # Extract domain name from URL
            domain = link.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
            domains.add(domain)

        return domains

    # Extract all IP addresses from "Received" headers
    def extract_ip_addresses_from_received_headers(self):
        ip_addresses = []
        if 'Received' in self.headers:
            received_headers = self.headers['Received']
            # Regex pattern for matching valid IPv4 addresses only
            # Ensuring that there are exactly three dots and no leading zeros in each octet
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
            # Find all matches in the received headers
            all_ip_addresses = re.findall(ip_pattern, received_headers)
            ip_addresses = [ip for ip in all_ip_addresses if ip.count('.') == 3]
        return ip_addresses
