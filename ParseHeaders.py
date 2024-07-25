from email import message_from_file
import os
import re
import PyPDF2
from docx import Document

class ParseHeaders:
    def __init__(self, eml_file_path):
        self.eml_file_path = eml_file_path
        self.headers = {}
        self.msg_content = None
        self.attachments = []

    def parse_headers(self):
        with open(self.eml_file_path, 'r') as file:
            msg = message_from_file(file)

            for header_name, header_value in msg.items():
                self.headers[header_name] = header_value

            self.msg_content = self.extract_msg_content(msg)

        return self.headers, self.msg_content

    def extract_msg_content(self, msg):
        msg_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get("Content-Disposition", None)
                if content_disposition:
                    dispositions = content_disposition.strip().split(";")
                    if dispositions[0].lower() == "attachment":
                        filename = part.get_filename()
                        if filename:
                            self.save_attachment(part, filename)
                            self.attachments.append(filename)
                else:
                    if part.get_content_type() == "text/plain":
                        msg_content += part.get_payload(decode=True).decode(part.get_content_charset())
        else:
            if msg.get_content_type() == "text/plain":
                msg_content = msg.get_payload(decode=True).decode(msg.get_content_charset())

        return msg_content

    def save_attachment(self, part, filename):
        # Determine the project directory
        project_dir = os.path.dirname(__file__)

        # Save file to the project directory
        attachment_path = os.path.join(project_dir, filename)
        with open(attachment_path, 'wb') as f:
            f.write(part.get_payload(decode=True))

    def extract_links_from_message(self, message_content):
        url_pattern = r'(?i)\b((?:https?|ftp|file):\/\/\S+|www\.\S+)\b'
        links = re.findall(url_pattern, message_content)
        for i, link in enumerate(links):
            if '"' in link:
                idx = link.find('"')
                links[i] = link[:idx]
        return links

    def extract_domain_names_from_message(self):
        domain_pattern = re.compile(r'from\s+([^\s]+)')
        domains = set()
        received_headers = self.headers.get('Received', [])
        if not isinstance(received_headers, list):
            received_headers = [received_headers]

        for header in received_headers:
            match = domain_pattern.search(header)
            if match:
                domain = match.group(1).split('(')[0]
                domains.add(domain.strip())

        return domains

    def extract_ip_addresses_from_received_headers(self):
        ip_addresses = []
        if 'Received' in self.headers:
            received_headers = self.headers['Received']
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
            all_ip_addresses = re.findall(ip_pattern, received_headers)
            ip_addresses = [ip for ip in all_ip_addresses if ip.count('.') == 3]
        return ip_addresses

    def extract_links_from_attached_files(self, attachment_file_path):
        filename, file_extension = os.path.splitext(attachment_file_path)
        links = []

        if file_extension == '.docx':
            links += self.extract_links_from_docx(attachment_file_path)
        elif file_extension == '.pdf':
            links += self.extract_links_from_pdf(attachment_file_path)
        elif file_extension == '.pptx':
            links += self.extract_links_from_pptx(attachment_file_path)
        elif file_extension == '.txt':
            links += self.extract_links_from_text_file(attachment_file_path)

        return links

    def extract_links_from_docx(self, docx_file_path):
        links = []
        try:
            doc = Document(docx_file_path)
            for rel in doc.part.rels.values():
                if "hyperlink" in rel.reltype:
                    link = rel.target_ref
                    links.append(link)

        except Exception as e:
            print(f"Error extracting links from DOCX {docx_file_path}: {str(e)}")

        print(f"Extracted links from DOCX: {links}")
        return links

    def extract_links_from_pdf(self, pdf_file_path):
        links = []
        with open(pdf_file_path, 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfFileReader(pdf_file)
            for page_num in range(pdf_reader.numPages):
                page = pdf_reader.getPage(page_num)
                links += re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                    page.extractText())
        return links

    def extract_links_from_text_file(self, txt_file_path):
        links = []
        with open(txt_file_path, 'r') as txt_file:
            text_content = txt_file.read()
            links += re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                text_content)
        return links

    def extract_domain(self, full_domain):
        parts = full_domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return full_domain

    def compare_received_from_domains(self):
        from_header = self.headers.get('From', '')
        received_header = self.headers.get('Received', '')

        # Extract domain from the From header
        from_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_header)
        if from_domain_match:
            from_domain = self.extract_domain(from_domain_match.group(1))
        else:
            from_domain = ''

        # print(f"Extracted From domain: {from_domain}")

        # Extract domain from the Received header
        received_domain_match = re.search(r'from\s+([a-zA-Z0-9.-]+)', received_header, re.IGNORECASE)
        if received_domain_match:
            received_domain = self.extract_domain(received_domain_match.group(1))
        else:
            received_domain = ''

        print(f"Extracted Received domain: {received_domain}")

        return from_domain, received_domain
