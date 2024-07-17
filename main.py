# import os
# import json
# import tkinter as tk
# from tkinter import filedialog
# from ParseHeaders import ParseHeaders
# from Detections import Detections
# import config
#
# class DetectionResults:
#     def __init__(self):
#         self.headers = {}
#         self.message_content = ""
#         self.spf_dkim_dmarc = []
#         self.links = []
#         self.link_results = {}
#         self.ip_addresses = []
#         self.ip_results = {}
#         self.domains = []
#         self.attachments = {}
#
#     def add_headers(self, headers):
#         self.headers = headers
#
#     def add_message_content(self, content):
#         self.message_content = content
#
#     def add_spf_dkim_dmarc(self, result):
#         self.spf_dkim_dmarc.append(result)
#
#     def add_link(self, link):
#         self.links.append(link)
#
#     def add_link_result(self, link, result):
#         self.link_results[link] = result
#
#     def add_ip_address(self, ip):
#         self.ip_addresses.append(ip)
#
#     def add_ip_result(self, ip, result):
#         self.ip_results[ip] = result
#
#     def add_domain(self, domain):
#         self.domains.append(domain)
#
#     def add_attachment_result(self, filename, result):
#         self.attachments[filename] = result
#
# def process_file(eml_file_path):
#     # Contains the dictionary of the message headers and message content
#     header_parser = ParseHeaders(eml_file_path)
#     detections_instance = Detections(header_parser, config.API_KEY_VIRUSTOTAL)  # For VirusTotal API
#     detections_instance2 = Detections(header_parser, config.API_KEY_ABUSEIPDB)  # For AbuseIPDB API
#
#     # Create DetectionResults object
#     detection_results = DetectionResults()
#
#     # Parse headers
#     headers_dict, message_content = header_parser.parse_headers()
#     detection_results.add_headers(headers_dict)
#     detection_results.add_message_content(message_content)
#
#     # Checks the SPF, DKIM, DMARC records considering all the email servers that the message passes through on the way
#     spf_dkim_dmarc_result = detections_instance.perform_detections()
#     detection_results.add_spf_dkim_dmarc(spf_dkim_dmarc_result)
#
#     # Extract links from the message content
#     links = header_parser.extract_links_from_message(message_content)
#     for link in links:
#         detection_results.add_link(link)
#
#     print()
#
#     # Extract and print IP addresses from "Received" headers
#     ip_addresses = header_parser.extract_ip_addresses_from_received_headers()
#     for ip in ip_addresses:
#         detection_results.add_ip_address(ip)
#
#     # ip_addr = '54.240.14.170'
#     ip_results = detections_instance2.check_ip_addresses_multithreaded(ip_addresses)
#     for ip, result in zip(ip_addresses, ip_results):
#         detection_results.add_ip_result(ip, result)
#
#     # Extract domain names from message content
#     domains = header_parser.extract_domain_names_from_message(message_content)
#     for domain in domains:
#         detection_results.add_domain(domain)
#
#     # VirusTotal gives just 4 requests in a minute for free
#     print("\nLink Tests:")
#     for link in links:
#         link_result = detections_instance.check_attached_link(link)
#         detection_results.add_link_result(link, link_result)
#
#     # Check attachments (if any)
#     if header_parser.attachments:
#         for attachment_filename in header_parser.attachments:
#             attachment_path = os.path.join(os.path.dirname(eml_file_path), attachment_filename)
#             analysis_result = detections_instance.scan_file(attachment_path)
#             if analysis_result:
#                 positives = analysis_result
#                 detection_results.add_attachment_result(attachment_filename, positives)
#
#     # You can now access the detection results as needed
#     # For example, to print all detection results:
#     print("\nDetection Results:")
#     print(json.dumps(detection_results.__dict__, indent=4))
#
# def browse_file():
#     file_path = filedialog.askopenfilename(filetypes=[("EML files", "*.eml")])
#     if file_path:
#         process_file(file_path)
#
# def create_gui():
#     root = tk.Tk()
#     root.title("EML File Processor")
#     root.geometry("600x300")
#
#     frame = tk.Frame(root)
#     frame.pack(pady=20)
#
#     browse_button = tk.Button(frame, text="Browse", command=browse_file)
#     browse_button.pack(pady=20)
#
#     root.mainloop()
#
# if __name__ == "__main__":
#     create_gui()
#
#
#
#

