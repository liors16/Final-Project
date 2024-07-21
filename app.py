import os
import json
from flask import Flask, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
from ParseHeaders import ParseHeaders
from Detections import Detections
import config

app = Flask(__name__)
app.config['ALLOWED_EXTENSIONS'] = {'eml'}

class DetectionResults:
    def __init__(self):
        self.headers = {}
        self.message_content = ""
        self.spf_dkim_dmarc = []
        self.links = []
        self.link_results = {}
        self.ip_addresses = []
        self.ip_results = {}
        self.domain_results = {}
        self.attachments = {}
        self.spf_result = None
        self.dkim_result = None
        self.dmarc_result = None
        self.domain_match = None

    def set_domain_match(self, match):
        self.domain_match = match

    def add_headers(self, headers):
        self.headers = headers

    def add_message_content(self, content):
        self.message_content = content

    def add_spf_dkim_dmarc(self, result):
        self.spf_result = result[0]
        self.dkim_result = result[1]
        self.dmarc_result = result[2]

    def add_link(self, link):
        self.links.append(link)

    def add_link_result(self, link, result):
        self.link_results[link] = result

    def add_ip_address(self, ip):
        self.ip_addresses.append(ip)

    def add_ip_result(self, ip, result):
        self.ip_results[ip] = result

    def add_domain_result(self, domain, positives, total):
        self.domain_results[domain] = {
            'positives': positives,
            'total': total
        }

    def add_attachment_result(self, filename, result):
        self.attachments[filename] = result

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Determine the project directory
        project_dir = os.path.dirname(__file__)

        # Save file to the project directory
        file_path = os.path.join(project_dir, filename)
        file.save(file_path)

        detection_results = process_file(file_path)
        conclusions = generate_conclusions(detection_results)
        return redirect(url_for('conclusions', conclusions=json.dumps(conclusions), detection_results=json.dumps(detection_results.__dict__)))
    else:
        flash('File type not allowed')
        return redirect(request.url)

@app.route('/conclusions')
def conclusions():
    conclusions_json = request.args.get('conclusions')
    conclusions = json.loads(conclusions_json)
    detection_results_json = request.args.get('detection_results')
    return render_template('conclusions.html', conclusions=conclusions, detection_results=detection_results_json)

@app.route('/results')
def results():
    detection_results_json = request.args.get('detection_results')
    detection_results = json.loads(detection_results_json)
    return render_template('results.html', results=detection_results)

def process_file(eml_file_path):
    header_parser = ParseHeaders(eml_file_path)
    detections_instance = Detections(header_parser, config.API_KEY_VIRUSTOTAL)
    detections_instance2 = Detections(header_parser, config.API_KEY_ABUSEIPDB)

    detection_results = DetectionResults()

    headers_dict, message_content = header_parser.parse_headers()
    detection_results.add_headers(headers_dict)
    detection_results.add_message_content(message_content)

    spf_dkim_dmarc_result = detections_instance.perform_detections()
    detection_results.add_spf_dkim_dmarc(spf_dkim_dmarc_result)

    links = header_parser.extract_links_from_message(message_content)
    for link in links:
        detection_results.add_link(link)

    ip_addresses = header_parser.extract_ip_addresses_from_received_headers()
    for ip in ip_addresses:
        detection_results.add_ip_address(ip)

    ip_results = detections_instance2.check_ip_addresses_multithreaded(ip_addresses)
    for ip, result in zip(ip_addresses, ip_results):
        if result is not None:
            detection_results.add_ip_result(ip, result)

    domain_match = header_parser.compare_received_from_domains()
    detection_results.set_domain_match(domain_match)
    # Extracted domain from "Received" header - it's actually the domain name that sent the message
    received_domain = domain_match[1]

    domain_analysis_result = detections_instance.check_domain(received_domain)
    if domain_analysis_result:
        detection_results.add_domain_result(received_domain, domain_analysis_result['positives'], domain_analysis_result['total'])


    if header_parser.attachments:
        for attachment_file_path in header_parser.attachments:
            analysis_result = detections_instance.scan_file(attachment_file_path)
            if analysis_result:
                positives = analysis_result
                detection_results.add_attachment_result(os.path.basename(attachment_file_path), positives)

                attached_file_links = header_parser.extract_links_from_attached_files(attachment_file_path)
                for link in attached_file_links:
                    link_analysis_result = detections_instance.check_attached_link(link)
                    if link_analysis_result:
                        detection_results.add_link_result(link, link_analysis_result)

    return detection_results

def generate_conclusions(detection_results):
    conclusions = {
        "is_malicious": False,
        "spf_result": detection_results.spf_result,
        "dkim_result": detection_results.dkim_result,
        "dmarc_result": detection_results.dmarc_result,
        "link_results": detection_results.link_results,
        "ip_results": detection_results.ip_results,
        "domain_results": detection_results.domain_results,
        "attachments": detection_results.attachments,
        "domain_match": True,
        "domain_from": detection_results.domain_match[0],
        "domain_received": detection_results.domain_match[1]
    }

    from_header_domain_name= detection_results.domain_match[0]
    received_header_domain_name = detection_results.domain_match[1]


    if not detection_results.spf_result or not detection_results.dkim_result or not detection_results.dmarc_result:
        conclusions["is_malicious"] = True

    for link, result in detection_results.link_results.items():
        if result["positives"] > 0:
            conclusions["is_malicious"] = True
            break

    for ip, result in detection_results.ip_results.items():
        if result["data"]["abuseConfidenceScore"] > 0:
            conclusions["is_malicious"] = True
            break

    for domain, analysis_result in detection_results.domain_results.items():
        if analysis_result["positives"] > 0:
            conclusions["is_malicious"] = True
            break

    for filename, result in detection_results.attachments.items():
        if result["positives"] > 0:
            conclusions["is_malicious"] = True
            break

    if from_header_domain_name != received_header_domain_name:
        conclusions["is_malicious"] = True
        conclusions['domain_match'] = False

    if from_header_domain_name == "gmail.com" and received_header_domain_name == "google.com":
        conclusions["is_malicious"] = False
        conclusions['domain_match'] = True


    return conclusions

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.run(debug=False)