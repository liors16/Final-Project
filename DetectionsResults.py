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
