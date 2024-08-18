from openai import OpenAI

class AttackPathByGPT:
    def __init__(self, results, api_key):
        self.results = results
        self.api_key = api_key
        self.client = OpenAI(api_key=api_key)

    def analyze(self):
        return_path = self.results.headers.get('Return-Path', '')
        from_address = self.results.headers.get('From', '')
        subject = self.results.headers.get('Subject', '')
        message_content = self.results.message_content

        spf_result = 'pass' if self.results.spf_result else 'fail'
        dkim_result = 'pass' if self.results.dkim_result else 'fail'
        dmarc_result = 'pass' if self.results.dmarc_result else 'fail'

        link_results = self.results.link_results
        links_analysis = {link: result.get('positives', 0) for link, result in link_results.items()}

        ip_results = self.results.ip_results
        ips_analysis = {ip: result.get('data', {}).get('abuseConfidenceScore', 0) for ip, result in ip_results.items()}

        domain_match = self.results.domain_match or ('', '')

        attachment_results = self.results.attachments
        attachments_analysis = {filename: result.get('positives', 0) for filename, result in attachment_results.items()}

        return self.send_to_chatgpt(return_path, from_address, subject, message_content, spf_result, dkim_result, dmarc_result,
                             links_analysis, ips_analysis, domain_match, attachments_analysis)

    def send_to_chatgpt(self, return_path, from_address, subject, message_content, spf_result, dkim_result,
                        dmarc_result, links_analysis, ips_analysis, domain_match, attachments_analysis):

        prompt = f"""
        Analyze the following email details.
        I require the response to look like this:
        Attack Type:
        Attack Path: Should contain the steps the attacker plans to take to make the attack succeed
        Summary:
        without adding any other word, but if there are suspicious flags according to the details I sent you, 
        then quote them and the number of engines that identified it as malicious in the Summary:

        The address from the "Return Path" header: {return_path}
        The address from the "from" header: {from_address}
        The message subject: {subject}
        The message content: {message_content}
        The SPF Result: {spf_result}
        The DKIM Result: {dkim_result}
        The DMARC Result: {dmarc_result}
        Attached Links and the number of engines that virus total identified the link as malicious: {links_analysis}
        The IP addresses and the number of engines that AbuseIPdb identified the address as malicious: {ips_analysis}
        The first domain address is the address that appeared in the "from" header. 
        The second domain address is the address that appeared in the "Received" Header: {domain_match}.
        The files attached to the message and the number of engines that Virus Total identified the files as malicious: {attachments_analysis}
        """

        response = self.client.chat.completions.create(
            messages=[
                {"role": "user", "content": prompt}
            ],
            model="gpt-4o-mini",
        )

        # Get the response of the chat
        chatgpt_response = response.choices[0].message.content
        print("ChatGPT Response:", chatgpt_response)
        return chatgpt_response

