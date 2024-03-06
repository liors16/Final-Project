from email import message_from_file


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

    def extract_msg_content(self, msg):
        # Extract the content of the email message (body)
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
