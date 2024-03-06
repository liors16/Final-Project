from EmailHeaderExtractor import ParseHeaders
from Detections import Detections


def main():

    # EML file path, it's just file name for now (temporary)
    eml_file_path = 'message.eml'

    # Contains the dictionary of the message headers and message content
    header_parser = ParseHeaders(eml_file_path)
    detections_instance = Detections(header_parser)

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


if __name__ == "__main__":
    main()
