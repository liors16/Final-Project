from concurrent.futures import ThreadPoolExecutor


class Detections:
    def __init__(self, header_parser):
        self.header_parser = header_parser

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
