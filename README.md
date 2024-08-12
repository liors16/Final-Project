# Email Threats Analyzer and Detection Tool Project.

## Overview:
This project is a comprehensive email security analysis tool,
designed to detect and analyze potential threats within email messages. 
The system parses email headers, extracts critical information, performs security checks on links, 
IP addresses, attachments, and leverages advanced AI (GPT-4) to analyze potential attack paths.

## Features:
1)Email Header Parsing: Extracts and processes email headers, message content, and attachments.
2)Link, IP, and Attachment Analysis: Utilizes the VirusTotal and AbuseIPDB API to scan links, IP addresses, and attachments for potential threats.
3)SPF, DKIM, DMARC Checks: Validates the email's authenticity by checking SPF, DKIM, and DMARC results.
4)AI-Driven Analysis: Uses GPT-4 to analyze the data and predict potential attack paths.
5)Comprehensive Reporting: Organizes and stores analysis results in a structured manner for further review.

## Classes:

1. **ParseHeaders**
   - Extracts and parses email components from `.eml` files.
   - Handles headers, message content, and attachments.

2. **Detections**
   - Performs SPF, DKIM, and DMARC checks on the email.
   - Provides results for authentication and legitimacy.
   - Analyzes links in the email using VirusTotal API.
   - Analyzes IP addresses using AbuseIPdb API.
   - Checks domain information from email headers.
   - Compares "From" and "Received" domains to detect mail spoofing attack.


3. **DetectionResults**
   - Stores and manages results from various analyses.
   - Provides methods to add and retrieve results.

4. **AttackPathByGPT**
   - Uses OpenAI's GPT model to analyze and summarize email security findings.
   - Generates a detailed analysis of the potential attack path and threats.

5. **app**
   - Creates all the objects from all classes to perform the analyzing and detections
   - Using the "process_file" function that returns all the results from all the scans 


## Installation:
Python 3.7+

## Install the required Python packages:
pip install -r requirements.txt

## Setting up Environment Variables in "config.py" file:
VIRUSTOTAL_API_KEY='your_virustotal_api_key'
ABUSEIPDB_API_KEY='your_abuseipdb_api_key'
OPENAI_API_KEY='your_openai_api_key'

