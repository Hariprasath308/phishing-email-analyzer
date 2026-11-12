# Phishing Email Analyzer

A beginner-friendly Python-based cybersecurity project that analyzes email text and identifies suspicious indicators.

## Features

- Suspicious keyword detection
- Sender email address extraction
- From and Reply-To domain comparison
- URL identification
- Basic risk assessment (LOW, MEDIUM, HIGH)
- Automatic text report generation

## Technologies Used

- Python 3
- Kali Linux
- Regular Expressions
- Email Parsing
- File Handling

## Project Structure

phishing-email-analyzer/
|
|-- analyzer.py
|-- README.md
|-- samples/
|   |-- sample_email.txt
|
|-- reports/
    |-- phishing_report.txt

## How to Run

1. Clone the repository.
2. Open the project directory.
3. Run:

python3 analyzer.py

## Output

The analyzer generates a report at:

reports/phishing_report.txt

## Disclaimer

This project is for educational purposes only.
It identifies basic suspicious indicators and cannot confirm whether an email is genuinely phishing.
Detected URLs are listed but never opened.
