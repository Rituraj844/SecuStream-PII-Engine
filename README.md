​​SecuStream: High-Performance Deterministic Data Anonymizer
​SecuStream is a lightweight, high-speed Python engine designed to identify and mask Personally Identifiable Information (PII) within large datasets. It is built to help organizations comply with global data privacy regulations like GDPR, HIPAA, and CCPA by securing data before it is used for AI training or analytics.

🚀 Key Features
​Multi-Format Support: Seamlessly process .csv, .json, .tsv, and raw .txt log files.
​Deterministic Masking: Uses SHA-256 hashing with a customizable salt to ensure data consistency (e.g., the same email is always masked to the same hash across files).
​Deep JSON Inspection: A recursive "walking" algorithm that scans through nested objects and lists to find hidden sensitive strings.
​Comprehensive PII Detection: Out-of-the-box support for:
​Emails
​IPv4 Addresses
​Credit Card Numbers (with length validation)
​Phone Numbers
​Names (Global pattern recognition)
​Compliance Audit Trails: Automatically generates a detailed JSON audit report summarizing the masking actions, types detected, and file paths.

🛠️ How It Works
​Detection: Uses optimized Regex patterns to scan every cell or string in your dataset.
​Masking: Applies a one-way cryptographic hash to the sensitive data, preserving the data structure for analytical utility without revealing the original value.
​Reporting: Outputs a masked file along with an audit JSON file for security review.
​
​💻 Quick Start
​1. Installation
​Simply clone the repository and ensure you have Python 3.x installed. No external dependencies are required (Standard Library only).
git clone https://github.com/Rituray844/SecuStream-Engine.git
cd SecuStream-Engine

2. Basic Usage
from secustream import generate_safe_output

# Process your sensitive data
audit_report = generate_safe_output("your_sensitive_data.csv")
print(f"Masked file saved at: {audit_report['masked_path']}")

📊 Performance Benchmark
​SecuStream is optimized for low memory overhead, making it suitable for processing large logs or database exports on standard hardware or even mobile-based environments.

Task                 Throughput          Security Level
Log Scrubbing        ~25MB/sec           SHA-256 Hashing
JSON Masking      Optimized Recursion    Format Preserving

🛡️ Security & Privacy
​Local Processing: All data stays on your machine. Nothing is uploaded to any cloud service.
​No Trace: Original data is never stored in memory longer than necessary.
​
🤝 Contribution & Grants
​This project is open for Open Source Grants (Gitcoin, Protocol Labs) and contributions from the privacy-tech community. If you find this tool useful, please give it a ⭐!
