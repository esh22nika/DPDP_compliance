# Hackverse - DPDP Compliance Toolkit

## Overview

Hackverse - DPDP is a centralized application designed to help organizations comply with the Digital Personal Data Protection (DPDP) Act, 2023. The toolkit provides a streamlined process to check, update, and generate privacy policies, ensuring compliance with legal requirements and data protection best practices.

## Features

- **Privacy Policy Checker**: Analyzes existing privacy policies and suggests improvements.
- **Automated Fixes**: Applies necessary updates to outdated or non-compliant privacy policies.
- **Policy Generator**: Creates a comprehensive privacy policy for websites that lack one.
- **Graphical Dashboard**: Displays compliance metrics using charts and visual statistics.
- **Security Scan Reports**: Provides insights into security vulnerabilities and necessary mitigations.
- **Database Integration**: Stores policy details and scan reports for historical tracking.

## Installation

### Prerequisites

Ensure you have the following installed:

- Python 3.8+
- pip
- SQLite (for database management)
- Required Python libraries:
  ```sh
  pip install PyPDF2 bs4 cohere pandas plotly plyer requests shodan streamlit validators whois google-generativeai together
  ```

### Setup Instructions

1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/Hackverse-DPDP.git
   cd Hackverse-DPDP
   ```
2. Set up the database:
   ```sh
   python setup_db.py
   ```
3. Run the application:
   ```sh
   streamlit run main.py
   ```

## API Dependencies

The project relies on the following external APIs:

- **Cohere API**: Used for AI-based text processing.
  - Endpoint: `https://api.cohere.com/v1/chat`
- **Together AI API**: Used for AI-powered interactions.
  - API Key required from [Together AI](https://www.together.xyz/)
- **Shodan API**: Used for security scanning.
- **Whois Lookup**: Utilized for domain information retrieval.

## Usage

- **Checking a Privacy Policy**: Enter the website URL, and the tool will analyze the existing policy for compliance.
- **Fixing a Policy**: If issues are found, apply recommended fixes and generate a revised policy.
- **Generating a New Policy**: For websites without a policy, generate one based on best practices.
- **Downloading Reports**: Security scan reports and updated policies can be downloaded as PDFs.

## Project Structure

```
Hackverse-DPDP/
│── main.py                # Entry point of the application
│── auth.py                # Authentication module
│── setup_db.py            # Database setup script
│── dpdp_act_2023.txt      # Reference document for DPDP compliance
│── Security_Scan_Report.pdf # Sample security scan report
│── security_scans.db      # Database for storing security scan results
│── /.streamlit            # Streamlit configuration files
│   ├── config.toml        # Application configuration file
│   ├── secrets.toml       # Stores API keys and credentials
│── /database              # SQLite database files
│   ├── users.db           # User authentication database
│── /pages                 # Streamlit pages for different functionalities
│   ├── 0_About_Us.py      # About Us page
│   ├── 1_Dashboard.py     # Graphical dashboard
│   ├── 2_Security_Scan.py # Security scan module
│   ├── 3_Scan_History.py  # Scan history records
│   ├── 4_Roadmap.py       # Roadmap and future updates
│   ├── 5_Settings.py      # User settings page
│   ├── 6_suggestion.py    # Suggestions module
│   ├── 7_updates.py       # Updates and patches section
│   ├── Generate_Policy.py # Policy generation module
│   ├── Privacy_Check.py   # Privacy policy checker
│── /__pycache__           # Compiled Python files
```

## Future Enhancements

- Integration with AI-based compliance recommendations.
- Multi-language support for privacy policies.
- Advanced in-house security scanning technology to detect more vulnerabilities instead of relying on external APIs.

## Demonstration video
https://drive.google.com/file/d/1O7A3k5pl2Ntsq0UKwJO7Tjc6SWJeOuAW/view?usp=sharing
