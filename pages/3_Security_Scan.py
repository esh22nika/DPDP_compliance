import streamlit as st
import requests
import socket
import sqlite3
import shodan
import ssl
import json
import os
from datetime import datetime
import whois
import hashlib
from urllib.parse import urlparse
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import google.generativeai as genai

url = st.session_state.get('policy_url')

# API Keys (replace with actual API keys)
SHODAN_API_KEY = st.secrets.get('SHODAN_API_KEY', '')
genai.configure(api_key="YOUR_GEMINI_API_KEY")
HAVEIBEENPWNED_API_KEY = st.secrets.get('HAVEIBEENPWNED_API_KEY', '')
BREACH_DIRECTORY_API_KEY='7d93764f6bmsh81095bf18419627p1fc415jsnf6df534c0add'
GOOGLE_DLP_API_KEY = st.secrets.get('GOOGLE_DLP_API_KEY', '')

class SecurityScanner:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.ip = socket.gethostbyname(self.domain)
        self.scan_results = {}
        self.db_path = 'security_scans.db'
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for storing security scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables for different scan types
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_scans (
            scan_id INTEGER PRIMARY KEY,
            domain TEXT,
            ip TEXT,
            open_ports TEXT,
            timestamp DATETIME
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_headers (
            scan_id INTEGER PRIMARY KEY,
            domain TEXT,
            csp TEXT,
            hsts TEXT,
            x_frame TEXT,
            referrer_policy TEXT,
            timestamp DATETIME
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scans (
            scan_id INTEGER PRIMARY KEY,
            domain TEXT,
            sql_injection_risk TEXT,
            xss_risk TEXT,
            api_exposure TEXT,
            sensitive_data_risk TEXT,
            timestamp DATETIME
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_metadata (
            scan_id INTEGER PRIMARY KEY,
            domain TEXT,
            domain_age INTEGER,
            ssl_expiry DATE,
            geolocation_risk TEXT,
            email_leaks TEXT,
            timestamp DATETIME
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def run_port_scan(self):
        """Perform port scan using Shodan API"""
        try:
            shodan_api = shodan.Shodan(SHODAN_API_KEY)
            results = shodan_api.host(self.ip)
            
            open_ports = [
                f"{port}"
                for port in results.get('ports', [])
            ]
            
            # Check for critical ports
            critical_ports = {
                22: 'SSH',
                3306: 'MySQL',
                3389: 'RDP',
                443: 'HTTPS',
                80: 'HTTP'
            }
            
            exposed_critical_ports = [
                f"{port} ({critical_ports[port]})" 
                for port in critical_ports.keys() 
                if port in results.get('ports', [])
            ]
            
            self.scan_results['port_scan'] = {
                'open_ports': open_ports,
                'critical_ports_exposed': exposed_critical_ports
            }
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO port_scans 
                (domain, ip, open_ports, timestamp) 
                VALUES (?, ?, ?, ?)
            ''', (
                self.domain, 
                self.ip, 
                json.dumps(open_ports), 
                datetime.now()
            ))
            conn.commit()
            conn.close()
            
            return exposed_critical_ports
        
        except shodan.APIError as e:
            st.error(f"Shodan API Error: {e}")
            return []
    
    def check_security_headers(self):
        """Check security headers of the website"""
        try:
            response = requests.get(self.url, timeout=5)
            headers = response.headers
            
            # Check specific security headers
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set')
            }
            
            self.scan_results['security_headers'] = security_headers
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_headers 
                (domain, csp, hsts, x_frame, referrer_policy, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                self.domain,
                security_headers['Content-Security-Policy'],
                security_headers['Strict-Transport-Security'],
                security_headers['X-Frame-Options'],
                security_headers['Referrer-Policy'],
                datetime.now()
            ))
            conn.commit()
            conn.close()
            
            return security_headers
        
        except requests.RequestException:
            st.error("Could not retrieve security headers")
            return {}
    
    def check_domain_metadata(self):
        """Retrieve domain metadata and risk assessment"""
        try:
            # Domain age via WHOIS
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            
            # Handle case where creation_date is a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # Take the first date if multiple exist

            # Calculate domain age
            domain_age = (datetime.now() - creation_date).days if creation_date else 'Unknown'

            # SSL Certificate info
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as secure_sock:
                    ssl_cert = secure_sock.getpeercert()
                    ssl_expiry = datetime.strptime(ssl_cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

            self.scan_results['domain_metadata'] = {
                'domain_age': domain_age,
                'ssl_expiry': ssl_expiry
            }

            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO domain_metadata 
                (domain, domain_age, ssl_expiry, timestamp) 
                VALUES (?, ?, ?, ?)
            ''', (
                self.domain,
                domain_age,
                ssl_expiry,
                datetime.now()
            ))
            conn.commit()
            conn.close()

            return self.scan_results['domain_metadata']

        except Exception as e:
            st.error(f"Domain metadata retrieval error: {e}")
            return {}

    
    
    def calculate_security_score(self):
        """Calculate comprehensive security score"""
        # Weights for different security aspects
        weights = {
            'port_exposure': 0.3,      # Penalize critical open ports, but common web ports (80, 443) shouldn't be major issues
            'security_headers': 0.3,  # Reward good headers, but missing headers shouldn't tank the score completely
            'domain_metadata': 0.2,    # Increase importance for SSL expiry and domain trustworthiness
            'sensitive_data': 0.4 
        }
        
        # Base score calculation logic
        port_score = 10 - (len(self.scan_results.get('port_scan', {}).get('critical_ports_exposed', [])) * 2)
        headers_score = sum([1 for header in self.scan_results.get('security_headers', {}).values() if header != 'Not Set']) * 2
        
        # Normalize and weight scores
        normalized_score = (
            (port_score * weights['port_exposure']) +
            (headers_score * weights['security_headers'])    
        )
        
        return min(max(normalized_score, 0), 10)
    
    def generate_remediation_steps(self):
        """Generate unique remediation steps based on vulnerabilities"""
        steps = []
        
        # Port exposure remediation
        if self.scan_results.get('port_scan', {}).get('critical_ports_exposed'):
            steps.append("Close unnecessary open ports using firewall rules")
            steps.append("Implement strict network segmentation")
        
        # Security headers
        headers = self.scan_results.get('security_headers', {})
        if headers.get('Content-Security-Policy') == 'Not Set':
            steps.append("Implement a strict Content Security Policy")
        
        if headers.get('Strict-Transport-Security') == 'Not Set':
            steps.append("Enable HTTP Strict Transport Security (HSTS)")
        
        return steps
def generate_pdf_report(scanner):
    """Generate a PDF report with security scan results"""
    pdf_filename = "Security_Scan_Report.pdf"
    
    # Create PDF
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750  # Initial Y position for text

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, y, "Security Scan Report")
    y -= 30

    # Port Scan Results
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Port Scan Results")
    y -= 20
    for port in scanner.scan_results.get('port_scan', {}).get('critical_ports_exposed', []):
        c.setFont("Helvetica", 10)
        c.drawString(70, y, f"- {port}")
        y -= 15

    # Security Headers
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Security Headers")
    y -= 20
    for header, value in scanner.scan_results.get('security_headers', {}).items():
        c.setFont("Helvetica", 10)
        c.drawString(70, y, f"{header}: {value}")
        y -= 15

    # Domain Metadata
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Domain Metadata")
    y -= 20
    domain_info = scanner.scan_results.get('domain_metadata', {})
    for key, value in domain_info.items():
        c.setFont("Helvetica", 10)
        c.drawString(70, y, f"{key}: {value}")
        y -= 15

    # Security Score
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Security Score")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(70, y, f"Score: {scanner.calculate_security_score()}/10")
    y -= 15

    # Remediation Steps
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Recommended Fixes")
    y -= 20
    for step in scanner.generate_remediation_steps():
        c.setFont("Helvetica", 10)
        c.drawString(70, y, f"- {step}")
        y -= 15

    # Save PDF
    c.save()
    return pdf_filename

def run_security_scan():
    st.set_page_config(page_title="Run security scan")
    st.title("Run Security Scan")
    if not st.session_state.get('user'):
        st.warning("Please login to access the policy generator")
        return
    # URL Input
    #url = st.text_input("Enter website URL:", placeholder="https://example.com")
    
    # Optional email for breach check
    #email = st.text_input("(Optional) Enter associated email for breach check:", placeholder="admin@example.com")
    
    if st.button("Start Security Scan"):
        if not url:
            st.error("Please enter a valid URL")
            return
        
        # Initialize scanner
        scanner = SecurityScanner(url)
        
        # Perform scans
        with st.spinner("Running comprehensive security scan..."):
            # Port Scan
            port_results = scanner.run_port_scan()
            st.subheader("Port Scan Results")
            for port in port_results:
                st.warning(f"Exposed Port: {port}")
            
            # Security Headers
            headers = scanner.check_security_headers()
            st.subheader("Security Headers")
            for header, value in headers.items():
                st.info(f"{header}: {value}")
            
            # Domain Metadata
            domain_info = scanner.check_domain_metadata()
            st.subheader("Domain Metadata")
            st.write(json.dumps(domain_info, default=str))
            
            # Email Leak Check
            #if email:
                #leaks = scanner.check_email_leaks(email)
                #st.subheader("Email Breach Check")
                #if leaks:
                    #for leak in leaks:
                        #st.error(f"Email found in {leak} breach")
                #else:
                    #st.success("No known breaches found for this email")
            
            # Calculate Security Score
            security_score = scanner.calculate_security_score()
            st.subheader("Security Score")
            st.metric("Comprehensive Security Rating", f"{security_score}/10")
            if security_score<4:
                st.subheader("Your website is not reliable")
            elif (security_score<=8)and(security_score>=5):
                st.subheader("website reliability needs improvement")
            else:
                st.subheader("website is mostly reliable")
                
                
            # Remediation Steps
            remediation_steps = scanner.generate_remediation_steps()
            st.subheader("Recommended Fixes")
            for step in remediation_steps:
                st.info(step)

            # Generate PDF Report
            pdf_filename = generate_pdf_report(scanner)
            with open(pdf_filename, "rb") as pdf_file:
                st.download_button(
                    label="Download Final Report",
                    data=pdf_file,
                    file_name="Security_Scan_Report.pdf",
                    mime="application/pdf"
                )
            # Detailed Report Toggle
            
            #if st.button("Generate Detailed Remediation Roadmap"):
                # Placeholder for more detailed, personalized remediation guide
                #st.switch_page("pages/5_Roadmap.py")
            if st.button("back to dashboard"):
                # Placeholder for more detailed, personalized remediation guide
                st.switch_page("pages/1_Dashboard.py")

# This allows the script to be run directly or imported
if __name__ == "__main__":
    run_security_scan()