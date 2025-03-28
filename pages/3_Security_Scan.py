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
genai.configure(api_key="AIzaSyDZjor43yqVq4bWRThkg-EraIh6vmlCw6s")
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
        CREATE TABLE IF NOT EXISTS header_scans (
            scan_id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            timestamp DATETIME NOT NULL
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
        """Perform port scan with robust error handling"""
        # First try Shodan if API key exists
        if SHODAN_API_KEY:
            try:
                shodan_api = shodan.Shodan(SHODAN_API_KEY)
                try:
                    results = shodan_api.host(self.ip)
                    
                    open_ports = [str(port) for port in results.get('ports', [])]
                    critical_ports = {22: 'SSH', 3306: 'MySQL', 3389: 'RDP'}
                    exposed_critical = [
                        f"{port} ({critical_ports[port]})" 
                        for port in critical_ports 
                        if port in results.get('ports', [])
                    ]

                    # Store results in database
                    try:
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
                    except sqlite3.Error as e:
                        st.warning(f"Database error: {e}")
                    finally:
                        conn.close()

                    return {
                        'open_ports': open_ports,
                        'critical_ports_exposed': exposed_critical,
                        'scan_type': 'shodan'
                    }

                except shodan.APIError as e:
                    st.warning(f"Shodan API error: {e}")
                except Exception as e:
                    st.warning(f"Shodan processing error: {e}")

            except Exception as e:
                st.warning(f"Shodan initialization failed: {e}")

        # Fallback to basic TCP scan
        return self._basic_tcp_port_scan()
    
    def _basic_tcp_port_scan(self):
            """Check common ports without Shodan"""
            common_ports = {
                80: 'HTTP',
                443: 'HTTPS',
                22: 'SSH',
                3389: 'RDP',
                3306: 'MySQL'
            }
            
            open_ports = []
            critical_exposed = []
            
            for port, service in common_ports.items():
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.5)
                        if s.connect_ex((self.ip, port)) == 0:
                            open_ports.append(f"{port} ({service})")
                            if port in [22, 3389, 3306]:  # Critical ports
                                critical_exposed.append(f"{port} ({service})")
                except:
                    continue
            
            return {
                'open_ports': open_ports,
                'critical_ports_exposed': critical_exposed,
                'scan_type': 'basic'  # Mark as limited scan
            }
        
    def get_all_security_headers_to_check(self):
        """Returns categorized headers with metadata"""
        return {
            'essential': [
                ('Content-Security-Policy', 3.0),
                ('Strict-Transport-Security', 3.0),
                ('X-Frame-Options', 2.5),
                ('X-Content-Type-Options', 2.0),
                ('Referrer-Policy', 2.0),
                ('Permissions-Policy', 2.0),
                ('Cross-Origin-Opener-Policy', 1.5),
                ('Cross-Origin-Embedder-Policy', 1.5)
            ],
            'recommended': [
                ('Cache-Control', 1.0),
                ('Clear-Site-Data', 0.5),
                ('Expect-CT', 0.5)
            ],
            'observational': [
                ('X-XSS-Protection', 0.3),
                ('Feature-Policy', 0.2),
                ('Public-Key-Pins', 0.1)
            ]
        }
    
    def check_all_headers(self):
        headers = requests.get(self.url, timeout=5).headers
        all_headers = self.get_all_security_headers_to_check()
        
        results = {}
        for category, headers_list in all_headers.items():
            results[category] = {
                header: {
                    'present': header in headers,
                    'value': headers.get(header),
                    'weight': weight
                }
                for header, weight in headers_list
            }
    
        return results
    def check_security_headers(self):
        """Check security headers with proper DB connection handling"""
        conn = None
        try:
            # First get the headers from the website
            response = requests.get(self.url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set')
            }
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert into header_scans table
            cursor.execute('''
                INSERT INTO header_scans (domain, timestamp)
                VALUES (?, ?)
            ''', (self.domain, datetime.now()))
            
            # Insert into security_headers table
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
            return security_headers
            
        except requests.RequestException:
            st.error("Could not retrieve security headers")
            return {}
        except sqlite3.Error as e:
            st.error(f"Database error: {e}")
            return {}
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return {}
        finally:
            if conn:
                conn.close()
    
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

    def calculate_header_score(self, header_results):
        total_score = 0
        max_possible = 0
        
        for category in header_results.values():
            for header_data in category.values():
                if header_data['present']:
                    total_score += header_data['weight']
                max_possible += header_data['weight']
        
        return (total_score / max_possible) * 100 if max_possible > 0 else 0
    
    def calculate_security_score(self):
        """Calculate comprehensive security score with robust error handling"""
        # Weights for different security aspects
        weights = {
            'port_exposure': 0.3,
            'security_headers': 0.4,
            'domain_metadata': 0.2,
            'sensitive_data': 0.1 
        }
        
        # Track available components and initialize scores
        available_components = {
            'port_exposure': False,
            'security_headers': False,
            'domain_metadata': False,
            'sensitive_data': False
        }
        
        # Initialize all scores with default values
        port_score = 5  # Neutral default
        headers_score = 5
        domain_score = 6  # Slightly positive default
        data_score = 5  # Neutral default
        
        # 1. Port Score Calculation
        port_results = self.scan_results.get('port_scan', {})
        if port_results:
            available_components['port_exposure'] = True
            critical_ports = len(port_results.get('critical_ports_exposed', []))  # Initialize here
            
            if port_results.get('scan_type') == 'shodan':
                port_score = max(0, 10 - critical_ports * 2)
            elif port_results.get('scan_type') == 'basic':
                port_score = max(0, 10 - critical_ports * 1.5)
            else:
                port_score = max(0, 8 - critical_ports)

        # 2. Headers Score Calculation
        try:
            header_results = self.check_all_headers()
            if header_results:
                available_components['security_headers'] = True
                headers_score = self.calculate_header_score(header_results) / 10
        except Exception as e:
            st.warning(f"Header scoring error: {e}")

        # 3. Domain Score Calculation
        domain_info = self.scan_results.get('domain_metadata', {})
        if domain_info:
            try:
                available_components['domain_metadata'] = True
                domain_score = self._calculate_domain_score(domain_info)
            except Exception as e:
                st.warning(f"Domain scoring error: {e}")

        # 4. Sensitive Data Score
        if hasattr(self, '_evaluate_sensitive_data'):
            try:
                data_score = self._evaluate_sensitive_data()
                available_components['sensitive_data'] = True
            except Exception as e:
                st.warning(f"Sensitive data scoring error: {e}")

        # Adjust weights based on available data
        total_available = sum(1 for v in available_components.values() if v)
        if total_available == 0:
            return 5  # Can't determine score
        
        # Normalize weights
        adjusted_weights = {
            k: (weights[k] if available_components[k] else 0)
            for k in weights
        }
        weight_sum = sum(adjusted_weights.values())
        
        if weight_sum == 0:
            return 5  # No valid components
        
        normalized_weights = {
            k: v/weight_sum 
            for k,v in adjusted_weights.items()
        }

        # Calculate weighted score
        weighted_score = (
            (port_score * normalized_weights.get('port_exposure', 0)) +
            (headers_score * normalized_weights.get('security_headers', 0)) +
            (domain_score * normalized_weights.get('domain_metadata', 0)) +
            (data_score * normalized_weights.get('sensitive_data', 0))
        )
        temp=max(round(weighted_score, 1),1)
        return min(temp, 10)  # Ensure score is between 0-10
    
    def _calculate_domain_score(self, domain_info):
        """Robust domain scoring with fallbacks"""
        score = 6  # Base neutral score
        
        # SSL Expiry (if available)
        if 'ssl_expiry' in domain_info:
            try:
                days_remaining = (domain_info['ssl_expiry'] - datetime.now()).days
                if days_remaining > 30:
                    score += 2
                elif days_remaining > 7:
                    pass  # Neutral
                else:
                    score -= 3
            except:
                pass
        
        # Domain Age (if available)
        if 'domain_age' in domain_info:
            try:
                if domain_info['domain_age'] > 365:  # Older than 1 year
                    score += 1
                elif domain_info['domain_age'] < 30:  # Very new
                    score -= 1
            except:
                pass
        
        return min(max(score, 1), 10)

    def generate_remediation_steps(self):
        """Generate remediation steps based on vulnerabilities"""
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
        
        if headers.get('X-Frame-Options') == 'Not Set':
            steps.append("Implement X-Frame-Options to prevent clickjacking")
        
        if headers.get('Referrer-Policy') == 'Not Set':
            steps.append("Configure Referrer-Policy to control referrer information")
        
        return steps if steps else ["No critical remediation steps identified"]
    
    
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


def get_dpdp_compliance_assessment(security_score, scan_results):
    """Get DPDP compliance assessment using Gemini API"""
    try:
        # Prepare prompt for Gemini
        prompt = f"""
        Based on these security scan results, provide a very concise (1 sentence) assessment 
        of DPDP (India's Digital Personal Data Protection Act) compliance readiness:
        
        Security Score: {security_score}/10
        Critical Ports Exposed: {len(scan_results.get('port_scan', {}).get('critical_ports_exposed', []))}
        Security Headers: {scan_results.get('security_headers', {})}
        SSL Valid: {'Yes' if scan_results.get('domain_metadata', {}).get('ssl_expiry') else 'No'}
        
        Respond with just one sentence about DPDP compliance readiness, nothing else.
        """
        
        # Initialize Gemini model (using 1.5 flash)
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        
        return response.text.strip()
    
    except Exception as e:
        st.error(f"Could not generate DPDP assessment: {e}")
        return "DPDP compliance assessment unavailable"

def display_compliance_progress(percentage):
    """Display a horizontal progress bar for compliance percentage"""
    st.write(f"DPDP Compliance Readiness: {percentage}%")
    st.progress(percentage / 100)
    st.markdown("""
    <style>
        .stProgress > div > div > div {
            background-color: #4CAF50;
        }
    </style>
    """, unsafe_allow_html=True)

def calculate_compliance_percentage(security_score,port_results):
    base_percentage = security_score * 8  # 0-10 to 0-80%
    
    # Handle different scan types
    if port_results.get('scan_type') == 'shodan':
        # Full penalty for critical ports in full scan
        base_percentage -= len(port_results.get('critical_ports_exposed', [])) * 5
    elif port_results.get('scan_type') == 'basic':
        # Reduced penalty for basic scan
        base_percentage -= len(port_results.get('critical_ports_exposed', [])) * 3
    else:
        # No port data - conservative penalty
        base_percentage *= 0.9  # 10% reduction
        st.warning("Port scan incomplete - compliance score adjusted conservatively")
    
    return min(max(base_percentage, 0), 95)

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
            if port_results.get('scan_type') == 'basic':
                st.warning("Used basic port scanner (Shodan unavailable)")

            if port_results.get('open_ports'):
                st.write("**All Open Ports:**")
                for port in port_results['open_ports']:
                    st.code(port)

            if port_results.get('critical_ports_exposed'):
                st.error("**Critical Ports Exposed:**")
                for port in port_results['critical_ports_exposed']:
                    st.error(port)
            else:
                st.success("No critical ports exposed")
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

           
            compliance_percentage = calculate_compliance_percentage(security_score=security_score,port_results=port_results)
            st.subheader("DPDP Compliance Assessment")
            
            # Display progress bar
            display_compliance_progress(compliance_percentage)
            
            # Get Gemini's assessment
            dpdp_assessment = get_dpdp_compliance_assessment(
                security_score, 
                scanner.scan_results
            )
            st.info(f"🔍 {dpdp_assessment}") 
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