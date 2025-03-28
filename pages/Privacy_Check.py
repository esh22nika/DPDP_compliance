import streamlit as st
import requests
from bs4 import BeautifulSoup
import re
import validators
import time
import pandas as pd
from io import BytesIO
import plotly.graph_objects as go
import google.generativeai as genai

st.set_page_config(
    page_title="DPDP Privacy Policy Compliance Checker",
    layout="wide"
)
genai.configure(api_key="AIzaSyDZjor43yqVq4bWRThkg-EraIh6vmlCw6s")  # Use your actual API key
model = genai.GenerativeModel('gemini-1.5-flash')

REQUIRED_CLAUSES = {
    "Purpose of Data Collection": r"(collect|gather|obtain|use|process).*?(data|information|personal details).*?(?:for|to).*?(improve|provide|enhance|personalize|deliver|optimize).*?(service|product|experience|content)",
    
    "User Rights & Consent": r"(right|entitled|ability|option).*?(access|delete|correct|modify|control|withdraw|opt.?out|request).*?(data|information|consent|details|personal information)",
    
    "Data Retention Policy": r"(retain|store|keep|maintain|hold|preserve).*?(data|information|records).*?(for|period of|up to|at least|maximum of).*?(\d+\s*(?:day|month|year|week|hour|minute|second)s?)",
    
    "Third-Party Sharing Policy": r"(share|disclose|provide|transfer|transmit).*?(data|information|details).*?(with|to).*?(third.?part|partner|affiliate|advertiser|vendor|service provider)",
    
    "Security Measures": r"(secur|protect|encrypt|safeguard|shield).*?(data|information|system|transmission|storage).*?(measure|method|protocol|standard|process|ssl|tls|firewall|two.?factor|authentication)",
    
    "Cookies Policy": r"(cookie|tracking technology|web beacon|pixel|local storage).*?(use|collect|track|monitor|store|gather)",
    
    "Children's Privacy": r"(child|minor|under.{1,5}13|under.{1,5}18).*?(privacy|data|information|protect|collect)",
    
    "International Data Transfer": r"(transfer|transmit|process|store).*?(data|information).*?(across borders|internationally|outside|foreign|different country)",
    
    "Data Breach Notification": r"(breach|leak|unauthorized access|compromise|incident).*?(notification|inform|alert|report)",
    
    "Grievance Redressal": r"(grievance|complaint|dispute|concern|issue).*?(contact|address|resolve|redress|grievance officer)"
}

RECOMMENDED_CLAUSES = {
    "Last Updated Date": r"(last|recently).*?(updated|modified|revised|changed).*?(on|at|as of).*?(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})",
    
    "Contact Information": r"(contact|reach|email|phone|address).*?(us|company|organization|team|privacy officer|data protection officer)",
    
    "Automated Decision Making": r"(automated|automatic|algorithm|ai|machine learning).*?(decision|processing|profiling|analysis)",
    
    "Right to Object": r"(right|option|ability).*?(object|opt-out|withdraw).*?(marketing|profiling|processing)",
    
    "Legitimate Interest": r"(legitimate|lawful|legal).*?(interest|basis|ground).*?(processing|collecting|using)"
}
def evaluate_clause_necessity(url, clause_name, current_status):
    """Use Gemini to determine if clause is actually needed for this website"""
    prompt = f"""
    Analyze whether a {clause_name} clause is genuinely required in the privacy policy 
    for {url} based on its likely business model and data practices. 
    
    Current status: {'Present' if current_status else 'Missing'}
    
    Consider:
    - Type of website (e.g., informational, e-commerce, social media)
    - Data collection practices
    - Applicable regulations
    - Industry standards
    
    Respond ONLY with one of these options:
    - "Essential" (if legally/morally required)
    - "Recommended" (if beneficial but not required)  
    - "Optional" (if not particularly relevant)
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        st.warning(f"Could not evaluate clause necessity: {e}")
        return "Recommended"  # Fallback value
    
def find_privacy_policy_url(base_url):
    """Find the privacy policy URL by checking common paths or looking for links"""
    common_paths = [
        "/privacy-policy", 
        "/privacy", 
        "/privacy-notice", 
        "/legal/privacy-policy",
        "/legal/privacy",
        "/about/privacy",
        "/en/privacy",
        "/policy/privacy"
    ]
    
    # Try common paths first
    for path in common_paths:
        policy_url = f"{base_url.rstrip('/')}{path}"
        try:
            response = requests.get(policy_url, timeout=5)
            if response.status_code == 200:
                return policy_url, response
        except:
            continue
    
    # If common paths don't work, try to find a link on the homepage
    try:
        response = requests.get(base_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Look for links containing privacy-related text
            privacy_keywords = ["privacy", "policy", "notice", "legal", "terms"]
            for link in soup.find_all("a", href=True):
                link_text = link.text.lower()
                if any(keyword in link_text for keyword in privacy_keywords):
                    href = link["href"]
                    if href.startswith("http"):
                        policy_url = href
                    else:
                        policy_url = f"{base_url.rstrip('/')}/{href.lstrip('/')}"
                    
                    try:
                        response = requests.get(policy_url, timeout=5)
                        if response.status_code == 200:
                            return policy_url, response
                    except:
                        continue
    except:
        pass
        
    return None, None

def get_policy_content(response):
    """Extract and clean text from the privacy policy page"""
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Remove script and style elements
    for script in soup(["script", "style", "header", "footer", "nav"]):
        script.extract()
    
    # Get text
    text = soup.get_text()
    
    # Normalize whitespace
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    
    return text

def check_clause(text, regex_pattern):
    """Check if a clause is present in the text and extract matched text"""
    matches = re.finditer(regex_pattern, text, re.IGNORECASE)
    found_matches = []
    
    for match in matches:
        start = max(0, match.start() - 30)
        end = min(len(text), match.end() + 30)
        found_matches.append(f"...{text[start:end]}...")
        
    return found_matches

def generate_report(compliance_results, recommendations, policy_url, compliance_score):
    """Generate downloadable report"""
    report = BytesIO()
    
    with pd.ExcelWriter(report, engine='xlsxwriter') as writer:
        # Summary sheet
        summary_data = {
            'Metric': ['URL Analyzed', 'Compliance Score', 'Required Clauses Found', 'Required Clauses Missing', 'Recommendations'],
            'Value': [
                policy_url,
                f"{compliance_score}/10",
                sum(1 for r in compliance_results if r['Status'] == 'Present'),
                sum(1 for r in compliance_results if r['Status'] == 'Missing'),
                len(recommendations)
            ]
        }
        
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        # Compliance details
        df_compliance = pd.DataFrame(compliance_results)
        df_compliance.to_excel(writer, sheet_name='Compliance Details', index=False)
        
        # Recommendations
        df_recommendations = pd.DataFrame(recommendations, columns=['Recommendation'])
        df_recommendations.to_excel(writer, sheet_name='Recommendations', index=False)
    
    report.seek(0)
    return report

def get_suggested_text(clause):
    """Return suggested text for missing clauses"""
    suggestions = {
        "Purpose of Data Collection": """
        We collect personal information to:
        - Provide and improve our services
        - Personalize your experience
        - Process transactions
        - Send periodic emails
        - Better understand how users interact with our website
        """,
        
        "User Rights & Consent": """
        You have the right to:
        - Access your personal information
        - Request correction of inaccurate data
        - Request deletion of your data
        - Withdraw consent at any time
        - Data portability
        - Lodge a complaint with a supervisory authority
        """,
        
        "Data Retention Policy": """
        We retain your personal information for as long as necessary to fulfill the purposes outlined in this privacy policy, unless a longer retention period is required or permitted by law. Generally, we keep basic user data for 24 months after your last interaction with our services.
        """,
        
        "Third-Party Sharing Policy": """
        We may share your information with:
        - Service providers who assist us in operating our website
        - Business partners with your consent
        - Legal authorities when required by law
        - Analytics and advertising partners
        
        We do not sell your personal information to third parties.
        """,
        
        "Security Measures": """
        We implement appropriate security measures including:
        - Encryption of transmitted data
        - Secure SSL connections
        - Regular security assessments
        - Access controls and authentication procedures
        - Firewalls and intrusion detection systems
        """,
        
        "Cookies Policy": """
        Our website uses cookies and similar technologies to enhance user experience, analyze usage, and assist in our marketing efforts. You can control cookies through your browser settings.
        """,
        
        "Children's Privacy": """
        Our services are not directed to individuals under the age of 13. We do not knowingly collect personal information from children. If you are a parent or guardian and believe your child has provided us with personal information, please contact us.
        """,
        
        "International Data Transfer": """
        Your information may be transferred to and processed in countries outside your residence where data protection laws may differ. We ensure appropriate safeguards are in place to protect your information.
        """,
        
        "Data Breach Notification": """
        In the event of a data breach that compromises your personal information, we will notify you and relevant authorities as required by applicable law without undue delay.
        """,
        
        "Grievance Redressal": """
        If you have concerns or complaints about how we handle your data, please contact our Grievance Officer at [email]. We will address your concerns promptly and appropriately.
        """
    }
    
    return suggestions.get(clause, "No suggestion available for this clause.")
def generate_new_policy(policy_text, compliance_results, recommendations):
    """Generate a new privacy policy text incorporating recommendations"""
    new_policy = policy_text
    
    # Add missing required clauses
    for result in compliance_results:
        if result['Status'] == 'Missing':
            suggested_text = get_suggested_text(result['Clause'])
            new_policy += f"\n\n=== {result['Clause']} ===\n{suggested_text}"
    
    # Add recommended clauses
    for rec in recommendations:
        if "Consider adding a" in rec:
            clause = rec.replace("Consider adding a ", "").replace(" section to your policy", "")
            suggested_text = get_suggested_text(clause)
            if suggested_text != "No suggestion available for this clause.":
                new_policy += f"\n\n=== {clause} ===\n{suggested_text}"
    
    return new_policy

def main(url):
    st.title("DPDP Privacy Policy Compliance Checker")
    
    with st.expander("About this tool", expanded=False):
        st.markdown("""
        This tool checks your website's privacy policy against key requirements of modern Data Protection and Privacy laws.
        
        **How it works:**
        1. Enter your website URL
        2. We'll locate your privacy policy
        3. Our tool will analyze the policy against 10 required and 5 recommended clauses
        4. Get a detailed report of compliance status and recommendations
        """)
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        st.write("")
        st.write("")
        check_button = st.button("Check Compliance", type="primary", use_container_width=True)
    
    if not url and check_button:
        st.warning("Please enter a valid URL to check")
        return
        
    if url and check_button:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if not validators.url(url):
            st.error("Invalid URL format. Please enter a valid website URL.")
            return
        
        with st.spinner("Looking for privacy policy..."):
            # Find privacy policy URL
            policy_url, response = find_privacy_policy_url(url)
            
            if not policy_url:
                st.error("Could not locate privacy policy on this website")
                return
                
            # Get the privacy policy content
            with st.spinner("Analyzing content..."):
                policy_text = get_policy_content(response).lower()
                
                # Check clauses
                results = []
                missing_clauses = []
                passed_checks = 0
                total_checks = len(REQUIRED_CLAUSES)
                
                for clause, regex in REQUIRED_CLAUSES.items():
                    matches = check_clause(policy_text, regex)
                    if matches:
                        status = "Present"
                        passed_checks += 1
                        evidence = matches[0] if matches else "N/A"
                    else:
                        status = "Missing"
                        missing_clauses.append(clause)
                        evidence = "No matches found"
                    
                    results.append({
                        "Clause": clause,
                        "Status": status,
                        "Evidence": evidence
                    })

                # Check recommended clauses
                recommendations = []
                for clause, regex in RECOMMENDED_CLAUSES.items():
                    matches = check_clause(policy_text, regex)
                    if not matches:
                        recommendations.append(f"Consider adding a {clause} section to your policy")

                # Calculate initial compliance score
                initial_score = round((passed_checks / total_checks) * 10, 1) if total_checks > 0 else 0
                
                # Get Gemini's assessment if most clauses are missing (adjust threshold as needed)
                if passed_checks < total_checks * 0.3:  # If less than 30% of clauses found
                    with st.spinner("Getting expert assessment..."):
                        try:
                            assessment_prompt = f"""
                            Based on general knowledge about {url}, provide:
                            1. A 1-10 privacy compliance score considering its likely practices
                            2. A brief (1 sentence) justification
                            3. Whether it needs a full privacy policy (Yes/No)
                            
                            Example response format:
                            7|Wikipedia is known for minimal data collection|No
                            """
                            
                            response = model.generate_content(assessment_prompt)
                            gemini_score, justification, needs_policy = response.text.split("|")
                            gemini_score = float(gemini_score.strip())
                            final_score = max(initial_score, gemini_score)  # Take the higher score
                            
                            st.info(f"🔍 Expert Assessment: {justification.strip()}")
                            if needs_policy.strip().lower() == "no":
                                recommendations.insert(0, "This site may not need a comprehensive privacy policy based on its operations")
                        except Exception as e:
                            st.warning(f"Could not get expert assessment: {e}")
                            final_score = initial_score
                else:
                    final_score = initial_score
                
                # Display results
                st.success(f" Privacy Policy found at: {policy_url}")
                
                # Basic metrics
                metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
                with metrics_col1:
                    st.metric("Final Compliance Score", f"{final_score}/10")
                with metrics_col2:
                    st.metric("Clauses Found", f"{passed_checks}/{total_checks}")
                with metrics_col3:
                    st.metric("Recommendations", len(recommendations))
                
                # Visual representation
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = final_score,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Compliance Score"},
                    gauge = {
                        'axis': {'range': [0, 10]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 3], 'color': "red"},
                            {'range': [3, 7], 'color': "orange"},
                            {'range': [7, 10], 'color': "green"}
                        ],
                        'threshold': {
                            'line': {'color': "black", 'width': 4},
                            'thickness': 0.75,
                            'value': 7
                        }
                    }
                ))
                st.plotly_chart(fig)
                
                # Detailed results
                tabs = st.tabs(["Clause Analysis", "Recommendations", "Export"])
                
                with tabs[0]:
                    for result in results:
                        with st.expander(f"{result['Clause']} ({result['Status']})"):
                            st.write(f"**Status:** {result['Status']}")
                            if result['Status'] == 'Present':
                                st.success(f"Evidence: {result['Evidence']}")
                            else:
                                st.error("No matching clause found")
                                st.write("**Suggested text:**")
                                st.markdown(get_suggested_text(result['Clause']))
                
                with tabs[1]:
                    if recommendations:
                        for rec in recommendations:
                            st.info(rec)
                    else:
                        st.success("No additional recommendations")
                
                with tabs[2]:
                    st.write("Export your compliance report:")
                    report_bytes = generate_report(results, recommendations, policy_url, final_score)
                    st.download_button(
                        label="Download Report (Excel)",
                        data=report_bytes,
                        file_name=f"privacy_report_{time.strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )