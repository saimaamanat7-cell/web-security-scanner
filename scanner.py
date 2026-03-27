import requests
import time
import urllib3
import os
from urllib.parse import quote_plus, urlparse, parse_qs
from bs4 import BeautifulSoup
import html
import sys
from datetime import datetime

# 🔒 Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 🔧 Global headers to mimic a real browser
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# 📁 Files
RESULT_FILE = os.path.join(os.path.dirname(__file__), "results.txt")
HTML_FILE = os.path.join(os.path.dirname(__file__), "report.html")

# ⏱ Configurable SQLi time threshold
TIME_THRESHOLD = 4  # seconds

# 📝 Logging
def log(msg):
    print(msg)
    with open(RESULT_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def html_write(lines):
    with open(HTML_FILE, "a", encoding="utf-8") as f:
        f.write(lines + "\n")

# 🔐 HTTPS check
def check_https(url):
    log("\n🔐 HTTPS Check:")
    html_write("<h3>🔐 HTTPS Check</h3>")
    if url.startswith("https://"):
        try:
            requests.get(url, timeout=10, verify=False, headers=HEADERS)
            log("✅ HTTPS is enabled and working")
            html_write("<p style='color:green'>✅ HTTPS is enabled and working</p>")
        except:
            log("⚠️ HTTPS enabled but issue detected")
            html_write("<p style='color:orange'>⚠️ HTTPS enabled but issue detected</p>")
    else:
        log("❌ Website is NOT using HTTPS")
        html_write("<p style='color:red'>❌ Website is NOT using HTTPS</p>")

# 🌐 Status check
def check_status(url):
    log("\n🌐 Status Check:")
    html_write("<h3>🌐 Status Check</h3>")
    try:
        start = time.time()
        r = requests.get(url, timeout=15, verify=False, headers=HEADERS)
        end = time.time()
        log(f"✅ Website reachable (Status Code: {r.status_code})")
        log(f"⏱ Response Time: {end-start:.2f}s")
        html_write(f"<p style='color:green'>✅ Website reachable (Status Code: {r.status_code})</p>")
        html_write(f"<p>⏱ Response Time: {end-start:.2f}s</p>")
        return r.text
    except Exception as e:
        log(f"❌ Cannot reach site: {e}")
        html_write(f"<p style='color:red'>❌ Cannot reach site: {e}</p>")
        return None

# 🔍 Security headers
def check_headers(url):
    log("\n🔍 Security Headers Check:")
    html_write("<h3>🔍 Security Headers Check</h3>")
    try:
        r = requests.get(url, timeout=15, verify=False, headers=HEADERS)
    except Exception as e:
        log(f"❌ Error fetching headers: {e}")
        html_write(f"<p style='color:red'>❌ Error fetching headers: {e}</p>")
        return

    headers = r.headers
    security_headers = {
        "Content-Security-Policy": "Prevents XSS attacks",
        "X-Frame-Options": "Prevents clickjacking",
        "X-Content-Type-Options": "Stops MIME sniffing",
        "Strict-Transport-Security": "Forces HTTPS (HSTS)"
    }

    for h, desc in security_headers.items():
        if h in headers:
            value = headers[h]
            log(f"✅ {h} found → {value}")
            html_write(f"<p style='color:green'>✅ {h}: {value}</p>")
        else:
            log(f"⚠️ {h} missing ({desc})")
            html_write(f"<p style='color:orange'>⚠️ {h} missing ({desc})</p>")

# 🔎 Extract parameters dynamically from URL + forms
def get_parameters(url, html_text):
    params = set()
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for key in query_params.keys():
        params.add(key)
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        for inp in form.find_all("input"):
            name = inp.get("name")
            type_attr = inp.get("type","text").lower()
            if name and type_attr not in ["password","submit","hidden","button"]:
                params.add(name)
    return list(params)

# 🧪 Advanced XSS testing
def check_xss(url, params):
    log("\n🧪 Advanced XSS Test:")
    html_write("<h3>🧪 Advanced XSS Test</h3>")

    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]

    found = False

    for param in params:
        for payload in payloads:
            test_url = f"{url}?{param}={quote_plus(payload)}"
            try:
                r = requests.get(test_url, timeout=10, verify=False, headers=HEADERS)
                response_text = html.unescape(r.text)
                if payload in response_text:
                    log(f"⚠️ XSS detected → Param: {param} | Payload: {payload}")
                    html_write(f"<p style='color:red'>⚠️ XSS detected → Param: {param} | Payload: {payload}</p>")
                    found = True
            except:
                continue

    if not found:
        log("✅ No XSS detected")
        html_write("<p style='color:green'>✅ No XSS detected</p>")

# 🧪 Advanced SQL Injection testing
def check_sqli(url, params):
    log("\n🧪 Advanced SQLi Test:")
    html_write("<h3>🧪 Advanced SQL Injection Test</h3>")

    payloads = [
        "'", '"', "' OR '1'='1", '" OR "1"="1',
        "'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--"
    ]

    found = False
    for param in params:
        for payload in payloads:
            test_url = f"{url}?{param}={quote_plus(payload)}"
            try:
                start = time.time()
                r = requests.get(test_url, timeout=10, verify=False, headers=HEADERS)
                end = time.time()
                errors = ["syntax error","mysql","sqlite","sqlstate","unclosed quotation"]
                for err in errors:
                    if err.lower() in r.text.lower():
                        log(f"⚠️ SQLi detected → Param: {param} | Payload: {payload}")
                        html_write(f"<p style='color:red'>⚠️ SQLi detected → Param: {param} | Payload: {payload}</p>")
                        found = True
                if ("WAITFOR" in payload or "SLEEP" in payload) and (end-start > TIME_THRESHOLD):
                    log(f"⚠️ Possible time-based SQLi → Param: {param} | Payload: {payload}")
                    html_write(f"<p style='color:red'>⚠️ Possible time-based SQLi → Param: {param} | Payload: {payload}</p>")
                    found = True
            except:
                continue

    if not found:
        log("✅ No SQL Injection detected")
        html_write("<p style='color:green'>✅ No SQL Injection detected</p>")

# 🌐 Scan a site
def scan_site(url):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_write(f"<h2>🌐 SCANNING: {url}</h2>")
    html_write(f"<p>🕒 Time: {now}</p><hr>")

    check_https(url)
    html_text = check_status(url)
    if html_text:
        check_headers(url)
        params = get_parameters(url, html_text)
        if not params:
            log("⚠️ No parameters found — using default common params")
            params = ["q","search","id","test","user","page"]
        check_xss(url, params)
        check_sqli(url, params)
    else:
        log("❌ Site unreachable — skipping XSS & SQLi")
        html_write("<p style='color:red'>❌ Site unreachable — skipping XSS & SQLi</p>")

    log("\n✅ Scan Completed!\n")
    html_write("<hr><br>")

# 🏁 Main
def main():
    # Clear old files
    open(RESULT_FILE,"w",encoding="utf-8").close()
    open(HTML_FILE,"w",encoding="utf-8").write("<html><body><h1>Web Security Scan Report</h1>")

    if len(sys.argv) != 2:
        log("Usage: python scanner.py http://example.com")
        return
    url = sys.argv[1]
    scan_site(url)

    html_write("</body></html>")
    log("✅ Scan Completed! HTML report generated at report.html")

if __name__ == "__main__":
    main()