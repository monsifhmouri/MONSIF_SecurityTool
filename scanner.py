import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

# ✅ فحص SQL Injection
def scan_sql_injection(url):
    payloads = ["'", '"', " OR 1=1 --", " OR '1'='1"]
    vulnerable = False

    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if "mysql" in response.text.lower() or "sql" in response.text.lower():
            console.print(f"[red]❌ الموقع قد يكون معرضًا لهجوم SQL Injection: {test_url}[/red]")
            vulnerable = True

    if not vulnerable:
        console.print("[green]✔ لا يوجد SQL Injection واضح[/green]")

# ✅ فحص XSS
def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(f"{url}{payload}")
    
    if payload in response.text:
        console.print(f"[red]❌ الموقع معرض لهجوم XSS: {url}[/red]")
    else:
        console.print("[green]✔ لا يوجد XSS واضح[/green]")
