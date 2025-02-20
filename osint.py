import shodan
import json
from rich.console import Console

console = Console()

# قراءة API Key من config.json
def get_shodan_api_key():
    try:
        with open("config.json", "r") as file:
            config = json.load(file)
            return config.get("shodan_api", "")
    except FileNotFoundError:
        console.print("[red]⚠ ملف config.json غير موجود![/red]")
        return ""

def shodan_scan(target):
    api_key = get_shodan_api_key()
    if not api_key:
        console.print("[red]⚠ لا يوجد مفتاح Shodan API![/red]")
        return

    api = shodan.Shodan(api_key)

    try:
        result = api.host(target)
        console.print(f"[bold yellow]🔍 معلومات حول {target}:[/bold yellow]")
        console.print(json.dumps(result, indent=4))
    except shodan.APIError as e:
        console.print(f"[red]⚠ خطأ أثناء البحث في Shodan: {e}[/red]")
