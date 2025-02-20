import bcrypt
import getpass
from rich.console import Console

console = Console()

# استخدم كلمة مرور قوية هنا
PASSWORD_HASH = bcrypt.hashpw(b"ur password", bcrypt.gensalt())

def verify_password():
    password = getpass.getpass("[bold cyan]أدخل كلمة المرور: [/bold cyan]").encode('utf-8')
    if bcrypt.checkpw(password, PASSWORD_HASH):
        console.print("[green]✔ تم التحقق من كلمة المرور![/green]")
        return True
    else:
        console.print("[red]❌ كلمة المرور خاطئة![/red]")
        return False
