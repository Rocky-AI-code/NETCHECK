import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.text import Text
import pyfiglet
import os
import signal
import sys
import socket

# Clear terminal (cross-platform)
os.system("cls" if os.name == "nt" else "clear")
console = Console()

# Banner
console.print(pyfiglet.figlet_format("Net\nCheck"), style="bold green")


def ascii_panel(title: str, body: str):
    panel = Panel(body, title=title, border_style="green", box=box.ASCII)
    console.print(panel)


def get_hostname(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return f"[bold green]{host}[/bold green]"
    except socket.herror:
        return "[bold red]Unknown Hostname[/bold red]"


def handle_interrupt(sig, frame):
    ascii_panel("SCAN CANCELLED", "User interrupted the scan with Ctrl+C.\nULTRON-X Terminated.")
    sys.exit(0)


signal.signal(signal.SIGINT, handle_interrupt)


def scan_network(subnet="192.168.1.0/24"):
    ascii_panel("NetCheck", f"Target Subnet: {subnet}\nStatus: Scanning active devices...")

    try:
        ping_output = subprocess.check_output(["nmap", "-sn", subnet], text=True)
    except FileNotFoundError:
        ascii_panel("ERROR", "nmap is not installed or not found in PATH.")
        return
    except Exception as e:
        ascii_panel("ERROR", f"Failed to run nmap:\n{e}")
        return

    ip_list = re.findall(r"Nmap scan report for ([\d.]+)", ping_output)

    if not ip_list:
        ascii_panel("Scan Result", "No active devices found.")
        return

    ascii_panel("Scan Results", f"Devices Online: [bold yellow]{len(ip_list)}[/bold yellow]\nScanning ports and services...")

    for ip in ip_list:
        console.print(f"\n[bold cyan]> Scanning IP: {ip}[/bold cyan]")
        host = get_hostname(ip)
        console.print(f"[bold magenta]  Hostname:[/bold magenta] {host}")

        try:
            result = subprocess.check_output(["nmap", "-sV", ip], text=True)
            cleaned = "\n".join(line for line in result.splitlines() if line.strip())
            ascii_panel(f"{ip}", cleaned)
        except subprocess.CalledProcessError:
            ascii_panel("ERROR", f"Failed to scan {ip}")

    ascii_panel("SCAN COMPLETE", "All devices have been scanned.\nULTRON-X Signing Off.")


if __name__ == "__main__":
    scan_network("192.168.1.0/24")