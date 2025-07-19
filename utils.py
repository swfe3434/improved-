import requests
import hmac
import hashlib
import time
from time import sleep
from random import uniform
from rich.console import Console

console = Console()

def handle_rate_limiting(response, max_retries=5, max_wait_time=300):
    """Handle rate limiting with exponential backoff."""
    retries = 0
    total_wait_time = 0
    while response.status_code in (429, 403) and retries < max_retries and (total_wait_time < max_wait_time):
        wait_time = min(uniform(20, 40) * 2 ** retries, max_wait_time - total_wait_time)
        console.print(f"[yellow]Rate limited or forbidden. Retrying in {wait_time:.2f} seconds... (Attempt {retries + 1}/{max_retries})[/yellow]")
        sleep(wait_time)
        total_wait_time += wait_time
        response = requests.request(response.request.method, response.url, headers=response.request.headers, data=response.request.body)
        retries += 1
    if response.status_code in (429, 403):
        console.print("[red]Failed to bypass rate limit after multiple attempts.[/red]")
    return response

def generate_encrypted_password(password):
    """Generate the encrypted password string for the login request."""
    timestamp = str(int(time.time()))
    return f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{password}"

def generate_hmac_signature(data, secret_key):
    """Generate the HMAC signature for the given data."""
    sorted_data = "&".join([f"{k}={v}" for k, v in sorted(data.items())])
    hmac_signature = hmac.new(secret_key.encode("utf-8"), sorted_data.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{hmac_signature}.{sorted_data}"
