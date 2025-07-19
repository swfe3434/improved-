import sys
import platform
import ctypes
from cryptography.fernet import Fernet
import json
import logging
from time import sleep
from random import uniform, choice, choices
import requests
import os
import re
import uuid
import time
import hashlib
import datetime
import hmac
from rich.console import Console
from rich.text import Text
from functools import wraps

# Constants
ENCRYPTION_KEY_URL = "https://firebasestorage.googleapis.com/v0/b/rehan-says.appspot.com/o/to.json?alt=media&token=4318a4d3-1d59-4359-b1ae-8c68c9918a12"
LOG_FILE = "report_bot.log"
SESSION_FILE = "session.json"
PASSWORD_PROMPT = "[bold green]Enter the password to continue: [/bold green]"
INVALID_PASSWORD_MSG = "[bold red]Invalid password. Access denied.[/bold red]"
PASSWORD_CORRECT_MSG = "[bold green]Password correct. Access granted.[/bold green]"
APP_EXPIRED_MSG = "[bold red]This application has expired. Please contact the developer for a new version.[/bold red]"
BATTLE_ARC_MODE_MSG = "[bold magenta]Battle Arc Mode (gand fad mode)[/bold magenta]"
NOTI_CLAIMING_MODE_MSG = "[bold magenta]Noti Claiming Mode (singles report)[/bold magenta]"
REPORT_OPTIONS = [
    "1 - Spam",
    "2 - Nudity",
    "3 - Hate Speech",
    "4. - Bullying",
    "5. - Self-harm",
    "6. - Violence",
    "7. - Illegal Goods",
    "8. - Intellectual Property",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
]
API_URLS = [
    "https://i.instagram.com/api/v1/users/web_profile_info/",
    "https://www.instagram.com/{username}/?__a=1&__d=dis",
]
CSRF_FETCH_URLS = [
    "https://i.instagram.com/api/v1/si/fetch_headers/?challenge_type=signup&guid={}",
    "https://i.instagram.com/api/v1/accounts/login/",
    "https://i.instagram.com/api/v1/accounts/two_factor_login/",
]

# Initialize rich console
console = Console(record=True)

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def exit_process(message=None, exit_code=0):
    """Exit the process with a given message and exit code."""
    if message:
        print(message)
    system = platform.system()
    if system == "Windows":
        ctypes.windll.kernel32.ExitProcess(exit_code)
    elif system in ["Linux", "Darwin"]:
        libc = ctypes.CDLL("libc.so.6")
        libc.exit(exit_code)
    else:
        sys.exit(exit_code)

def retry_on_failure(max_retries=3):
    """Decorator to retry a function on connection errors or timeouts."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_retries:
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.ConnectionError as e:
                    console.print(f"[red]Connection error: {e}. Retrying...[/red]")
                    logging.error(f"Connection error in {func.__name__}: {e}")
                    attempts += 1
                    sleep(uniform(5, 10))
                except requests.exceptions.Timeout as e:
                    console.print(f"[red]Request timed out: {e}. Retrying...[/red]")
                    logging.error(f"Timeout in {func.__name__}: {e}")
                    attempts += 1
                    sleep(uniform(5, 10))
                except Exception as e:
                    console.print(f"[red]Unexpected error in {func.__name__}: {e}[/red]")
                    logging.error(f"Unexpected error in {func.__name__}: {e}")
                    raise
            console.print(f"[red]Max attempts reached in {func.__name__}.[/red]")
            logging.error(f"Max attempts reached in {func.__name__}")
            raise Exception(f"Failed after {max_retries} attempts")
        return wrapper
    return decorator


@retry_on_failure(max_retries=3)
def get_encrypted_config(url):
    """Fetch and decrypt the remote configuration."""
    response = requests.get(url)
    if response.status_code == 200:
        encrypted_data = response.text.strip().encode()
        fernet = Fernet(ENCRYPTION_KEY.encode())
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        config = {}
        for line in decrypted_data.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
        return config
    else:
        console.print(f"[red]Failed to fetch encrypted config. Status code: {response.status_code}[/red]")
        exit_process()

def sha256_hash(text):
    """Return the SHA256 hash of a given text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def verify_password():
    """Prompt for and verify the password."""
    password = console.input(PASSWORD_PROMPT).strip()
    hashed_password = sha256_hash(password)
    expected_hash = sha256_hash(CONFIG["PASSWORD"])
    if hashed_password != expected_hash:
        console.print(INVALID_PASSWORD_MSG)
        logging.error("Invalid password entered.")
        exit_process()
    console.print(PASSWORD_CORRECT_MSG)
    logging.info("Password verified successfully.")
    return True

def check_app_expiry():
    """Check if the application has expired."""
    if datetime.datetime.now() > EXPIRY_DATE:
        console.print(APP_EXPIRED_MSG)
        logging.error("Application has expired.")
        exit_process()

def simulate_human_behavior():
    """Wait for a random duration to simulate human behavior."""
    delay = uniform(1.0, 3.0)
    console.print(f"[yellow]WAIT {delay:.2f} seconds...[/yellow]")
    logging.info(f"Simulating human behavior with {delay:.2f} seconds delay")
    sleep(delay)

def display_banner():
    """Display the application banner."""
    os.system("cls" if os.name == "nt" else "clear")
    console.print(
        "\n[cyan]============================================================[/cyan]\n"
        "                     [red]The REPORT BOT[/red]\n"
        "                                by [magenta]@OgRehan[/magenta]\n"
        " Developer : [cyan]@tipsandgamer[/cyan]\n"
        "[cyan]============================================================[/cyan]\n"
    )
    logging.info("Application started.")

from instagram_api import InstagramAPI
from utils import handle_rate_limiting, generate_encrypted_password, generate_hmac_signature

def handle_two_factor_auth(username, password, device_id, retries=3):
    """Handle two-factor authentication."""
    console.print("[bold yellow]Two-factor authentication required. Please enter the OTP from your authenticator app.[/bold yellow]")
    logging.info("Two-factor authentication required for login.")
    csrf_token, session = fetch_csrf_token()
    attempts = 0
    while attempts < retries:
        otp = console.input(f"[green]Enter the OTP sent to your phone/email (Attempt {attempts + 1}/{retries}): [/green]").strip()
        if not otp:
            console.print("[red]Invalid OTP. Please try again.[/red]")
            logging.error("Invalid OTP entered.")
            attempts += 1
            continue
        try:
            data = {"username": username, "verification_code": otp, "device_id": device_id, "csrf_token": csrf_token}
            signature = generate_hmac_signature(data)
            response = session.post("https://i.instagram.com/api/v1/accounts/two_factor_login/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9", "X-CSRFToken": csrf_token}, data=signature, allow_redirects=True)
            response = handle_rate_limiting(response)
            logging.info(f"2FA response: Status {response.status_code}, Headers: {dict(response.headers)}, Body: {response.text[:200]}, Cookies: {dict(response.cookies)}")
            if "authenticated" in response.text:
                console.print("[green]2FA login successful.[/green]")
                logging.info(f"2FA login successful for {username}")
                if "sessionid" not in response.cookies or "csrftoken" not in response.cookies:
                    console.print("[red]Missing sessionid or csrftoken in 2FA response cookies.[/red]")
                    logging.error(f"Missing sessionid or csrftoken in 2FA response cookies: {dict(response.cookies)}")
                    attempts += 1
                    continue
                save_session(response.cookies["sessionid"], response.cookies["csrftoken"])
                return response
            else:
                try:
                    json_response = response.json()
                    message = json_response.get("message", "Unknown error")
                    error_type = json_response.get("error_type", "Unknown")
                    full_response = json.dumps(json_response, indent=2)
                except ValueError:
                    message = response.text[:200]
                    error_type = "Unknown"
                    full_response = response.text[:200]
                console.print(f"[red]2FA login failed: {message} (Error Type: {error_type}, Status: {response.status_code})[/red]")
                console.print(f"[red]Full response: {full_response}[/red]")
                logging.error(f"2FA login failed for {username}: {message} (Error Type: {error_type}, Status: {response.status_code}, Response: {full_response}, Headers: {dict(response.headers)})")
                attempts += 1
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error during 2FA login: {e}[/red]")
            logging.error(f"Network error during 2FA login: {e}")
            attempts += 1
            sleep(uniform(20, 40))
    console.print("[red]Failed to complete 2FA login after multiple attempts. Exiting.[/red]")
    logging.error("Failed to complete 2FA login after multiple attempts.")
    exit_process()

def load_session(session_file=SESSION_FILE):
    """Load session from a file."""
    try:
        if os.path.exists(session_file) and os.path.getsize(session_file) > 0:
            with open(session_file, "r") as f:
                session = json.load(f)
                if validate_session(session["sessionid"], session["csrftoken"]):
                    console.print("[green]Session loaded and validated successfully.[/green]")
                    logging.info("Session loaded and validated successfully.")
                    return (session["sessionid"], session["csrftoken"])
                else:
                    console.print("[bold yellow]Session validation failed. Please log in again.[/bold yellow]")
                    logging.info("Invalid session file found.")
        else:
            console.print("[bold yellow]No valid session file found. Please log in.[/bold yellow]")
            logging.info("No session file found, or file is empty.")
    except json.JSONDecodeError:
        console.print("[bold red]Error decoding session file. Please log in again.[/bold red]")
        logging.error("Error decoding session file.")
        if os.path.exists(session_file):
            os.remove(session_file)
            logging.info("Removed corrupted session file.")
    except Exception as e:
        console.print(f"[red]Error loading session: {e}[/red]")
        logging.error(f"Error loading session: {e}")
    return (None, None)

def save_session(session_id, csrf_token, session_file=SESSION_FILE):
    """Save session to a file."""
    try:
        with open(session_file, "w") as f:
            json.dump({"sessionid": session_id, "csrftoken": csrf_token}, f, indent=2)
        console.print("[green]Session saved successfully.[/green]")
        logging.info("Session saved successfully.")
    except Exception as e:
        console.print(f"[red]Error saving session: {e}[/red]")
        logging.error(f"Error saving session: {e}")

import argparse

@retry_on_failure(max_retries=3)
def main_menu():
    """Display the main menu and handle user input."""
    parser = argparse.ArgumentParser(description="Instagram Report Bot")
    parser.add_argument("-u", "--username", help="Instagram username")
    parser.add_argument("-p", "--password", help="Instagram password")
    parser.add_argument("-s", "--secret", help="Secret key")
    parser.add_argument("-m", "--mode", choices=["battle", "noti"], help="Reporting mode")
    parser.add_argument("-t", "--targets", nargs="+", help="Target usernames")
    parser.add_argument("-r", "--reason", type=int, choices=range(1, 9), help="Report reason (1-8)")
    parser.add_argument("-n", "--num-reports", type=int, help="Number of reports to send in battle mode")

    args = parser.parse_args()

    console.print(Text("Welcome to the Report Bot!", style="bold blue"))
    console.print("[bold yellow]Disclaimer: This script is for educational purposes only. The developers are not responsible for any misuse of this script. Use at your own risk.[/bold yellow]")

    secret_key = args.secret or console.input("[bold green]Enter the secret key: [/bold green]").strip()
    if not secret_key:
        console.print("[red]Secret key cannot be empty.[/red]", style="bold red")
        logging.error("Empty secret key entered.")
        exit_process()

    verify_password()
    check_app_expiry()

    username = args.username or console.input("[bold green]Enter your Instagram username: [/bold green]").strip()
    if not username:
        console.print("[red]Username cannot be empty.[/red]", style="bold red")
        exit_process()

    password = args.password or console.input("[bold green]Enter your Instagram password: [/bold green]").strip()
    if not password:
        console.print("[red]Password cannot be empty.[/red]", style="bold red")
        exit_process()

    api = InstagramAPI(username, password, secret_key)
    if not api.login():
        console.print("[red]Login failed. Exiting.[/red]")
        exit_process()

    mode = args.mode or console.input(f"[cyan]Select Mode: \n1 - Battle Arc Mode (battle)\n2 - Noti Claiming Mode (noti)\nEnter your choice: [/cyan]").strip()
    if mode == "battle":
        battle_arc_mode(api, args.targets, args.reason, args.num_reports)
    elif mode == "noti":
        noti_claiming_mode(api, args.targets, args.reason)
    else:
        console.print("[red]Invalid choice. Exiting.[/red]")
        logging.error("Invalid mode selected.")
        exit_process()

def noti_claiming_mode(api, targets, reason):
    """
    Handles the 'Noti Claiming Mode'.

    In this mode, the script reports a list of target users for a specific reason.
    The user can provide the targets and reason as command-line arguments or will be prompted for them.
    """
    console.print(Text("Noti Claiming Mode - Singles Report", style="bold blue"))
    logging.info("Noti Claiming Mode started.")
    if not targets:
        try:
            num_targets = int(console.input("[yellow]How many targets do you want to report? (kitne dushman hai?) : [/yellow]").strip())
            if num_targets <= 0:
                console.print("[red]Please enter a number greater than zero.[/red]")
                logging.error("Invalid number of targets entered.")
                return
            targets = []
            for i in range(num_targets):
                target_username = console.input(f"[cyan]Enter username of target {i + 1}: [/cyan]").strip()
                if target_username:
                    targets.append(target_username)
                else:
                    console.print("[yellow]Username cannot be empty. Skipping this target.[/yellow]")
                    logging.warning(f"Empty username for target {i + 1}")
        except ValueError:
            console.print("[red]Invalid input. Please enter a valid number.[/red]")
            logging.error("Invalid input for number of targets.")
            return

    if not reason:
        console.print("[bold blue]Select Report Reason:[/bold blue]")
        for option in REPORT_OPTIONS:
            console.print(f"[yellow]{option}[/yellow]")
        while True:
            try:
                reason = int(console.input("[blue]Choose Report Type (1-8): [/blue]").strip())
                if 1 <= reason <= 8:
                    break
                else:
                    console.print("[red]Invalid choice. Please choose a number between 1 and 8.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a number.[/red]")

    for target in targets:
        try:
            console.print(f"[cyan]Fetching ID for {target}...[/cyan]")
            user_id = api.get_user_id(target)
            console.print(f"[green]Target ID for {target}: {user_id}[/green]")
            if not api.report_user(user_id, reason):
                console.print(f"[red]Failed to report {target}.[/red]")
                logging.error(f"Failed to report {target}")
        except Exception as e:
            console.print(f"[red]Error reporting {target}: {e}[/red]")
            logging.error(f"Error reporting {target}: {e}")
    console.print("[green]All reports have been submitted. Thank you for your service.[/green]")
    logging.info("All reports submitted in Noti Claiming Mode.")

def battle_arc_mode(api, targets, reason, num_reports):
    """
    Handles the 'Battle Arc Mode'.

    In this mode, the script reports a single target user multiple times for a specific reason.
    The user can provide the target, reason, and number of reports as command-line arguments or will be prompted for them.
    """
    console.print(Text("Battle Arc Mode - Mass Report", style="bold blue"))
    logging.info("Battle Arc Mode started.")

    if not targets:
        target_username = console.input("[bold green]Enter the target username: [/bold green]").strip()
        if not target_username:
            console.print("[red]Username cannot be empty. Please try again.[/red]")
            return
        targets = [target_username]

    if not reason:
        console.print("[bold blue]Select Report Reason:[/bold blue]")
        for option in REPORT_OPTIONS:
            console.print(f"[yellow]{option}[/yellow]")
        while True:
            try:
                reason = int(console.input("[blue]Choose Report Type (1-8): [/blue]").strip())
                if 1 <= reason <= 8:
                    break
                else:
                    console.print("[red]Invalid choice. Please choose a number between 1 and 8.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a number.[/red]")

    if not num_reports:
        while True:
            try:
                num_reports = int(console.input("[bold yellow]Enter the number of reports to send: [/bold yellow]").strip())
                if num_reports > 0:
                    break
                else:
                    console.print("[red]Please enter a number greater than zero.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a valid number.[/red]")

    for target_username in targets:
        try:
            user_id = api.get_user_id(target_username)
            console.print(f"[yellow]Target ID for {target_username}: {user_id}[/yellow]")
            success_count = 0
            for i in range(num_reports):
                try:
                    if api.report_user(user_id, reason):
                        console.print(f"[green]Report {i + 1} successfully sent.[/green]")
                        success_count += 1
                    else:
                        console.print(f"[red]Report {i + 1} failed.[/red]")
                        logging.error(f"Report {i + 1} failed for {user_id}")
                        break
                except Exception as e:
                    console.print(f"[red]Error sending report {i + 1} for {user_id}: {e}[/red]")
                    logging.error(f"Error sending report {i + 1} for {user_id}: {e}")
                    break
                sleep(uniform(20, 40))
            console.print(f"[green]All reports have been submitted. Successfully sent {success_count}/{num_reports} reports.[/green]")
            logging.info(f"Completed reporting for {user_id}: {success_count}/{num_reports} reports successful")
        except ValueError as error:
            console.print(f"[red]Error: {error}[/red]")
            logging.error(f"Error in Battle Arc Mode: {error}")
            continue
        except Exception as e:
            console.print(f"[red]Unexpected error in Battle Arc Mode: {e}[/red]")
            logging.error(f"Unexpected error in Battle Arc Mode: {e}")
            continue

if __name__ == "__main__":
    display_banner()
    CONFIG = get_encrypted_config(ENCRYPTION_KEY_URL)
    ENCRYPTION_KEY = CONFIG.get("ENCRYPTION_KEY")
    EXPIRY_DATE = datetime.datetime.strptime(CONFIG.get("EXPIRY_DATE"), "%Y-%m-%d")
    main_menu()
    console.print("[bold blue]Script finished.[/bold blue]")
    logging.info("Script finished.")
