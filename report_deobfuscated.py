import sys
import platform
import ctypes
from cryptography.fernet import Fernet, InvalidToken # Ensure InvalidToken is imported
import json
import logging
from time import sleep
from random import uniform, choice # Uniform and choice are from random, not time
import requests # Ensure requests is imported directly
import os
import re
import uuid
import time
import hashlib
import datetime # Ensure datetime is imported directly
import hmac
from functools import wraps
import argparse # Needed for command-line arguments

# --- Direct Rich Console Imports (ALWAYS UNCONDITIONAL AND AT TOP) ---
from rich.console import Console
from rich.text import Text

# --- instagrapi specific imports and exceptions ---
from instagrapi import Client
from instagrapi.exceptions import BadPassword, LoginRequired, ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, ClientError

# --- Custom API client and utilities (assuming these files are in the same directory) ---
from instagram_api import InstagramAPI

# --- Constants ---
LOG_FILE = "report_bot.log"
# SESSION_FILE is managed by instagrapi internally now, no longer a global here for manual saving
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
    "4. - Bullying", # Note: these have periods in the middle
    "5. - Self-harm",
    "6. - Violence",
    "7. - Illegal Goods",
    "8. - Intellectual Property",
]
USER_AGENTS = [ # Used for non-instagrapi fallback requests
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
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

# Initialize rich console (this line is now safe because Console is imported unconditionally)
console = Console(record=True)

# Set up logging globally (temporarily set to DEBUG to see full details)
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")


# --- Utility Functions ---

def exit_process(message=None, exit_code=0):
    """Exit the process with a given message and exit code."""
    if message:
        console.print(message)
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


# The problematic get_local_config function has been removed.
# Its logic is now integrated directly into main_menu's config loading.

def sha256_hash(text):
    """Return the SHA256 hash of a given text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def verify_password_from_config(password_from_config_file, entered_password):
    """Verify the bot's local access password."""
    hashed_entered_password = sha256_hash(entered_password) # Hash the user's input
    # Assuming password_from_config_file is the plaintext password like "drsudo"
    expected_password_hash = sha256_hash(password_from_config_file)

    if hashed_entered_password != expected_password_hash:
        console.print(INVALID_PASSWORD_MSG)
        logging.error("Invalid password entered for bot access.")
        exit_process()
    console.print(PASSWORD_CORRECT_MSG)
    logging.info("Password verified successfully for bot access.")
    return True

def check_app_expiry_from_config(expiry_date_from_config_file):
    """Check if the application has expired."""
    if datetime.datetime.now() > expiry_date_from_config_file:
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

# --- Core Bot Logic Functions (These use InstagramAPI class from instagram_api.py) ---

@retry_on_failure(max_retries=3)
def noti_claiming_mode(api, targets, reason):
    """
    Handles the 'Noti Claiming Mode'.
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
            user_id = api.get_user_id(target) # Use InstagramAPI's get_user_id
            console.print(f"[green]Target ID for {target}: {user_id}[/green]")

            if api.report_user(user_id, reason): # Use InstagramAPI's report_user
                console.print(f"[green]Report successfully sent for {target}.[/green]")
                logging.info(f"Report sent successfully for {target}")
            else:
                console.print(f"[red]Failed to report {target}.[/red]")
                logging.error(f"Failed to report {target}")
        except Exception as e:
            console.print(f"[red]Error reporting {target}: {e}[/red]")
            logging.error(f"Error reporting {target}: {e}")
    console.print("[green]All reports have been submitted. Thank you for your service.[/green]")
    logging.info("All reports submitted in Noti Claiming Mode.")

@retry_on_failure(max_retries=3)
def battle_arc_mode(api, targets, reason, num_reports):
    """
    Handles the 'Battle Arc Mode'.
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

@retry_on_failure(max_retries=3)
def main_menu():
    """Display the main menu and handle user input."""
    parser = argparse.ArgumentParser(description="Instagram Report Bot")
    parser.add_argument("-u", "--username", help="Your Instagram username.")
    parser.add_argument("-p", "--password", help="Your Instagram password.")
    parser.add_argument("-s", "--secret", help="The secret key for the script (bot's access password).")
    parser.add_argument("-m", "--mode", choices=["battle", "noti"], help="The reporting mode ('battle' or 'noti').")
    parser.add_argument("-t", "--targets", nargs="+", help="Space-separated target usernames.")
    parser.add_argument("-r", "--reason", type=int, choices=range(1, 9), help="The report reason (a number from 1 to 8).")
    parser.add_argument("-n", "--num-reports", type=int, help="The number of reports to send in 'Battle Arc Mode'.")

    args = parser.parse_args()

    # --- Local Config Loading Logic ---
    CONFIG = {} # Initialize CONFIG here
    try:
        # Load the *actual* secret key from the file
        with open("secret.key", "rb") as key_file:
            encryption_key = key_file.read()
        fernet = Fernet(encryption_key) # Initialize Fernet with the *actual* key

        # Load and decrypt the encrypted config file
        with open("config.json.encrypted", "rb") as f:
            encrypted_config_data = f.read()

        decrypted_config_bytes = fernet.decrypt(encrypted_config_data)
        CONFIG = json.loads(decrypted_config_bytes.decode('utf-8'))
        console.print("[green]Local configuration loaded and decrypted successfully.[/green]")
        logging.info("Local configuration loaded and decrypted successfully.")
    except InvalidToken:
        console.print("[red]Error: Invalid encryption key or corrupted encrypted config file.[/red]")
        logging.error("Invalid encryption key or corrupted encrypted config file.")
        console.print("[yellow]Ensure your 'secret.key' matches the key used to encrypt 'config.json'. You might need to regenerate both and re-encrypt.[/yellow]")
        exit_process(exit_code=1)
    except FileNotFoundError as e:
        console.print(f"[red]Error: Configuration file missing ({e}).[/red]")
        console.print("[yellow]Please ensure you have `config.json`, `secret.key`, and `config.json.encrypted` in the correct directory.[/yellow]")
        exit_process(exit_code=1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Decrypted config is not valid JSON. File might be corrupted ({e}).[/red]")
        logging.error(f"Decrypted config is not valid JSON: {e}")
        exit_process(exit_code=1)
    except Exception as e:
        console.print(f"[red]An unexpected error occurred during config loading: {e}[/red]")
        logging.error(f"Error loading or decrypting local config: {e}")
        exit_process(exit_code=1)

    # Global variables from config (set them *after* CONFIG is loaded)
    global BOT_ACCESS_PASSWORD_FROM_CONFIG, EXPIRY_DATE, INSTAGRAM_HMAC_SECRET
    BOT_ACCESS_PASSWORD_FROM_CONFIG = CONFIG.get("KEY")
    try:
        EXPIRY_DATE = datetime.datetime.strptime(CONFIG.get("EXPIRY_DATE"), "%Y-%m-%d")
    except (ValueError, TypeError):
        console.print('[red]Error: Invalid EXPIRY_DATE format in config.json. Use YYYY-MM-DD. Exiting.[/red]')
        logging.error('Configuration error: Invalid EXPIRY_DATE format.')
        exit_process(exit_code=1)
    INSTAGRAM_HMAC_SECRET = CONFIG.get("INSTAGRAM_HMAC_SECRET")

    if not BOT_ACCESS_PASSWORD_FROM_CONFIG or not INSTAGRAM_HMAC_SECRET:
        console.print("[red]Error: Missing 'KEY' or 'INSTAGRAM_HMAC_SECRET' in config.json. Exiting.[/red]")
        logging.error("Missing critical configuration values in config.json.")
        exit_process(exit_code=1)


    console.print(Text("Welcome to the Report Bot!", style="bold blue"))
    console.print("[bold yellow]Disclaimer: This script is for educational purposes only. The developers are not responsible for any misuse of this script. Use at your own risk.[/bold yellow]")

    # Verify bot access password and app expiry
    if args.secret:
        entered_password = args.secret
    else:
        entered_password = console.input(PASSWORD_PROMPT).strip()
    verify_password_from_config(BOT_ACCESS_PASSWORD_FROM_CONFIG, entered_password)
    check_app_expiry_from_config(EXPIRY_DATE)

    username = args.username or console.input("[bold green]Enter your Instagram username: [/bold green]").strip()
    if not username:
        console.print("[red]Username cannot be empty.[/red]", style="bold red")
        logging.error("Empty username entered.")
        exit_process()

    password = args.password or console.input("[bold green]Enter your Instagram password: [/bold green]").strip()
    if not password:
        console.print("[red]Password cannot be empty.[/red]", style="bold red")
        logging.error("Empty password entered.")
        exit_process()

    simulate_human_behavior()

    # Initialize the InstagramAPI client with instagrapi integration
    api_client = InstagramAPI(username, password, INSTAGRAM_HMAC_SECRET) # Pass secret key for internal HMAC

    # Perform login (instagrapi handles all complexities)
    if not api_client.login(): # This call now uses instagrapi.Client().login() internally
        console.print("[red]Login failed with Instagram. Exiting.[/red]")
        exit_process()

    mode = args.mode or console.input(f"[cyan]Select Mode: \n1 - Battle Arc Mode (type 'battle')\n2 - Noti Claiming Mode (type 'noti')\nEnter your choice: [/cyan]").strip()

    if mode == "battle":
        battle_arc_mode(api_client, args.targets, args.reason, args.num_reports)
    elif mode == "noti":
        noti_claiming_mode(api_client, args.targets, args.reason)
    else:
        console.print("[red]Invalid choice. Exiting.[/red]")
        logging.error("Invalid mode selected.")
        exit_process()

    console.print("[bold blue]Script finished.[/bold blue]")
    logging.info("Script finished.")

if __name__ == "__main__":
    display_banner()
    main_menu()
