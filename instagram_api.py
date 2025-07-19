import requests
import re
import uuid
import time
import hmac
import hashlib
from random import choice, uniform
from rich.console import Console

from utils import handle_rate_limiting, generate_encrypted_password, generate_hmac_signature

console = Console()

class InstagramAPI:
    def __init__(self, username, password, secret_key):
        self.username = username
        self.password = password
        self.secret_key = secret_key
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.session_id = None
        self.csrf_token = None
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        ]
        self.csrf_fetch_urls = [
            "https://i.instagram.com/api/v1/si/fetch_headers/?challenge_type=signup&guid={}",
            "https://i.instagram.com/api/v1/accounts/login/",
            "https://i.instagram.com/api/v1/accounts/two_factor_login/",
        ]

    def fetch_csrf_token(self, retries=3):
        for attempt in range(retries):
            for endpoint in self.csrf_fetch_urls:
                for user_agent in self.user_agents:
                    headers = {
                        "User-Agent": user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br",
                        "X-Requested-With": "XMLHttpRequest",
                        "X-CSRFToken": "missing",
                        "X-Instagram-AJAX": "1",
                        "X-IG-App-ID": "936619743392459",
                    }
                    try:
                        response = self.session.get(endpoint.format(str(uuid.uuid4())), headers=headers)
                        response.raise_for_status()
                        cookies = response.cookies
                        csrf_token = cookies.get("csrftoken", None)
                        if csrf_token:
                            return csrf_token
                        if "signup" in endpoint:
                            try:
                                data = response.json()
                                csrf_token = data.get("config", {}).get("csrf_token", None)
                                if csrf_token:
                                    return csrf_token
                            except ValueError:
                                pass
                        if "fetch_headers" in endpoint:
                            try:
                                match = re.search(r'"csrf_token":"(\w+)"', response.text)
                                if match:
                                    csrf_token = match.group(1)
                                    return csrf_token
                            except Exception:
                                pass
                    except Exception:
                        pass
            time.sleep(uniform(5, 10))
        return "missing"

    def login(self, max_retries=5):
        for retries in range(max_retries):
            self.csrf_token = self.fetch_csrf_token()
            encrypted_password = generate_encrypted_password(self.password)
            data = {
                "username": self.username,
                "enc_password": encrypted_password,
                "device_id": self.device_id,
                "first_factor": "password",
                "csrf_token": self.csrf_token,
                "login_attempt_count": str(retries),
            }
            signature = generate_hmac_signature(data, self.secret_key)
            headers = {
                "User-Agent": choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "X-CSRFToken": self.csrf_token,
            }
            try:
                response = self.session.post("https://i.instagram.com/api/v1/accounts/login/", headers=headers, data=signature, allow_redirects=True)
                response = handle_rate_limiting(response)
                if "authenticated" in response.text:
                    self.session_id = response.cookies["sessionid"]
                    self.csrf_token = response.cookies["csrftoken"]
                    return True
                else:
                    try:
                        json_response = response.json()
                        message = json_response.get("message", "Unknown error")
                        error_type = json_response.get("error_type", "Unknown")
                        if "checkpoint_challenge_required" in error_type:
                            console.print(f"[red]Challenge required. Please complete verification in a browser.[/red]")
                        elif "incorrect_password" in error_type:
                            console.print(f"[red]Incorrect password.[/red]")
                        else:
                            console.print(f"[red]Login failed: {message}[/red]")
                    except ValueError:
                        console.print(f"[red]Login failed with status code: {response.status_code}[/red]")
                    time.sleep(uniform(20, 40))
            except requests.exceptions.RequestException as e:
                console.print(f"[red]Network error during login: {e}[/red]")
                time.sleep(uniform(20, 40))
        return False

    def report_user(self, user_id, reason_id):
        headers = {
            "User-Agent": choice(self.user_agents),
            "Referer": "https://www.instagram.com/",
            "Cookie": f"sessionid={self.session_id}; csrftoken={self.csrf_token}",
            "X-CSRFToken": self.csrf_token,
            "X-IG-App-ID": "936619743392459"
        }
        try:
            response = self.session.post(f"https://i.instagram.com/users/{user_id}/flag/", headers=headers, data=f"source_name=&reason_id={reason_id}&frx_context=", allow_redirects=False)
            response = handle_rate_limiting(response)
            if response.status_code == 200:
                return True
            else:
                console.print(f"[red]Failed to report user. Status code: {response.status_code}[/red]")
                return False
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error while reporting user: {e}[/red]")
            return False

    def get_user_id(self, username):
        try:
            response = self.session.get(f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", "Cookie": f"csrftoken={self.csrf_token}; sessionid={self.session_id}", "X-CSRFToken": self.csrf_token, "X-IG-App-ID": "936619743392459"})
            response.raise_for_status()
            json_response = response.json()
            user_id = json_response.get("data", {}).get("user", {}).get("id")
            if not user_id:
                raise ValueError(f"No user ID found for {username} via API.")
            return user_id
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]API failed for {username}: {e}. Trying fallback method...[/yellow]")
            try:
                fallback_response = self.session.get(f"https://www.instagram.com/{username}/?__a=1&__d=dis", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"})
                fallback_response.raise_for_status()
                fallback_json = fallback_response.json()
                user_id = fallback_json.get("graphql", {}).get("user", {}).get("id")
                if not user_id:
                    raise ValueError(f"No user ID found for {username} via fallback method.")
                return user_id
            except requests.exceptions.RequestException as e:
                raise ValueError(f"Failed to fetch ID for {username}: {e}")
