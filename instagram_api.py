from instagrapi import Client
from instagrapi.exceptions import BadPassword, LoginRequired, ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, ClientError
from rich.console import Console
import requests
from random import choice

console = Console()

class InstagramAPI:
    def __init__(self, username, password, secret_key):
        self.username = username
        self.password = password
        self.secret_key = secret_key
        self.client = Client()
        self.client.challenge_code_handler = lambda username, choice: ""

    def login(self):
        try:
            self.client.login(self.username, self.password, relogin=True)
            self.session_id = self.client.sessionid
            self.csrf_token = self.client.csrftoken
            return True
        except ChallengeRequired:
            console.print("[red]Challenge required. Please log in to your Instagram account in a browser to resolve the challenge.[/red]")
            return False
        except (BadPassword, LoginRequired, TwoFactorRequired, PleaseWaitFewMinutes, ClientError) as e:
            console.print(f"[red]Login failed: {e}[/red]")
            return False

    def report_user(self, user_id, reason_id):
        headers = {
            "User-Agent": choice(self.client.USER_AGENTS),
            "Referer": "https://www.instagram.com/",
            "Cookie": f"sessionid={self.session_id}; csrftoken={self.csrf_token}",
            "X-CSRFToken": self.csrf_token,
            "X-IG-App-ID": "936619743392459"
        }
        try:
            response = requests.post(f"https://i.instagram.com/users/{user_id}/flag/", headers=headers, data=f"source_name=&reason_id={reason_id}&frx_context=", allow_redirects=False)
            if response.status_code == 200:
                return True
            else:
                console.print(f"[red]Failed to report user. Status code: {response.status_code}[/red]")
                return False
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error while reporting user: {e}[/red]")
            return False

    def get_user_id(self, username):
        user_id = self.client.user_id_from_username(username)
        if not user_id:
            raise ValueError(f"No user ID found for {username} via API.")
        return user_id
