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
            return True
        except ChallengeRequired:
            console.print("[red]Challenge required. Please log in to your Instagram account in a browser to resolve the challenge.[/red]")
            return False
        except (BadPassword, LoginRequired, TwoFactorRequired, PleaseWaitFewMinutes, ClientError) as e:
            console.print(f"[red]Login failed: {e}[/red]")
            return False

    def report_user(self, user_id, reason_id):
        try:
            return self.client.user_report(user_id, reason_id)
        except Exception as e:
            console.print(f"[red]Failed to report user: {e}[/red]")
            return False

    def get_user_id(self, username):
        user_id = self.client.user_id_from_username(username)
        if not user_id:
            raise ValueError(f"No user ID found for {username} via API.")
        return user_id
