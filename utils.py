import time
import hmac
import hashlib
import json
from time import sleep
from random import uniform

def generate_hmac_signature(data, secret_key):
    """
    Generate HMAC-SHA256 signature for the given data.
    """
    return hmac.new(secret_key.encode('utf-8'), json.dumps(data).encode('utf-8'), hashlib.sha256).hexdigest()

def generate_encrypted_password(password):
    """
    Encrypt password in the format required by Instagram.
    This is a simplified version and might need adjustment.
    """
    return f"#PWD_INSTAGRAM:0:{int(time.time())}:{password}"

def handle_rate_limiting(response):
    """
    Handle rate limiting from Instagram.
    """
    if response.status_code == 429:
        print("Rate limited. Waiting for 60 seconds.")
        sleep(60)
    return response
