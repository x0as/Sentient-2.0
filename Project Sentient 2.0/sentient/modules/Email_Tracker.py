import requests
from bs4 import BeautifulSoup
import time
import random

# ANSI color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Updated user agents for better compatibility
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15"
]

def get_random_user_agent():
    return random.choice(user_agents)

def safe_request(func):
    """Decorator to handle common HTTP errors gracefully"""
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            if isinstance(result, str) and result.startswith("Error:"):
                # Convert HTTP errors to "Unknown" status
                if any(code in result for code in ["403", "404", "405", "412", "429", "503"]):
                    return "Unknown"
            return result
        except Exception as e:
            return "Unknown"
    return wrapper

@safe_request
def Instagram(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Origin': 'https://www.instagram.com',
            'Connection': 'keep-alive',
            'Referer': 'https://www.instagram.com/'
        }
        data = {"email": email}
        response = session.get("https://www.instagram.com/accounts/emailsignup/", headers=headers, timeout=10)
        if response.status_code != 200:
            return "Unknown"
        token = session.cookies.get('csrftoken')
        if not token:
            return "Unknown"
        headers["x-csrftoken"] = token
        headers["Referer"] = "https://www.instagram.com/accounts/emailsignup/"
        response = session.post(
            url="https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
            headers=headers,
            data=data,
            timeout=10
        )
        if response.status_code == 200:
            if "Another account is using the same email." in response.text or "email_is_taken" in response.text:
                return True
            return False
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Twitter(email):
    try:
        session = requests.Session()
        response = session.get(
            url="https://api.twitter.com/i/users/email_available.json",
            params={"email": email},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()["taken"]
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Pinterest(email):
    try:
        session = requests.Session()
        headers = {'User-Agent': get_random_user_agent()}
        response = session.get(
            "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
            params={"source_url": "/", "data": '{"options": {"email": "' + email + '"}, "context": {}}'},
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()["resource_response"]
            if data["message"] == "Invalid email.":
                return False
            return data["data"] is not False
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Imgur(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en,en-US;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://imgur.com',
            'DNT': '1',
            'Connection': 'keep-alive',
            'TE': 'Trailers',
        }
        r = session.get("https://imgur.com/register?redirect=%2Fuser", headers=headers, timeout=10)
        headers["X-Requested-With"] = "XMLHttpRequest"
        data = {'email': email}
        response = session.post('https://imgur.com/signin/ajax_email_available', headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            if data["available"]:
                return False
            if "Invalid email domain" in response.text:
                return False
            return True
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Reddit(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json',
        }
        data = {"email": email}
        response = session.post("https://www.reddit.com/api/check_email.json", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return not response.json().get("valid", True)
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def LinkedIn(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {"email": email}
        response = session.post("https://www.linkedin.com/checkpoint/rp/request-password-reset-submit", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "We just emailed a link" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Facebook(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
        }
        params = {"email": email}
        response = session.get("https://www.facebook.com/login/identify/", headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return "No search results" not in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Spotify(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
        }
        params = {'validate': '1', 'email': email}
        response = session.get('https://spclient.wg.spotify.com/signup/public/v1/account',
                headers=headers,
                params=params,
                timeout=10)
        if response.status_code == 200:
            status = response.json()["status"]
            return status == 20
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def FireFox(email):
    try:
        session = requests.Session()
        data = {"email": email}
        response = session.post("https://api.accounts.firefox.com/v1/account/status", data=data, timeout=10)
        if response.status_code == 200:
            return "false" not in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def LastPass(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en,en-US;q=0.5',
            'Referer': 'https://lastpass.com/',
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',
            'Connection': 'keep-alive',
            'TE': 'Trailers',
        }
        params = {
            'check': 'avail',
            'skipcontent': '1',
            'mistype': '1',
            'username': email,
        }
        response = session.get(
            'https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username='+str(email).replace("@", "%40"),       
            params=params,
            headers=headers,
            timeout=10)
        if response.status_code == 200:
            if "no" in response.text:
                return True
            return False
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Archive(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en,en-US;q=0.5',
            'Content-Type': 'multipart/form-data; boundary=---------------------------',
            'Origin': 'https://archive.org',
            'Connection': 'keep-alive',
            'Referer': 'https://archive.org/account/signup',
            'Sec-GPC': '1',
            'TE': 'Trailers',
        }
        data = '-----------------------------\r\nContent-Disposition: form-data; name="input_name"\r\n\r\nusername\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_value"\r\n\r\n' + email + \
            '\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_validator"\r\n\r\ntrue\r\n-----------------------------\r\nContent-Disposition: form-data; name="submit_by_js"\r\n\r\ntrue\r\n-------------------------------\r\n'
        response = session.post('https://archive.org/account/signup', headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "is already taken." in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Tumblr(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json',
        }
        data = {"email": email}
        response = session.post("https://www.tumblr.com/svc/account/email-check", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return response.json().get("email_exists", False)
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def TikTok(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json',
        }
        data = {"email": email}
        response = session.post("https://www.tiktok.com/forgot-password/email", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return "We sent an email" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Snapchat(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {"email": email}
        response = session.post("https://accounts.snapchat.com/accounts/merlin/login", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "EMAIL_NOT_FOUND" not in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def ProtonMail(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json',
        }
        data = {"Username": email}
        response = session.post("https://account.proton.me/api/core/v4/users/available", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return not response.json().get("Available", True)
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Zoho(email):
    try:
        session = requests.Session()
        headers = {
            'User-Agent': get_random_user_agent(),
        }
        data = {"email": email}
        response = session.post("https://accounts.zoho.com/accounts/forgotpassword", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "We have sent an email" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Adobe(email):
    try:
        session = requests.Session()
        headers = {'User-Agent': get_random_user_agent()}
        data = {"username": email}
        response = session.post("https://account.adobe.com/forgotPassword", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "We sent you an email" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Dropbox(email):
    try:
        session = requests.Session()
        headers = {'User-Agent': get_random_user_agent()}
        data = {"email": email}
        response = session.post("https://www.dropbox.com/ajax_send_reset", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "We sent a link" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

@safe_request
def Github(email):
    try:
        session = requests.Session()
        headers = {'User-Agent': get_random_user_agent()}
        data = {"email": email}
        response = session.post("https://github.com/password_reset", headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            return "sent you an email" in response.text
        return "Unknown"
    except Exception as e:
        return "Unknown"

def email_tracker_cli(email):
    """
    Main function to track email across multiple platforms
    Returns dict with platform names as keys and status as values
    """
    sites = [
        ("Instagram", Instagram),
        ("Twitter", Twitter),
        ("Pinterest", Pinterest),
        ("Imgur", Imgur),
        ("Reddit", Reddit),
        ("LinkedIn", LinkedIn),
        ("Facebook", Facebook),
        ("Spotify", Spotify),
        ("FireFox", FireFox),
        ("LastPass", LastPass),
        ("Archive", Archive),
        ("Tumblr", Tumblr),
        ("TikTok", TikTok),
        ("Snapchat", Snapchat),
        ("ProtonMail", ProtonMail),
        ("Zoho", Zoho),
        ("Adobe", Adobe),
        ("Dropbox", Dropbox),
        ("Github", Github),
    ]
    
    results = {}
    for name, func in sites:
        try:
            # Add small delay between requests to avoid rate limiting
            time.sleep(random.uniform(0.1, 0.3))
            
            found = func(email)
            if found is True:
                results[name] = "FOUND"
            elif found is False:
                results[name] = "NOT FOUND"
            elif found == "Unknown":
                results[name] = "UNKNOWN"
            elif isinstance(found, str) and found.startswith("Error"):
                results[name] = "UNKNOWN"
            else:
                results[name] = f"UNKNOWN"
        except Exception as e:
            results[name] = "UNKNOWN"
    
    return results

if __name__ == "__main__":
    email = input("Enter the email to track: ")
    results = email_tracker_cli(email)
    for name, status in results.items():
        if status == "FOUND":
            print(f"{GREEN}[FOUND]{RESET} {name}")
        elif status == "NOT FOUND":
            print(f"{RED}[NOT FOUND]{RESET} {name}")
        elif status == "UNKNOWN":
            print(f"{YELLOW}[UNKNOWN]{RESET} {name}")
        else:
            print(f"{YELLOW}[UNKNOWN]{RESET} {name}: {status}")