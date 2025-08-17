import os
import requests
import json
import sys
import tweepy
import time
import logging
import re
import html
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QTextEdit, QPushButton, QFileDialog, QLabel,
                             QInputDialog, QMessageBox, QLineEdit, QFormLayout,
                             QDialog, QMenuBar, QTextBrowser, QCheckBox, QListWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QAction
from dateutil.parser import parse

CREDENTIALS_FILE = "social_credentials.enc"
FERNET_KEY_FILE = "fernet_key.key"

# Setup logging to file
logging.basicConfig(
    filename="client.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_fernet():
    """Generate or load Fernet key for encryption/decryption."""
    try:
        if os.path.exists(FERNET_KEY_FILE):
            with open(FERNET_KEY_FILE, "rb") as f:
                key = f.read()
                logging.info("Loaded existing Fernet key")
        else:
            key = Fernet.generate_key()
            with open(FERNET_KEY_FILE, "wb") as f:
                f.write(key)
            logging.info("Generated and saved new Fernet key")
        return Fernet(key)
    except Exception as e:
        logging.error(f"Failed to load or generate Fernet key: {str(e)}")
        return None

def load_credentials():
    try:
        if os.path.exists(CREDENTIALS_FILE):
            fernet = get_fernet()
            if fernet is None:
                logging.error("Cannot load credentials: Fernet key unavailable")
                return {}
            with open(CREDENTIALS_FILE, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        return {}
    except Exception as e:
        logging.error(f"Failed to load credentials: {str(e)}")
        return {}

def save_credentials(creds):
    try:
        fernet = get_fernet()
        if fernet is None:
            logging.error("Cannot save credentials: Fernet key unavailable")
            return
        encrypted_data = fernet.encrypt(json.dumps(creds, indent=2).encode())
        with open(CREDENTIALS_FILE, "wb") as f:
            f.write(encrypted_data)
        logging.info("Credentials saved successfully (encrypted)")
    except Exception as e:
        logging.error(f"Failed to save credentials: {str(e)}")

def pleroma_oauth_setup(instance_url):
    app_name = "PleromaMediaClient"
    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
    scopes = "read write"

    try:
        logging.info(f"Registering Pleroma app at {instance_url}/api/v1/apps")
        response = requests.post(
            f"{instance_url}/api/v1/apps",
            data={
                "client_name": app_name,
                "redirect_uris": redirect_uri,
                "scopes": scopes
            },
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Failed to register Pleroma app: {response.status_code} - {response.json()}")
            return None, f"Failed to register app: {response.json()}"
        app_data = response.json()
        client_id = app_data["client_id"]
        client_secret = app_data["client_secret"]

        auth_url = (
            f"{instance_url}/oauth/authorize"
            f"?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&scope={scopes}"
            f"&force_login=true"
        )
        logging.info("Pleroma app registered successfully")
        return {"client_id": client_id, "client_secret": client_secret, "auth_url": auth_url}, None
    except requests.RequestException as e:
        logging.error(f"Network error registering Pleroma app: {str(e)}")
        return None, f"Network error registering Pleroma app: {str(e)}"

def upload_pleroma_media(instance_url, access_token, media_path):
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        logging.info(f"Uploading media to Pleroma: {media_path}")
        with open(media_path, "rb") as file:
            response = requests.post(
                f"{instance_url}/api/v1/media",
                headers=headers,
                files={"file": file},
                timeout=10
            )
        if response.status_code != 200:
            logging.error(f"Pleroma media upload failed: {response.status_code} - {response.json()}")
            return None, f"Media upload failed: {response.json()}"
        logging.info("Pleroma media uploaded successfully")
        return response.json().get("id"), None
    except requests.RequestException as e:
        logging.error(f"Network error uploading Pleroma media: {str(e)}")
        return None, f"Network error uploading Pleroma media: {str(e)}"

def post_to_pleroma(instance_url, access_token, status_text, media_ids=None):
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {
        "status": status_text or "",
        "visibility": "public"
    }
    if media_ids:
        data["media_ids[]"] = media_ids
    try:
        logging.info(f"Posting to Pleroma: {status_text[:50]}...")
        response = requests.post(
            f"{instance_url}/api/v1/statuses",
            headers=headers,
            data=data,
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Pleroma post failed: {response.status_code} - {response.json()}")
            return None, None, f"Post failed: {response.json()}"
        post_data = response.json()
        logging.info(f"Pleroma post successful: {post_data.get('url')}")
        return post_data.get("url"), post_data.get("id"), None
    except requests.RequestException as e:
        logging.error(f"Network error posting to Pleroma: {str(e)}")
        return None, None, f"Network error posting to Pleroma: {str(e)}"

def upload_misskey_media(instance_url, access_token, media_path):
    try:
        logging.info(f"Uploading media to Misskey: {media_path}")
        with open(media_path, "rb") as file:
            response = requests.post(
                f"{instance_url}/api/drive/files/create",
                data={"i": access_token},
                files={"file": file},
                timeout=10
            )
        if response.status_code != 200:
            logging.error(f"Misskey media upload failed: {response.status_code} - {response.json()}")
            return None, f"Media upload failed: {response.json()}"
        logging.info("Misskey media uploaded successfully")
        return response.json().get("id"), None
    except requests.RequestException as e:
        logging.error(f"Network error uploading Misskey media: {str(e)}")
        return None, f"Network error uploading Misskey media: {str(e)}"

def post_to_misskey(instance_url, access_token, status_text, media_ids=None):
    data = {"i": access_token, "text": status_text or "", "visibility": "public"}
    if media_ids:
        data["fileIds"] = media_ids
    try:
        logging.info(f"Posting to Misskey: {status_text[:50]}...")
        response = requests.post(
            f"{instance_url}/api/notes/create",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Misskey post failed: {response.status_code} - {response.json()}")
            return None, None, f"Post failed: {response.json()}"
        note_data = response.json()
        logging.debug(f"Misskey API response: {json.dumps(note_data, indent=2)}")
        note_id = note_data["createdNote"].get("id")
        note_url = note_data["createdNote"].get("url") or f"{instance_url}/notes/{note_id}"
        logging.info(f"Misskey post successful: {note_url}")
        return note_url, note_id, None
    except requests.RequestException as e:
        logging.error(f"Network error posting to Misskey: {str(e)}")
        return None, None, f"Network error posting to Misskey: {str(e)}"

def post_to_x(media_paths, status_text, primary_url, x_creds):
    try:
        logging.info(f"Posting to X: {status_text[:50]}...")
        # Initialize tweepy.Client for X API v2
        client = tweepy.Client(
            consumer_key=x_creds["api_key"],
            consumer_secret=x_creds["api_secret"],
            access_token=x_creds["access_token"],
            access_token_secret=x_creds["access_token_secret"]
        )
        # Initialize tweepy.API for v1.1 media uploads and credential validation
        auth = tweepy.OAuth1UserHandler(
            x_creds["api_key"], x_creds["api_secret"],
            x_creds["access_token"], x_creds["access_token_secret"]
        )
        api = tweepy.API(auth)

        # Validate credentials
        try:
            user = api.verify_credentials()
            logging.info(f"X API credentials validated successfully for user: {user.screen_name}")
            # Check for read-only permissions
            response = api.rate_limit_status()
            access_level = response.get('resources', {}).get('account', {}).get('/account/verify_credentials', {}).get('x-access-level', '')
            if access_level == 'read':
                logging.error("X API credentials have read-only permissions")
                return False, "Error: X API credentials have read-only permissions. Go to https://developer.x.com, set 'Read and Write' permissions in App settings, and regenerate tokens."
        except tweepy.TweepyException as e:
            logging.error(f"X API credential validation failed: {str(e)}")
            return False, f"Error: Invalid X API credentials. Please reconfigure at https://developer.x.com: {str(e)}"

        # Check post limit
        creds = load_credentials()
        x_post_count = creds.get("x", {}).get("x_post_count", 0)
        x_post_month = creds.get("x", {}).get("x_post_month", "")
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        if x_post_month != current_month:
            x_post_count = 0  # Reset count at the start of a new month
            x_post_month = current_month

        if x_post_count >= 500:
            logging.error("X post limit reached: 500 posts per month")
            return False, "Error: X post limit reached (500 posts per month). Please wait until next month or upgrade to Basic tier at https://developer.x.com."

        # Prepare status text with primary URL (if provided)
        status_text = f"{status_text} {primary_url}" if primary_url else status_text
        if len(status_text) > 280:
            status_text = status_text[:277] + "..."  # Truncate to fit X's limit
            logging.warning(f"Status text truncated to 280 characters: {status_text}")

        # Upload media (using v1.1 endpoint)
        media_ids = []
        if media_paths:
            for media_path in media_paths:
                media = api.media_upload(media_path)
                media_ids.append(media.media_id_string)
                logging.debug(f"Uploaded media to X: {media_path}, media_id={media.media_id_string}")

        # Post to X using v2 endpoint
        response = client.create_tweet(text=status_text, media_ids=media_ids if media_ids else None)
        
        # Increment post counter
        x_post_count += 1
        creds["x"]["x_post_count"] = x_post_count
        creds["x"]["x_post_month"] = current_month
        save_credentials(creds)
        logging.info(f"X post successful: tweet_id={response.data['id']}, posts this month: {x_post_count}/500")
        return True, None
    except tweepy.TweepyException as e:
        logging.error(f"Error posting to X: {str(e)} - Response: {getattr(e, 'response', 'No response details')}")
        return False, f"Error posting to X: {str(e)}. Please verify 'Read and Write' permissions at https://developer.x.com or reconfigure credentials."

class PleromaClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Poster")
        self.setFixedSize(400, 520)

        # Menu bar
        self.menu_bar = QMenuBar()
        self.setMenuBar(self.menu_bar)

        accounts_menu = self.menu_bar.addMenu("Accounts")
        self.pleroma_oauth_action = QAction("Setup Pleroma OAuth", self)
        self.pleroma_oauth_action.triggered.connect(self.setup_pleroma_oauth)
        accounts_menu.addAction(self.pleroma_oauth_action)

        self.misskey_oauth_action = QAction("Setup Misskey API Key", self)
        self.misskey_oauth_action.triggered.connect(self.setup_misskey_api)
        accounts_menu.addAction(self.misskey_oauth_action)

        self.x_config_action = QAction("Configure X API", self)
        self.x_config_action.triggered.connect(self.configure_x)
        accounts_menu.addAction(self.x_config_action)

        crosspost_menu = self.menu_bar.addMenu("Crosspost")
        self.total_crosspost_action = QAction("Total Cross Post", self, checkable=True)
        self.total_crosspost_action.triggered.connect(lambda: self.set_crosspost_mode("total"))
        crosspost_menu.addAction(self.total_crosspost_action)

        self.pleroma_to_misskey_action = QAction("Pleroma to Misskey Repost", self, checkable=True)
        self.pleroma_to_misskey_action.triggered.connect(lambda: self.set_crosspost_mode("pleroma_to_misskey"))
        crosspost_menu.addAction(self.pleroma_to_misskey_action)

        self.misskey_to_pleroma_action = QAction("Misskey to Pleroma Repost", self, checkable=True)
        self.misskey_to_pleroma_action.triggered.connect(lambda: self.set_crosspost_mode("misskey_to_pleroma"))
        crosspost_menu.addAction(self.misskey_to_pleroma_action)

        # Help menu
        help_menu = self.menu_bar.addMenu("Help")
        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self.show_help)
        help_menu.addAction(self.about_action)

        # Load saved settings
        creds = load_credentials()
        self.crosspost_mode = creds.get("settings", {}).get("crosspost_mode", "total")
        self.total_crosspost_action.setChecked(self.crosspost_mode == "total")
        self.pleroma_to_misskey_action.setChecked(self.crosspost_mode == "pleroma_to_misskey")
        self.misskey_to_pleroma_action.setChecked(self.crosspost_mode == "misskey_to_pleroma")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Enter your post text here...")
        self.layout.addWidget(self.text_edit)

        # Service checkboxes
        self.service_layout = QVBoxLayout()
        self.pleroma_checkbox = QCheckBox("Post to Pleroma")
        self.pleroma_checkbox.setChecked(
            creds.get("settings", {}).get("pleroma_checked", bool(creds.get("pleroma", {}).get("access_token")))
        )
        self.pleroma_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.pleroma_checkbox)

        self.misskey_checkbox = QCheckBox("Post to Misskey")
        self.misskey_checkbox.setChecked(
            creds.get("settings", {}).get("misskey_checked", bool(creds.get("misskey", {}).get("access_token")))
        )
        self.misskey_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.misskey_checkbox)

        self.x_checkbox = QCheckBox("Post to X")
        self.x_checkbox.setChecked(
            creds.get("settings", {}).get("x_checked", bool(creds.get("x", {}).get("api_key")))
        )
        self.x_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.x_checkbox)
        self.layout.addLayout(self.service_layout)

        # X post count label
        self.x_post_count_label = QLabel("X Posts This Month: 0/500")
        self.update_x_post_count_label(creds)
        self.layout.addWidget(self.x_post_count_label)

        # Media selection
        self.media_label = QLabel("No media selected")
        self.layout.addWidget(self.media_label)
        self.media_list = QListWidget()
        self.media_list.setMaximumHeight(80)
        self.layout.addWidget(self.media_list)
        self.select_media_button = QPushButton("Select Media (Up to 1 video or 4 images)")
        self.select_media_button.clicked.connect(self.select_media)
        self.layout.addWidget(self.select_media_button)

        self.post_button = QPushButton("Post to Selected Services")
        self.post_button.clicked.connect(self.post_content)
        self.layout.addWidget(self.post_button)

        self.status_label = QLabel("")
        self.layout.addWidget(self.status_label)

        self.media_paths = []
        logging.info("PleromaClientGUI initialized")

    def save_checkbox_states(self):
        creds = load_credentials()
        creds["settings"] = creds.get("settings", {})
        creds["settings"]["pleroma_checked"] = self.pleroma_checkbox.isChecked()
        creds["settings"]["misskey_checked"] = self.misskey_checkbox.isChecked()
        creds["settings"]["x_checked"] = self.x_checkbox.isChecked()
        save_credentials(creds)
        logging.info("Checkbox states saved")

    def set_crosspost_mode(self, mode):
        self.crosspost_mode = mode
        self.total_crosspost_action.setChecked(mode == "total")
        self.pleroma_to_misskey_action.setChecked(mode == "pleroma_to_misskey")
        self.misskey_to_pleroma_action.setChecked(mode == "misskey_to_pleroma")
        self.status_label.setText(f"Crosspost mode set to: {mode.replace('_', ' ').title()}")
        creds = load_credentials()
        creds["settings"] = creds.get("settings", {})
        creds["settings"]["crosspost_mode"] = mode
        save_credentials(creds)
        logging.info(f"Crosspost mode set to: {mode}")

    def find_pleroma_post(self, max_attempts=5, delay=2):
        if not self.misskey_user or "@" not in self.misskey_user:
            logging.error(f"Invalid Misskey username: {self.misskey_user}")
            return None, f"Invalid Misskey username: {self.misskey_user}. Must be in format username@instance.com"
        logging.info(f"Fetching Pleroma user profile for {self.misskey_user} to find Misskey post: {self.misskey_url}")
        time.sleep(delay)  # Wait for federation
        post_time = datetime.now(timezone.utc)
        for attempt in range(max_attempts):
            try:
                # Search for user profile
                response = requests.get(
                    f"{self.instance_url}/api/v1/accounts/search",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    params={"q": self.misskey_user, "limit": 1},
                    timeout=10
                )
                if response.status_code != 200:
                    logging.error(f"Failed to search Pleroma user profile (attempt {attempt + 1}/{max_attempts}): {response.status_code} - {response.json()}")
                    return None, f"Failed to search Pleroma user profile (attempt {attempt + 1}/{max_attempts}): {response.json()}"
                users = response.json()
                if not users or not isinstance(users, list) or len(users) == 0:
                    logging.error(f"No user found for {self.misskey_user} in Pleroma search")
                    return None, f"No user found for {self.misskey_user} in Pleroma search"
                user_id = users[0].get("id")
                if not user_id:
                    logging.error(f"No user ID found for {self.misskey_user} in Pleroma profile")
                    return None, f"No user ID found for {self.misskey_user} in Pleroma profile"

                # Fetch user's public statuses
                response = requests.get(
                    f"{self.instance_url}/api/v1/accounts/{user_id}/statuses",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    params={"limit": 10},
                    timeout=10
                )
                if response.status_code != 200:
                    logging.error(f"Failed to fetch Pleroma user statuses (attempt {attempt + 1}/{max_attempts}): {response.status_code} - {response.json()}")
                    return None, f"Failed to fetch Pleroma user statuses (attempt {attempt + 1}/{max_attempts}): {response.json()}"
                posts = response.json()
                logging.info(f"Pleroma user statuses fetched for {self.misskey_user}: {len(posts)} posts")
                logging.debug(f"Pleroma statuses: {[{'id': p['id'], 'content': p.get('content'), 'created_at': p.get('created_at')} for p in posts]}")
                for post in posts:
                    post_text = post.get("content", "").strip()
                    post_visibility = post.get("visibility")
                    created_at_str = post.get("created_at", "")
                    if not created_at_str:
                        logging.warning(f"Skipping post {post.get('id')} with missing created_at")
                        continue
                    # Strip HTML tags and unescape entities
                    post_text = html.unescape(post_text)
                    post_text = re.sub(r'<[^>]+>', '', post_text).strip()
                    logging.debug(f"Cleaned post text for post {post.get('id')}: {post_text}")
                    try:
                        post_created_at = parse(created_at_str)
                        if post_created_at.tzinfo is None:
                            post_created_at = post_created_at.replace(tzinfo=timezone.utc)
                        time_diff = (post_time - post_created_at).total_seconds()
                        if (self.status_text and post_text == self.status_text and post_visibility == "public" and time_diff < 60):
                            logging.info(f"Found Misskey post in Pleroma user profile: post_id={post['id']}")
                            return post["id"], None
                    except ValueError as e:
                        logging.warning(f"Failed to parse created_at for post {post.get('id')}: {created_at_str}, error: {str(e)}")
                        continue
                logging.warning(f"Misskey post not found in Pleroma user profile (attempt {attempt + 1}/{max_attempts})")
                time.sleep(1)
            except requests.RequestException as e:
                logging.error(f"Network error fetching Pleroma user profile/statuses (attempt {attempt + 1}/{max_attempts}): {str(e)}")
                return None, f"Network error fetching Pleroma user profile/statuses (attempt {attempt + 1}/{max_attempts}): {str(e)}"
        logging.error(f"Misskey post not found in Pleroma user profile after {max_attempts} attempts")
        return None, f"Misskey post not found in Pleroma user profile after {max_attempts} attempts. Ensure Pleroma recognizes the Misskey user ({self.misskey_user}) at https://fedi.nekos.farm/users/{self.misskey_user} or search for {self.misskey_user} and check federation."

def find_misskey_note(instance_url, access_token, post_url, post_text, username):
    try:
        logging.info(f"Searching for Misskey note with URL: {post_url}, text: {post_text[:50]}..., username: {username}")
        response = requests.post(
            f"{instance_url}/api/notes/search",
            headers={"Content-Type": "application/json"},
            json={"i": access_token, "query": post_url, "limit": 10},
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Misskey note search failed: {response.status_code} - {response.text}")
            return None, f"Misskey note search failed: {response.status_code} - {response.text}"
        
        notes = response.json()
        if not notes:
            logging.warning(f"No Misskey notes found for URL: {post_url}")
            return None, "No matching Misskey note found. The post may not have propagated yet."

        for note in notes:
            if note is None:
                logging.warning("Encountered None note in Misskey search results")
                continue
            note_text = note.get("text", "" if note.get("text") is None else note.get("text")).strip()
            note_user = note.get("user", {}).get("username", "")
            note_host = note.get("user", {}).get("host", "")
            note_full_username = f"{note_user}@{note_host}" if note_host else note_user
            if post_url in note_text and note_full_username == username:
                logging.info(f"Found matching Misskey note: {note['id']}")
                return note["id"], None
        logging.warning(f"No matching Misskey note found for URL: {post_url}, username: {username}")
        return None, "No matching Misskey note found. Check username or post content."
    except requests.RequestException as e:
        logging.error(f"Misskey note search failed: Network error: {str(e)}")
        return None, f"Misskey note search failed: Network error: {str(e)}"

def renote_to_misskey(instance_url, access_token, note_id):
    try:
        logging.info(f"Renoting Misskey note: note_id={note_id}")
        response = requests.post(
            f"{instance_url}/api/notes/create",
            json={"i": access_token, "renoteId": note_id},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Failed to renote: {response.status_code} - {response.json()}")
            return False, f"Failed to renote: {response.json()}"
        logging.info("Misskey renote successful")
        return True, None
    except requests.RequestException as e:
        logging.error(f"Network error renoting to Misskey: {str(e)}")
        return False, f"Network error renoting to Misskey: {str(e)}"

def reblog_to_pleroma(instance_url, access_token, post_id):
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        logging.info(f"Reblogging Pleroma post: post_id={post_id}")
        response = requests.post(
            f"{instance_url}/api/v1/statuses/{post_id}/reblog",
            headers=headers,
            timeout=10
        )
        if response.status_code != 200:
            logging.error(f"Failed to reblog: {response.status_code} - {response.json()}")
            return False, f"Failed to reblog: {response.json()}"
        logging.info("Pleroma reblog successful")
        return True, None
    except requests.RequestException as e:
        logging.error(f"Network error reblogging to Pleroma: {str(e)}")
        return False, f"Network error reblogging to Pleroma: {str(e)}"

class OAuthDialog(QDialog):
    def __init__(self, auth_url, title):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(400, 200)
        layout = QVBoxLayout()

        self.url_browser = QTextBrowser()
        self.url_browser.setHtml(f'<a href="{auth_url}">{auth_url}</a>')
        self.url_browser.setOpenExternalLinks(True)
        layout.addWidget(self.url_browser)

        self.copy_button = QPushButton("Copy URL")
        self.copy_button.clicked.connect(self.copy_url)
        layout.addWidget(self.copy_button)

        self.auth_code = QLineEdit()
        self.auth_code.setPlaceholderText("Paste authorization code here...")
        layout.addWidget(self.auth_code)

        self.save_button = QPushButton("Submit")
        self.save_button.clicked.connect(self.accept)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        logging.info(f"Opened OAuth dialog for {title}")

    def copy_url(self):
        QApplication.clipboard().setText(self.url_browser.toPlainText())
        QMessageBox.information(self, "Copied", "URL copied to clipboard.")
        logging.info("Copied OAuth URL to clipboard")

class MisskeyAPIDialog(QDialog):
    def __init__(self, instance_url):
        super().__init__()
        self.setWindowTitle("Misskey API Key Setup")
        self.setFixedSize(400, 300)
        layout = QVBoxLayout()

        self.instructions = QTextBrowser()
        self.instructions.setHtml(
            "Generate an API key in Misskey:<br>"
            "1. Go to <a href='{}/settings/api'>{}/settings/api</a><br>"
            "2. Click 'Generate Access Token'.<br>"
            "3. Select these permissions:<br>"
            "&nbsp;&nbsp;- write:notes (to post and renote)<br>"
            "&nbsp;&nbsp;- write:drive (to upload media)<br>"
            "4. Copy the token and paste it below.<br>"
            "Note: Ensure your Misskey account follows the Pleroma account (e.g., noc@fedi.nekos.farm) to see its posts.".format(instance_url, instance_url)
        )
        self.instructions.setOpenExternalLinks(True)
        layout.addWidget(self.instructions)

        self.open_button = QPushButton("Open Misskey API Settings")
        self.open_button.clicked.connect(lambda: QDesktopServices.openUrl(f"{instance_url}/settings/api"))
        layout.addWidget(self.open_button)

        self.api_key = QLineEdit()
        self.api_key.setPlaceholderText("Paste Misskey API key here...")
        layout.addWidget(self.api_key)

        self.save_button = QPushButton("Submit")
        self.save_button.clicked.connect(self.accept)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        logging.info(f"Opened Misskey API dialog for {instance_url}")

class XAPIDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("X API Key Setup")
        self.setFixedSize(400, 500)  # Increased height for detailed instructions
        layout = QVBoxLayout()

        self.instructions = QTextBrowser()
        self.instructions.setHtml(
            "<h2>X API Setup</h2>"
            "<p>Generate X API credentials with <b>Read and Write</b> permissions (required for posting):</p>"
            "<ol>"
            "<li>Go to <a href='https://developer.x.com'>https://developer.x.com</a> and sign in with your X account.</li>"
            "<li>Ensure your Developer Account is approved (check email/phone verification).</li>"
            "<li>Create a new Project (e.g., 'Social Media Client') in the Developer Portal.</li>"
            "<li>Create an App within the Project.</li>"
            "<li>In App settings, under 'User authentication settings', select '<b>Read and Write</b>' permissions and set App type to 'Web App' or 'Automated App'.</li>"
            "<li>If 'Read and Write' is not available:"
            "<ul>"
            "<li>Verify your X account (email/phone) and Developer Account status.</li>"
            "<li>Create a new Project and App, as older apps may be restricted.</li>"
            "<li>Contact X Developer Support at <a href='https://developer.x.com/en/support'>https://developer.x.com/en/support</a>.</li>"
            "</ul></li>"
            "<li>Go to 'Keys and Tokens' tab, regenerate API Key, API Secret, Access Token, and Access Token Secret.</li>"
            "<li>Paste them below and click Submit.</li>"
            "</ol>"
            "<p><b>Important:</b> Free tier has a 500 posts/month limit. Read-only permissions will cause 403 Forbidden errors when posting.</p>"
            "<p>Install tweepy: <code>pip install tweepy</code> if not already installed.</p>"
        )
        self.instructions.setOpenExternalLinks(True)
        layout.addWidget(self.instructions)

        self.open_button = QPushButton("Open X Developer Portal")
        self.open_button.clicked.connect(lambda: QDesktopServices.openUrl("https://developer.x.com"))
        layout.addWidget(self.open_button)

        self.form_layout = QFormLayout()
        self.api_key = QLineEdit()
        self.api_secret = QLineEdit()
        self.access_token = QLineEdit()
        self.access_token_secret = QLineEdit()

        self.form_layout.addRow("API Key:", self.api_key)
        self.form_layout.addRow("API Secret:", self.api_secret)
        self.form_layout.addRow("Access Token:", self.access_token)
        self.form_layout.addRow("Access Token Secret:", self.access_token_secret)
        layout.addLayout(self.form_layout)

        self.save_button = QPushButton("Submit")
        self.save_button.clicked.connect(self.validate_and_save)
        layout.addWidget(self.save_button)

        self.setLayout(layout)

        # Load existing credentials
        creds = load_credentials()
        x_creds = creds.get("x", {})
        self.api_key.setText(x_creds.get("api_key", ""))
        self.api_secret.setText(x_creds.get("api_secret", ""))
        self.access_token.setText(x_creds.get("access_token", ""))
        self.access_token_secret.setText(x_creds.get("access_token_secret", ""))
        logging.info("Opened X API setup dialog")

    def validate_and_save(self):
        api_key = self.api_key.text().strip()
        api_secret = self.api_secret.text().strip()
        access_token = self.access_token.text().strip()
        access_token_secret = self.access_token_secret.text().strip()

        if not all([api_key, api_secret, access_token, access_token_secret]):
            QMessageBox.warning(self, "Error", "All fields are required.")
            logging.error("X API setup failed: Missing credentials")
            return

        # Test credentials with v1.1 verify_credentials
        try:
            auth = tweepy.OAuth1UserHandler(api_key, api_secret, access_token, access_token_secret)
            api = tweepy.API(auth)
            user = api.verify_credentials()
            logging.info(f"X API credentials validated successfully for user: {user.screen_name}")
            # Check for read-only permissions
            response = api.rate_limit_status()
            access_level = response.get('resources', {}).get('account', {}).get('/account/verify_credentials', {}).get('x-access-level', '')
            if access_level == 'read':
                QMessageBox.warning(
                    self, "Error",
                    "Credentials have read-only permissions. Go to https://developer.x.com, set 'Read and Write' permissions in App settings, and regenerate tokens."
                )
                logging.error("X API credentials have read-only permissions")
                return
        except tweepy.TweepyException as e:
            QMessageBox.warning(
                self, "Error",
                f"Invalid credentials: {str(e)}. Ensure the app has 'Read and Write' permissions in the X Developer Portal at https://developer.x.com."
            )
            logging.error(f"X API credentials validation failed: {str(e)}")
            return

        # Save credentials
        creds = load_credentials()
        creds["x"] = {
            "api_key": api_key,
            "api_secret": api_secret,
            "access_token": access_token,
            "access_token_secret": access_token_secret,
            "x_post_count": creds.get("x", {}).get("x_post_count", 0),
            "x_post_month": creds.get("x", {}).get("x_post_month", "")
        }
        save_credentials(creds)
        QMessageBox.information(
            self, "Success",
            "X API credentials saved successfully. Ensure 'Read and Write' permissions are set to avoid posting errors."
        )
        logging.info("X API credentials saved")
        self.accept()

class HelpDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Help - Social Media Client")
        self.setFixedSize(400, 300)
        layout = QVBoxLayout()

        # Editable help content
        help_content = (
            "<h2>Poster</h2>"
            "<p>This application allows posting to Pleroma, Misskey, and X, with crossposting and reposting features.</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Post text and media (up to 1 video or 4 images).</li>"
            "<li>Enable/disable services via checkboxes.</li>"
            "<li>Crosspost modes: Total, Pleroma to Misskey, Misskey to Pleroma.</li>"
            "</ul>"
            "<p><b>GitHub Repository:</b><br>"
            "<a href='https://github.com/m0nnnna/poster'>Poster</a></p>"
            "<p><b>Credits:</b><br>"
            "Developed by FrenSoft.<br>"
            "Made with Python & love.<br>"
            "Special thanks to my autism and AI.</p>"
            "<p><b>Support:</b><br>"
            "Report issues or contribute on GitHub.</p>"
        )
        
        self.help_browser = QTextBrowser()
        self.help_browser.setHtml(help_content)
        self.help_browser.setOpenExternalLinks(True)
        layout.addWidget(self.help_browser)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        layout.addWidget(self.close_button)

        self.setLayout(layout)
        logging.info("Opened Help dialog")

class PleromaClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Social Media Client")
        self.setFixedSize(400, 520)

        # Menu bar
        self.menu_bar = QMenuBar()
        self.setMenuBar(self.menu_bar)

        accounts_menu = self.menu_bar.addMenu("Accounts")
        self.pleroma_oauth_action = QAction("Setup Pleroma OAuth", self)
        self.pleroma_oauth_action.triggered.connect(self.setup_pleroma_oauth)
        accounts_menu.addAction(self.pleroma_oauth_action)

        self.misskey_oauth_action = QAction("Setup Misskey API Key", self)
        self.misskey_oauth_action.triggered.connect(self.setup_misskey_api)
        accounts_menu.addAction(self.misskey_oauth_action)

        self.x_config_action = QAction("Configure X API", self)
        self.x_config_action.triggered.connect(self.configure_x)
        accounts_menu.addAction(self.x_config_action)

        crosspost_menu = self.menu_bar.addMenu("Crosspost")
        self.total_crosspost_action = QAction("Total Cross Post", self, checkable=True)
        self.total_crosspost_action.triggered.connect(lambda: self.set_crosspost_mode("total"))
        crosspost_menu.addAction(self.total_crosspost_action)

        self.pleroma_to_misskey_action = QAction("Pleroma to Misskey Repost", self, checkable=True)
        self.pleroma_to_misskey_action.triggered.connect(lambda: self.set_crosspost_mode("pleroma_to_misskey"))
        crosspost_menu.addAction(self.pleroma_to_misskey_action)

        self.misskey_to_pleroma_action = QAction("Misskey to Pleroma Repost", self, checkable=True)
        self.misskey_to_pleroma_action.triggered.connect(lambda: self.set_crosspost_mode("misskey_to_pleroma"))
        crosspost_menu.addAction(self.misskey_to_pleroma_action)

        # Help menu
        help_menu = self.menu_bar.addMenu("Help")
        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self.show_help)
        help_menu.addAction(self.about_action)

        # Load saved settings
        creds = load_credentials()
        self.crosspost_mode = creds.get("settings", {}).get("crosspost_mode", "total")
        self.total_crosspost_action.setChecked(self.crosspost_mode == "total")
        self.pleroma_to_misskey_action.setChecked(self.crosspost_mode == "pleroma_to_misskey")
        self.misskey_to_pleroma_action.setChecked(self.crosspost_mode == "misskey_to_pleroma")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Enter your post text here...")
        self.layout.addWidget(self.text_edit)

        # Service checkboxes
        self.service_layout = QVBoxLayout()
        self.pleroma_checkbox = QCheckBox("Post to Pleroma")
        self.pleroma_checkbox.setChecked(
            creds.get("settings", {}).get("pleroma_checked", bool(creds.get("pleroma", {}).get("access_token")))
        )
        self.pleroma_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.pleroma_checkbox)

        self.misskey_checkbox = QCheckBox("Post to Misskey")
        self.misskey_checkbox.setChecked(
            creds.get("settings", {}).get("misskey_checked", bool(creds.get("misskey", {}).get("access_token")))
        )
        self.misskey_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.misskey_checkbox)

        self.x_checkbox = QCheckBox("Post to X")
        self.x_checkbox.setChecked(
            creds.get("settings", {}).get("x_checked", bool(creds.get("x", {}).get("api_key")))
        )
        self.x_checkbox.stateChanged.connect(self.save_checkbox_states)
        self.service_layout.addWidget(self.x_checkbox)
        self.layout.addLayout(self.service_layout)

        # X post count label
        self.x_post_count_label = QLabel("X Posts This Month: 0/500")
        self.update_x_post_count_label(creds)
        self.layout.addWidget(self.x_post_count_label)

        # Media selection
        self.media_label = QLabel("No media selected")
        self.layout.addWidget(self.media_label)
        self.media_list = QListWidget()
        self.media_list.setMaximumHeight(80)
        self.layout.addWidget(self.media_list)
        self.select_media_button = QPushButton("Select Media (Up to 1 video or 4 images)")
        self.select_media_button.clicked.connect(self.select_media)
        self.layout.addWidget(self.select_media_button)

        self.post_button = QPushButton("Post to Selected Services")
        self.post_button.clicked.connect(self.post_content)
        self.layout.addWidget(self.post_button)

        self.status_label = QLabel("")
        self.layout.addWidget(self.status_label)

        self.media_paths = []
        logging.info("PleromaClientGUI initialized")

    def update_x_post_count_label(self, creds):
        x_post_count = creds.get("x", {}).get("x_post_count", 0)
        x_post_month = creds.get("x", {}).get("x_post_month", "")
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        if x_post_month != current_month:
            x_post_count = 0
            creds["x"] = creds.get("x", {})
            creds["x"]["x_post_count"] = x_post_count
            creds["x"]["x_post_month"] = current_month
            save_credentials(creds)
        self.x_post_count_label.setText(f"X Posts This Month: {x_post_count}/500")
        if x_post_count >= 450:
            self.status_label.setText("Warning: Approaching X post limit (500/month)")
            logging.warning(f"Approaching X post limit: {x_post_count}/500")

    def save_checkbox_states(self):
        creds = load_credentials()
        creds["settings"] = creds.get("settings", {})
        creds["settings"]["pleroma_checked"] = self.pleroma_checkbox.isChecked()
        creds["settings"]["misskey_checked"] = self.misskey_checkbox.isChecked()
        creds["settings"]["x_checked"] = self.x_checkbox.isChecked()
        save_credentials(creds)
        logging.info("Checkbox states saved")

    def set_crosspost_mode(self, mode):
        self.crosspost_mode = mode
        self.total_crosspost_action.setChecked(mode == "total")
        self.pleroma_to_misskey_action.setChecked(mode == "pleroma_to_misskey")
        self.misskey_to_pleroma_action.setChecked(mode == "misskey_to_pleroma")
        self.status_label.setText(f"Crosspost mode set to: {mode.replace('_', ' ').title()}")
        creds = load_credentials()
        creds["settings"] = creds.get("settings", {})
        creds["settings"]["crosspost_mode"] = mode
        save_credentials(creds)
        logging.info(f"Crosspost mode set to: {mode}")

    def show_help(self):
        dialog = HelpDialog()
        dialog.exec()

    def setup_pleroma_oauth(self):
        instance_url, ok = QInputDialog.getText(self, "Pleroma Instance", "Enter Pleroma instance URL (e.g., https://fedi.nekos.farm):")
        if not ok or not instance_url:
            self.status_label.setText("Pleroma OAuth cancelled.")
            logging.info("Pleroma OAuth setup cancelled by user")
            return
        if not instance_url.startswith("http"):
            instance_url = f"https://{instance_url}"

        pleroma_user, ok = QInputDialog.getText(self, "Pleroma Username", "Enter Pleroma username (e.g., noc@fedi.nekos.farm):")
        if not ok or not pleroma_user:
            self.status_label.setText("Pleroma OAuth cancelled: No username provided.")
            logging.info("Pleroma OAuth cancelled: No username provided")
            return
        if "@" not in pleroma_user:
            self.status_label.setText("Pleroma OAuth cancelled: Invalid username format. Must be username@instance.com")
            logging.error(f"Invalid Pleroma username format: {pleroma_user}")
            return

        creds = load_credentials()
        pleroma_data, error = pleroma_oauth_setup(instance_url)
        if error:
            self.status_label.setText(f"Pleroma OAuth failed: {error}")
            return

        dialog = OAuthDialog(pleroma_data["auth_url"], "Pleroma OAuth")
        if dialog.exec():
            auth_code = dialog.auth_code.text()
            if not auth_code:
                self.status_label.setText("Pleroma OAuth cancelled.")
                logging.info("Pleroma OAuth cancelled: no auth code provided")
                return

            try:
                response = requests.post(
                    f"{instance_url}/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": pleroma_data["client_id"],
                        "client_secret": pleroma_data["client_secret"],
                        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                        "code": auth_code
                    },
                    timeout=10
                )
                if response.status_code != 200:
                    self.status_label.setText(f"Pleroma OAuth failed: {response.json()}")
                    logging.error(f"Pleroma OAuth token request failed: {response.status_code} - {response.json()}")
                    return

                token_data = response.json()
                creds["pleroma"] = {
                    "instance_url": instance_url,
                    "client_id": pleroma_data["client_id"],
                    "client_secret": pleroma_data["client_secret"],
                    "access_token": token_data["access_token"],
                    "username": pleroma_user
                }
                save_credentials(creds)
                self.pleroma_checkbox.setChecked(True)
                self.status_label.setText("Pleroma OAuth setup complete.")
                logging.info("Pleroma OAuth setup complete")
            except requests.RequestException as e:
                self.status_label.setText(f"Pleroma OAuth failed: Network error: {str(e)}")
                logging.error(f"Pleroma OAuth token request failed: {str(e)}")

    def setup_misskey_api(self):
        instance_url, ok = QInputDialog.getText(self, "Misskey Instance", "Enter Misskey instance URL (e.g., https://frennet.xyz):")
        if not ok or not instance_url:
            self.status_label.setText("Misskey API setup cancelled.")
            logging.info("Misskey API setup cancelled by user")
            return
        if not instance_url.startswith("http"):
            instance_url = f"https://{instance_url}"

        misskey_user, ok = QInputDialog.getText(self, "Misskey Username", "Enter Misskey username (e.g., mona@frennet.xyz):")
        if not ok or not misskey_user:
            self.status_label.setText("Misskey API setup cancelled: No username provided.")
            logging.info("Misskey API setup cancelled: No username provided")
            return
        if "@" not in misskey_user:
            self.status_label.setText("Misskey API setup cancelled: Invalid username format. Must be username@instance.com")
            logging.error(f"Invalid Misskey username format: {misskey_user}")
            return

        dialog = MisskeyAPIDialog(instance_url)
        if dialog.exec():
            api_key = dialog.api_key.text()
            if not api_key:
                self.status_label.setText("Misskey API setup cancelled.")
                logging.info("Misskey API setup cancelled: no API key provided")
                return

            try:
                logging.info(f"Testing Misskey API key at {instance_url}/api/meta")
                response = requests.post(
                    f"{instance_url}/api/meta",
                    headers={"Content-Type": "application/json"},
                    json={"i": api_key},
                    timeout=10
                )
                if response.status_code != 200:
                    self.status_label.setText(f"Misskey API key invalid: {response.json()}")
                    logging.error(f"Misskey API key invalid: {response.status_code} - {response.json()}")
                    return
                logging.info("Misskey API key validated successfully")
            except requests.RequestException as e:
                self.status_label.setText(f"Misskey API key test failed: Network error: {str(e)}")
                logging.error(f"Misskey API key test failed: {str(e)}")
                return

            creds = load_credentials()
            creds["misskey"] = {
                "instance_url": instance_url,
                "access_token": api_key,
                "username": misskey_user
            }
            save_credentials(creds)
            self.misskey_checkbox.setChecked(True)
            self.status_label.setText("Misskey API key setup complete.")
            logging.info("Misskey API key setup complete")

    def configure_x(self):
        dialog = XAPIDialog()
        if dialog.exec():
            self.x_checkbox.setChecked(True)
            creds = load_credentials()
            self.update_x_post_count_label(creds)
            self.status_label.setText("X API setup complete.")

    def select_media(self):
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(
            self, "Select Media Files", "", "Media Files (*.jpg *.png *.mp4)"
        )
        if file_paths:
            images = [p for p in file_paths if p.lower().endswith(('.jpg', '.png'))]
            videos = [p for p in file_paths if p.lower().endswith('.mp4')]
            if len(videos) > 1 or (videos and images) or len(images) > 4:
                QMessageBox.warning(
                    self, "Invalid Selection",
                    "Select up to 1 video file (.mp4) or up to 4 image files (.jpg, .png)."
                )
                logging.error("Invalid media selection: more than 1 video or mixed video/images or more than 4 images")
                return
            self.media_paths = file_paths
            self.media_list.clear()
            for path in file_paths:
                self.media_list.addItem(path.split('/')[-1])
            self.media_label.setText(f"Selected: {len(file_paths)} file(s)")
            logging.info(f"Media selected: {file_paths}")
        else:
            self.media_paths = []
            self.media_list.clear()
            self.media_label.setText("No media selected")
            logging.info("Media selection cancelled")

    def post_content(self):
        status_text = self.text_edit.toPlainText().strip()
        if not status_text and not self.media_paths:
            self.status_label.setText("Error: Post must have text or media.")
            logging.error("Post attempt failed: No text or media provided")
            return

        creds = load_credentials()
        pleroma_creds = creds.get("pleroma", {})
        misskey_creds = creds.get("misskey", {})
        x_creds = creds.get("x", {})
        posted_services = []
        original_account = None

        self.post_button.setEnabled(False)
        self.status_label.setText("Posting, please wait...")

        if self.crosspost_mode == "total":
            primary_url = None
            if self.pleroma_checkbox.isChecked() and pleroma_creds.get("access_token"):
                media_ids = []
                for media_path in self.media_paths:
                    media_id, error = upload_pleroma_media(pleroma_creds["instance_url"], pleroma_creds["access_token"], media_path)
                    if error:
                        self.status_label.setText(f"Error: {error}")
                        self.post_button.setEnabled(True)
                        return
                    media_ids.append(media_id)
                pleroma_url, _, error = post_to_pleroma(pleroma_creds["instance_url"], pleroma_creds["access_token"], status_text, media_ids)
                if error:
                    self.status_label.setText(f"Error: {error}")
                    self.post_button.setEnabled(True)
                    return
                primary_url = pleroma_url
                posted_services.append(f"Pleroma: {pleroma_url}")
                original_account = original_account or "Pleroma"

            if self.misskey_checkbox.isChecked() and misskey_creds.get("access_token"):
                media_ids = []
                for media_path in self.media_paths:
                    media_id, error = upload_misskey_media(misskey_creds["instance_url"], misskey_creds["access_token"], media_path)
                    if error:
                        self.status_label.setText(f"Error: {error}")
                        self.post_button.setEnabled(True)
                        return
                    media_ids.append(media_id)
                misskey_url, _, error = post_to_misskey(misskey_creds["instance_url"], misskey_creds["access_token"], status_text, media_ids)
                if error:
                    self.status_label.setText(f"Error: {error}")
                    self.post_button.setEnabled(True)
                    return
                primary_url = primary_url or misskey_url
                posted_services.append(f"Misskey: {misskey_url}")
                original_account = original_account or "Misskey"

            if self.x_checkbox.isChecked() and x_creds.get("api_key"):
                success, error = post_to_x(self.media_paths, status_text, primary_url, x_creds)
                if error:
                    self.status_label.setText(f"Error posting to X: {error}")
                    self.post_button.setEnabled(True)
                    return
                posted_services.append("X")
                self.update_x_post_count_label(load_credentials())

            if not posted_services:
                self.status_label.setText("Error: No services selected or configured.")
                logging.error("Post failed: No services selected or configured")
                self.post_button.setEnabled(True)
                return

        elif self.crosspost_mode == "pleroma_to_misskey":
            if not self.pleroma_checkbox.isChecked() or not pleroma_creds.get("access_token"):
                self.status_label.setText("Error: Pleroma not configured or disabled.")
                logging.error("Pleroma to Misskey repost failed: Pleroma not configured or disabled")
                self.post_button.setEnabled(True)
                return
            if not pleroma_creds.get("username"):
                self.status_label.setText("Error: Pleroma username not configured.")
                logging.error("Pleroma to Misskey repost failed: Pleroma username not configured")
                self.post_button.setEnabled(True)
                return

            media_ids = []
            for media_path in self.media_paths:
                media_id, error = upload_pleroma_media(pleroma_creds["instance_url"], pleroma_creds["access_token"], media_path)
                if error:
                    self.status_label.setText(f"Error: {error}")
                    self.post_button.setEnabled(True)
                    return
                media_ids.append(media_id)
            pleroma_url, _, error = post_to_pleroma(pleroma_creds["instance_url"], pleroma_creds["access_token"], status_text, media_ids)
            if error:
                self.status_label.setText(f"Error: {error}")
                self.post_button.setEnabled(True)
                return
            posted_services.append(f"Pleroma: {pleroma_url}")
            original_account = "Pleroma"

            if self.x_checkbox.isChecked() and x_creds.get("api_key"):
                success, error = post_to_x(self.media_paths, status_text, pleroma_url, x_creds)
                if error:
                    self.status_label.setText(f"Error posting to X: {error}")
                    self.post_button.setEnabled(True)
                    return
                posted_services.append("X")
                self.update_x_post_count_label(load_credentials())

            if self.misskey_checkbox.isChecked() and misskey_creds.get("access_token"):
                note_id, error = find_misskey_note(
                    misskey_creds["instance_url"], misskey_creds["access_token"], pleroma_url, status_text, pleroma_creds["username"]
                )
                if error or not note_id:
                    logging.warning(f"Failed to find Misskey note: {error}. Posting as new note.")
                    media_ids = []
                    for media_path in self.media_paths:
                        media_id, error = upload_misskey_media(misskey_creds["instance_url"], misskey_creds["access_token"], media_path)
                        if error:
                            self.status_label.setText(f"Error: {error}")
                            self.post_button.setEnabled(True)
                            return
                        media_ids.append(media_id)
                    misskey_url, _, error = post_to_misskey(
                        misskey_creds["instance_url"], misskey_creds["access_token"], 
                        f"{status_text} {pleroma_url}", media_ids
                    )
                    if error:
                        self.status_label.setText(f"Error posting to Misskey: {error}")
                        self.post_button.setEnabled(True)
                        return
                    posted_services.append(f"Misskey: {misskey_url}")
                else:
                    success, error = renote_to_misskey(misskey_creds["instance_url"], misskey_creds["access_token"], note_id)
                    if error:
                        self.status_label.setText(f"Error renoting to Misskey: {error}")
                        self.post_button.setEnabled(True)
                        return
                    posted_services.append("Misskey (renote)")

        elif self.crosspost_mode == "misskey_to_pleroma":
            if not self.misskey_checkbox.isChecked() or not misskey_creds.get("access_token"):
                self.status_label.setText("Error: Misskey not configured or disabled.")
                logging.error("Misskey to Pleroma repost failed: Misskey not configured or disabled")
                self.post_button.setEnabled(True)
                return
            if not misskey_creds.get("username"):
                self.status_label.setText("Error: Misskey username not configured.")
                logging.error("Misskey to Pleroma repost failed: Misskey username not configured")
                self.post_button.setEnabled(True)
                return

            media_ids = []
            for media_path in self.media_paths:
                media_id, error = upload_misskey_media(misskey_creds["instance_url"], misskey_creds["access_token"], media_path)
                if error:
                    self.status_label.setText(f"Error: {error}")
                    self.post_button.setEnabled(True)
                    return
                media_ids.append(media_id)
            misskey_url, misskey_note_id, error = post_to_misskey(misskey_creds["instance_url"], misskey_creds["access_token"], status_text, media_ids)
            if error:
                self.status_label.setText(f"Error: {error}")
                self.post_button.setEnabled(True)
                return
            posted_services.append(f"Misskey: {misskey_url}")
            original_account = "Misskey"

            if self.x_checkbox.isChecked() and x_creds.get("api_key"):
                success, error = post_to_x(self.media_paths, status_text, misskey_url, x_creds)
                if error:
                    self.status_label.setText(f"Error posting to X: {error}")
                    self.post_button.setEnabled(True)
                    return
                posted_services.append("X")
                self.update_x_post_count_label(load_credentials())

            if self.pleroma_checkbox.isChecked() and pleroma_creds.get("access_token"):
                self.thread = PleromaPostThread(
                    pleroma_creds["instance_url"], pleroma_creds["access_token"], misskey_url, status_text, misskey_creds["username"]
                )
                self.thread.result.connect(self.handle_pleroma_result)
                self.thread.start()
                self.posted_services = posted_services
                self.original_account = original_account
                return

        self.finalize_post(posted_services, original_account)

    def handle_pleroma_result(self, status_message, post_id, error):
        if error:
            self.status_label.setText(status_message)
            self.post_button.setEnabled(True)
            return
        self.posted_services.append(status_message)
        self.finalize_post(self.posted_services, self.original_account)

    def finalize_post(self, posted_services, original_account):
        if posted_services:
            self.status_label.setText(f"Posted by {original_account or 'multiple accounts'}: {', '.join(posted_services)}")
            logging.info(f"Post successful: {', '.join(posted_services)}")
            self.text_edit.clear()
            self.media_paths = []
            self.media_list.clear()
            self.media_label.setText("No media selected")
            logging.info("Cleared text box and media selection")
        else:
            self.status_label.setText("Error: No services selected or configured.")
            logging.error("Post failed: No services selected or configured")
        self.post_button.setEnabled(True)

def main():
    app = QApplication(sys.argv)
    window = PleromaClientGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()