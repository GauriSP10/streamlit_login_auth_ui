import re
import json
from trycourier import Courier
import secrets
from argon2 import PasswordHasher
import requests


ph = PasswordHasher()


def check_usr_pass(username: str, password: str, users_auth_file: str) -> bool:
    """
    Authenticates the username and password. The former is case insensitive.
    """
    with open(users_auth_file, "r") as auth_json:
        authorized_user_data = json.load(auth_json)

    for registered_user in authorized_user_data:
        if registered_user['username'].lower() == username.lower():
            try:
                passwd_verification_bool = ph.verify(registered_user['password'], password)
            except:
                pass
            else:
                if passwd_verification_bool:
                    return True
    return False


def load_lottieurl(url: str) -> str:
    """
    Fetches the lottie animation using the URL.
    """
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        pass


def check_valid_name(name_sign_up: str) -> bool:
    """
    Checks if the user entered a valid name while creating the account.
    """
    name_regex = (r'^[A-Za-z_][A-Za-z0-9_]*')

    if re.search(name_regex, name_sign_up):
        return True
    return False


def check_valid_email(email_sign_up: str) -> bool:
    """
    Checks if the user entered a valid email while creating the account.
    """
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

    if re.fullmatch(regex, email_sign_up):
        return True
    return False


def check_unique_email(email_sign_up: str, users_auth_file) -> bool:
    """
    Checks if the email already exists (since email needs to be unique).
    """
    authorized_user_data_master = list()
    with open(users_auth_file, "r") as auth_json:
        authorized_users_data = json.load(auth_json)

        for user in authorized_users_data:
            authorized_user_data_master.append(user['email'])

    if email_sign_up in authorized_user_data_master:
        return False
    return True


def check_valid_username(name_sign_up: str) -> str:
    """Checks if username is valid.

    1. usernames with leading and trailing whitespace are invalid.
    The following usernames are invalid.
    username = " smith"
    username = "smith "
    username = " smith "

    2. usernames with more than 1 word are invalid.
    The following usernames are invalid.
    username = "joe smith"
    username = "joe  smith"
    username = "joe smith general"

    3. usernames that contain a non-alphanumeric char are invalid.
    The following username is invalid.
    username = "4horsemen!"

    4. minimum usernames length is 4
    The following usernames are invalid.
    username = "joe"
    username = "bea"

    5. maximum username length is 16
    The following username is invalid.
    username = "joeklDedfnkdfedfefdtw"

    Args:
        name_sign_up: username

    Returns:
        valid if username is valid otherwise a string about the issue.
    """

    if name_sign_up.startswith(' '):
        return 'leading white space'

    if name_sign_up.endswith(' '):
        return 'trailing white space'

    if name_sign_up.count(' ') >= 1:
        return 'more than 1 word'

    if not name_sign_up.isalnum():
        return 'not alpha-numeric'

    if len(name_sign_up) < 4:
        return 'number of characters is below 4'

    if len(name_sign_up) > 16:
        return 'number of characters is above 16'

    return 'valid'


def check_unique_usr(username_sign_up: str, users_auth_file: str):
    """Checks if the username is in users file.

    The username check is case insensitive meaning "smith" and
    "Smith" are the same.

    Args:
        username_sign_up: The username to check in users file.
        users_auth_file: The file where all the users info are recorded.

    Returns:
        True if username is not in users file. False if username is already existing.
    """
    authorized_user_data_master = list()
    with open(users_auth_file, "r") as auth_json:
        authorized_users_data = json.load(auth_json)

        for user in authorized_users_data:
            authorized_user_data_master.append(user['username'].lower())

    if username_sign_up.lower() in authorized_user_data_master:
        return False
    return True


def register_new_usr(name_sign_up: str, email_sign_up: str, username_sign_up: str, password_sign_up: str, users_auth_file: str) -> None:
    """
    Saves the information of the new user in the users_auth_file.
    """
    new_usr_data = {'username': username_sign_up, 'name': name_sign_up, 'email': email_sign_up, 'password': ph.hash(password_sign_up)}

    with open(users_auth_file, "r") as auth_json:
        authorized_user_data = json.load(auth_json)

    with open(users_auth_file, "w") as auth_json_write:
        authorized_user_data.append(new_usr_data)
        json.dump(authorized_user_data, auth_json_write)
        

def check_email_exists(email_forgot_passwd: str, users_auth_file: str):
    """
    Checks if the email entered is present in the users file.
    """
    with open(users_auth_file, "r") as auth_json:
        authorized_users_data = json.load(auth_json)

        for user in authorized_users_data:
            if user['email'] == email_forgot_passwd:
                return True, user['username']
    return False, None


def generate_random_passwd() -> str:
    """
    Generates a random password to be sent in email.
    """
    password_length = 10
    return secrets.token_urlsafe(password_length)


def send_passwd_in_email(auth_token: str, username_forgot_passwd: str, email_forgot_passwd: str, company_name: str, random_password: str) -> None:
    """
    Triggers an email to the user containing the randomly generated password.
    """
    client = Courier(auth_token = auth_token)

    resp = client.send_message(
    message={
        "to": {
        "email": email_forgot_passwd
        },
        "content": {
        "title": company_name + ": Login Password!",
        "body": "Hi! " + username_forgot_passwd + "," + "\n" + "\n" + "Your temporary login password is: " + random_password  + "\n" + "\n" + "{{info}}"
        },
        "data":{
        "info": "Please reset your password at the earliest for security reasons."
        }
    }
    )


def change_passwd(email_: str, random_password: str, users_auth_file: str) -> None:
    """
    Replaces the old password with the newly generated password.
    """
    with open(users_auth_file, "r") as auth_json:
        authorized_users_data = json.load(auth_json)

    with open(users_auth_file, "w") as auth_json_:
        for user in authorized_users_data:
            if user['email'] == email_:
                user['password'] = ph.hash(random_password)
        json.dump(authorized_users_data, auth_json_)
    

def check_current_passwd(email_reset_passwd: str, current_passwd: str, users_auth_file: str) -> bool:
    """
    Authenticates the password entered against the username when 
    resetting the password.
    """
    with open(users_auth_file, "r") as auth_json:
        authorized_users_data = json.load(auth_json)

        for user in authorized_users_data:
            if user['email'] == email_reset_passwd:
                try:
                    if ph.verify(user['password'], current_passwd) == True:
                        return True
                except:
                    pass
    return False

# Author: Gauri Prabhakar
# GitHub: https://github.com/GauriSP10/streamlit_login_auth_ui
