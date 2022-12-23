from typing import Union, List
import re
import json
from trycourier import Courier
import secrets
from argon2 import PasswordHasher
import requests
from trycourier.exceptions import CourierAPIException


ph = PasswordHasher()


def get_users_data(users_auth_file: str) -> List[dict]:
    """Gets the users data.

    Read the users auth file where users info are saved. Convert
    it to a list of dictionary.

    Args:
        users_auth_file: The json file were users info are saved.

    Returns:
        A list of dict of users data.
    """
    with open(users_auth_file, "r") as auth_json:
        return json.load(auth_json)


def check_usr_pass(username: str, password: str, users_auth_file: str) -> bool:
    """
    Authenticates the username and password. The former is case insensitive.
    """
    authorized_users_data = get_users_data(users_auth_file)

    for registered_user in authorized_users_data:
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


def check_unique_email(email: str, users_auth_file: str) -> bool:
    """Checks if email is not in users auth file.

    Lookup in the users auth file if email is not there. Email checking
    is case insensitive.

    Args:
        email: The email to check in users auth file.
        users_auth_file: The json file where users info are saved.

    Returns:
        True if not found in users auth file. False if it exists already.
    """
    is_existing, _ = check_email_exists(email, users_auth_file)
    if is_existing:
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
        True if username is not in users file.
        False if username is already existing.
    """
    authorized_user_data_master = list()
    authorized_users_data = get_users_data(users_auth_file)

    for user in authorized_users_data:
        authorized_user_data_master.append(user['username'].lower())

    if username_sign_up.lower() in authorized_user_data_master:
        return False
    return True


def register_new_usr(name_sign_up: str, email_sign_up: str,
                     username_sign_up: str, password_sign_up:
                     str, users_auth_file: str) -> None:
    """
    Saves the information of the new user in the users_auth_file.
    """
    new_usr_data = {'username': username_sign_up, 'name': name_sign_up,
                     'email': email_sign_up,
                     'password': ph.hash(password_sign_up)}

    authorized_users_data = get_users_data(users_auth_file)
    authorized_users_data.append(new_usr_data)

    with open(users_auth_file, "w") as auth_json_write:
        json.dump(authorized_users_data, auth_json_write)


def check_email_exists(email: str, users_auth_file: str):
    """Checks if email is present in the users auth file.

    Read the users auth file and check if email is present. Email
    checking is case insensitive.

    Args:
        email: The email to check in users auth file.
        users_auth_file: The json file where users info are saved.

    Returns:
        A tuple of bool and str or None. If email is present return
        (True, username) otherwise return (False, None).
    """
    authorized_users_data = get_users_data(users_auth_file)

    for user in authorized_users_data:
        if user['email'].lower() == email.lower():
            return True, user['username']
    return False, None


def generate_random_passwd() -> str:
    """
    Generates a random password to be sent in email.
    """
    password_length = 10
    return secrets.token_urlsafe(password_length)


def send_passwd_in_email(
        auth_token: str,
        username_forgot_passwd: str,
        email_forgot_passwd: str,
        company_name: str,
        random_password: str) -> Union[str, CourierAPIException]:
    """Sends email to the user.

    Triggers an email to the user containing the randomly generated
    password. If the developer does not use courier auth token, the
    email will not be sent. If the developer uses the courier auth token
    and the email failed to be sent to the user, the developer will
    receive a copy of that email.
    """
    client = Courier(auth_token=auth_token)

    try:
        client.send_message(
            message={
                "to": {
                    "email": email_forgot_passwd
                },
                "content": {
                    "title": company_name + ": Login Password!",
                    "body": "Hi! " + username_forgot_passwd + "," + "\n" + "\n" + "Your temporary login password is: " + random_password  + "\n" + "\n" + "{{info}}"
                },
                "data": {
                    "info": "Please reset your password at the earliest for security reasons."
                }
            })
    except CourierAPIException as err:
        return err
    else:
        return 'OK'


def change_passwd(email_: str, random_password: str, users_auth_file: str) -> None:
    """
    Replaces the old password with the newly generated password.
    """
    authorized_users_data = get_users_data(users_auth_file)

    for user in authorized_users_data:
        if user['email'] == email_:
            user['password'] = ph.hash(random_password)
            break

    with open(users_auth_file, "w") as auth_json_:
        json.dump(authorized_users_data, auth_json_)


def check_current_passwd(email: str, password: str, users_auth_file: str) -> bool:
    """Checks the email and password.

    Read the users auth file and check if email owns the password.
    This is used when user resets the password.
    """
    authorized_users_data = get_users_data(users_auth_file)

    for user in authorized_users_data:
        if user['email'].lower() == email.lower():
            try:
                if ph.verify(user['password'], password):
                    return True
            except:
                pass
    return False

# Author: Gauri Prabhakar
# GitHub: https://github.com/GauriSP10/streamlit_login_auth_ui
