from typing import Union, Optional
import re
import json
import secrets

from trycourier import Courier
from argon2 import PasswordHasher
import requests
from trycourier.exceptions import CourierAPIException
import deta
from typing import NewType

DetaDbType = NewType('DetaDbType', deta.base._Base)


ph = PasswordHasher()


def get_users_data(users_auth_file: str) -> list[dict]:
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


def check_username_and_password(
        username: str, password: str, users_auth_file: str,
        detadb: Optional[DetaDbType]) -> bool:
    """Authenticates the username and password.

    If detadb is used, check username and password from detadb. The username
    is case insensitive.

    Args:
       username: The username of user.
       password: The password of user.
       users_auth_file: The json file where users info are saved.
       detadb: The pointer to the deta base.

    Returns:
        True if username and password are valid otherwise False.
    """
    if detadb is not None:
        if len(username) and len(password):
            user: dict = detadb.get(username.lower())  # deta key is lower case
            if user is None:
                return False

            try:
                is_password_ok = ph.verify(user['password'], password)
            except:
                pass
            else:
                if is_password_ok:
                    return True

    # Else read json file.
    else:
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


def check_unique_email(email: str, users_auth_file: str, detadb: Optional[DetaDbType]) -> bool:
    """Checks if email is not in users auth file or deta base.

    Lookup the email in the user auth file or in deta base. The email is
    case insensitive.

    Args:
        email: The email to check in users auth file or deta base.
        users_auth_file: The json file where users info are saved.
        detadb: The database pointer that can query the deta base.

    Returns:
        True if not found in users auth file or deta base otherwise False.
    """
    # Check username in deta base
    if detadb is not None:
        if len(email):
            res = detadb.fetch({'email': email.lower()})  # email in deta is in lower case
            users: list[dict] = res.items
            if len(users):
                return False

    # Else read json file.
    else:
        is_existing, _ = check_email_exists(email, users_auth_file, detadb)
        if is_existing:
            return False
    return True


def check_valid_password(password: str) -> str:
    """Checks if password is valid.

    1. password with whitespace is invalid.
    The following sample passwords are invalid.
    password = " kul89_mkou"
    password = "smith kul89_mkou"
    password = "covid19 "

    2. If length is below 8 it is invalid.
    password = "Kb584"

    3. If length is above 64 it is invalid.

    Args:
        password: The password to check.

    Returns:
        valid if password is valid otherwise a string about the issue.
        It can be 'there is whitespace', 'number of characters is below 8',
        'number of characters is above 64'.
    """
    if password.count(' ') >= 1:
        return 'there is whitespace'

    if len(password) < 8:
        return 'number of characters is below 8'

    if len(password) > 64:
        return 'number of characters is above 64'

    return 'valid'


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


def check_unique_username(username_sign_up: str, users_auth_file: str, detadb: Optional[DetaDbType]) -> bool:
    """Checks if the username is in users auth file or deta base.

    If detadb is specified, we look into the cloud deta base. If not we will
    search if username is in json file. The username check is case insensitive
    meaning "smith" and "Smith" are the same.

    Args:
        username_sign_up: The username to check in users file.
        users_auth_file: The file where all the users info are recorded.
        detadb: The database pointer that can query the deta base.

    Returns:
        True if username is not in users file.
        False if username is already existing.
    """
    # Check username in deta base
    if detadb is not None:
        if len(username_sign_up):
            user: dict = detadb.get(username_sign_up.lower())  # deta key is lower case
            if user is not None:
                return False

    # Else read json file.
    else:
        authorized_user_data_master = list()
        authorized_users_data = get_users_data(users_auth_file)

        for user in authorized_users_data:
            authorized_user_data_master.append(user['username'].lower())

        if username_sign_up.lower() in authorized_user_data_master:
            return False
    return True


def register_new_user(name_sign_up: str, email_sign_up: str,
                      username_sign_up: str, password_sign_up:
                      str, users_auth_file: str,
                      detadb: Optional[DetaDbType]) -> None:
    """Saves new user info in the users_auth_file or in deta base.

    username and email are converted to lowercase before saving.
    """
    username_sign_up = username_sign_up.lower()
    email_sign_up = email_sign_up.lower()

    new_usr_data = {'username': username_sign_up,
                    'name': name_sign_up,
                    'email': email_sign_up,
                    'password': ph.hash(password_sign_up)}

    # Save to deta db.
    if detadb is not None:
        detadb.insert(new_usr_data, key=username_sign_up)

    # Else save it to default users auth json file.
    else:
        authorized_users_data = get_users_data(users_auth_file)
        authorized_users_data.append(new_usr_data)

        with open(users_auth_file, "w") as auth_json_write:
            json.dump(authorized_users_data, auth_json_write)


def check_email_exists(email: str, users_auth_file: str, detadb: Optional[DetaDbType]) -> tuple[bool, Optional[str]]:
    """Checks if email is present in the users auth file or in deta base.

    Read the users auth file and check if email is present. Email
    checking is case insensitive.

    Args:
        email: The email to check in users auth file.
        users_auth_file: The json file where users info are saved.
        detadb: A pointer to handle deta base functionalities.

    Returns:
        A tuple of bool and str or None. If email is present return
        (True, username) otherwise return (False, None).
    """
    email = email.lower()

    # Check email in deta base
    if detadb is not None:
        if len(email):
            res = detadb.fetch({'email': email})
            users: list[dict] = res.items
            for user in users:
                return True, user['username']

    # Else check email from json file.
    else:
        authorized_users_data = get_users_data(users_auth_file)
        for user in authorized_users_data:
            if user['email'] == email:
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


def change_passwd(email: str, random_password: str, users_auth_file: str, detadb: Optional[DetaDbType]) -> None:
    """
    Replaces the old password with the newly generated password.

    Args:
        email: The user email connected to the password to be changed.
        random_password: A password to save.
        users_auth_file: The json file where users info are saved.
        detadb: A pointer to handle deta base functionalities.

    Returns:
        None
    """
    email = email.lower()

    # Check email and password in deta base
    if detadb is not None:
        if len(email) and len(random_password):
            res = detadb.fetch({'email': email})
            users: list[dict] = res.items
            for user in users:
                if user['email'] == email:
                    hashed_password = ph.hash(random_password)
                    user_update = {
                        'password': hashed_password
                    }
                    detadb.update(user_update, user['username'])
                    break

    # Else read json file.
    else:
        authorized_users_data = get_users_data(users_auth_file)

        for user in authorized_users_data:
            if user['email'] == email:
                user['password'] = ph.hash(random_password)
                break

        with open(users_auth_file, "w") as auth_json_:
            json.dump(authorized_users_data, auth_json_)


def check_email_and_password(email: str, password: str, users_auth_file: str, detadb: Optional[DetaDbType]) -> bool:
    """Checks the email and password.

    Read the users auth file or deta base and check if email owns the password.
    This is used when user resets the password.

    Args:
        email: The user email.
        password: The password owned by email.
        users_auth_file: The json file where users info are saved.
        detadb: A pointer to handle deta base functionalities.

    Returns:
       True if email owns the password otherwise False.
    """
    email = email.lower()

    # Check email and password in deta base
    if detadb is not None:
        if len(email) and len(password):
            res = detadb.fetch({'email': email})
            users: list[dict] = res.items
            if len(users) and users[0]['email'] == email:
                try:
                    if ph.verify(users[0]['password'], password):
                        return True
                except:
                    return False

    # Else read json file.
    else:
        authorized_users_data = get_users_data(users_auth_file)

        for user in authorized_users_data:
            if user['email'] == email:
                try:
                    if ph.verify(user['password'], password):
                        return True
                except:
                    pass
    return False

# Author: Gauri Prabhakar
# GitHub: https://github.com/GauriSP10/streamlit_login_auth_ui
