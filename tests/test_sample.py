from streamlit_login_auth_ui.utils import check_unique_username
from streamlit_login_auth_ui.utils import check_username_and_password
from streamlit_login_auth_ui.utils import check_valid_username
from streamlit_login_auth_ui.utils import check_email_exists
from streamlit_login_auth_ui.utils import check_unique_email
from streamlit_login_auth_ui.utils import check_email_and_password
from streamlit_login_auth_ui.utils import check_valid_password


def test_unique_username_1(username='smith', users_auth_file='./tests/users.json'):
    """Returns False"""
    assert not check_unique_username(username, users_auth_file, None)


def test_unique_username_2(username='peter', users_auth_file='./tests/users.json'):
    """Returns True"""
    assert check_unique_username(username, users_auth_file, None)


def test_check_usr_pass_1(username='smith', password='door_5954', users_auth_file='./tests/users.json'):
    """Returns True"""
    assert check_username_and_password(username, password, users_auth_file, None)


def test_check_usr_pass_2(username='Smith', password='door_5954', users_auth_file='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns True because username check is case insensitive. smith is the one 
    registered in users.json. The one we are checking is Smith with capital S.
    smith and Smith are the same person.
    """
    assert check_username_and_password(username, password, users_auth_file, None)


def test_check_usr_pass_3(username='Will', password='door_5954', users_auth_file='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns False because Will username does not exist in users.json.    
    """
    assert not check_username_and_password(username, password, users_auth_file, None)


def test_check_usr_pass_4(username='smith', password='window_5954', users_auth_file='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns False because password window_5954 is incorrect for smith username.
    """
    assert not check_username_and_password(username, password, users_auth_file, None)


def test_check_valid_username_1(username: str = ' peace'):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "leading white space"
    """
    assert check_valid_username(username) == "leading white space"


def test_check_valid_username_2(username: str = 'peace '):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "trailing white space"
    """
    assert check_valid_username(username) == "trailing white space"


def test_check_valid_username_3(username: str = 'peace man'):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "more than 1 word"
    """
    assert check_valid_username(username) == "more than 1 word"


def test_check_valid_username_4(username: str = 'believe?'):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "not alpha-numeric"
    """
    assert check_valid_username(username) == "not alpha-numeric"


def test_check_valid_username_5(username: str = 'nia'):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "number of characters is below 4"
    """
    assert check_valid_username(username) == "number of characters is below 4"


def test_check_valid_username_6(username: str = 'dieseltoyotamobilemars'):
    """Checks if username is valid.

    Args:
        username: The username to check if valid.

    Returns:
        "number of characters is above 16"
    """
    assert check_valid_username(username) == "number of characters is above 16"


def test_check_email_exists_1(email='smithjudgematter58@gmail.com',
                              users_auth_file='./tests/users.json'):
    """Checks email if it exists."""
    status, _ = check_email_exists(email, users_auth_file, None)
    assert status  # returns True


def test_check_unique_email_1(email='smithjudgematter58@gmail.com',
                              users_auth_file='./tests/users.json'):
    """Returns False meaning the email had already existed."""
    assert not check_unique_email(email, users_auth_file, None)


def test_check_unique_email_2(email='diego_1285khyub@gmail.com',
                              users_auth_file='./tests/users.json'):
    """Returns True meaning email has not yet existed in users auth file."""
    assert check_unique_email(email, users_auth_file, None)


def test_check_email_and_password_1(email='gggg@gmail.com',
                                    password='gggg',
                                    users_auth_file='./tests/users.json'):
    """Checks email and password.

    This will return True because the email gggg@gmail.com has gggg
    password in users auth file users.json.    
    """
    assert check_email_and_password(email, password, users_auth_file, None)


def test_check_valid_password_1(password="Judge582yt"):
    assert check_valid_password(password) == 'valid'


def test_check_valid_password_2(password=" Jloe25"):
    assert check_valid_password(password) == 'there is whitespace'


def test_check_valid_password_3(password="mmP58"):
    assert check_valid_password(password) == 'number of characters is below 8'


def test_check_valid_password_3(password="mkLjudfeft256dfdrefmkded5fedf!fdrefdf>ldrefdrefodkfdfdrefdf2dfe5dferd8"):
    assert check_valid_password(password) == 'number of characters is above 64'
