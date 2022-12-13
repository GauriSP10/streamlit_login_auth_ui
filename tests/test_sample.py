from streamlit_login_auth_ui.utils import check_unique_usr, check_usr_pass


def test_unique_username_1(username='smith', users_info='./tests/users.json'):
    """Returns False"""
    assert not check_unique_usr(username, users_info)


def test_unique_username_2(username='peter', users_info='./tests/users.json'):
    """Returns True"""
    assert check_unique_usr(username, users_info)


def test_check_usr_pass_1(username='smith', password='door_5954', users_info='./tests/users.json'):
    """Returns True"""
    assert check_usr_pass(username, password, users_info)


def test_check_usr_pass_2(username='Smith', password='door_5954', users_info='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns True because username check is case insensitive. smith is the one 
    registered in users.json. The one we are checking is Smith with capital S.
    smith and Smith are the same person.
    """
    assert check_usr_pass(username, password, users_info)


def test_check_usr_pass_3(username='Will', password='door_5954', users_info='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns False because Will username does not exist in users.json.    
    """
    assert not check_usr_pass(username, password, users_info)


def test_check_usr_pass_4(username='smith', password='window_5954', users_info='./tests/users.json'):
    """Checks if username and password is in the users.json.

    It returns False because password window_5954 is incorrect for smith username.
    """
    assert not check_usr_pass(username, password, users_info)
