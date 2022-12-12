from streamlit_login_auth_ui.utils import is_empty, check_unique_usr


def test_empty_username_1(username=' '):
    assert is_empty(username)


def test_empty_username_2(username='  '):
    assert is_empty(username)


def test_empty_username_3(username='john'):
    assert not is_empty(username)


def test_unique_username_1(username='smith', users_info='./tests/users.json'):
    """Returns False"""
    assert not check_unique_usr(username, users_info)


def test_unique_username_2(username='', users_info='./tests/users.json'):
    """Returns None"""
    assert check_unique_usr(username, users_info) is None


def test_unique_username_3(username='peter', users_info='./tests/users.json'):
    """Returns True"""
    assert check_unique_usr(username, users_info)
