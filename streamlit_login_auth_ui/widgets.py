from typing import Optional
import json
import os

import streamlit as st
from streamlit_lottie import st_lottie
from streamlit_option_menu import option_menu
from streamlit_cookies_manager import EncryptedCookieManager
from .utils import check_username_and_password
from .utils import load_lottieurl
from .utils import check_valid_name
from .utils import check_valid_email
from .utils import check_unique_email
from .utils import check_unique_username
from .utils import register_new_user
from .utils import check_email_exists
from .utils import generate_random_passwd
from .utils import send_passwd_in_email
from .utils import change_passwd
from .utils import check_email_and_password
from .utils import check_valid_username, check_valid_password
from .utils import get_users_data
import deta
from typing import NewType

DetaDbType = NewType('DetaDbType', deta.base._Base)


class __login__:
    """
    Builds the UI for the Login/ Sign Up page.
    """

    def __init__(
        self, auth_token: str, company_name: str, width, height,
        logout_button_name: str = 'Logout', hide_menu_bool: bool = False,
        hide_footer_bool: bool = False,
        lottie_url: str = "https://assets8.lottiefiles.com/packages/lf20_ktwnwv5m.json",
        users_auth_file='_secret_auth_.json',
        is_disable_login: bool = False,
        detadb: Optional[DetaDbType] = None,
        is_only_login: bool = False,
        cookie_password: str = '9d68d6f2-4258-45c9-96eb-2d6bc74ddbb5-d8f49cab-edbb-404a-94d0-b25b1d4a564b',
        cookie_prefix: str = 'streamlit_login_ui_yummy_cookies'):
        """
        Arguments:
        -----------
        1. self
        2. auth_token : The unique authorization token received from - https://www.courier.com/email-api/
        3. company_name : This is the name of the person/ organization which will send the password reset email.
        4. width : Width of the animation on the login page.
        5. height : Height of the animation on the login page.
        6. logout_button_name : The logout button name.
        7. hide_menu_bool : Pass True if the streamlit menu should be hidden.
        8. hide_footer_bool : Pass True if the 'made with streamlit' footer should be hidden.
        9. lottie_url : The lottie animation you would like to use on the login page. Explore animations at - https://lottiefiles.com/featured
        10. users_auth_file : The json file where registered users info are saved.
        11. is_disable_login : Disables username and password widget and allow the user to login without those.
        12. detadb : Deta database
        13. is_only_login : Only login widget is usable, others are disabled.
        14. cookie_password : Cookie password
        15. cookie_prefix : Cookie prefix
        """
        self.auth_token = auth_token
        self.company_name = company_name
        self.width = width
        self.height = height
        self.logout_button_name = logout_button_name
        self.hide_menu_bool = hide_menu_bool
        self.hide_footer_bool = hide_footer_bool
        self.lottie_url = lottie_url
        self.users_auth_file = users_auth_file
        self.is_disable_login = is_disable_login
        self.detadb = detadb
        self.is_only_login = is_only_login
        self.cookie_password = cookie_password
        self.cookie_password = cookie_prefix

        self.cookies = EncryptedCookieManager(
            prefix=cookie_prefix,
            password=self.cookie_password)

        if not self.cookies.ready():
            st.stop()


    def check_auth_json_file_exists(self) -> bool:
        """
        Checks if the auth file (where the user info is stored) already exists.
        """
        file_names = []
        for path in os.listdir('./'):
            if os.path.isfile(os.path.join('./', path)):
                file_names.append(path)

        present_files = []
        for file_name in file_names:
            if self.users_auth_file in file_name:
                present_files.append(file_name)

            present_files = sorted(present_files)
            if len(present_files) > 0:
                return True
        return False

    def get_username(self) -> Optional[str]:
        """Gets username of the user who logged in.

        Returns:
            username or None
        """
        if not st.session_state['LOGOUT_BUTTON_HIT']:
            fetched_cookies = self.cookies
            if '__streamlit_login_signup_ui_username__' in fetched_cookies.keys():
                username = fetched_cookies['__streamlit_login_signup_ui_username__']
                return username
        return None
 

    def login_widget(self) -> None:
        """
        Creates the login widget, checks and sets cookies, authenticates the users.
        """

        # Checks if cookie exists.
        if not st.session_state['LOGGED_IN']:
            if not st.session_state['LOGOUT_BUTTON_HIT']:
                fetched_cookies = self.cookies
                if '__streamlit_login_signup_ui_username__' in fetched_cookies.keys():
                    if fetched_cookies['__streamlit_login_signup_ui_username__'] != '1c9a923f-fb21-4a91-b3f3-5f18e3f01182':
                        st.session_state['LOGGED_IN'] = True

        if not st.session_state['LOGGED_IN']:
            st.session_state['LOGOUT_BUTTON_HIT'] = False 

            del_login = st.empty()
            with del_login.form("Login Form"):
                username = st.text_input(
                    "Username",
                    placeholder='Your unique username',
                    disabled=self.is_disable_login)
                password = st.text_input(
                    "Password",
                    placeholder='Your password',
                    type='password',
                    disabled=self.is_disable_login)

                st.markdown("###")
                login_submit_button = st.form_submit_button(label='Login')

                if login_submit_button:
                    authenticate_user_check = check_username_and_password(
                        username, password, self.users_auth_file, self.detadb)

                    if not authenticate_user_check and not self.is_disable_login:
                        st.error("Invalid Username or Password!")
                    else:
                        st.session_state['LOGGED_IN'] = True
                        self.cookies['__streamlit_login_signup_ui_username__'] = username
                        self.cookies.save()
                        del_login.empty()
                        st.experimental_rerun()


    def delete_accnt_widget(self) -> None:
        """Deletes user account.

        Creates the delete account widget, authenticates the users with
        username and password before deleting the user account from file.
        """
        with st.form("Delete Account Form", clear_on_submit=True):
            username = st.text_input(
                "Username",
                placeholder='Your unique username',
                disabled=self.is_only_login
            )
            password = st.text_input(
                "Password",
                placeholder='Your password',
                type='password',
                disabled=self.is_only_login
            )

            st.markdown("###")
            delete_submit_button = st.form_submit_button(label='Delete Account')

            if delete_submit_button:
                is_valid_user = check_username_and_password(
                    username, password, self.users_auth_file, self.detadb)

                if not is_valid_user:
                    st.error("Invalid Username or Password!")
                else:
                    is_user_deleted = False

                    # Delete user from deta base.
                    if self.detadb is not None:
                        user: dict = self.detadb.get(username.lower())  # deta key is lower case
                        if len(user):
                            self.detadb.delete(username.lower())  # deta key is lower case
                            is_user_deleted = True
                    else:
                        authorized_users_data = get_users_data(self.users_auth_file)

                        # Save users who are not to be deleted.
                        updated_users = [user for user in authorized_users_data if user['username'] != username]

                        with open(self.users_auth_file, "w") as auth_json_write:
                            json.dump(updated_users, auth_json_write)
                        is_user_deleted = True

                    if is_user_deleted:
                        st.success("Account is successfully deleted!")


    def animation(self) -> None:
        """
        Renders the lottie animation.
        """
        lottie_json = load_lottieurl(self.lottie_url)
        st_lottie(lottie_json, width=self.width, height=self.height)


    def sign_up_widget(self) -> None:
        """
        Creates the sign-up widget and stores the user info in a secure way in the users_auth_file.
        """
        with st.form("Sign Up Form"):
            name_sign_up = st.text_input(
                "Name *",
                placeholder='Please enter your name',
                disabled=self.is_only_login
            )
            email_sign_up = st.text_input(
                "Email *",
                placeholder='Please enter your email',
                disabled=self.is_only_login
            )
            username_sign_up = st.text_input(
                "Username *",
                placeholder='Enter a unique username',
                help='Minimum character is 4, maximum is 16, no whitespace, case insensitive.',
                disabled=self.is_only_login
            )
            password_sign_up = st.text_input(
                "Password *",
                placeholder='Create a strong password',
                type='password',
                help='Minimum character is 8, maximum is 64, and no whitespace.',
                disabled=self.is_only_login
            )
            st.markdown("###")
            sign_up_submit_button = st.form_submit_button(label='Register')

            if sign_up_submit_button:
                is_registration_ok = True

                valid_name_check = check_valid_name(name_sign_up)
                valid_email_check = check_valid_email(email_sign_up)
                unique_email_check = check_unique_email(email_sign_up, self.users_auth_file, self.detadb)
                valid_username_message = check_valid_username(username_sign_up)
                unique_username_check = check_unique_username(username_sign_up, self.users_auth_file, self.detadb)
                valid_password_check = check_valid_password(password_sign_up)

                if not valid_name_check:
                    st.error("Please enter a valid name!")
                    is_registration_ok = False

                elif not valid_email_check:
                    st.error("Please enter a valid Email!")
                    is_registration_ok = False

                elif not unique_email_check:
                    st.error("Email already exists!")
                    is_registration_ok = False

                elif valid_username_message != 'valid':
                    st.error(f"Username is invalid -> {valid_username_message}")
                    is_registration_ok = False

                elif not unique_username_check:
                    st.error(f'Sorry, username {username_sign_up} already exists!')
                    is_registration_ok = False

                elif valid_password_check != 'valid':
                    st.error(f'password is invalid -> {valid_password_check}')
                    is_registration_ok = False

                if is_registration_ok:
                    register_new_user(name_sign_up, email_sign_up, username_sign_up, password_sign_up, self.users_auth_file, self.detadb)                    
                    st.success("Registration Successful!")


    def forgot_password(self) -> None:
        """Creates the forgot password widget.
        
        Asks the user's email for password reset. If courier auth token is
        defined by the developer, and email will be sent to the user which
        contains a random password to be used for resetting the password.

        Returns:
            None
        """
        with st.form("Forgot Password Form"):
            email_forgot_passwd = st.text_input(
                "Email",
                placeholder='Please enter your email',
                disabled=self.is_only_login
            )

            st.markdown("###")
            forgot_passwd_submit_button = st.form_submit_button(label='Get Password')

            if forgot_passwd_submit_button:
                email_exists_check, username_forgot_passwd = check_email_exists(email_forgot_passwd, self.users_auth_file, self.detadb)
                
                if not email_exists_check:
                    st.error("Email ID not registered with us!")

                if email_exists_check:
                    random_password = generate_random_passwd()

                    res = send_passwd_in_email(
                        self.auth_token,
                        username_forgot_passwd,
                        email_forgot_passwd,
                        self.company_name,
                        random_password)
                    if res == 'OK':
                        change_passwd(email_forgot_passwd, random_password, self.users_auth_file, self.detadb)
                        st.success("Secure Password Sent Successfully!")
                    else:
                        st.error(f"Failed to send email!, {res.message}")


    def reset_password(self) -> None:
        """
        Creates the reset password widget and after user authentication (email and the password shared over that email), 
        resets the password and updates the same in the users auth file.
        """
        with st.form("Reset Password Form"):
            email_reset_passwd = st.text_input(
                "Email",
                placeholder='Please enter your email',
                disabled=self.is_only_login
            )
            current_passwd = st.text_input(
                "Temporary Password",
                placeholder='Please enter the password you received in the email',
                disabled=self.is_only_login
            )
            new_passwd = st.text_input(
                "New Password",
                placeholder='Please enter a new, strong password',
                type='password',
                disabled=self.is_only_login
            )
            new_passwd_1 = st.text_input(
                "Re - Enter New Password",
                placeholder='Please re- enter the new password',
                type='password',
                disabled=self.is_only_login
            )

            st.markdown("###")
            reset_passwd_submit_button = st.form_submit_button(label='Reset Password')

            if reset_passwd_submit_button:
                email_exists_check, username_reset_passwd = check_email_exists(email_reset_passwd, self.users_auth_file, self.detadb)
                current_passwd_check = check_email_and_password(email_reset_passwd, current_passwd, self.users_auth_file, self.detadb)

                if not email_exists_check:
                    st.error("Email does not exist!")

                elif not current_passwd_check:
                    st.error("Incorrect temporary password!")

                elif new_passwd != new_passwd_1:
                    st.error("Passwords don't match!")

                if email_exists_check:
                    if current_passwd_check:
                        change_passwd(email_reset_passwd, new_passwd, self.users_auth_file, self.detadb)
                        st.success("Password Reset Successfully!")
                

    def logout_widget(self) -> None:
        """
        Creates the logout widget in the sidebar only if the user is logged in.
        """
        if st.session_state['LOGGED_IN']:
            del_logout = st.sidebar.empty()
            del_logout.markdown("#")
            logout_click_check = del_logout.button(self.logout_button_name)

            if logout_click_check:
                st.session_state['LOGOUT_BUTTON_HIT'] = True
                st.session_state['LOGGED_IN'] = False
                self.cookies['__streamlit_login_signup_ui_username__'] = '1c9a923f-fb21-4a91-b3f3-5f18e3f01182'
                del_logout.empty()
                st.experimental_rerun()
        

    def nav_sidebar(self):
        """
        Creates the side navigaton bar
        """
        main_page_sidebar = st.sidebar.empty()
        with main_page_sidebar:
            selected_option = option_menu(
                menu_title='Navigation',
                menu_icon='list-columns-reverse',
                icons=['box-arrow-in-right', 'person-plus', 'x-circle','arrow-counterclockwise', 'trash'],
                options=['Login', 'Create Account', 'Forgot Password?', 'Reset Password', 'Delete Account'],
                styles={
                    "container": {"padding": "5px"},
                    "nav-link": {"font-size": "14px", "text-align": "left", "margin": "0px"}})
        return main_page_sidebar, selected_option


    def hide_menu(self) -> None:
        """
        Hides the streamlit menu situated in the top right.
        """
        st.markdown(""" <style>
        #MainMenu {visibility: hidden;}
        </style> """, unsafe_allow_html=True)


    def hide_footer(self) -> None:
        """
        Hides the 'made with streamlit' footer.
        """
        st.markdown(""" <style>
        footer {visibility: hidden;}
        </style> """, unsafe_allow_html=True)


    def build_login_ui(self):
        """
        Brings everything together, calls important functions.
        """
        if 'LOGGED_IN' not in st.session_state:
            st.session_state['LOGGED_IN'] = False

        if 'LOGOUT_BUTTON_HIT' not in st.session_state:
            st.session_state['LOGOUT_BUTTON_HIT'] = False

        # If we are using deta bases, do not create a local users auth file
        # like __secret_auth__.json, etc.
        if self.detadb is None:
            auth_json_exists_bool = self.check_auth_json_file_exists()
            if not auth_json_exists_bool:
                with open(self.users_auth_file, "w") as auth_json:
                    json.dump([], auth_json)

        main_page_sidebar, selected_option = self.nav_sidebar()

        if selected_option == 'Login':
            c1, c2 = st.columns([7, 3])
            with c1:
                self.login_widget()
            with c2:
                if not st.session_state['LOGGED_IN']:
                    self.animation()

        if selected_option == 'Create Account':
            self.sign_up_widget()

        if selected_option == 'Forgot Password?':
            self.forgot_password()

        if selected_option == 'Reset Password':
            self.reset_password()

        if selected_option == 'Delete Account':
            c1, c2 = st.columns([7, 3])
            with c1:
                self.delete_accnt_widget()
            with c2:
                self.animation()

        self.logout_widget()

        if st.session_state['LOGGED_IN']:
            main_page_sidebar.empty()

        if self.hide_menu_bool:
            self.hide_menu()

        if self.hide_footer_bool:
            self.hide_footer()

        return st.session_state['LOGGED_IN']

# Author: Gauri Prabhakar
# GitHub: https://github.com/GauriSP10/streamlit_login_auth_ui
