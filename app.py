import streamlit as st
from streamlit_login_auth_ui.widgets import __login__
from streamlit_login_auth_ui.mydeta import deta_db


# Defaults
db = None  # not using deta bases
users_auth_file = '_secret_auth_.json'
auth_token = 'courier_auth_token'  # Cannot reset password

######## USERS AUTH FILE ########
# Where to save the users auth file?

# 1.1 Save users auth file in deta bases cloud
# Developer should register at https://www.deta.sh/. Create project and
# get project key. There is free deta bases.

# deta_project_key = st.secrets['Deta_Project_Key']  # comment it if you don't use it
# deta_db_name = st.secrets['Deta_Db_Name']  # comment it if you don't use it
# db = deta_db(deta_project_key, deta_db_name)  # comment it if you don't use it

# 1.2 Save users auth file locally or cloud (not reliable) from secrets.toml
# users_auth_file = st.secrets['secrets_users_auth_file']

######## COURIER AUTH TOKEN ########
# This is used to reset password if forgotten.

# 2.1 Use real courier auth token
# Don't show it.
# Can reset password. Developer should register at https://www.courier.com/.
# There is free tier.
auth_token = st.secrets['secrets_courier_auth_token']  # comment it if you don't use it

# If True, only login widget is enabled. Users cannot register, etc. but can
# login with username and password.
is_only_login = False

# cookie_password = st.secrets['cookie_password']
# cookie_prefix = st.secrets['cookie_predix']

__login__obj = __login__(
    auth_token=auth_token,
    company_name="Shims",
    width=200,
    height=250,
    logout_button_name='Logout',
    hide_menu_bool=False,
    hide_footer_bool=False,
    lottie_url='https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json',
    users_auth_file=users_auth_file,
    is_disable_login=False,
    detadb=db,
    is_only_login=is_only_login,
    # cookie_password=cookie_password,
    # cookie_prefix=cookie_prefix
)

is_logged_in = __login__obj.build_login_ui()

if is_logged_in:
    st.markdown("Your Streamlit Application Begins here!")
    username = __login__obj.get_username()
    st.markdown(st.session_state)
    st.write(username)
