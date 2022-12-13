import streamlit as st
from streamlit_login_auth_ui.widgets import __login__

__login__obj = __login__(
   auth_token = "courier_auth_token",
   company_name = "Shims",
   width = 200, height = 250,
   logout_button_name = 'Logout',
   hide_menu_bool = False,
   hide_footer_bool = False,
   lottie_url = 'https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json')

is_logged_in = __login__obj.build_login_ui()

if is_logged_in:
   st.markdown("Your Streamlit Application Begins here!")
   username = __login__obj.get_username()   
   st.markdown(st.session_state)
   st.write(username)
