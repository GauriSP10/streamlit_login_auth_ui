
HOW TO INSTALL ALL LIBRARIES:
python3.10 -m venv venv
source venv/bin/activate
python3.10 -m pip install -r requirement.txt

# Streamlit Login/ Sign Up Library   [![Downloads](https://static.pepy.tech/personalized-badge/streamlit-login-auth-ui?period=month&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/streamlit-login-auth-ui)

The streamlit_login_auth_ui library is meant for streamlit application developers.
It lets you connect your streamlit application to a pre-built and secure Login/ Sign-Up page.

You can customize specific parts of the page without any hassle!

The library grants users an option to reset their password, users can click on ```Forgot Password?``` after which an Email is triggered containing a temporary, randomly generated password.

The library also sets encrypted cookies to remember and automatically authenticate the users without password. \
The users can logout using the ```Logout``` button.


## Authors
- [@gauriprabhakar](https://github.com/GauriSP10)

## PyPi
https://pypi.org/project/streamlit-login-auth-ui/

## The UI:
![login_streamlit](https://user-images.githubusercontent.com/75731631/185765909-a70dd7af-240d-4a90-9140-45d6292e76f0.png)
 
## Installation

```python
pip install streamlit-login-auth-ui
```

## How to implement the library?

To import the library, just paste this at the starting of the code:
```python
from streamlit_login_auth_ui.widgets import __login__
```

All you need to do is create an object for the ```__login__``` class and pass the following parameters:
1. auth_token : The unique authorization token received from - https://www.courier.com/email-api/
2. company_name : This is the name of the person/ organization which will send the password reset email.
3. width : Width of the animation on the login page.
4. height : Height of the animation on the login page.
5. logout_button_name : The logout button name.
6. hide_menu_bool : Pass True if the streamlit menu should be hidden.
7. hide_footer_bool : Pass True if the 'made with streamlit' footer should be hidden.
8. lottie_url : The lottie animation you would like to use on the login page. Explore animations at - https://lottiefiles.com/featured

#### Mandatory Arguments:
* ```auth_token```
* ```company_name```
* ```width```
* ```height```

#### Non Mandatory Arguments:
* ```logout_button_name```     [default = 'Logout']
* ```hide_menu_bool```         [default = False]
* ```hide_footer_bool```       [default = False]
* ```lottie_url```             [default = https://assets8.lottiefiles.com/packages/lf20_ktwnwv5m.json]

After doing that, just call the ```build_login_ui()``` function using the object you just created and store the return value in a variable.

# Example:
```python
import streamlit as st
from streamlit_login_auth_ui.widgets import __login__

__login__obj = __login__(auth_token = "courier_auth_token", 
                    company_name = "Shims",
                    width = 200, height = 250, 
                    logout_button_name = 'Logout', hide_menu_bool = False, 
                    hide_footer_bool = False, 
                    lottie_url = 'https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json')

LOGGED_IN = __login__obj.build_login_ui()

if LOGGED_IN == True:

    st.markown("Your Streamlit Application Begins here!")
```

That's it! The library handles the rest. \
Just make sure you call/ build your application indented under ```if st.session_state['LOGGED_IN'] == True:```, this guarantees that your application runs only after the user is securely logged in. 

## Explanation
### Login page
The login page, authenticates the user.

### Create Account page
Stores the user info in a secure way in the ```_secret_auth_.json``` file. \
![create_account_streamlit](https://user-images.githubusercontent.com/75731631/185765826-3bb5d2ca-c549-46ff-bf14-2cc42d295588.png)

### Forgot Password page
After user authentication (email), triggers an email to the user containing a random password. \
![forgot_password_streamlit](https://user-images.githubusercontent.com/75731631/185765851-18db4775-b1f0-4cfe-86a7-93bda88227dd.png)

### Reset Password page
After user authentication (email and the password shared over email), resets the password and updates the same \
in the ```_secret_auth_.json``` file. \
![reset_password_streamlit](https://user-images.githubusercontent.com/75731631/185765859-a0cf45b0-bfa4-489d-8060-001a9372843a.png)

### Logout button
Generated in the sidebar only if the user is logged in, allows users to logout. \
![logout_streamlit](https://user-images.githubusercontent.com/75731631/185765879-dbe17dda-93e3-4417-b5fc-5ce1d4dc8ecc.png)

__Cookies are automatically created and destroyed depending on the user authentication status.__

## Version
v0.2.0

## License
[MIT](https://github.com/GauriSP10/streamlit_login_auth_ui/blob/main/LICENSE)






