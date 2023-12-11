"""Module for handling authentication, interactions with Firebase and JWT cookies.

This solution is refactored from the ‘streamlit_authenticator’ package . It leverages JSON
Web Token (JWT) cookies to maintain the user’s login state across browser sessions. For the
backend, It uses Google’s Firebase Admin Python SDK. This solution ensures that the content
of the page and user settings panel are only displayed if the user is authenticated. Similarly,
the login page can only be accessed if the user is not authenticated. Upon registration, the
user is sent a verification link to their e-mail address.
Important - to make this app run, put the following variables in your secrets.toml file:
COOKIE_KEY - a random string key for your passwordless reauthentication
FIREBASE_API_KEY - Key for your Firebase API (how to find it -
https://firebase.google.com/docs/projects/api-keys#find-api-keys
)
firebase_auth_token - Information extracted from Firebase login token JSON (how to get one -
https://firebase.google.com/docs/admin/setup#initialize_the_sdk_in_non-google_environments
)
"""

import math
import time
from contextlib import suppress
from datetime import datetime, timedelta
from functools import partial
from typing import Dict, Final, Optional, Sequence, Union

import extra_streamlit_components as stx
import firebase_admin
import jwt
import requests
import streamlit as st
from email_validator import EmailNotValidError, validate_email
from firebase_admin import auth

TITLE: Final = "Example app"

POST_REQUEST_URL_BASE: Final = "https://identitytoolkit.googleapis.com/v1/accounts:"
post_request = partial(
    requests.post,
    headers={"content-type": "application/json; charset=UTF-8"},
    timeout=10,
)
success = partial(st.success, icon="✅")
error = partial(st.error, icon="🚨")


def pretty_title(title: str) -> None:
    """Make a centered title, and give it a red line. Adapted from
    'streamlit_extras.colored_headers' package.
    Parameters:
    -----------
    title : str
        The title of your page.
    """
    st.markdown(
        f"<h2 style='text-align: center'>{title}</h2>",
        unsafe_allow_html=True,
    )
    st.markdown(
        (
            '<hr style="background-color: #ff4b4b; margin-top: 0;'
            ' margin-bottom: 0; height: 3px; border: none; border-radius: 3px;">'
        ),
        unsafe_allow_html=True,
    )


def parse_error_message(response: requests.Response) -> str:
    """
    Parses an error message from a requests.Response object and makes it look better.

    Parameters:
        response (requests.Response): The response object to parse.

    Returns:
        str: Prettified error message.

    Raises:
        KeyError: If the 'error' key is not present in the response JSON.
    """
    return (
        response.json()["error"]["message"]
        .casefold()
        .replace("_", " ")
        .replace("email", "e-mail")
    )


def authenticate_user(
    email: str, password: str, require_email_verification: bool = True
) -> Optional[Dict[str, Union[str, bool, int]]]:
    """
    Authenticates a user with the given email and password using the Firebase Authentication
    REST API.

    Parameters:
        email (str): The email address of the user to authenticate.
        password (str): The password of the user to authenticate.
        require_email_verification (bool): Specify whether a user has to be e-mail verified to
        be authenticated

    Returns:
        dict or None: A dictionary containing the authenticated user's ID token, refresh token,
        and other information, if authentication was successful. Otherwise, None.

    Raises:
        requests.exceptions.RequestException: If there was an error while authenticating the user.
    """

    url = f"{POST_REQUEST_URL_BASE}signInWithPassword?key={st.secrets['FIREBASE_API_KEY']}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
        "emailVerified": require_email_verification,
    }
    response = post_request(url, json=payload)
    if response.status_code != 200:
        error(f"Authentication failed: {parse_error_message(response)}")
        return None
    response = response.json()
    if require_email_verification and "idToken" not in response:
        error("Invalid e-mail or password.")
        return None
    return response


def forgot_password_form(preauthorized: Union[str, Sequence[str], None]) -> None:
    """Creates a Streamlit widget to reset a user's password. Authentication uses
    the Firebase Authentication REST API.

    Parameters:
        preauthorized (Union[str, Sequence[str], None]): An optional domain or a list of
        domains which are authorized to register.
    """

    with st.form("Forgot password"):
        email = st.text_input("E-mail", key="forgot_password")
        if not st.form_submit_button("Reset password"):
            return None
    if "@" not in email and isinstance(preauthorized, str):
        email = f"{email}@{preauthorized}"

    url = f"{POST_REQUEST_URL_BASE}sendOobCode?key={st.secrets['FIREBASE_API_KEY']}"
    payload = {"requestType": "PASSWORD_RESET", "email": email}
    response = post_request(url, json=payload)
    if response.status_code == 200:
        return success(f"Password reset link has been sent to {email}")
    return error(f"Error sending password reset email: {parse_error_message(response)}")


def register_user_form(preauthorized: Union[str, Sequence[str], None]) -> None:
    """Creates a Streamlit widget for user registration.

    Password strength is validated using entropy bits (the power of the password alphabet).
    Upon registration, a validation link is sent to the user's email address.

    Parameters:
        preauthorized (Union[str, Sequence[str], None]): An optional domain or a list of
        domains which are authorized to register.
    """

    with st.form(key="register_form"):
        email, name, password, confirm_password, register_button = (
            st.text_input("E-mail"),
            st.text_input("Name"),
            st.text_input("Password", type="password"),
            st.text_input("Confirm password", type="password"),
            st.form_submit_button(label="Submit"),
        )
    if not register_button:
        return None
    # Below are some checks to ensure proper and secure registration
    if password != confirm_password:
        return error("Passwords do not match")
    if not name:
        return error("Please enter your name")
    if "@" not in email and isinstance(preauthorized, str):
        email = f"{email}@{preauthorized}"
    if preauthorized and not email.endswith(preauthorized):
        return error("Domain not allowed")
    try:
        validate_email(email, check_deliverability=True)
    except EmailNotValidError as e:
        return error(e)

    # Need a password that has minimum 66 entropy bits (the power of its alphabet)
    # I multiply this number by 1.5 to display password strength with st.progress
    # For an explanation, read this -
    # https://en.wikipedia.org/wiki/Password_strength#Entropy_as_a_measure_of_password_strength
    alphabet_chars = len(set(password))
    strength = int(len(password) * math.log2(alphabet_chars) * 1.5)
    if strength < 100:
        st.progress(strength)
        return st.warning(
            "Password is too weak. Please choose a stronger password.", icon="⚠️"
        )
    auth.create_user(
        email=email, password=password, display_name=name, email_verified=False
    )
    # Having registered the user, send them a verification e-mail
    token = authenticate_user(email, password, require_email_verification=False)[
        "idToken"
    ]
    url = f"{POST_REQUEST_URL_BASE}sendOobCode?key={st.secrets['FIREBASE_API_KEY']}"
    payload = {"requestType": "VERIFY_EMAIL", "idToken": token}
    response = post_request(url, json=payload)
    if response.status_code != 200:
        return error(f"Error sending verification email: {parse_error_message(response)}")
    success(
        "Your account has been created successfully. To complete the registration process, "
        "please verify your email address by clic
