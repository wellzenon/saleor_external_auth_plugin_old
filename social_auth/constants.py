import os

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")
AUTH_URI = os.environ.get("AUTH_URI")
AUTH_SCOPE = os.environ.get("AUTH_SCOPE")
AUTH_ACCESSS_TYPE = os.environ.get("AUTH_ACCESSS_TYPE")
AUTH_INCLUDE_GRANTED_SCOPES = os.environ.get("AUTH_INCLUDE_GRANTED_SCOPES")
AUTH_RESPONSE_TYPE = os.environ.get("AUTH_RESPONSE_TYPE")
TOKENS_URI = os.environ.get("TOKENS_URI")
TOKENS_GRANT_TYPE = os.environ.get("TOKENS_GRANT_TYPE")
USER_INFO_URI = os.environ.get("USER_INFO_URI")

CONFIGURATION_FIELD = "providers_config_list"
DEFAULT_CONFIGURATION_TEXT = """
{
    "GOOGLE": 
        {
            "CLIENT_ID": "your google id",
            "CLIENT_SECRET": "your google secret",
            "REDIRECT_URI": "http://localhost:3000/auth/google",
            "AUTH_URI": "https://accounts.google.com/o/oauth2/v2/auth",
            "AUTH_SCOPE": "openid email profile",
            "AUTH_ACCESSS_TYPE": "offline",
            "AUTH_INCLUDE_GRANTED_SCOPES": "true",
            "AUTH_RESPONSE_TYPE": "code",
            "TOKENS_URI": "https://oauth2.googleapis.com/token",
            "TOKENS_GRANT_TYPE": "authorization_code",
            "USER_INFO_URI": "https://www.googleapis.com/oauth2/v2/userinfo"
        },
    "FACEBOOK":
        {
            "PROVIDER_NAME":"facebook",
            "CLIENT_ID": "your facebook id",
            "CLIENT_SECRET": "your facebook secret",
            "REDIRECT_URI": "http://localhost:3000/auth/facebook",
            "AUTH_URI": "https://accounts.google.com/o/oauth2/v2/auth",
            "AUTH_SCOPE": "openid email profile",
            "AUTH_ACCESSS_TYPE": "offline",
            "AUTH_INCLUDE_GRANTED_SCOPES": "true",
            "AUTH_RESPONSE_TYPE": "code",
            "TOKENS_URI": "https://oauth2.googleapis.com/token",
            "TOKENS_GRANT_TYPE": "authorization_code",
            "USER_INFO_URI": "https://www.googleapis.com/oauth2/v2/userinfo"
        }
}
"""
