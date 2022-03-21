import imp


import os

API_ENDPOINT = os.environ.get("API_ENDPOINT")
SCOPE = os.environ.get("SCOPE")
ACCESSS_TYPE = os.environ.get("ACCESSS_TYPE")
INCLUDE_GRANTED_SCOPES = os.environ.get("INCLUDE_GRANTED_SCOPES")
RESPONSE_TYPE = os.environ.get("RESPONSE_TYPE")
STATE = os.environ.get("STATE")
GRANT_TYPE = os.environ.get("GRANT_TYPE")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")
TOKENS_URI = os.environ.get("TOKENS_URI")
USER_INFO_URI = os.environ.get("USER_INFO_URI")
