from dataclasses import dataclass
from typing import List, Optional

from saleor.account.models import User

PluginConfigurationType = List[dict]
NoneType = type(None)


class ConfigurationTypeField:
    STRING = "String"
    MULTILINE = "Multiline"
    BOOLEAN = "Boolean"
    SECRET = "Secret"
    SECRET_MULTILINE = "SecretMultiline"
    PASSWORD = "Password"
    OUTPUT = "OUTPUT"
    CHOICES = [
        (STRING, "Field is a String"),
        (MULTILINE, "Field is a Multiline"),
        (BOOLEAN, "Field is a Boolean"),
        (SECRET, "Field is a Secret"),
        (PASSWORD, "Field is a Password"),
        (SECRET_MULTILINE, "Field is a Secret multiline"),
        (OUTPUT, "Field is a read only"),
    ]


@dataclass
class ExternalAccessTokens:
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    csrf_token: Optional[str] = None
    user: Optional["User"] = None


@dataclass
class Provider:
    CLIENT_ID: str
    CLIENT_SECRET: Optional[str]
    REDIRECT_URI: Optional[str]
    AUTH_URI: Optional[str]
    AUTH_SCOPE: Optional[str]
    AUTH_ACCESSS_TYPE: Optional[str]
    AUTH_INCLUDE_GRANTED_SCOPES: Optional[str]
    AUTH_RESPONSE_TYPE: Optional[str]
    TOKENS_URI: str
    TOKENS_GRANT_TYPE: Optional[str]
    USER_INFO_URI: str
