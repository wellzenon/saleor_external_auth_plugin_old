import json
from xmlrpc.client import boolean
import requests
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Tuple, Union

from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse
from saleor.plugins.base_plugin import BasePlugin

from saleor.account.thumbnails import create_user_avatar_thumbnails
from saleor.account.models import User
from saleor.core.jwt import (
    create_access_token,
    create_refresh_token,
)

from django.middleware.csrf import _get_new_csrf_token
from django.utils import timezone
from saleor.graphql.core.utils import add_hash_to_file_name, validate_image_file
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from . import constants

if TYPE_CHECKING:
    # flake8: noqa
    from channel.models import Channel

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


class SocialLoginPlugin(BasePlugin):
    """Abstract class for storing all methods available for any plugin.

    All methods take previous_value parameter.
    previous_value contains a value calculated by the previous plugin in the queue.
    If the plugin is first, it will use default value calculated by the manager.
    """

    PLUGIN_NAME = "Social Authentication Plugin"
    PLUGIN_ID = "plugin.socialauth"
    PLUGIN_DESCRIPTION = "A plugin for social authentication"
    CONFIG_STRUCTURE = {
        constants.CONFIGURATION_FIELD: {
            "type": ConfigurationTypeField.MULTILINE,
            "help_text": "Provide all necessary configuration for each provider",
            "label": "Providers Configuration List",
        }
    }
    CONFIGURATION_PER_CHANNEL = False
    DEFAULT_CONFIGURATION = [
        {
            "name": constants.CONFIGURATION_FIELD,
            "value": constants.DEFAULT_CONFIGURATION_TEXT,
        }
    ]
    DEFAULT_ACTIVE = False

    @classmethod
    def check_plugin_id(cls, plugin_id: str) -> bool:
        """Check if given plugin_id matches with the PLUGIN_ID of this plugin."""
        return cls.PLUGIN_ID == plugin_id

    def __init__(
        self,
        *,
        configuration: PluginConfigurationType,
        active: bool,
        channel: Optional["Channel"] = None,
    ):
        self.configuration = self.get_plugin_configuration(configuration)
        self.providers = json.loads(
            *{
                item["value"]
                for item in self.configuration
                if item["name"] == constants.CONFIGURATION_FIELD
            }
        )
        self.active = active
        self.channel = channel

    def __str__(self):
        return self.PLUGIN_NAME

    def get_provider(self, payload: dict) -> dict:
        provider_name = payload.get("provider").lower()

        provider, *rest = [
            v for k, v in self.providers.items() if k.lower() == provider_name
        ] or list(self.providers.values())

        return provider

    #  Handle authentication request.
    #
    #  Overwrite this method if the plugin handles authentication flow.
    def external_authentication_url(
        self, payload: dict, request: WSGIRequest, **kwargs
    ) -> dict:

        provider = self.get_provider(payload)
        redirect_uri = payload.get("redirectUri", provider.get("REDIRECT_URI"))

        authorization_url = (
            f'{provider.get("AUTH_URI")}?'
            f'scope={provider.get("AUTH_SCOPE")}&'
            f'access_type={provider.get("AUTH_ACCESSS_TYPE")}&'
            f'include_granted_scopes={provider.get("AUTH_INCLUDE_GRANTED_SCOPES")}&'
            f'response_type={provider.get("AUTH_RESPONSE_TYPE")}&'
            f"state=TODOimplementstate&"
            f'client_id={provider.get("CLIENT_ID")}&'
            f"redirect_uri={redirect_uri}"
        )

        return {"authorizationUrl": authorization_url}

    #  Handle authentication request responsible for obtaining access tokens.
    #
    #  Overwrite this method if the plugin handles authentication flow.

    def external_obtain_access_tokens(
        self, payload: dict, request: WSGIRequest, previous_value: ExternalAccessTokens
    ) -> ExternalAccessTokens:

        provider = self.get_provider(payload)
        redirect_uri = payload.get("redirectUri", provider.get("REDIRECT_URI"))

        data = {
            "code": payload.get("code"),
            "client_id": provider.get("CLIENT_ID"),
            "client_secret": provider.get("CLIENT_SECRET"),
            "redirect_uri": redirect_uri,
            "grant_type": provider.get("TOKENS_GRANT_TYPE"),
        }

        credentials = requests.post(provider.get("TOKENS_URI"), data=data).json()

        # if r.status_code < 200 or r.status_code >= 300:
        #     raise Error(content.error_description)

        headers = {
            "Authorization": f"{credentials.get('token_type')} {credentials.get('access_token')}"
        }

        userinfo = requests.get(provider.get("USER_INFO_URI"), headers=headers).json()

        def is_email_verified(userinfo: dict) -> boolean:
            return userinfo.get("verified_email", False)

        def get_user(userinfo: dict) -> Optional[User]:
            user = User.objects.filter(email=userinfo.get("email")).first()

            if user == None and is_email_verified(userinfo):
                user = User(
                    email=userinfo.get("email"),
                    first_name=userinfo.get("given_name"),
                    last_name=userinfo.get("family_name"),
                )

            return user

        def set_user_avatar(user, avatar_uri):
            response = requests.get(avatar_uri)
            content_type = response.headers["Content-Type"]
            filename = (
                user.email.replace("@", "").replace(".", "")
                + "."
                + content_type.split("/")[1]
            )

            file = SimpleUploadedFile(
                content=response.content, name=filename, content_type=content_type
            )

            validate_image_file(file, "image", ValidationError)
            add_hash_to_file_name(file)
            if user.avatar:
                user.avatar.delete_sized_images()
                user.avatar.delete()
            user.avatar = file

        user = get_user(userinfo)
        user.last_login = timezone.now()
        update_fields = ["last_login"]

        if userinfo["picture"] and not user.avatar:
            set_user_avatar(user=user, avatar_uri=userinfo["picture"])
            update_fields.append("avatar")

        if user.id:
            user.save(update_fields=update_fields)
        else:
            user.save()

        if "avatar" in update_fields:
            create_user_avatar_thumbnails.delay(user_id=user.pk)

        access_token = create_access_token(user)
        csrf_token = _get_new_csrf_token()
        refresh_token = create_refresh_token(user, {"csrfToken": csrf_token})
        request.refresh_token = refresh_token
        request._cached_user = user

        return ExternalAccessTokens(
            user=user,
            token=access_token,
            refresh_token=refresh_token,
            csrf_token=csrf_token,
        )

    #  Authenticate user which should be assigned to the request.
    #
    #  Overwrite this method if the plugin handles authentication flow.

    def authenticate_user(
        self, request: WSGIRequest, previous_value: Any
    ) -> Union["User", NoneType]:
        pass

    #  Handle logout request.
    #
    #  Overwrite this method if the plugin handles logout flow.
    external_logout: Callable[[dict], Any]

    #  Handle authentication refresh request.
    #
    #  Overwrite this method if the plugin handles authentication flow and supports
    #  refreshing the access.
    external_refresh: Callable[[dict, WSGIRequest], ExternalAccessTokens]

    #  Verify the provided authentication data.
    #
    #  Overwrite this method if the plugin should validate the authentication data.
    external_verify: Callable[[dict, WSGIRequest], Tuple[Union["User", NoneType], dict]]

    get_client_token: Callable[[Any, Any], Any]

    #  Handle received http request.
    #
    #  Overwrite this method if the plugin expects the incoming requests.
    webhook: Callable[[WSGIRequest, str, Any], HttpResponse]
