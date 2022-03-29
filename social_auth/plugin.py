from pkg_resources import get_provider
from typing import TYPE_CHECKING, Optional

from django.core.handlers.wsgi import WSGIRequest
from saleor.plugins.base_plugin import BasePlugin

from .auth import (
    get_providers_from_config,
    get_provider,
    get_credentials,
    get_tokens,
    get_userinfo,
    get_user,
)
from .types import ConfigurationTypeField, ExternalAccessTokens, PluginConfigurationType
from . import constants

if TYPE_CHECKING:
    # flake8: noqa
    from channel.models import Channel


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
        self.providers = get_providers_from_config(self.configuration)
        self.active = active
        self.channel = channel

    def __str__(self):
        return self.PLUGIN_NAME

    def external_authentication_url(
        self, payload: dict, request: WSGIRequest, **kwargs
    ) -> dict:

        provider = get_provider(self.providers)(payload)
        scope = provider.get("AUTH_SCOPE")
        authorization_url = (
            f'{provider.get("AUTH_URI")}?'
            + (f"scope={scope}&" if scope else "")
            + f'access_type={provider.get("AUTH_ACCESSS_TYPE")}&'
            + f'include_granted_scopes={provider.get("AUTH_INCLUDE_GRANTED_SCOPES")}&'
            + f'response_type={provider.get("AUTH_RESPONSE_TYPE")}&'
            + f"state=TODOimplementstate&"
            + f'client_id={provider.get("CLIENT_ID")}&'
            + f'redirect_uri={payload.get("redirectUri", provider.get("REDIRECT_URI"))}'
        )

        return {"authorizationUrl": authorization_url}

    def external_obtain_access_tokens(
        self, payload: dict, request: WSGIRequest, previous_value: ExternalAccessTokens
    ) -> ExternalAccessTokens:

        provider = get_provider(self.providers)(payload)
        credentials = get_credentials(provider)(payload)
        userinfo = get_userinfo(provider)(credentials)
        user = get_user(provider)(userinfo)
        tokens = get_tokens(user)

        request.refresh_token = tokens.refresh_token
        request._cached_user = user

        return tokens
