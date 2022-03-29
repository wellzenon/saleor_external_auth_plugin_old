import json
import requests
from xmlrpc.client import boolean
from typing import Callable, Dict, Optional
from saleor.account.thumbnails import create_user_avatar_thumbnails
from saleor.account.models import User
from django.utils import timezone
from saleor.graphql.core.utils import add_hash_to_file_name, validate_image_file
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from .types import ExternalAccessTokens, Provider, PluginConfigurationType

from saleor.core.jwt import (
    create_access_token,
    create_refresh_token,
)

from django.middleware.csrf import _get_new_csrf_token


def get_providers_from_config(
    configuration: PluginConfigurationType,
) -> Dict[str, Provider]:
    return json.loads(*{item["value"] for item in configuration})


def get_provider(providers: dict) -> Callable[[dict], Provider]:
    def get_provider_by_payload(payload: dict) -> Provider:
        name = payload.get("provider").lower()
        try:
            return [v for k, v in providers.items() if k.lower() == name][0]
        except:
            return list(providers.values())[0]

    return get_provider_by_payload


def get_credentials(provider: Provider) -> Callable[[dict], dict]:
    def get_credentials_by_payload(payload: dict) -> dict:
        data = {
            "code": payload.get("code"),
            "client_id": provider.get("CLIENT_ID"),
            "client_secret": provider.get("CLIENT_SECRET"),
            "redirect_uri": payload.get("redirectUri", provider.get("REDIRECT_URI")),
            "grant_type": provider.get("TOKENS_GRANT_TYPE"),
        }

        return requests.post(provider.get("TOKENS_URI"), data=data).json()

    return get_credentials_by_payload


def get_userinfo(provider: Provider) -> Callable[[dict], dict]:
    def get_userinfo_by_credentials(credentials: dict) -> dict:
        headers = {
            "Authorization": f"{credentials.get('token_type')} {credentials.get('access_token')}"
        }
        userinfo_uri = provider.get("USER_INFO_URI")

        if provider.get("PROVIDER_NAME").lower() == "google":
            return requests.get(userinfo_uri, headers=headers).json()

        return requests.get(
            f"{userinfo_uri}&access_token={credentials.get('access_token')}"
        ).json()

    return get_userinfo_by_credentials


def is_email_verified(userinfo: dict, provider: Provider) -> boolean:
    if provider.get("PROVIDER_NAME").lower() == "facebook" and userinfo.get("email"):
        return True
    return userinfo.get("verified_email", False)


def update_user(avatar_uri: Optional[str]) -> Callable[[User], User]:
    def update(user: User) -> User:
        user.last_login = timezone.now()
        update_fields = ["last_login"]

        if avatar_uri and not user.avatar:
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
            update_fields.append("avatar")

        if user.id:
            user.save(update_fields=update_fields)
        else:
            user.save()

        if "avatar" in update_fields:
            create_user_avatar_thumbnails.delay(user_id=user.pk)

        return user

    return update


def get_user(provider: Provider) -> Callable[[dict], Optional[User]]:
    def get_user_by_userinfo(userinfo: dict) -> Optional[User]:
        user = User.objects.filter(email=userinfo.get("email")).first()
        if user == None and is_email_verified(userinfo, provider):
            user = (
                User(
                    email=userinfo.get("email"),
                    first_name=userinfo.get("given_name"),
                    last_name=userinfo.get("family_name"),
                )
                if provider.get("PROVIDER_NAME").lower() == "google"
                else User(
                    email=userinfo.get("email"),
                    first_name=userinfo.get("first_name"),
                    last_name=userinfo.get("last_name"),
                )
            )

        avatar_uri = (
            userinfo["picture"]
            if provider.get("PROVIDER_NAME").lower() == "google"
            else userinfo["picture"]["data"]["url"]
        )
        update_user(avatar_uri)(user)

        return user

    return get_user_by_userinfo


def get_tokens(user: User) -> ExternalAccessTokens:
    access_token = create_access_token(user)
    csrf_token = _get_new_csrf_token()
    refresh_token = create_refresh_token(user, {"csrfToken": csrf_token})

    return ExternalAccessTokens(
        user=user,
        token=access_token,
        refresh_token=refresh_token,
        csrf_token=csrf_token,
    )
