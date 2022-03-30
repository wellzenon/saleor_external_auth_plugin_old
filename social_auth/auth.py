import json
from multiprocessing import context
import requests
from xmlrpc.client import boolean
from typing import Callable, Dict, Optional, Tuple
from saleor.account.thumbnails import create_user_avatar_thumbnails
from saleor.account.models import User
from django.utils import timezone
from saleor.graphql.core.utils import add_hash_to_file_name, validate_image_file
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from .types import (
    Context,
    ExternalAccessTokens,
    Payload,
    Provider,
    PluginConfigurationType,
)

from saleor.core.jwt import (
    create_access_token,
    create_refresh_token,
)

from django.middleware.csrf import _get_new_csrf_token


def get_providers_from_config(
    configuration: PluginConfigurationType,
) -> Dict[str, Provider]:
    return json.loads(*{item["value"] for item in configuration})


def get_context(providers: Dict[str, Provider]) -> Callable[[Payload], Context]:
    def set_payload(payload: Payload) -> Context:
        name = payload.get("provider").lower()
        try:
            provider = [v for k, v in providers.items() if k.lower() == name][0]
        except:
            provider = list(providers.values())[0]

        return Context(payload=payload, provider=provider)

    return set_payload


def get_auth_url(context: Context) -> Dict[str, str]:
    payload = context.payload
    provider = context.provider
    scope = provider.get("AUTH_SCOPE")

    return {
        "authorizationUrl": (
            f'{provider.get("AUTH_URI")}?'
            + (f"scope={scope}&" if scope else "")
            + f'access_type={provider.get("AUTH_ACCESSS_TYPE")}&'
            + f'include_granted_scopes={provider.get("AUTH_INCLUDE_GRANTED_SCOPES")}&'
            + f'response_type={provider.get("AUTH_RESPONSE_TYPE")}&'
            + f"state=TODOimplementstate&"
            + f'client_id={provider.get("CLIENT_ID")}&'
            + f'redirect_uri={payload.get("redirectUri", provider.get("REDIRECT_URI"))}'
        )
    }


def get_credentials(context: Context) -> Context:
    payload = context.payload
    provider = context.provider

    data = {
        "code": payload.get("code"),
        "client_id": provider.get("CLIENT_ID"),
        "client_secret": provider.get("CLIENT_SECRET"),
        "redirect_uri": payload.get("redirectUri", provider.get("REDIRECT_URI")),
        "grant_type": provider.get("TOKENS_GRANT_TYPE"),
    }

    return Context(
        payload=payload,
        provider=provider,
        data={
            "credentials": requests.post(provider.get("TOKENS_URI"), data=data).json()
        },
    )


def get_userinfo(context: Context) -> Context:
    credentials = context.data.get("credentials")
    provider = context.provider

    headers = {
        "Authorization": f"{credentials.get('token_type')} {credentials.get('access_token')}"
    }
    userinfo_uri = provider.get("USER_INFO_URI")

    # TODO change the multiprovider logic
    if provider.get("PROVIDER_NAME").lower() == "facebook":
        return Context(
            payload=context.payload,
            provider=provider,
            data={
                "userinfo": requests.get(
                    f"{userinfo_uri}&access_token={credentials.get('access_token')}"
                ).json()
            },
        )

    return Context(
        payload=context.payload,
        provider=provider,
        data={"userinfo": requests.get(userinfo_uri, headers=headers).json()},
    )


def is_email_verified(context: Context) -> boolean:
    userinfo = context.data.get("userinfo")
    provider = context.provider

    # TODO change the multiprovider logic
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


def get_user(context: Context) -> Optional[User]:
    userinfo = context.data.get("userinfo")
    provider = context.provider

    user = User.objects.filter(email=userinfo.get("email")).first()

    if user == None and is_email_verified(context):
        user = (
            User(
                email=userinfo.get("email"),
                first_name=userinfo.get("first_name"),
                last_name=userinfo.get("last_name"),
            )
            if provider.get("PROVIDER_NAME").lower()
            == "facebook"  # TODO change the multiprovider logic
            else User(
                email=userinfo.get("email"),
                first_name=userinfo.get("given_name"),
                last_name=userinfo.get("family_name"),
            )
        )

    avatar_uri = (
        userinfo["picture"]
        if provider.get("PROVIDER_NAME").lower()
        == "google"  # TODO change the multiprovider logic
        else userinfo["picture"]["data"]["url"]
    )
    update_user(avatar_uri)(user)

    return user


def get_tokens(user: User) -> Tuple[User, ExternalAccessTokens]:
    access_token = create_access_token(user)
    csrf_token = _get_new_csrf_token()
    refresh_token = create_refresh_token(user, {"csrfToken": csrf_token})

    return (
        user,
        ExternalAccessTokens(
            user=user,
            token=access_token,
            refresh_token=refresh_token,
            csrf_token=csrf_token,
        ),
    )
