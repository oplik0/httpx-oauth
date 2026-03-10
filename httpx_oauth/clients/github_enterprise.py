from typing import Any, Optional, TypedDict, cast

import httpx

from httpx_oauth.clients.github import GitHubOAuth2AuthorizeParams
from httpx_oauth.exceptions import GetIdEmailError, GetProfileError
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token, RefreshTokenError


class GitHubEnterpriseOAuth2(BaseOAuth2[GitHubOAuth2AuthorizeParams]):
    """OAuth2 client for GitHub Enterprise.

    Uses a configurable host to support self-hosted GitHub Enterprise instances.
    """

    display_name = "GitHub Enterprise"

    def __init__(
        self,
        host: str,
        client_id: str,
        client_secret: str,
        scopes: Optional[list[str]] = None,
        name: str = "github-enterprise",
    ):
        """
        Args:
            host: The GitHub Enterprise host (e.g. `github.example.com`).
                  Should not include a scheme or trailing slash.
            client_id: The client ID provided by the OAuth2 provider.
            client_secret: The client secret provided by the OAuth2 provider.
            scopes: The default scopes to be used in the authorization URL.
                    Defaults to `["user", "user:email"]`.
            name: A unique name for the OAuth2 client.
        """
        if scopes is None:
            scopes = ["user", "user:email"]

        base_url = f"https://{host}"
        authorize_endpoint = f"{base_url}/login/oauth/authorize"
        access_token_endpoint = f"{base_url}/login/oauth/access_token"
        self.api_base_url = f"{base_url}/api/v3"

        super().__init__(
            client_id,
            client_secret,
            authorize_endpoint,
            access_token_endpoint,
            access_token_endpoint,
            name=name,
            base_scopes=scopes,
            token_endpoint_auth_method="client_secret_post",
        )

    async def refresh_token(self, refresh_token: str) -> OAuth2Token:
        """
        Requests a new access token using a refresh token.

        Args:
            refresh_token: The refresh token.

        Returns:
            An access token response dictionary.

        Raises:
            RefreshTokenError: An error occurred while refreshing the token.
        """
        assert self.refresh_token_endpoint is not None
        async with self.get_httpx_client() as client:
            request, auth = self.build_request(
                client,
                "POST",
                self.refresh_token_endpoint,
                auth_method=self.token_endpoint_auth_method,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
            )
            response = await self.send_request(
                client, request, auth, exc_class=RefreshTokenError
            )

            data = self.get_json(response, exc_class=RefreshTokenError)

            # GitHub Enterprise sends errors with a 200 status code
            if "error" in data:
                raise RefreshTokenError(cast(str, data["error"]), response)

            return OAuth2Token(data)

    async def get_profile(self, token: str) -> dict[str, Any]:
        profile_endpoint = f"{self.api_base_url}/user"
        async with httpx.AsyncClient(
            headers={**self.request_headers, "Authorization": f"token {token}"}
        ) as client:
            response = await client.get(profile_endpoint)

            if response.status_code >= 400:
                raise GetProfileError(response=response)

            return cast(dict[str, Any], response.json())

    async def get_emails(self, token: str) -> list[dict[str, Any]]:
        """
        Return the emails of the authenticated user from the API provider.

        Args:
            token: The access token.

        Returns:
            A list of emails as described in the GitHub Enterprise API.

        Raises:
            httpx_oauth.exceptions.GetProfileError:
                An error occurred while getting the emails.
        """
        emails_endpoint = f"{self.api_base_url}/user/emails"
        async with httpx.AsyncClient(
            headers={**self.request_headers, "Authorization": f"token {token}"}
        ) as client:
            response = await client.get(emails_endpoint)

            if response.status_code >= 400:
                raise GetProfileError(response=response)

            return cast(list[dict[str, Any]], response.json())

    async def get_id_email(self, token: str) -> tuple[str, Optional[str]]:
        """
        Returns the id and the email (if available) of the authenticated user
        from the API provider.

        Args:
            token: The access token.

        Returns:
            A tuple with the id and the email of the authenticated user.

        Raises:
            httpx_oauth.exceptions.GetIdEmailError:
                An error occurred while getting the id and email.
        """
        try:
            profile = await self.get_profile(token)
        except GetProfileError as e:
            raise GetIdEmailError(response=e.response) from e

        id = profile["id"]
        email = profile.get("email")

        # No public email, make a separate call to /user/emails
        if email is None:
            try:
                emails = await self.get_emails(token)
            except GetProfileError as e:
                raise GetIdEmailError(response=e.response) from e

            # Use the primary email if it exists, otherwise the first
            email = next(
                (e["email"] for e in emails if e.get("primary")), emails[0]["email"]
            )

        return str(id), email
