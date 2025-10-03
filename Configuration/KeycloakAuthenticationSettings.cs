using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace new_assistant.Configuration;

/// <summary>
/// Сильнопечатные настройки Keycloak для конфигурации аутентификации через OpenID Connect.
/// </summary>
public sealed class KeycloakAuthenticationSettings
{
    public string Authority { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public bool RequireHttpsMetadata { get; init; } = true;
    public string ResponseType { get; init; } = OpenIdConnectResponseType.Code;
    public bool UsePkce { get; init; } = true;
    public string CallbackPath { get; init; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; init; } = "/signout-callback-oidc";
    public string PostLogoutRedirectUri { get; init; } = "/";
    public IReadOnlyCollection<string> Scopes { get; init; } = Array.Empty<string>();
    public string RoleClaim { get; init; } = "realm_access.roles";
    public string NameClaim { get; init; } = "preferred_username";
}
