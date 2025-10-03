using System;

namespace new_assistant.Configuration;

/// <summary>
/// Strongly-typed settings for <see cref="Microsoft.AspNetCore.HttpOverrides.ForwardedHeadersOptions"/> allow-lists.
/// Values come from the <c>ForwardedHeaders</c> configuration section.
/// </summary>
public sealed class ForwardedHeadersSettings
{
    /// <summary>
    /// Explicit list of reverse proxy IP addresses that are allowed to forward client information headers.
    /// </summary>
    public string[] KnownProxies { get; init; } = Array.Empty<string>();

    /// <summary>
    /// CIDR ranges representing networks whose nodes are allowed to forward client information headers.
    /// </summary>
    public string[] KnownNetworks { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Optional override for <see cref="Microsoft.AspNetCore.HttpOverrides.ForwardedHeadersOptions.ForwardLimit"/>.
    /// </summary>
    public int? ForwardLimit { get; init; }

    /// <summary>
    /// Optional override for <see cref="Microsoft.AspNetCore.HttpOverrides.ForwardedHeadersOptions.RequireHeaderSymmetry"/>.
    /// </summary>
    public bool? RequireHeaderSymmetry { get; init; }
}
