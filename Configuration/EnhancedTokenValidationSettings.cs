using System;

namespace new_assistant.Configuration;

/// <summary>
/// Расширенные настройки валидации JWT токенов для повышения безопасности.
/// </summary>
public sealed class EnhancedTokenValidationSettings
{
    /// <summary>
    /// Максимальное время жизни токена в минутах.
    /// </summary>
    public int MaxTokenLifetimeMinutes { get; init; } = 60;

    /// <summary>
    /// Допустимое отклонение времени в секундах для валидации exp/nbf claims.
    /// </summary>
    public int ClockSkewSeconds { get; init; } = 30;

    /// <summary>
    /// Требовать наличие audience claim.
    /// </summary>
    public bool RequireAudience { get; init; } = true;

    /// <summary>
    /// Требовать подписанные токены.
    /// </summary>
    public bool RequireSignedTokens { get; init; } = true;

    /// <summary>
    /// Валидировать время жизни токена.
    /// </summary>
    public bool ValidateLifetime { get; init; } = true;

    /// <summary>
    /// Валидировать подпись токена.
    /// </summary>
    public bool ValidateIssuerSigningKey { get; init; } = true;

    /// <summary>
    /// Список обязательных claims в токене.
    /// </summary>
    public string[] RequiredClaims { get; init; } = { "sub", "iat", "exp", "aud" };
}
