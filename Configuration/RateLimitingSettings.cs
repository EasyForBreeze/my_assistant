using System;

namespace new_assistant.Configuration;

/// <summary>
/// Настройки rate limiting для защиты от брутфорса и DDoS атак.
/// </summary>
public sealed class RateLimitingSettings
{
    /// <summary>
    /// Максимальное количество запросов в минуту для аутентификации.
    /// </summary>
    public int AuthRequestsPerMinute { get; init; } = 10;

    /// <summary>
    /// Максимальное количество API запросов в минуту для обычных пользователей.
    /// </summary>
    public int ApiRequestsPerMinute { get; init; } = 100;

    /// <summary>
    /// Максимальное количество API запросов в минуту для администраторов.
    /// </summary>
    public int AdminApiRequestsPerMinute { get; init; } = 500;

    /// <summary>
    /// Время блокировки в минутах при превышении лимитов.
    /// </summary>
    public int BlockDurationMinutes { get; init; } = 15;

    /// <summary>
    /// Включить rate limiting.
    /// </summary>
    public bool Enabled { get; init; } = true;
}
