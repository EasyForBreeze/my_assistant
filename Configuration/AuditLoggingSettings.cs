using System;

namespace new_assistant.Configuration;

/// <summary>
/// Настройки аудит логирования для отслеживания действий пользователей.
/// </summary>
public sealed class AuditLoggingSettings
{
    /// <summary>
    /// Включить аудит логирование.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Логировать все HTTP запросы.
    /// </summary>
    public bool LogAllRequests { get; init; } = false;

    /// <summary>
    /// Логировать только изменения данных (POST, PUT, DELETE).
    /// </summary>
    public bool LogDataChanges { get; init; } = true;

    /// <summary>
    /// Логировать аутентификацию и авторизацию.
    /// </summary>
    public bool LogAuthentication { get; init; } = true;

    /// <summary>
    /// Логировать доступ к Keycloak Admin API.
    /// </summary>
    public bool LogKeycloakAccess { get; init; } = true;

    /// <summary>
    /// Логировать создание/обновление страниц Confluence.
    /// </summary>
    public bool LogConfluenceOperations { get; init; } = true;

    /// <summary>
    /// Максимальный размер тела запроса для логирования в байтах.
    /// </summary>
    public int MaxRequestBodySize { get; init; } = 4096;

    /// <summary>
    /// Исключить чувствительные заголовки из логов.
    /// </summary>
    public string[] ExcludeHeaders { get; init; } = 
    {
        "Authorization",
        "Cookie",
        "X-API-Key",
        "X-Auth-Token"
    };
}
