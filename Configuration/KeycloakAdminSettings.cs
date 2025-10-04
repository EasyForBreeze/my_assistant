namespace new_assistant.Configuration;

/// <summary>
/// Настройки для работы с Keycloak Admin API
/// </summary>
public sealed class KeycloakAdminSettings
{
    /// <summary>
    /// Базовый URL Keycloak сервера
    /// </summary>
    public string BaseUrl { get; init; } = string.Empty;
    
    /// <summary>
    /// Основной реалм для админ операций
    /// </summary>
    public string Realm { get; init; } = string.Empty;
    
    /// <summary>
    /// Client ID для админ клиента
    /// </summary>
    public string ClientId { get; init; } = string.Empty;
    
    /// <summary>
    /// Client Secret для админ клиента
    /// </summary>
    public string ClientSecret { get; init; } = string.Empty;
    
    /// <summary>
    /// Использовать устаревший путь для аутентификации
    /// </summary>
    public bool UseLegacyAuthPath { get; init; } = false;
    
    /// <summary>
    /// Максимальное время ожидания запроса (в секундах)
    /// </summary>
    public int RequestTimeoutSeconds { get; init; } = 30;
    
    /// <summary>
    /// Максимальное количество результатов поиска
    /// </summary>
    public int MaxSearchResults { get; init; } = 10;
    
    /// <summary>
    /// Максимальное количество параллельных запросов
    /// </summary>
    public int MaxConcurrentRequests { get; init; } = 3;
    
    /// <summary>
    /// Реалмы, которые следует исключить из поиска
    /// </summary>
    public List<string> ExcludedRealms { get; } = new() { "master" };
}
