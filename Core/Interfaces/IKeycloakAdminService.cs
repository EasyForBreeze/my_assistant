using new_assistant.Core.Entities;
using new_assistant.Core.DTOs;

namespace new_assistant.Core.Interfaces;

/// <summary>
/// Интерфейс для работы с Keycloak Admin API.
/// </summary>
public interface IKeycloakAdminService
{
    /// <summary>
    /// Получить список всех клиентов из Keycloak.
    /// </summary>
    Task<IEnumerable<KeycloakClientDto>> GetClientsAsync(CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить клиента по ID.
    /// </summary>
    Task<KeycloakClientDto?> GetClientAsync(string clientId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Создать нового клиента в Keycloak.
    /// </summary>
    Task<string> CreateClientAsync(CreateKeycloakClientRequest request, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Обновить существующего клиента в Keycloak.
    /// </summary>
    Task UpdateClientAsync(string clientId, UpdateKeycloakClientRequest request, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Удалить клиента из Keycloak.
    /// </summary>
    Task DeleteClientAsync(string clientId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить секрет клиента.
    /// </summary>
    Task<string?> GetClientSecretAsync(string clientId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Сгенерировать новый секрет для клиента.
    /// </summary>
    Task<string> RegenerateClientSecretAsync(string clientId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Поиск клиентов по подстроке во всех реалмах (кроме master).
    /// </summary>
    Task<ClientsSearchResponse> SearchClientsAsync(string searchTerm, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Поиск клиентов с отслеживанием прогресса.
    /// </summary>
    Task<ClientsSearchResponse> SearchClientsWithProgressAsync(
        string searchTerm, 
        IProgress<SearchProgress> progress, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить список всех реалмов (кроме master).
    /// </summary>
    Task<IEnumerable<string>> GetRealmsListAsync(CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить детальную информацию о клиенте.
    /// </summary>
    Task<ClientDetailsDto?> GetClientDetailsAsync(string clientId, string realm, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить события клиента.
    /// </summary>
    Task<IEnumerable<ClientEventDto>> GetClientEventsAsync(string clientId, string realm, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить роли клиента (локальные и сервисные).
    /// </summary>
    Task<(List<string> LocalRoles, List<string> ServiceRoles)> GetClientRolesAsync(string clientId, string realm, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить эндпоинты клиента.
    /// </summary>
    Task<List<string>> GetClientEndpointsAsync(string clientId, string realm, CancellationToken cancellationToken = default);
}

/// <summary>
/// DTO для клиента Keycloak.
/// </summary>
public class KeycloakClientDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public string Protocol { get; set; } = "openid-connect";
    public bool PublicClient { get; set; } = false;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> WebOrigins { get; set; } = new();
    public Dictionary<string, object> Attributes { get; set; } = new();
}

/// <summary>
/// Запрос на создание клиента.
/// </summary>
public class CreateKeycloakClientRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool PublicClient { get; set; } = false;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> WebOrigins { get; set; } = new();
    public Dictionary<string, object> Attributes { get; set; } = new();
}

/// <summary>
/// Запрос на обновление клиента.
/// </summary>
public class UpdateKeycloakClientRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> WebOrigins { get; set; } = new();
    public Dictionary<string, object> Attributes { get; set; } = new();
}
