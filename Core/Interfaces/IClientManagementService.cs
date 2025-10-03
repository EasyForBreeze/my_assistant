using new_assistant.Core.Entities;

namespace new_assistant.Core.Interfaces;

/// <summary>
/// Интерфейс для управления клиентами с учетом бизнес-логики и прав доступа.
/// </summary>
public interface IClientManagementService
{
    /// <summary>
    /// Получить список клиентов доступных пользователю.
    /// </summary>
    Task<IEnumerable<KeycloakClient>> GetUserClientsAsync(string userId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить клиента по ID с проверкой прав доступа.
    /// </summary>
    Task<KeycloakClient?> GetClientAsync(Guid clientId, string userId, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Создать нового клиента.
    /// </summary>
    Task<KeycloakClient> CreateClientAsync(CreateClientRequest request, string userId, string userName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Обновить существующего клиента.
    /// </summary>
    Task<KeycloakClient> UpdateClientAsync(Guid clientId, UpdateClientRequest request, string userId, string userName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Удалить клиента.
    /// </summary>
    Task DeleteClientAsync(Guid clientId, string userId, string userName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Предоставить доступ пользователю к клиенту (только для админов).
    /// </summary>
    Task GrantUserAccessAsync(Guid clientId, string targetUserId, string targetUserName, string accessLevel, string grantedByUserId, string grantedByUserName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Отозвать доступ пользователя к клиенту.
    /// </summary>
    Task RevokeUserAccessAsync(Guid clientId, string targetUserId, string revokedByUserId, string revokedByUserName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Заблокировать клиента (только для админов).
    /// </summary>
    Task BlockClientAsync(Guid clientId, string reason, string blockedByUserId, string blockedByUserName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Разблокировать клиента (только для админов).
    /// </summary>
    Task UnblockClientAsync(Guid clientId, string unblockedByUserId, string unblockedByUserName, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Проверить имеет ли пользователь доступ к клиенту.
    /// </summary>
    Task<bool> HasAccessToClientAsync(Guid clientId, string userId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Запрос на создание клиента.
/// </summary>
public class CreateClientRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ClientType { get; set; } = "confidential";
    public List<string> RedirectUris { get; set; } = new();
}

/// <summary>
/// Запрос на обновление клиента.
/// </summary>
public class UpdateClientRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public bool IsActive { get; set; } = true;
}
