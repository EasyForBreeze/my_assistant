using System;
using System.ComponentModel.DataAnnotations;

namespace new_assistant.Core.Entities;

/// <summary>
/// Сущность представляющая Keycloak клиента в нашей системе.
/// </summary>
public class KeycloakClient
{
    public Guid Id { get; set; }
    
    /// <summary>
    /// ID клиента в Keycloak.
    /// </summary>
    [Required]
    public string KeycloakClientId { get; set; } = string.Empty;
    
    /// <summary>
    /// Имя клиента для отображения.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// Описание клиента.
    /// </summary>
    [MaxLength(1000)]
    public string? Description { get; set; }
    
    /// <summary>
    /// Тип клиента (public, confidential, bearer-only).
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string ClientType { get; set; } = "confidential";
    
    /// <summary>
    /// Redirect URIs для клиента.
    /// </summary>
    public List<string> RedirectUris { get; set; } = new();
    
    /// <summary>
    /// ID пользователя создавшего клиента.
    /// </summary>
    [Required]
    public string CreatedByUserId { get; set; } = string.Empty;
    
    /// <summary>
    /// Имя пользователя создавшего клиента.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string CreatedByUserName { get; set; } = string.Empty;
    
    /// <summary>
    /// Дата создания.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Дата последнего обновления.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// ID страницы в Confluence Wiki.
    /// </summary>
    public string? ConfluencePageId { get; set; }
    
    /// <summary>
    /// URL страницы в Confluence Wiki.
    /// </summary>
    public string? ConfluencePageUrl { get; set; }
    
    /// <summary>
    /// Активен ли клиент.
    /// </summary>
    public bool IsActive { get; set; } = true;
    
    /// <summary>
    /// Заблокирован ли клиент администратором.
    /// </summary>
    public bool IsBlocked { get; set; } = false;
    
    /// <summary>
    /// Причина блокировки.
    /// </summary>
    [MaxLength(500)]
    public string? BlockReason { get; set; }
    
    /// <summary>
    /// Пользователи имеющие доступ к редактированию этого клиента.
    /// </summary>
    public List<ClientUserAccess> UserAccess { get; set; } = new();
}
