using System;
using System.ComponentModel.DataAnnotations;

namespace new_assistant.Core.Entities;

/// <summary>
/// Связь между клиентом и пользователем для управления доступом.
/// </summary>
public class ClientUserAccess
{
    public Guid Id { get; set; }
    
    /// <summary>
    /// ID клиента.
    /// </summary>
    public Guid KeycloakClientId { get; set; }
    
    /// <summary>
    /// Навигационное свойство к клиенту.
    /// </summary>
    public KeycloakClient KeycloakClient { get; set; } = null!;
    
    /// <summary>
    /// ID пользователя в Keycloak.
    /// </summary>
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    /// <summary>
    /// Имя пользователя.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string UserName { get; set; } = string.Empty;
    
    /// <summary>
    /// Email пользователя.
    /// </summary>
    [MaxLength(255)]
    public string? UserEmail { get; set; }
    
    /// <summary>
    /// Уровень доступа (read, write, admin).
    /// </summary>
    [Required]
    [MaxLength(20)]
    public string AccessLevel { get; set; } = "write";
    
    /// <summary>
    /// Кем был предоставлен доступ.
    /// </summary>
    [Required]
    public string GrantedByUserId { get; set; } = string.Empty;
    
    /// <summary>
    /// Имя пользователя предоставившего доступ.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string GrantedByUserName { get; set; } = string.Empty;
    
    /// <summary>
    /// Дата предоставления доступа.
    /// </summary>
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Активен ли доступ.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
