using System;
using System.ComponentModel.DataAnnotations;

namespace new_assistant.Core.Entities;

/// <summary>
/// Сущность для аудит логирования всех действий в системе.
/// </summary>
public class AuditLog
{
    public Guid Id { get; set; }
    
    /// <summary>
    /// Тип события (ClientCreated, ClientUpdated, ClientDeleted, UserAccessGranted, etc.).
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string EventType { get; set; } = string.Empty;
    
    /// <summary>
    /// Описание события.
    /// </summary>
    [Required]
    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;
    
    /// <summary>
    /// ID пользователя выполнившего действие.
    /// </summary>
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    /// <summary>
    /// Имя пользователя выполнившего действие.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string UserName { get; set; } = string.Empty;
    
    /// <summary>
    /// IP адрес пользователя.
    /// </summary>
    [MaxLength(45)] // IPv6 максимум 45 символов
    public string? IpAddress { get; set; }
    
    /// <summary>
    /// User Agent браузера.
    /// </summary>
    [MaxLength(500)]
    public string? UserAgent { get; set; }
    
    /// <summary>
    /// ID связанного клиента (если применимо).
    /// </summary>
    public Guid? KeycloakClientId { get; set; }
    
    /// <summary>
    /// Навигационное свойство к клиенту.
    /// </summary>
    public KeycloakClient? KeycloakClient { get; set; }
    
    /// <summary>
    /// Дополнительные данные в JSON формате.
    /// </summary>
    public string? AdditionalData { get; set; }
    
    /// <summary>
    /// Дата и время события.
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Уровень серьезности (Info, Warning, Error).
    /// </summary>
    [Required]
    [MaxLength(20)]
    public string Severity { get; set; } = "Info";
    
    /// <summary>
    /// Категория события (Authentication, ClientManagement, ConfluenceIntegration).
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string Category { get; set; } = string.Empty;
}
