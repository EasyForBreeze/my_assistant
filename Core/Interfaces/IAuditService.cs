using new_assistant.Core.Entities;

namespace new_assistant.Core.Interfaces;

/// <summary>
/// Интерфейс для аудит логирования.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Записать событие в аудит лог.
    /// </summary>
    Task LogEventAsync(AuditLogEntry entry, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить аудит логи с фильтрацией.
    /// </summary>
    Task<IEnumerable<AuditLog>> GetAuditLogsAsync(AuditLogFilter filter, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Получить статистику по аудит логам.
    /// </summary>
    Task<AuditStatistics> GetAuditStatisticsAsync(DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default);
}

/// <summary>
/// Запись для аудит лога.
/// </summary>
public class AuditLogEntry
{
    public string EventType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public Guid? KeycloakClientId { get; set; }
    public string? AdditionalData { get; set; }
    public string Severity { get; set; } = "Info";
    public string Category { get; set; } = string.Empty;
}

/// <summary>
/// Фильтр для поиска аудит логов.
/// </summary>
public class AuditLogFilter
{
    public DateTime? FromDate { get; set; }
    public DateTime? ToDate { get; set; }
    public string? UserId { get; set; }
    public string? EventType { get; set; }
    public string? Category { get; set; }
    public string? Severity { get; set; }
    public Guid? KeycloakClientId { get; set; }
    public int PageNumber { get; set; } = 1;
    public int PageSize { get; set; } = 50;
}

/// <summary>
/// Статистика по аудит логам.
/// </summary>
public class AuditStatistics
{
    public int TotalEvents { get; set; }
    public Dictionary<string, int> EventsByType { get; set; } = new();
    public Dictionary<string, int> EventsByCategory { get; set; } = new();
    public Dictionary<string, int> EventsBySeverity { get; set; } = new();
    public Dictionary<string, int> EventsByUser { get; set; } = new();
}
