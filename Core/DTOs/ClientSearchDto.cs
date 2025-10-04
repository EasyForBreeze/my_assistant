using System.ComponentModel.DataAnnotations;

namespace new_assistant.Core.DTOs;

/// <summary>
/// Результат поиска клиента из Keycloak
/// </summary>
public class ClientSearchResult
{
    /// <summary>
    /// Уникальный ID клиента в Keycloak
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    
    /// <summary>
    /// Название клиента
    /// </summary>
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// Реалм, в котором находится клиент
    /// </summary>
    public string Realm { get; set; } = string.Empty;
    
    /// <summary>
    /// Описание клиента (опционально)
    /// </summary>
    public string? Description { get; set; }
    
    /// <summary>
    /// Статус клиента (активен/неактивен)
    /// </summary>
    public bool Enabled { get; set; } = true;
    
    /// <summary>
    /// Время последнего изменения
    /// </summary>
    public DateTime LastModified { get; set; }
    
    /// <summary>
    /// Поля, в которых найден поисковый запрос
    /// </summary>
    public List<string> MatchedFields { get; set; } = new();
}

/// <summary>
/// Результат поиска клиентов по реалмам
/// </summary>
public class ClientsSearchResponse
{
    /// <summary>
    /// Найденные клиенты
    /// </summary>
    public List<ClientSearchResult> Clients { get; set; } = new();
    
    /// <summary>
    /// Общее количество найденных клиентов
    /// </summary>
    public int TotalFound { get; set; }
    
    /// <summary>
    /// Время выполнения поиска
    /// </summary>
    public TimeSpan SearchTime { get; set; }
    
    /// <summary>
    /// Количество реалмов, в которых проводился поиск
    /// </summary>
    public int RealmsSearched { get; set; }
    
    /// <summary>
    /// Статус поиска
    /// </summary>
    public SearchStatus Status { get; set; } = SearchStatus.Completed;
    
    /// <summary>
    /// Сообщеие об ошибке (если есть)
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Прогресс выполнения поиска
/// </summary>
public class SearchProgress
{
    /// <summary>
    /// Текущий статус поиска
    /// </summary>
    public string Status { get; set; } = string.Empty;
    
    /// <summary>
    /// Общее количество реалмов для поиска
    /// </summary>
    public int TotalRealms { get; set; }
    
    /// <summary>
    /// Количество реалмов, в которых поиск завершен
    /// </summary>
    public int CompletedRealms { get; set; }
    
    /// <summary>
    /// Текущий реалм, в котором происходит поиск
    /// </summary>
    public string? CurrentRealm { get; set; }
    
    /// <summary>
    /// Реалмы, в которых поиск завершен
    /// </summary>
    public List<string> CompletedRealmsList { get; set; } = new();
    
    /// <summary>
    /// Количество клиентов, найденных на данный момент
    /// </summary>
    public int ResultsFound { get; set; }
    
    /// <summary>
    /// Процент выполнения поиска
    /// </summary>
    public int Percentage => TotalRealms == 0 ? 0 : (CompletedRealms * 100) / TotalRealms;
    
    /// <summary>
    /// Поиск завершен
    /// </summary>
    public bool IsComplete { get; set; }
}

/// <summary>
/// Статус выполнения поиска
/// </summary>
public enum SearchStatus
{
    Waiting,
    InProgress,
    Completed,
    Error,
    PartialSuccess
}
