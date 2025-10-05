using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using new_assistant.Configuration;
using new_assistant.Core.DTOs;
using Microsoft.Extensions.Logging;

namespace new_assistant.Infrastructure.Services;

/// <summary>
/// HTTP клиент для работы с Keycloak Admin API
/// </summary>
public class KeycloakHttpClient
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakAdminSettings _settings;
    private readonly ILogger<KeycloakHttpClient> _logger;
    private readonly SemaphoreSlim _semaphore;
    private string? _cachedToken;
    private DateTime _tokenExpiresAt = DateTime.MinValue;

    public KeycloakHttpClient(
        HttpClient httpClient, 
        KeycloakAdminSettings settings,
        ILogger<KeycloakHttpClient> logger)
    {
        _httpClient = httpClient;
        _settings = settings;
        _logger = logger;
        _semaphore = new SemaphoreSlim(_settings.MaxConcurrentRequests, _settings.MaxConcurrentRequests);
        
        ConfigureHttpClient();
    }

    private void ConfigureHttpClient()
    {
        _httpClient.BaseAddress = new Uri(_settings.BaseUrl);
        _httpClient.Timeout = TimeSpan.FromSeconds(_settings.RequestTimeoutSeconds);
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
    }

    /// <summary>
    /// Поиск клиентов в конкретном реалме
    /// </summary>
    public async Task<List<ClientSearchResult>> SearchClientsInRealmAsync(
        string realm, 
        string searchTerm, 
        CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            
            // Keycloak Admin API endpoint для поиска клиентов
            var endpoint = $"/admin/realms/{realm}/clients?search={WebUtility.UrlEncode(searchTerm)}&max={_settings.MaxSearchResults}";
            
            _logger.LogInformation("Выполняется поиск в реалме {Realm}: {SearchTerm}", realm, searchTerm);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка поиска в реалме {Realm}: {StatusCode} {ReasonPhrase}", 
                    realm, response.StatusCode, response.ReasonPhrase);
                
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    // Реалм не найден - это нормально, просто пропускаем его
                    return new List<ClientSearchResult>();
                }
                
                return new List<ClientSearchResult>();
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            
            if (string.IsNullOrWhiteSpace(content))
            {
                return new List<ClientSearchResult>();
            }
            
            var clients = JsonSerializer.Deserialize<List<JsonElement>>(content, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new List<JsonElement>();
            
            var results = clients.Select(ParseClientFromJson).Where(c => 
                SearchTermMatches(c, searchTerm)).ToList();
                
            _logger.LogInformation("Найдено {Count} клиентов в реалме {Realm}", results.Count, realm);
            
            return results;
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Поиск в реалме {Realm} отменен", realm);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при поиске в реалме {Realm}", realm);
            return new List<ClientSearchResult>();
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Получение списка реалмов
    /// </summary>
    public async Task<List<string>> GetRealmsListAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _logger.LogInformation("Токен получен: {TokenPreview}", token);
            
            // Пробуем разные варианты endpoint для разных версий Keycloak
            var endpoints = new[]
            {
                "/admin/realms?briefRepresentation=true",           // Стандартный с briefRepresentation
            };
            
            foreach (var endpoint in endpoints)
            {
                _logger.LogInformation("Тестируем endpoint: {BaseUrl}{Endpoint}", _settings.BaseUrl, endpoint);
                
                var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                request.Headers.Add("Accept", "application/json");
                request.Headers.Add("User-Agent", "KeycloakAssistant/1.0");
                
                var response = await _httpClient.SendAsync(request, cancellationToken);
                
                _logger.LogInformation("Endpoint {Endpoint}: {StatusCode} {ReasonPhrase}", endpoint, response.StatusCode, response.ReasonPhrase);
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    _logger.LogInformation("Успешный ответ с endpoint {Endpoint}: {ContentLength} байт", endpoint, content.Length);
                    _logger.LogInformation("Содержимое ответа: {Content}", content);
                    
                    var realms = JsonSerializer.Deserialize<List<JsonElement>>(content, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    }) ?? new List<JsonElement>();
                    
                    _logger.LogInformation("Найдено {Count} реалмов", realms.Count);
                    
                    // Парсим реалмы - с briefRepresentation=true может быть только id
                    var realmNames = new List<string>();
                    foreach (var realm in realms)
                    {
                        // Пробуем разные варианты полей
                        var realmName = realm.TryGetProperty("realm", out var realmProp) ? realmProp.GetString() :
                                       realm.TryGetProperty("id", out var idProp) ? idProp.GetString() :
                                       realm.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
                        
                        if (!string.IsNullOrEmpty(realmName))
                        {
                            realmNames.Add(realmName);
                        }
                    }
                    
                    var filteredRealms = realmNames
                        .Where(r => !_settings.ExcludedRealms.Contains(r))
                        .ToList();
                    
                    _logger.LogInformation("Отфильтровано {Count} реалмов (исключены: {Excluded})", 
                        filteredRealms.Count, string.Join(", ", _settings.ExcludedRealms));
                    
                    return filteredRealms;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    _logger.LogWarning("Endpoint {Endpoint} не подошел: {StatusCode} - {ErrorContent}", 
                        endpoint, response.StatusCode, errorContent);
                }
            }
            
            // Если ни один endpoint не сработал
            _logger.LogError("Не удалось получить список реалмов ни по одному из endpoint");
            return new List<string>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении списка реалмов");
            return new List<string>();
        }
    }

    /// <summary>
    /// Получение admin token для Keycloak
    /// </summary>
    private async Task<string> GetAdminTokenAsync(CancellationToken cancellationToken = default)
    {
        // Проверяем кэшированный токен
        if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiresAt)
        {
            return _cachedToken;
        }
        
        // Всегда используем token endpoint для client_credentials
        var authEndpoint = "/realms/master/protocol/openid-connect/token";
            
        var tokenRequest = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", _settings.ClientId),
            new("client_secret", _settings.ClientSecret)
        };
        
        // Создаем временный HttpClient только для получения токена
        using var tokenHttpClient = new HttpClient();
        tokenHttpClient.BaseAddress = new Uri(_settings.BaseUrl);
        
        var formContent = new FormUrlEncodedContent(tokenRequest);
        var request = new HttpRequestMessage(HttpMethod.Post, authEndpoint)
        {
            Content = formContent
        };
        
        // Убираем все заголовки кроме Content-Type
        request.Content!.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");
        
        var response = await tokenHttpClient.SendAsync(request, cancellationToken);
        
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException($"Не удалось получить токен: {response.StatusCode} - {errorContent}");
        }
        
        var tokenResponse = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
        
        _cachedToken = tokenResponse.GetProperty("access_token").GetString() 
            ?? throw new InvalidOperationException("Токен не найден в ответе");
            
        var expiresIn = tokenResponse.GetProperty("expires_in").GetInt32();
        _tokenExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn - 60); // Оставляем минуту запаса
        
        return _cachedToken;
    }

    /// <summary>
    /// Парсинг клиента из JSON ответа Keycloak
    /// </summary>
    private ClientSearchResult ParseClientFromJson(JsonElement element)
    {
        var clientId = element.TryGetProperty("clientId", out var cidProp) ? cidProp.GetString() ?? "" : "";
        var name = element.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? clientId : clientId;
        var description = element.TryGetProperty("description", out var descProp) ? descProp.GetString() : null;
        var enabled = !element.TryGetProperty("enabled", out var enabledProp) || enabledProp.GetBoolean();
        
        var lastModifiedProp = element.TryGetProperty("lastModifiedDate", out var lmd) ? lmd : default;
        var lastModified = lastModifiedProp.ValueKind == JsonValueKind.Number 
            ? DateTimeOffset.FromUnixTimeMilliseconds(lmd.GetInt64()).DateTime
            : DateTime.UtcNow;
        
        return new ClientSearchResult
        {
            ClientId = clientId,
            Name = name,
            Description = description,
            Enabled = enabled,
            LastModified = lastModified
        };
    }

    /// <summary>
    /// Проверка совпадения поискового термина
    /// </summary>
    private static bool SearchTermMatches(ClientSearchResult client, string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
            return true;
            
        var term = searchTerm.ToLowerInvariant();
        var matchedFields = new List<string>();
        
        if (client.Name.ToLowerInvariant().Contains(term))
            matchedFields.Add("Название");
            
        if (!string.IsNullOrEmpty(client.Description) && 
            client.Description.ToLowerInvariant().Contains(term))
            matchedFields.Add("Описание");
            
        if (client.ClientId.ToLowerInvariant().Contains(term))
            matchedFields.Add("Client ID");
        
        client.MatchedFields = matchedFields;
        return matchedFields.Any();
    }
}
