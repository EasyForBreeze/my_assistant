using System.Diagnostics;
using System.Text.Json;
using new_assistant.Core.Interfaces;
using new_assistant.Core.DTOs;
using new_assistant.Configuration;
using Microsoft.Extensions.Logging;

namespace new_assistant.Infrastructure.Services;

/// <summary>
/// Реализация сервиса для работы с Keycloak Admin API
/// </summary>
public class KeycloakAdminService : IKeycloakAdminService
{
    private readonly KeycloakHttpClient _httpClient;
    private readonly KeycloakAdminSettings _settings;
    private readonly ILogger<KeycloakAdminService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public KeycloakAdminService(
        KeycloakHttpClient httpClient,
        KeycloakAdminSettings settings,
        ILogger<KeycloakAdminService> logger,
        IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClient;
        _settings = settings;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Поиск клиентов с отслеживанием прогресса
    /// </summary>
    public async Task<ClientsSearchResponse> SearchClientsWithProgressAsync(
        string searchTerm, 
        IProgress<SearchProgress> progress, 
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var response = new ClientsSearchResponse();

        try
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                response.Status = SearchStatus.Waiting;
                return response;
            }

            _logger.LogInformation("Начинается поиск клиентов по термину: {SearchTerm}", searchTerm);
            
            response.Status = SearchStatus.InProgress;
            
            // 1. Получаем список реалмов
            progress?.Report(new SearchProgress 
            { 
                Status = "Получение списка реалмов...",
                TotalRealms = 0,
                CompletedRealms = 0
            });

            var realms = await _httpClient.GetRealmsListAsync(cancellationToken);
            
            progress?.Report(new SearchProgress 
            { 
                Status = $"Найдено {realms.Count} реалмов для поиска",
                TotalRealms = realms.Count,
                CompletedRealms = 0,
                CurrentRealm = null
            });

            if (realms.Count == 0)
            {
                _logger.LogWarning("Не найдено доступных реалмов для поиска");
                response.Status = SearchStatus.Completed;
                response.ErrorMessage = "Нет доступных реалмов для поиска";
                return response;
            }

            // 2. Параллельный поиск по реалмам
            var searchTasks = realms.Select(async realm =>
            {
                try
                {
                    progress?.Report(new SearchProgress 
                    { 
                        Status = $"Поиск в реалме '{realm}'...",
                        TotalRealms = realms.Count,
                        CurrentRealm = realm
                    });

                    var realmResults = await _httpClient.SearchClientsInRealmAsync(realm, searchTerm, cancellationToken);
                    
                    // Помечаем каждому результату реалм
                    foreach (var result in realmResults)
                    {
                        result.Realm = realm;
                    }

                    progress?.Report(new SearchProgress 
                    { 
                        Status = $"Поиск в реалме '{realm}' завершен",
                        TotalRealms = realms.Count,
                        CurrentRealm = null,
                        CompletedRealms = response.RealmsSearched + 1,
                        ResultsFound = response.TotalFound + realmResults.Count
                    });

                    return realmResults;
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Поиск в реалме {Realm} отменен", realm);
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка поиска в реалме {Realm}", realm);
                    return new List<ClientSearchResult>();
                }
            });

            // 3. Собираем результаты
            var allResults = await Task.WhenAll(searchTasks);
            
            response.Clients = allResults
                .SelectMany(results => results)
                .OrderBy(c => c.Name)
                .Take(_settings.MaxSearchResults)
                .ToList();
                
            response.TotalFound = response.Clients.Count;
            response.RealmsSearched = realms.Count;
            response.Status = response.Clients.Any() ? SearchStatus.Completed : SearchStatus.Completed;
            
            progress?.Report(new SearchProgress 
            { 
                Status = $"Поиск завершен. Найдено {response.TotalFound} клиентов",
                TotalRealms = realms.Count,
                CompletedRealms = realms.Count,
                ResultsFound = response.TotalFound,
                IsComplete = true
            });

            _logger.LogInformation("Поиск завершен: найдено {Count} клиентов за {ElapsedMs}ms", 
                response.TotalFound, stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Поиск отменен пользователем");
            response.Status = SearchStatus.Completed;
            response.ErrorMessage = "Поиск отменен";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка во время поиска клиентов");
            response.Status = SearchStatus.Error;
            response.ErrorMessage = ex.Message;
        }
        finally
        {
            stopwatch.Stop();
            response.SearchTime = stopwatch.Elapsed;
        }

        return response;
    }

    /// <summary>
    /// Простой поиск клиентов без прогресса
    /// </summary>
    public async Task<ClientsSearchResponse> SearchClientsAsync(
        string searchTerm, 
        CancellationToken cancellationToken = default)
    {
        var progress = new Progress<SearchProgress>();
        return await SearchClientsWithProgressAsync(searchTerm, progress, cancellationToken);
    }

    /// <summary>
    /// Получение списка реалмов
    /// </summary>
    public async Task<IEnumerable<string>> GetRealmsListAsync(CancellationToken cancellationToken = default)
    {
        return await _httpClient.GetRealmsListAsync(cancellationToken);
    }

    #region Реализация существующих методов (заглушки для совместимости)

    public Task<IEnumerable<KeycloakClientDto>> GetClientsAsync(CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать получение списка клиентов
        throw new NotImplementedException("Метод GetClientsAsync будет реализован позже");
    }

    public Task<KeycloakClientDto?> GetClientAsync(string clientId, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать получение клиента по ID
        throw new NotImplementedException("Метод GetClientAsync будет реализован позже");
    }

    public Task<string> CreateClientAsync(CreateKeycloakClientRequest request, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать создание клиента
        throw new NotImplementedException("Метод CreateClientAsync будет реализован позже");
    }

    public Task UpdateClientAsync(string clientId, UpdateKeycloakClientRequest request, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать обновление клиента
        throw new NotImplementedException("Метод UpdateClientAsync будет реализован позже");
    }

    public Task DeleteClientAsync(string clientId, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать удаление клиента
        throw new NotImplementedException("Метод DeleteClientAsync будет реализован позже");
    }

    public Task<string?> GetClientSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать получение секрета клиента
        throw new NotImplementedException("Метод GetClientSecretAsync будет реализован позже");
    }

    public Task<string> RegenerateClientSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        // TODO: Реализовать перегенерацию секрета клиента
        throw new NotImplementedException("Метод RegenerateClientSecretAsync называется позже");
    }
    
    public async Task<ClientDetailsDto?> GetClientDetailsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение деталей клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            // Получаем полную информацию о клиенте из KeyCloak
            var clientJson = await _httpClient.GetClientFullInfoAsync(realm, clientId, cancellationToken);
            
            if (clientJson == null)
            {
                _logger.LogWarning("Клиент {ClientId} не найден в реалме {Realm}", clientId, realm);
                return null;
            }
            
            // Получаем internal ID клиента для дальнейших запросов
            var internalId = GetStringProperty(clientJson.Value, "id");
            
            // Получаем дополнительную информацию
            var roles = internalId != null ? await GetClientRolesAsync(internalId, realm, cancellationToken) : (new List<string>(), new List<string>());
            var endpoints = await GetClientEndpointsAsync(clientId, realm, cancellationToken);
            var events = await GetClientEventsAsync(clientId, realm, cancellationToken);
            var secret = internalId != null ? await _httpClient.GetClientSecretAsync(realm, internalId, cancellationToken) : null;
            
            // Парсим JSON и формируем детальную информацию
            var details = new ClientDetailsDto
            {
                // Основная информация
                Id = GetStringProperty(clientJson.Value, "id") ?? Guid.NewGuid().ToString(),
                ClientId = GetStringProperty(clientJson.Value, "clientId") ?? clientId,
                Name = GetStringProperty(clientJson.Value, "name"),
                Description = GetStringProperty(clientJson.Value, "description"),
                Enabled = GetBoolProperty(clientJson.Value, "enabled", true),
                Protocol = GetStringProperty(clientJson.Value, "protocol") ?? "openid-connect",
                
                // URLs
                RootUrl = GetStringProperty(clientJson.Value, "rootUrl"),
                BaseUrl = GetStringProperty(clientJson.Value, "baseUrl"),
                AdminUrl = GetStringProperty(clientJson.Value, "adminUrl"),
                
                // Lists
                RedirectUris = GetStringArrayProperty(clientJson.Value, "redirectUris"),
                WebOrigins = GetStringArrayProperty(clientJson.Value, "webOrigins"),
                
                // Capability config
                ClientAuthentication = !GetBoolProperty(clientJson.Value, "publicClient", false), // publicClient = false означает требуется аутентификация
                StandardFlow = GetBoolProperty(clientJson.Value, "standardFlowEnabled", true),
                ServiceAccountsRoles = GetBoolProperty(clientJson.Value, "serviceAccountsEnabled", false),
                ServiceAccountsEnabled = GetBoolProperty(clientJson.Value, "serviceAccountsEnabled", false),
                AuthorizationServicesEnabled = GetBoolProperty(clientJson.Value, "authorizationServicesEnabled", false),
                
                // Определяем ClientType
                ClientType = GetBoolProperty(clientJson.Value, "publicClient", false) ? "public" : 
                            GetBoolProperty(clientJson.Value, "bearerOnly", false) ? "bearer-only" : "confidential",
                AccessType = GetBoolProperty(clientJson.Value, "publicClient", false) ? "public" : 
                            GetBoolProperty(clientJson.Value, "bearerOnly", false) ? "bearer-only" : "confidential",
                
                // Дополнительная информация
                ClientSecret = secret,
                LocalRoles = roles.Item1,
                ServiceRoles = roles.Item2,
                Endpoints = endpoints,
                Events = events.ToList(),
                Realm = realm,
                CreatedAt = DateTime.UtcNow.AddDays(-30), // KeyCloak не хранит дату создания в стандартных полях
                UpdatedAt = DateTime.UtcNow,
                Attributes = GetAttributesProperty(clientJson.Value)
            };
            
            _logger.LogInformation("Детали клиента {ClientId} успешно получены из KeyCloak", clientId);
            return details;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении деталей клиента {ClientId} в реалме {Realm}", clientId, realm);
            return null;
        }
    }
    
    // Вспомогательные методы для парсинга JSON
    private string? GetStringProperty(JsonElement json, string propertyName)
    {
        return json.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String 
            ? prop.GetString() 
            : null;
    }
    
    private bool GetBoolProperty(JsonElement json, string propertyName, bool defaultValue)
    {
        return json.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.True || prop.ValueKind == JsonValueKind.False
            ? prop.GetBoolean() 
            : defaultValue;
    }
    
    private List<string> GetStringArrayProperty(JsonElement json, string propertyName)
    {
        if (json.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.Array)
        {
            return prop.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString() ?? string.Empty)
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();
        }
        return new List<string>();
    }
    
    private Dictionary<string, object> GetAttributesProperty(JsonElement json)
    {
        var attributes = new Dictionary<string, object>();
        
        if (json.TryGetProperty("attributes", out var attrProp) && attrProp.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in attrProp.EnumerateObject())
            {
                attributes[property.Name] = property.Value.ToString();
            }
        }
        
        return attributes;
    }

    public async Task<IEnumerable<ClientEventDto>> GetClientEventsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        return await GetClientEventsAsync(clientId, realm, 10, cancellationToken);
    }

    public async Task<IEnumerable<ClientEventDto>> GetClientEventsAsync(string clientId, string realm, int maxEvents, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение {MaxEvents} событий клиента {ClientId} в реалме {Realm}", maxEvents, clientId, realm);
            
            // Получаем события из реалма с указанием количества
            var eventsJson = await _httpClient.GetRealmEventsAsync(realm, maxEvents, cancellationToken);
            
            var clientEvents = new List<ClientEventDto>();
            
            foreach (var eventJson in eventsJson)
            {
                // Фильтруем события по clientId
                var eventClientId = eventJson.TryGetProperty("clientId", out var clientIdProp) ? clientIdProp.GetString() : null;
                
                if (eventClientId == clientId)
                {
                    var evt = new ClientEventDto
                    {
                        Id = eventJson.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? Guid.NewGuid().ToString() : Guid.NewGuid().ToString(),
                        Time = eventJson.TryGetProperty("time", out var timeProp) && timeProp.ValueKind == JsonValueKind.Number
                            ? DateTimeOffset.FromUnixTimeMilliseconds(timeProp.GetInt64()).DateTime
                            : DateTime.UtcNow,
                        Type = eventJson.TryGetProperty("type", out var typeProp) ? typeProp.GetString() ?? "UNKNOWN" : "UNKNOWN",
                        Details = eventJson.TryGetProperty("details", out var detailsProp) ? detailsProp.ToString() : null,
                        UserId = eventJson.TryGetProperty("userId", out var userIdProp) ? userIdProp.GetString() : null,
                        IpAddress = eventJson.TryGetProperty("ipAddress", out var ipProp) ? ipProp.GetString() : null
                    };
                    
                    clientEvents.Add(evt);
                }
            }
            
            _logger.LogInformation("Получено {Count} событий для клиента {ClientId}", clientEvents.Count, clientId);
            
            // Сортируем по времени (новые сначала)
            return clientEvents.OrderByDescending(e => e.Time).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении событий клиента {ClientId} в реалме {Realm}", clientId, realm);
            return new List<ClientEventDto>();
        }
    }

    public async Task<IEnumerable<ClientEventDto>> GetAllClientEventsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение всех событий клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            // Получаем больше событий (1000) для полного поиска
            var eventsJson = await _httpClient.GetRealmEventsAsync(realm, 1000, cancellationToken);
            
            var clientEvents = new List<ClientEventDto>();
            
            foreach (var eventJson in eventsJson)
            {
                // Фильтруем события по clientId
                var eventClientId = eventJson.TryGetProperty("clientId", out var clientIdProp) ? clientIdProp.GetString() : null;
                
                if (eventClientId == clientId)
                {
                    var evt = new ClientEventDto
                    {
                        Id = eventJson.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? Guid.NewGuid().ToString() : Guid.NewGuid().ToString(),
                        Time = eventJson.TryGetProperty("time", out var timeProp) && timeProp.ValueKind == JsonValueKind.Number
                            ? DateTimeOffset.FromUnixTimeMilliseconds(timeProp.GetInt64()).DateTime
                            : DateTime.UtcNow,
                        Type = eventJson.TryGetProperty("type", out var typeProp) ? typeProp.GetString() ?? "UNKNOWN" : "UNKNOWN",
                        Details = eventJson.TryGetProperty("details", out var detailsProp) ? detailsProp.ToString() : null,
                        UserId = eventJson.TryGetProperty("userId", out var userIdProp) ? userIdProp.GetString() : null,
                        IpAddress = eventJson.TryGetProperty("ipAddress", out var ipProp) ? ipProp.GetString() : null
                    };
                    
                    clientEvents.Add(evt);
                }
            }
            
            _logger.LogInformation("Получено {Count} событий для клиента {ClientId}", clientEvents.Count, clientId);
            
            // Сортируем по времени (новые сначала)
            return clientEvents.OrderByDescending(e => e.Time).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении всех событий клиента {ClientId} в реалме {Realm}", clientId, realm);
            return new List<ClientEventDto>();
        }
    }

    public async Task<IEnumerable<string>> GetAllEventTypesAsync(string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение всех типов событий из реалма {Realm}", realm);
            
            // Получаем события из реалма для анализа типов
            var eventsJson = await _httpClient.GetRealmEventsAsync(realm, 1000, cancellationToken);
            
            var eventTypes = new HashSet<string>();
            
            foreach (var eventJson in eventsJson)
            {
                if (eventJson.TryGetProperty("type", out var typeProp) && typeProp.ValueKind == JsonValueKind.String)
                {
                    var eventType = typeProp.GetString();
                    if (!string.IsNullOrEmpty(eventType))
                    {
                        eventTypes.Add(eventType);
                    }
                }
            }
            
            _logger.LogInformation("Найдено {Count} уникальных типов событий в реалме {Realm}", eventTypes.Count, realm);
            
            return eventTypes.OrderBy(t => t).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении типов событий из реалма {Realm}", realm);
            return new List<string>();
        }
    }
    
    public async Task<(List<string> LocalRoles, List<string> ServiceRoles)> GetClientRolesAsync(string clientInternalId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение ролей клиента {ClientId} в реалме {Realm}", clientInternalId, realm);
            
            // Получаем локальные роли клиента
            var localRolesJson = await _httpClient.GetClientRolesAsync(realm, clientInternalId, cancellationToken);
            
            var localRoles = new List<string>();
            foreach (var roleJson in localRolesJson)
            {
                var roleName = roleJson.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
                if (!string.IsNullOrEmpty(roleName))
                {
                    localRoles.Add(roleName);
                }
            }
            
            // Получаем service account роли
            var serviceRoles = new List<string>();
            
            // Сначала получаем service account пользователя
            var serviceAccountUserId = await _httpClient.GetServiceAccountUserIdAsync(realm, clientInternalId, cancellationToken);
            
            if (serviceAccountUserId != null)
            {
                _logger.LogInformation("Service account пользователь найден: {UserId}", serviceAccountUserId);
                
                // Получаем role mappings для service account пользователя
                var roleMappingsJson = await _httpClient.GetUserRoleMappingsAsync(realm, serviceAccountUserId, cancellationToken);
                
                foreach (var roleJson in roleMappingsJson)
                {
                    var roleName = roleJson.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
                    if (!string.IsNullOrEmpty(roleName))
                    {
                        serviceRoles.Add(roleName);
                    }
                }
            }
            else
            {
                _logger.LogInformation("Service account не включен для клиента {ClientId}", clientInternalId);
            }
            
            _logger.LogInformation("Получено {LocalCount} локальных и {ServiceCount} сервисных ролей", 
                localRoles.Count, serviceRoles.Count);
            
            return (localRoles, serviceRoles);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении ролей клиента {ClientId} в реалме {Realm}", clientInternalId, realm);
            return (new List<string>(), new List<string>());
        }
    }
    
    public async Task<List<string>> GetClientEndpointsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Получение эндпоинтов клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            var endpoints = new List<string>();
            
            try
            {
                // Получаем well-known конфигурацию
                var httpClient = _httpClientFactory.CreateClient();
                var wellKnownUrl = $"{_settings.BaseUrl}/realms/{realm}/.well-known/openid-configuration";
                var wellKnownResponse = await httpClient.GetAsync(wellKnownUrl, cancellationToken);
                
                if (wellKnownResponse.IsSuccessStatusCode)
                {
                    var wellKnownContent = await wellKnownResponse.Content.ReadAsStringAsync(cancellationToken);
                    var wellKnown = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(wellKnownContent);
                    
                    // Извлекаем основные эндпоинты
                    if (wellKnown.TryGetProperty("issuer", out var issuer))
                        endpoints.Add($"Issuer: {issuer.GetString()}");
                    
                    if (wellKnown.TryGetProperty("authorization_endpoint", out var authEndpoint))
                        endpoints.Add($"Authorization: {authEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("token_endpoint", out var tokenEndpoint))
                        endpoints.Add($"Token: {tokenEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("userinfo_endpoint", out var userinfoEndpoint))
                        endpoints.Add($"UserInfo: {userinfoEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("end_session_endpoint", out var logoutEndpoint))
                        endpoints.Add($"Logout: {logoutEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("jwks_uri", out var jwksEndpoint))
                        endpoints.Add($"JWKS: {jwksEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("introspection_endpoint", out var introspectionEndpoint))
                        endpoints.Add($"Introspection: {introspectionEndpoint.GetString()}");
                    
                    if (wellKnown.TryGetProperty("revocation_endpoint", out var revocationEndpoint))
                        endpoints.Add($"Revocation: {revocationEndpoint.GetString()}");
                    
                    _logger.LogInformation("Получено {Count} эндпоинтов из well-known конфигурации", endpoints.Count);
                }
                else
                {
                    _logger.LogWarning("Не удалось получить well-known конфигурацию, используем базовые эндпоинты");
                    // Fallback на базовые эндпоинты
                    endpoints.Add($"Authorization: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/auth");
                    endpoints.Add($"Token: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/token");
                    endpoints.Add($"UserInfo: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/userinfo");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Ошибка при получении well-known конфигурации, используем базовые эндпоинты");
                // Fallback на базовые эндпоинты
                endpoints.Add($"Authorization: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/auth");
                endpoints.Add($"Token: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/token");
                endpoints.Add($"UserInfo: {_settings.BaseUrl}/realms/{realm}/protocol/openid-connect/userinfo");
            }
            
            return endpoints;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении эндпоинтов клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }

    /// <summary>
    /// Регенерация client secret
    /// </summary>
    public async Task<string?> RegenerateClientSecretAsync(string clientId, string realm, string internalId, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Регенерация secret для клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            var newSecret = await _httpClient.RegenerateClientSecretAsync(realm, internalId, cancellationToken);
            
            if (newSecret != null)
            {
                _logger.LogInformation("Secret успешно регенерирован для клиента {ClientId}", clientId);
                return newSecret;
            }
            
            _logger.LogWarning("Не удалось регенерировать secret для клиента {ClientId}", clientId);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при регенерации secret клиента {ClientId}", clientId);
            return null;
        }
    }

    /// <summary>
    /// Обновить детали клиента в Keycloak
    /// </summary>
    public async Task UpdateClientDetailsAsync(ClientDetailsDto clientDetails, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Обновление деталей клиента {ClientId} в реалме {Realm}", clientDetails.ClientId, clientDetails.Realm);
            
            // Формируем объект для отправки в Keycloak API
            var updateData = new
            {
                id = clientDetails.Id,
                clientId = clientDetails.ClientId,
                name = clientDetails.Name,
                description = clientDetails.Description,
                enabled = clientDetails.Enabled,
                protocol = clientDetails.Protocol,
                publicClient = clientDetails.AccessType == "public",
                bearerOnly = clientDetails.AccessType == "bearer-only",
                standardFlowEnabled = clientDetails.StandardFlow,
                implicitFlowEnabled = false,
                directAccessGrantsEnabled = false,
                serviceAccountsEnabled = clientDetails.ServiceAccountsRoles,
                authorizationServicesEnabled = clientDetails.AuthorizationServicesEnabled,
                rootUrl = clientDetails.RootUrl ?? "",
                baseUrl = clientDetails.BaseUrl ?? "",
                adminUrl = clientDetails.AdminUrl ?? "",
                redirectUris = clientDetails.RedirectUris,
                webOrigins = clientDetails.WebOrigins,
                attributes = clientDetails.Attributes
            };

            // Сериализуем в JsonElement для отправки
            var json = JsonSerializer.Serialize(updateData);
            var jsonElement = JsonSerializer.Deserialize<JsonElement>(json);

            // Вызываем HTTP метод для обновления клиента
            await _httpClient.UpdateClientAsync(clientDetails.Realm, clientDetails.Id, jsonElement, cancellationToken);
            
            _logger.LogInformation("Детали клиента {ClientId} успешно обновлены в реалме {Realm}", clientDetails.ClientId, clientDetails.Realm);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при обновлении деталей клиента {ClientId} в реалме {Realm}", clientDetails.ClientId, clientDetails.Realm);
            throw;
        }
    }

    /// <summary>
    /// Синхронизировать локальные роли клиента с Keycloak
    /// </summary>
    public async Task SyncClientLocalRolesAsync(string clientId, string realm, string internalId, List<string> currentRoles, List<string> newRoles, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Синхронизация локальных ролей для клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            // Определяем роли которые нужно добавить
            var rolesToAdd = newRoles.Except(currentRoles).ToList();
            
            // Определяем роли которые нужно удалить
            var rolesToDelete = currentRoles.Except(newRoles).ToList();
            
            // Удаляем роли
            foreach (var role in rolesToDelete)
            {
                try
                {
                    await _httpClient.DeleteClientRoleAsync(realm, internalId, role, cancellationToken);
                    _logger.LogInformation("Роль '{Role}' удалена для клиента {ClientId}", role, clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка при удалении роли '{Role}' для клиента {ClientId}", role, clientId);
                    // Продолжаем удаление других ролей
                }
            }
            
            // Добавляем новые роли
            foreach (var role in rolesToAdd)
            {
                try
                {
                    await _httpClient.CreateClientRoleAsync(realm, internalId, role, cancellationToken);
                    _logger.LogInformation("Роль '{Role}' создана для клиента {ClientId}", role, clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка при создании роли '{Role}' для клиента {ClientId}", role, clientId);
                    // Продолжаем создание других ролей
                }
            }
            
            _logger.LogInformation("Синхронизация локальных ролей завершена: добавлено {Added}, удалено {Deleted}", 
                rolesToAdd.Count, rolesToDelete.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при синхронизации локальных ролей клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }

    /// <summary>
    /// Синхронизировать service account роли с Keycloak
    /// </summary>
    public async Task SyncServiceAccountRolesAsync(string clientId, string realm, string internalId, List<string> currentRoles, List<string> newRoles, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Синхронизация service account ролей для клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            // Получаем service account пользователя
            var serviceAccountUserId = await _httpClient.GetServiceAccountUserIdAsync(realm, internalId, cancellationToken);
            
            if (serviceAccountUserId == null)
            {
                _logger.LogWarning("Service account не найден для клиента {ClientId}", clientId);
                throw new InvalidOperationException($"Service account не включен для клиента {clientId}");
            }
            
            // Определяем роли которые нужно добавить
            var rolesToAdd = newRoles.Except(currentRoles).ToList();
            
            // Определяем роли которые нужно удалить
            var rolesToDelete = currentRoles.Except(newRoles).ToList();
            
            // Удаляем роли
            foreach (var role in rolesToDelete)
            {
                try
                {
                    await _httpClient.RemoveRoleFromUserAsync(realm, serviceAccountUserId, role, cancellationToken);
                    _logger.LogInformation("Роль '{Role}' удалена у service account для клиента {ClientId}", role, clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка при удалении роли '{Role}' у service account для клиента {ClientId}", role, clientId);
                    // Продолжаем удаление других ролей
                }
            }
            
            // Добавляем новые роли
            foreach (var role in rolesToAdd)
            {
                try
                {
                    await _httpClient.AssignRealmRoleToUserAsync(realm, serviceAccountUserId, role, cancellationToken);
                    _logger.LogInformation("Роль '{Role}' назначена service account для клиента {ClientId}", role, clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка при назначении роли '{Role}' service account для клиента {ClientId}", role, clientId);
                    // Продолжаем назначение других ролей
                }
            }
            
            _logger.LogInformation("Синхронизация service account ролей завершена: добавлено {Added}, удалено {Deleted}", 
                rolesToAdd.Count, rolesToDelete.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при синхронизации service account ролей клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }

    #endregion
}
