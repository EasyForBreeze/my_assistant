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
    /// Получение полной информации о клиенте по clientId
    /// </summary>
    public async Task<JsonElement?> GetClientFullInfoAsync(string realm, string clientId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            
            // Сначала получаем список клиентов с фильтром по clientId
            var endpoint = $"/admin/realms/{realm}/clients?clientId={System.Net.WebUtility.UrlEncode(clientId)}";
            
            _logger.LogInformation("Получение полной информации о клиенте {ClientId} в реалме {Realm}", clientId, realm);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения клиента {ClientId}: {StatusCode}", clientId, response.StatusCode);
                return null;
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            
            if (string.IsNullOrWhiteSpace(content))
            {
                return null;
            }
            
            // KeyCloak возвращает массив клиентов
            var clients = JsonSerializer.Deserialize<List<JsonElement>>(content, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            
            if (clients == null || clients.Count == 0)
            {
                _logger.LogWarning("Клиент {ClientId} не найден в реалме {Realm}", clientId, realm);
                return null;
            }
            
            // Возвращаем первого клиента (должен быть только один с таким clientId)
            _logger.LogInformation("Полная информация о клиенте {ClientId} успешно получена", clientId);
            return clients[0];
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении полной информации о клиенте {ClientId} в реалме {Realm}", clientId, realm);
            return null;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Получение client secret
    /// </summary>
    public async Task<string?> GetClientSecretAsync(string realm, string clientInternalId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/client-secret";
            
            _logger.LogInformation("Получение client secret для клиента {ClientId} в реалме {Realm}", clientInternalId, realm);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения client secret: {StatusCode}", response.StatusCode);
                return null;
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var secretJson = JsonSerializer.Deserialize<JsonElement>(content);
            
            if (secretJson.TryGetProperty("value", out var secretValue))
            {
                return secretValue.GetString();
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении client secret");
            return null;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Регенерация client secret
    /// </summary>
    public async Task<string?> RegenerateClientSecretAsync(string realm, string clientInternalId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/client-secret";
            
            _logger.LogInformation("Регенерация client secret для клиента {ClientId} в реалме {Realm}", clientInternalId, realm);
            
            var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка регенерации client secret: {StatusCode}", response.StatusCode);
                return null;
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var secretJson = JsonSerializer.Deserialize<JsonElement>(content);
            
            if (secretJson.TryGetProperty("value", out var secretValue))
            {
                var newSecret = secretValue.GetString();
                _logger.LogInformation("Client secret успешно регенерирован для клиента {ClientId}", clientInternalId);
                return newSecret;
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при регенерации client secret");
            return null;
        }
        finally
        {
            _semaphore.Release();
        }
    }
    
    /// <summary>
    /// Получение ролей клиента
    /// </summary>
    public async Task<List<JsonElement>> GetClientRolesAsync(string realm, string clientInternalId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/roles";
            
            _logger.LogInformation("Получение ролей клиента {ClientId} в реалме {Realm}", clientInternalId, realm);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения ролей клиента: {StatusCode}", response.StatusCode);
                return new List<JsonElement>();
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var roles = JsonSerializer.Deserialize<List<JsonElement>>(content, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            
            return roles ?? new List<JsonElement>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении ролей клиента");
            return new List<JsonElement>();
        }
        finally
        {
            _semaphore.Release();
        }
    }
    
    /// <summary>
    /// Получение событий из реалма
    /// </summary>
    public async Task<List<JsonElement>> GetRealmEventsAsync(string realm, CancellationToken cancellationToken = default)
    {
        return await GetRealmEventsAsync(realm, 100, cancellationToken);
    }

    /// <summary>
    /// Получение событий из реалма с указанием количества
    /// </summary>
    public async Task<List<JsonElement>> GetRealmEventsAsync(string realm, int maxEvents, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/events?max={maxEvents}";
            
            _logger.LogInformation("Получение событий из реалма {Realm}", realm);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения событий: {StatusCode}", response.StatusCode);
                return new List<JsonElement>();
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var events = JsonSerializer.Deserialize<List<JsonElement>>(content, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            
            return events ?? new List<JsonElement>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении событий из реалма");
            return new List<JsonElement>();
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Получение service account пользователя для клиента
    /// </summary>
    public async Task<string?> GetServiceAccountUserIdAsync(string realm, string clientInternalId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/service-account-user";
            
            _logger.LogInformation("Получение service account пользователя для клиента {ClientId}", clientInternalId);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения service account пользователя: {StatusCode}", response.StatusCode);
                return null;
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var userJson = JsonSerializer.Deserialize<JsonElement>(content);
            
            if (userJson.TryGetProperty("id", out var userId))
            {
                return userId.GetString();
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении service account пользователя");
            return null;
        }
        finally
        {
            _semaphore.Release();
        }
    }
    
    /// <summary>
    /// Получение role mappings для пользователя
    /// </summary>
    public async Task<List<JsonElement>> GetUserRoleMappingsAsync(string realm, string userId, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/users/{userId}/role-mappings";
            
            _logger.LogInformation("Получение role mappings для пользователя {UserId}", userId);
            
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения role mappings: {StatusCode}", response.StatusCode);
                return new List<JsonElement>();
            }
            
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var roleMappingsJson = JsonSerializer.Deserialize<JsonElement>(content);
            
            var allRoles = new List<JsonElement>();
            
            // Получаем realm roles
            if (roleMappingsJson.TryGetProperty("realmMappings", out var realmMappings) && 
                realmMappings.ValueKind == JsonValueKind.Array)
            {
                allRoles.AddRange(realmMappings.EnumerateArray());
            }
            
            // Получаем client roles
            if (roleMappingsJson.TryGetProperty("clientMappings", out var clientMappings) && 
                clientMappings.ValueKind == JsonValueKind.Object)
            {
                foreach (var clientMapping in clientMappings.EnumerateObject())
                {
                    if (clientMapping.Value.TryGetProperty("mappings", out var mappings) && 
                        mappings.ValueKind == JsonValueKind.Array)
                    {
                        allRoles.AddRange(mappings.EnumerateArray());
                    }
                }
            }
            
            return allRoles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении role mappings");
            return new List<JsonElement>();
        }
        finally
        {
            _semaphore.Release();
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

    /// <summary>
    /// Обновить клиента в Keycloak
    /// </summary>
    public async Task UpdateClientAsync(string realm, string internalId, JsonElement clientData, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            
            var endpoint = $"/admin/realms/{realm}/clients/{internalId}";
            _logger.LogInformation($"Обновление клиента {internalId} в реалме {realm}");

            var request = new HttpRequestMessage(HttpMethod.Put, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("Accept", "application/json");
            request.Content = JsonContent.Create(clientData);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError($"Ошибка обновления клиента {internalId}: {response.StatusCode} - {errorContent}");
                throw new HttpRequestException($"Не удалось обновить клиента: {response.StatusCode} - {errorContent}");
            }

            _logger.LogInformation($"Клиент {internalId} успешно обновлен в реалме {realm}");
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Создать роль клиента
    /// </summary>
    public async Task CreateClientRoleAsync(string realm, string clientInternalId, string roleName, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/roles";
            
            _logger.LogInformation($"Создание роли '{roleName}' для клиента {clientInternalId} в реалме {realm}");

            var roleData = new
            {
                name = roleName,
                description = $"Role {roleName}",
                clientRole = true
            };

            var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("Accept", "application/json");
            request.Content = JsonContent.Create(roleData);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError($"Ошибка создания роли '{roleName}': {response.StatusCode} - {errorContent}");
                throw new HttpRequestException($"Не удалось создать роль: {response.StatusCode} - {errorContent}");
            }

            _logger.LogInformation($"Роль '{roleName}' успешно создана для клиента {clientInternalId}");
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Удалить роль клиента
    /// </summary>
    public async Task DeleteClientRoleAsync(string realm, string clientInternalId, string roleName, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/clients/{clientInternalId}/roles/{roleName}";
            
            _logger.LogInformation($"Удаление роли '{roleName}' для клиента {clientInternalId} в реалме {realm}");

            var request = new HttpRequestMessage(HttpMethod.Delete, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("Accept", "application/json");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError($"Ошибка удаления роли '{roleName}': {response.StatusCode} - {errorContent}");
                throw new HttpRequestException($"Не удалось удалить роль: {response.StatusCode} - {errorContent}");
            }

            _logger.LogInformation($"Роль '{roleName}' успешно удалена для клиента {clientInternalId}");
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Получить доступные realm роли для назначения пользователю
    /// </summary>
    public async Task<List<JsonElement>> GetAvailableRealmRolesAsync(string realm, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            var endpoint = $"/admin/realms/{realm}/roles";
            
            _logger.LogInformation($"Получение realm ролей для реалма {realm}");

            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("Accept", "application/json");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ошибка получения realm ролей: {StatusCode}", response.StatusCode);
                return new List<JsonElement>();
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var roles = JsonSerializer.Deserialize<List<JsonElement>>(content);
            
            return roles ?? new List<JsonElement>();
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Назначить realm роль пользователю
    /// </summary>
    public async Task AssignRealmRoleToUserAsync(string realm, string userId, string roleName, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            
            // Сначала получаем полную информацию о роли
            var rolesEndpoint = $"/admin/realms/{realm}/roles/{roleName}";
            var roleRequest = new HttpRequestMessage(HttpMethod.Get, rolesEndpoint);
            roleRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var roleResponse = await _httpClient.SendAsync(roleRequest, cancellationToken);
            if (!roleResponse.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Не удалось найти роль '{roleName}'");
            }
            
            var roleContent = await roleResponse.Content.ReadAsStringAsync(cancellationToken);
            var roleData = JsonSerializer.Deserialize<JsonElement>(roleContent);
            
            // Назначаем роль пользователю
            var endpoint = $"/admin/realms/{realm}/users/{userId}/role-mappings/realm";
            _logger.LogInformation($"Назначение роли '{roleName}' пользователю {userId} в реалме {realm}");

            var assignRequest = new HttpRequestMessage(HttpMethod.Post, endpoint);
            assignRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            assignRequest.Headers.Add("Accept", "application/json");
            assignRequest.Content = JsonContent.Create(new[] { roleData });
            
            var response = await _httpClient.SendAsync(assignRequest, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError($"Ошибка назначения роли '{roleName}': {response.StatusCode} - {errorContent}");
                throw new HttpRequestException($"Не удалось назначить роль: {response.StatusCode} - {errorContent}");
            }

            _logger.LogInformation($"Роль '{roleName}' успешно назначена пользователю {userId}");
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Удалить любую роль у пользователя (realm или client role)
    /// </summary>
    public async Task RemoveRoleFromUserAsync(string realm, string userId, string roleName, CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            
            // Получаем все role mappings пользователя
            var allMappingsEndpoint = $"/admin/realms/{realm}/users/{userId}/role-mappings";
            var mappingsRequest = new HttpRequestMessage(HttpMethod.Get, allMappingsEndpoint);
            mappingsRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var mappingsResponse = await _httpClient.SendAsync(mappingsRequest, cancellationToken);
            if (!mappingsResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning($"Не удалось получить role mappings для поиска роли '{roleName}'");
                return;
            }
            
            var mappingsContent = await mappingsResponse.Content.ReadAsStringAsync(cancellationToken);
            var roleMappingsJson = JsonSerializer.Deserialize<JsonElement>(mappingsContent);
            
            // Сначала проверяем realm roles
            if (roleMappingsJson.TryGetProperty("realmMappings", out var realmMappings) && 
                realmMappings.ValueKind == JsonValueKind.Array)
            {
                var roleInRealm = realmMappings.EnumerateArray().FirstOrDefault(r => 
                    r.TryGetProperty("name", out var name) && name.GetString() == roleName);
                
                if (roleInRealm.ValueKind != JsonValueKind.Undefined)
                {
                    // Это realm role - удаляем через realm endpoint
                    _logger.LogInformation($"Удаление realm роли '{roleName}' у пользователя {userId}");
                    
                    var deleteEndpoint = $"/admin/realms/{realm}/users/{userId}/role-mappings/realm";
                    var deleteRequest = new HttpRequestMessage(HttpMethod.Delete, deleteEndpoint);
                    deleteRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    deleteRequest.Headers.Add("Accept", "application/json");
                    deleteRequest.Content = JsonContent.Create(new[] { roleInRealm });
                    
                    var response = await _httpClient.SendAsync(deleteRequest, cancellationToken);
                    
                    if (!response.IsSuccessStatusCode)
                    {
                        var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                        _logger.LogError($"Ошибка удаления realm роли '{roleName}': {response.StatusCode} - {errorContent}");
                        throw new HttpRequestException($"Не удалось удалить realm роль: {response.StatusCode}");
                    }
                    
                    _logger.LogInformation($"Realm роль '{roleName}' успешно удалена");
                    return;
                }
            }
            
            // Проверяем client roles
            if (roleMappingsJson.TryGetProperty("clientMappings", out var clientMappings) && 
                clientMappings.ValueKind == JsonValueKind.Object)
            {
                foreach (var clientMapping in clientMappings.EnumerateObject())
                {
                    if (clientMapping.Value.TryGetProperty("mappings", out var mappings) && 
                        mappings.ValueKind == JsonValueKind.Array)
                    {
                        var roleInClient = mappings.EnumerateArray().FirstOrDefault(r => 
                            r.TryGetProperty("name", out var name) && name.GetString() == roleName);
                        
                        if (roleInClient.ValueKind != JsonValueKind.Undefined)
                        {
                            // Это client role - получаем ID клиента и удаляем
                            var clientId = clientMapping.Value.TryGetProperty("id", out var idProp) ? 
                                idProp.GetString() : null;
                            
                            if (clientId != null)
                            {
                                _logger.LogInformation($"Удаление client роли '{roleName}' (client: {clientMapping.Name}) у пользователя {userId}");
                                
                                var deleteEndpoint = $"/admin/realms/{realm}/users/{userId}/role-mappings/clients/{clientId}";
                                var deleteRequest = new HttpRequestMessage(HttpMethod.Delete, deleteEndpoint);
                                deleteRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                                deleteRequest.Headers.Add("Accept", "application/json");
                                deleteRequest.Content = JsonContent.Create(new[] { roleInClient });
                                
                                var response = await _httpClient.SendAsync(deleteRequest, cancellationToken);
                                
                                if (!response.IsSuccessStatusCode)
                                {
                                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                                    _logger.LogError($"Ошибка удаления client роли '{roleName}': {response.StatusCode} - {errorContent}");
                                    throw new HttpRequestException($"Не удалось удалить client роль: {response.StatusCode}");
                                }
                                
                                _logger.LogInformation($"Client роль '{roleName}' успешно удалена");
                                return;
                            }
                        }
                    }
                }
            }
            
            _logger.LogWarning($"Роль '{roleName}' не найдена ни в realm, ни в client roles для пользователя {userId}");
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
