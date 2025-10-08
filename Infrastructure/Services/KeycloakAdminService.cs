using System.Diagnostics;
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

    public KeycloakAdminService(
        KeycloakHttpClient httpClient,
        KeycloakAdminSettings settings,
        ILogger<KeycloakAdminService> logger)
    {
        _httpClient = httpClient;
        _settings = settings;
        _logger = logger;
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
            // TODO: Реализовать получение полной информации о клиенте из Keycloak
            // Пока возвращаем заглушку
            _logger.LogInformation("Получение деталей клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            await Task.Delay(100, cancellationToken); // Имитация запроса
            
            return new ClientDetailsDto
            {
                Id = Guid.NewGuid().ToString(),
                ClientId = clientId,
                Name = $"Client {clientId}",
                Description = "Детальное описание клиента (заглушка)",
                Enabled = true,
                Protocol = "openid-connect",
                ClientType = "confidential",
                AccessType = "confidential",
                RootUrl = "https://example.com",
                BaseUrl = "/",
                AdminUrl = "https://example.com/admin",
                RedirectUris = new List<string> { "https://example.com/*" },
                WebOrigins = new List<string> { "https://example.com" },
                ServiceAccountsEnabled = true,
                AuthorizationServicesEnabled = false,
                
                // Capability config
                ClientAuthentication = true,
                StandardFlow = true,
                ServiceAccountsRoles = false,
                
                ClientSecret = "***secret***",
                LocalRoles = new List<string> { "admin", "user" },
                ServiceRoles = new List<string> { "service-account" },
                Endpoints = new List<string> 
                { 
                    $"https://auth.local/realms/{realm}/protocol/openid-connect/token",
                    $"https://auth.local/realms/{realm}/protocol/openid-connect/auth"
                },
                Events = new List<ClientEventDto>(),
                Realm = realm,
                CreatedAt = DateTime.UtcNow.AddDays(-30),
                UpdatedAt = DateTime.UtcNow.AddDays(-1),
                Attributes = new Dictionary<string, object>()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении деталей клиента {ClientId} в реалме {Realm}", clientId, realm);
            return null;
        }
    }
    
    public async Task<IEnumerable<ClientEventDto>> GetClientEventsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            // TODO: Реализовать получение событий клиента из Keycloak
            _logger.LogInformation("Получение событий клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            await Task.CompletedTask;
            return new List<ClientEventDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении событий клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }
    
    public async Task<(List<string> LocalRoles, List<string> ServiceRoles)> GetClientRolesAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            // TODO: Реализовать получение ролей клиента из Keycloak
            _logger.LogInformation("Получение ролей клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            await Task.CompletedTask;
            return (new List<string>(), new List<string>());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении ролей клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }
    
    public async Task<List<string>> GetClientEndpointsAsync(string clientId, string realm, CancellationToken cancellationToken = default)
    {
        try
        {
            // TODO: Реализовать получение эндпоинтов клиента
            _logger.LogInformation("Получение эндпоинтов клиента {ClientId} в реалме {Realm}", clientId, realm);
            
            await Task.CompletedTask;
            return new List<string>
            {
                $"https://auth.local/realms/{realm}/protocol/openid-connect/token",
                $"https://auth.local/realms/{realm}/protocol/openid-connect/auth",
                $"https://auth.local/realms/{realm}/protocol/openid-connect/userinfo"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при получении эндпоинтов клиента {ClientId} в реалме {Realm}", clientId, realm);
            throw;
        }
    }

    #endregion
}
