namespace new_assistant.Core.DTOs;

/// <summary>
/// Детальная информация о клиенте для просмотра/редактирования.
/// </summary>
public class ClientDetailsDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public string Protocol { get; set; } = "openid-connect";
    public string ClientType { get; set; } = "confidential"; // public, confidential, bearer-only
    public string AccessType { get; set; } = "confidential"; // public, confidential, bearer-only
    public string? RootUrl { get; set; }
    public string? BaseUrl { get; set; }
    public string? AdminUrl { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> WebOrigins { get; set; } = new();
    public bool ServiceAccountsEnabled { get; set; } = false;
    public bool StandardFlowEnabled { get; set; } = false;
    public bool AuthorizationServicesEnabled { get; set; } = false;
    
    // Capability config
    public bool ClientAuthentication { get; set; } = true;
    public bool StandardFlow { get; set; } = true;
    public bool ServiceAccountsRoles { get; set; } = false;
    public string? ClientSecret { get; set; }
    public List<string> LocalRoles { get; set; } = new();
    public List<string> ServiceRoles { get; set; } = new();
    public List<string> Endpoints { get; set; } = new();
    public List<ClientEventDto> Events { get; set; } = new();
    public string Realm { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public Dictionary<string, object> Attributes { get; set; } = new();
}

/// <summary>
/// Событие клиента.
/// </summary>
public class ClientEventDto
{
    public string Id { get; set; } = string.Empty;
    public DateTime Time { get; set; }
    public string Type { get; set; } = string.Empty;
    public string? Details { get; set; }
    public string? UserId { get; set; }
    public string? IpAddress { get; set; }
}