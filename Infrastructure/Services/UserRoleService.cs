using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using new_assistant.Core.Interfaces;

namespace new_assistant.Infrastructure.Services;

/// <summary>
/// Реализация сервиса для работы с ролями пользователей.
/// </summary>
public class UserRoleService : IUserRoleService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public UserRoleService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    public bool IsAdmin()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        return user?.IsInRole("Assistant-Admin") == true;
    }
    
    public bool IsUser()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        return user?.IsInRole("Assistant-User") == true;
    }
    
    public string? GetUserRole()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true)
            return null;
            
        if (user.IsInRole("Assistant-Admin"))
            return "Assistant-Admin";
            
        if (user.IsInRole("Assistant-User"))
            return "Assistant-User";
            
        return null;
    }
    
    public string? GetUserName()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        return user?.Identity?.Name;
    }
    
    public string? GetUserId()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        return user?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
               user?.FindFirst("sub")?.Value;
    }
    
    public bool HasAccessToPage(string pagePath)
    {
        var role = GetUserRole();
        if (role == null)
            return false;
            
        // Определяем доступ к страницам в зависимости от роли
        return role switch
        {
            "Assistant-Admin" => IsAdminPageAccessible(pagePath),
            "Assistant-User" => IsUserPageAccessible(pagePath),
            _ => false
        };
    }
    
    private static bool IsAdminPageAccessible(string pagePath)
    {
        // Администраторы имеют доступ ко всем страницам
        return true;
    }
    
    private static bool IsUserPageAccessible(string pagePath)
    {
        // Обычные пользователи имеют доступ только к определенным страницам
        var allowedPages = new[]
        {
            "/",
            "/clients",
            "/hangfire"
        };
        
        return allowedPages.Contains(pagePath.ToLowerInvariant());
    }
}
