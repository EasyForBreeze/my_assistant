using System.Security.Claims;

namespace new_assistant.Core.Interfaces;

/// <summary>
/// Сервис для работы с ролями пользователей.
/// </summary>
public interface IUserRoleService
{
    /// <summary>
    /// Проверяет, является ли текущий пользователь администратором.
    /// </summary>
    /// <returns>True, если пользователь имеет роль Assistant-Admin</returns>
    bool IsAdmin();
    
    /// <summary>
    /// Проверяет, является ли текущий пользователь обычным пользователем.
    /// </summary>
    /// <returns>True, если пользователь имеет роль Assistant-User</returns>
    bool IsUser();
    
    /// <summary>
    /// Получает роль текущего пользователя.
    /// </summary>
    /// <returns>Роль пользователя или null, если роль не найдена</returns>
    string? GetUserRole();
    
    /// <summary>
    /// Получает имя текущего пользователя.
    /// </summary>
    /// <returns>Имя пользователя или null, если не найдено</returns>
    string? GetUserName();
    
    /// <summary>
    /// Получает ID текущего пользователя.
    /// </summary>
    /// <returns>ID пользователя или null, если не найден</returns>
    string? GetUserId();
    
    /// <summary>
    /// Получает все роли текущего пользователя.
    /// </summary>
    /// <returns>Список ролей пользователя</returns>
    IEnumerable<string> GetRoles();
    
    /// <summary>
    /// Проверяет, имеет ли пользователь доступ к указанной странице.
    /// </summary>
    /// <param name="pagePath">Путь к странице</param>
    /// <returns>True, если доступ разрешен</returns>
    bool HasAccessToPage(string pagePath);
}
