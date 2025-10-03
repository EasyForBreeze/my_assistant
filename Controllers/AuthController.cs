using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace new_assistant.Controllers;

/// <summary>
/// Контроллер для обработки авторизации через Keycloak.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    /// <summary>
    /// Инициирует авторизацию через Keycloak.
    /// </summary>
    /// <param name="returnUrl">URL для перенаправления после авторизации</param>
    /// <returns>Результат авторизации</returns>
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        };
        
        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }
    
    /// <summary>
    /// Выход из системы.
    /// </summary>
    /// <returns>Результат выхода</returns>
    [HttpGet("logout")]
    public IActionResult Logout()
    {
        // Очищаем все cookie аутентификации
        HttpContext.Session.Clear();
        
        // Выполняем SignOut с перенаправлением на Keycloak logout
        return SignOut(new AuthenticationProperties
        {
            RedirectUri = "/"
        }, CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
    }
}
