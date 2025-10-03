using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using new_assistant.Configuration;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using new_assistant.Infrastructure.Data;
using new_assistant.Core.Interfaces;
using new_assistant.Infrastructure.Services;
using Serilog;
using Hangfire;
using Hangfire.PostgreSql;
using Hangfire.Dashboard;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

// Настройка Serilog для структурированного логирования
builder.Host.UseSerilog((context, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "KeycloakAssistant")
        .WriteTo.Console()
        .WriteTo.PostgreSQL(
            context.Configuration.GetConnectionString("DefaultConnection")!,
            "audit_logs",
            needAutoCreateTable: true);
});

// Считываем и валидируем конфигурацию Keycloak на раннем этапе, чтобы приложение упало сразу, если в appsettings.json ошибка.
var keycloakAuthSettings = builder.Configuration
    .GetSection("Authentication:Keycloak")
    .Get<KeycloakAuthenticationSettings>()
    ?? throw new InvalidOperationException("Keycloak configuration is missing. Check the Authentication:Keycloak section in appsettings.json.");

var forwardedHeadersSettings = builder.Configuration
    .GetSection("ForwardedHeaders")
    .Get<ForwardedHeadersSettings>()
    ?? new ForwardedHeadersSettings();

var rateLimitingSettings = builder.Configuration
    .GetSection("RateLimiting")
    .Get<RateLimitingSettings>()
    ?? new RateLimitingSettings();

var tokenValidationSettings = builder.Configuration
    .GetSection("TokenValidation")
    .Get<EnhancedTokenValidationSettings>()
    ?? new EnhancedTokenValidationSettings();

var auditSettings = builder.Configuration
    .GetSection("AuditLogging")
    .Get<AuditLoggingSettings>()
    ?? new AuditLoggingSettings();

// Регистрируем настройки как singleton, чтобы их можно было инжектировать через IOptionsSnapshot/IOptionsMonitor при необходимости.
builder.Services.AddSingleton(keycloakAuthSettings);
builder.Services.AddSingleton(rateLimitingSettings);
builder.Services.AddSingleton(tokenValidationSettings);
builder.Services.AddSingleton(auditSettings);

// Настройка Entity Framework с PostgreSQL
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
        options.EnableDetailedErrors();
    }
});

// Настройка Hangfire для фоновых задач
builder.Services.AddHangfire(configuration => configuration
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UsePostgreSqlStorage(options =>
    {
        options.UseNpgsqlConnection(builder.Configuration.GetConnectionString("DefaultConnection"));
    }));

builder.Services.AddHangfireServer();

// Регистрация сервисов
// builder.Services.AddScoped<IKeycloakAdminService, KeycloakAdminService>();
// builder.Services.AddScoped<IClientManagementService, ClientManagementService>();
// builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IUserRoleService, UserRoleService>();

// Настройка MediatR для CQRS
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));

// Настройка AutoMapper
builder.Services.AddAutoMapper(typeof(Program).Assembly);

// Настройка FluentValidation
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// Настройка Blazor SSR + Interactive Server
// Добавляем базовые веб-сервисы
builder.Services.AddControllers();

// Добавляем Blazor Server
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();


// Настраиваем глобальную политику обработки cookies: требуем secure-канал и запрещаем доступ из JS.
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.Unspecified;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

// Готовим сегменты пути до claim с ролями (realm_access.roles по умолчанию), чтобы переиспользовать их в обработчике токена.
var roleClaimPathSegments = keycloakAuthSettings.RoleClaim
    .Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

// Добавляем куки-схему и OpenID Connect с PKCE: куки хранят локальную сессию, а OIDC отвечает за challenge/выход.
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        // HttpOnly и Secure обеспечиваются через CookiePolicy, здесь дополнительно ограничиваем время жизни и включаем sliding expiration.
        options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.LogoutPath = "/signout-oidc123";
        options.LoginPath = "/api/auth/login";
        options.AccessDeniedPath = "/api/auth/login";
        options.ReturnUrlParameter = "returnUrl";
        options.Cookie.Name = ".AspNetCore.Cookies";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
        options.Cookie.IsEssential = true;
        options.Cookie.Path = "/";
        options.Cookie.Domain = null;
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        // Основные параметры OIDC берём из настроек, чтобы не хардкодить значения в коде.
        options.Authority = keycloakAuthSettings.Authority;
        options.ClientId = keycloakAuthSettings.ClientId;
        options.ClientSecret = keycloakAuthSettings.ClientSecret;
        options.RequireHttpsMetadata = keycloakAuthSettings.RequireHttpsMetadata;
        options.ResponseType = keycloakAuthSettings.ResponseType;
        options.UsePkce = keycloakAuthSettings.UsePkce;
        options.CallbackPath = keycloakAuthSettings.CallbackPath;
        options.SignedOutCallbackPath = keycloakAuthSettings.SignedOutCallbackPath;
        options.SignedOutRedirectUri = keycloakAuthSettings.PostLogoutRedirectUri;
        options.SaveTokens = true; // сохраняем токены в AuthenticationProperties, чтобы позже можно было обращаться к Keycloak.
        options.GetClaimsFromUserInfoEndpoint = true; // userinfo помогает получить расширенные claim'ы, если они настроены в Keycloak.
        
        // Настройка перенаправлений после авторизации
        options.Events.OnTicketReceived = context =>
        {
            // После успешной авторизации перенаправляем на главную страницу
            context.ReturnUri = "/";
            return Task.CompletedTask;
        };

        // Перезаписываем список scope, чтобы использовать только то, что задано в конфигурации.
        options.Scope.Clear();
        foreach (var scope in keycloakAuthSettings.Scopes)
        {
            options.Scope.Add(scope);
        }

        // Задаём claim для имени пользователя и ролей, чтобы ASP.NET автоматически выставил User.Identity.Name и User.IsInRole.
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = keycloakAuthSettings.NameClaim,
            RoleClaimType = ClaimTypes.Role,
            ValidateIssuer = true,
            ValidIssuer = keycloakAuthSettings.Authority,
            ValidateAudience = tokenValidationSettings.RequireAudience,
            ValidAudience = keycloakAuthSettings.ClientId,
            ValidateLifetime = tokenValidationSettings.ValidateLifetime,
            ValidateIssuerSigningKey = tokenValidationSettings.ValidateIssuerSigningKey,
            RequireSignedTokens = tokenValidationSettings.RequireSignedTokens,
            RequireAudience = tokenValidationSettings.RequireAudience,
            ClockSkew = TimeSpan.FromSeconds(tokenValidationSettings.ClockSkewSeconds),
            RequireExpirationTime = true,
            ValidateTokenReplay = true
        };

        // Keycloak помещает роли в nested JSON (realm_access.roles), поэтому вручную маппим их на стандартные claims.
        options.Events.OnTokenValidated = context =>
        {
            if (context.Principal?.Identity is ClaimsIdentity identity &&
                context.SecurityToken is JwtSecurityToken accessToken &&
                roleClaimPathSegments.Length > 0)
            {
                using var payloadDocument = JsonDocument.Parse(accessToken.Payload.SerializeToJson());
                if (TryResolveJsonElement(payloadDocument.RootElement, roleClaimPathSegments, out var rolesElement) &&
                    rolesElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var role in rolesElement.EnumerateArray())
                    {
                        var roleName = role.GetString();
                        if (!string.IsNullOrWhiteSpace(roleName))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Role, roleName));
                        }
                    }
                }
            }

            return Task.CompletedTask;
        };
    });

// Подключаем стандартный Authorization middleware, чтобы можно было навешивать политики на endpoints.
builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();

// Настройка Data Protection для корректной работы с cookie
builder.Services.AddDataProtection()
    .SetApplicationName("KeyCloakAssistant")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "KeyCloakAssistant", "Keys")))
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .UseCryptographicAlgorithms(new Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel.AuthenticatedEncryptorConfiguration()
    {
        EncryptionAlgorithm = Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.EncryptionAlgorithm.AES_256_CBC,
        ValidationAlgorithm = Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ValidationAlgorithm.HMACSHA256
    });

// Добавляем Rate Limiting для защиты от брутфорса и DDoS
if (rateLimitingSettings.Enabled)
{
    builder.Services.AddRateLimiter(options =>
    {
        // Политика для аутентификации
        options.AddFixedWindowLimiter("auth", limiterOptions =>
        {
            limiterOptions.PermitLimit = rateLimitingSettings.AuthRequestsPerMinute;
            limiterOptions.Window = TimeSpan.FromMinutes(1);
            limiterOptions.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 3;
        });

        // Политика для обычных API запросов
        options.AddFixedWindowLimiter("api", limiterOptions =>
        {
            limiterOptions.PermitLimit = rateLimitingSettings.ApiRequestsPerMinute;
            limiterOptions.Window = TimeSpan.FromMinutes(1);
            limiterOptions.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 10;
        });

        // Политика для администраторов
        options.AddFixedWindowLimiter("admin", limiterOptions =>
        {
            limiterOptions.PermitLimit = rateLimitingSettings.AdminApiRequestsPerMinute;
            limiterOptions.Window = TimeSpan.FromMinutes(1);
            limiterOptions.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 20;
        });

        options.RejectionStatusCode = 429;
        options.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.StatusCode = 429;
            await context.HttpContext.Response.WriteAsync("Too many requests. Please try again later.", token);
        };
    });
}

// Forwarded headers позволяют корректно обрабатывать HTTPS-схему и IP-адреса, если приложение работает за reverse proxy.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();

    if (builder.Environment.IsDevelopment() &&
        forwardedHeadersSettings.KnownNetworks.Length == 0 &&
        forwardedHeadersSettings.KnownProxies.Length == 0)
    {
        // The development experience should work without a reverse proxy, so we avoid restricting
        // forwarded headers locally unless values are explicitly configured.
        return;
    }

    foreach (var proxy in forwardedHeadersSettings.KnownProxies)
    {
        options.KnownProxies.Add(ParseProxyAddress(proxy));
    }

    foreach (var network in forwardedHeadersSettings.KnownNetworks)
    {
        options.KnownNetworks.Add(ParseNetwork(network));
    }

    if (options.KnownNetworks.Count == 0 && options.KnownProxies.Count == 0)
    {
        throw new InvalidOperationException(
            "ForwardedHeaders configuration requires at least one KnownProxies or KnownNetworks entry.");
    }

    if (forwardedHeadersSettings.ForwardLimit is int forwardLimit)
    {
        if (forwardLimit <= 0)
        {
            throw new InvalidOperationException("ForwardedHeaders: ForwardLimit must be a positive integer.");
        }

        options.ForwardLimit = forwardLimit;
    }

    if (forwardedHeadersSettings.RequireHeaderSymmetry is bool requireHeaderSymmetry)
    {
        options.RequireHeaderSymmetry = requireHeaderSymmetry;
    }
});

var app = builder.Build();

// Добавляем промежуточное ПО, чтобы обеспечить HTTPS, аутентификацию и авторизацию до обработки запросов.
app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();

// Статические файлы должны быть ДО аутентификации

app.UseCookiePolicy();

// Rate limiting должен быть до аутентификации
if (rateLimitingSettings.Enabled)
{
    app.UseRateLimiter();
}

app.UseAuthentication();
app.UseAuthorization();

// Глобальные security-заголовки защищают от XSS, кликаджекинга и утечки referrer'а.
app.Use(async (context, next) =>
{
    context.Response.Headers[HeaderNames.XContentTypeOptions] = "nosniff";
    context.Response.Headers[HeaderNames.XFrameOptions] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

    var cspNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
    context.Items[CspExtensions.CspNonceHttpContextItemKey] = cspNonce;

    context.Response.OnStarting(() =>
    {
        if (context.Response.ContentType is { Length: > 0 } contentType &&
            !contentType.StartsWith("text/html", StringComparison.OrdinalIgnoreCase))
        {
            return Task.CompletedTask;
        }

        var websocketScheme = context.Request.IsHttps ? "wss" : "ws";
        var websocketEndpoint = $"{websocketScheme}://{context.Request.Host}";

        var directives = new[]
        {
            "default-src 'self'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "object-src 'none'",
            "manifest-src 'self'",
            "media-src 'self'",
            "img-src 'self' data: blob:",
            "font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com",
            $"connect-src 'self' {websocketEndpoint} {keycloakAuthSettings.Authority}",
            $"style-src 'self' 'nonce-{cspNonce}' 'unsafe-inline' https://fonts.googleapis.com",
            "style-src-attr 'unsafe-inline'", // Необходимо для MudBlazor inline стилей
            $"script-src 'self' 'nonce-{cspNonce}' 'wasm-unsafe-eval'",
            "script-src-attr 'none'",
            "worker-src 'self' blob:",
            "upgrade-insecure-requests" // Автоматически обновляет HTTP запросы до HTTPS
        };

        var csp = string.Join("; ", directives);
        context.Response.Headers[HeaderNames.ContentSecurityPolicy] = csp;
        return Task.CompletedTask;
    });

    await next().ConfigureAwait(false);
});

// Настройка маршрутизации для Blazor Server
// Добавляем статические файлы для CSS/JS
app.UseStaticFiles();

// Настройка маршрутизации для API
app.MapControllers();

// API информация (перенесем на /api)
app.MapGet("/api", () => new { 
    Message = "KeyCloak Assistant API", 
    Version = "1.0.0",
    Timestamp = DateTime.UtcNow,
    Endpoints = new[] {
        "/api/health - Health check",
        "/hangfire - Background jobs dashboard"
    }
});

// Hangfire Dashboard (только для админов)
app.MapHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = new[] { new HangfireAuthorizationFilter() }
});

// Настройка маршрутизации для Blazor (должно быть в конце)
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();

static IPAddress ParseProxyAddress(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException("ForwardedHeaders: KnownProxies entries must not be empty.");
    }

    if (!IPAddress.TryParse(value, out var address))
    {
        throw new InvalidOperationException($"ForwardedHeaders: '{value}' is not a valid IP address.");
    }

    return address;
}

static Microsoft.AspNetCore.HttpOverrides.IPNetwork ParseNetwork(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException("ForwardedHeaders: KnownNetworks entries must not be empty.");
    }

    var parts = value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length != 2)
    {
        throw new InvalidOperationException(
            $"ForwardedHeaders: '{value}' must use CIDR notation (for example, 10.0.0.0/24).");
    }

    if (!IPAddress.TryParse(parts[0], out var networkAddress))
    {
        throw new InvalidOperationException($"ForwardedHeaders: '{parts[0]}' is not a valid IP address.");
    }

    if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefixLength))
    {
        throw new InvalidOperationException($"ForwardedHeaders: '{parts[1]}' is not a valid prefix length.");
    }

    var maxPrefix = networkAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
    if (prefixLength < 0 || prefixLength > maxPrefix)
    {
        throw new InvalidOperationException(
            $"ForwardedHeaders: prefix length must be between 0 and {maxPrefix} for {networkAddress.AddressFamily} networks.");
    }

    return new Microsoft.AspNetCore.HttpOverrides.IPNetwork(networkAddress, prefixLength);
}

static bool TryResolveJsonElement(JsonElement root, IReadOnlyList<string> pathSegments, out JsonElement result)
{
    var current = root;
    foreach (var segment in pathSegments)
    {
        if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out var next))
        {
            result = default;
            return false;
        }

        current = next;
    }

    result = current;
    return true;
}

// Фильтр авторизации для Hangfire Dashboard
public class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext context)
    {
        var httpContext = context.GetHttpContext();
        return httpContext.User.Identity?.IsAuthenticated == true && 
               httpContext.User.IsInRole("Assistant-Admin");
    }
}
