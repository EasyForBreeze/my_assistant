## Reverse proxy configuration

The application only trusts `X-Forwarded-*` headers from the reverse proxies listed in the `ForwardedHeaders` configuration
section. Populate the allow-list with the ingress or load-balancer addresses that terminate traffic before it reaches the app.

```json
"ForwardedHeaders": {
  "KnownProxies": [
    "203.0.113.10",
    "203.0.113.11"
  ],
  "KnownNetworks": [
    "10.240.0.0/16"
  ],
  "ForwardLimit": 2,
  "RequireHeaderSymmetry": false
}
```

* **KnownProxies** – individual IPs for trusted reverse proxies. Provide one entry per address.
* **KnownNetworks** – CIDR ranges for internal networks that host trusted proxies (for example, Kubernetes node subnets).
* **ForwardLimit** – optional override if the infrastructure introduces additional proxy hops. Must be a positive integer.
* **RequireHeaderSymmetry** – optional toggle when upstream components do not emit both `X-Forwarded-For` and
  `X-Forwarded-Proto`.

Configuration values can be supplied via `appsettings.json`, environment variables, or any other ASP.NET Core configuration
provider. For containerised deployments, define environment variables such as:

```bash
ForwardedHeaders__KnownProxies__0=198.51.100.10
ForwardedHeaders__KnownProxies__1=198.51.100.11
ForwardedHeaders__KnownNetworks__0=10.42.0.0/16
ForwardedHeaders__ForwardLimit=3
ForwardedHeaders__RequireHeaderSymmetry=false
```

At least one proxy or network must be configured in non-development environments; otherwise the application will refuse to
start to avoid trusting spoofed headers.

## Content Security Policy

The security-header middleware now emits a strict Content Security Policy (CSP) tailored for the MudBlazor + SignalR stack. The policy locks down every fetch directive to the application origin (`'self'`) and only permits WebSocket/SSE traffic required by SignalR (the middleware emits `connect-src 'self' wss://<host>` or `ws://<host>` depending on the request). Inline script and style blocks **must** opt in via the request nonce that the middleware generates. The current policy looks like this (line breaks added for readability):

```
default-src 'self';
base-uri 'self';
frame-ancestors 'none';
form-action 'self';
object-src 'none';
manifest-src 'self';
media-src 'self';
img-src 'self' data: blob:;
font-src 'self' data: https://fonts.gstatic.com;
connect-src 'self' wss://<host>;
style-src 'self' 'nonce-<request-nonce>' https://fonts.googleapis.com;
style-src-attr 'none';
script-src 'self' 'nonce-<request-nonce>' 'wasm-unsafe-eval';
script-src-attr 'none';
worker-src 'self' blob:;
```

### Getting the nonce in Razor / components

The middleware stores the nonce in `HttpContext.Items` under the key exposed by `CspExtensions.CspNonceHttpContextItemKey`. Use the helpers from `Configuration/CspExtensions.cs` to retrieve it in your Razor layout, components, or pages:

```csharp
@using new_assistant.Configuration
@inject Microsoft.AspNetCore.Http.IHttpContextAccessor HttpContextAccessor

var nonce = HttpContextAccessor.HttpContext!.GetRequiredCspNonce();
```

Apply the nonce to every inline `<script>` or `<style>` element:

```html
<script nonce="@nonce">
    window.appConfiguration = @Json.Serialize(Model.Configuration);
</script>

<style nonce="@nonce">
    body { background-color: var(--mud-palette-background); }
</style>
```

MudBlazor components that output inline `<style>` tags (for example, `MudThemeProvider`) support the `Nonce` parameter. Pass the nonce through so the generated blocks survive CSP enforcement:

```razor
<MudThemeProvider Nonce="@nonce">
    @Body
</MudThemeProvider>
```

### Verifying the policy

1. Open the application in a browser.
2. Use the DevTools **Network** tab and reload the page. The `Content-Security-Policy` header should appear on all HTML responses with the nonce value.
3. Watch the **Console** for CSP violations. Legitimate endpoints to allow include:
   - `/_content/MudBlazor/*` static assets (already covered by `'self'`).
   - `/_blazor` or other SignalR hubs (covered by `connect-src`).
   - Data URIs for embedded fonts/images (enabled via `font-src`/`img-src`).
4. If new third-party resources are introduced, extend the relevant directive intentionally rather than loosening the entire policy.