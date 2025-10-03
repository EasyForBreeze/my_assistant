using Microsoft.AspNetCore.Http;

namespace new_assistant.Configuration;

public static class CspExtensions
{
    public const string CspNonceHttpContextItemKey = "SecurityHeaders.Csp.Nonce";

    public static string? TryGetCspNonce(this HttpContext context)
    {
        if (context.Items.TryGetValue(CspNonceHttpContextItemKey, out var nonce) &&
            nonce is string nonceValue)
        {
            return nonceValue;
        }

        return null;
    }

    public static string GetRequiredCspNonce(this HttpContext context)
    {
        return TryGetCspNonce(context) ??
            throw new InvalidOperationException("CSP nonce is not available on the current request. Ensure the security header middleware executes before rendering the response.");
    }
}
