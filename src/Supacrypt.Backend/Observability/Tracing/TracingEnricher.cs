using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Grpc.Core;

namespace Supacrypt.Backend.Observability.Tracing;

public class TracingEnricher
{
    public static void EnrichCryptoOperation(Activity activity, string operation, string? keyId, string? algorithm)
    {
        activity.SetTag("crypto.operation.type", operation);
        
        if (!string.IsNullOrEmpty(keyId))
        {
            // Sanitize key ID for privacy
            activity.SetTag("crypto.key.id", SanitizeKeyId(keyId));
        }
        
        if (!string.IsNullOrEmpty(algorithm))
        {
            activity.SetTag("crypto.algorithm", algorithm);
        }
        
        activity.SetTag("service.component", "crypto");
    }

    public static void EnrichAzureKeyVaultOperation(Activity activity, string operation, string? vaultName, string? keyName)
    {
        activity.SetTag("akv.operation", operation);
        
        if (!string.IsNullOrEmpty(vaultName))
        {
            activity.SetTag("akv.vault.name", vaultName);
        }
        
        if (!string.IsNullOrEmpty(keyName))
        {
            activity.SetTag("akv.key.name", SanitizeKeyId(keyName));
        }
        
        activity.SetTag("service.component", "azure-key-vault");
        activity.SetTag("cloud.provider", "azure");
        activity.SetTag("cloud.service", "key-vault");
    }

    public static void EnrichGrpcOperation(Activity activity, string method, ServerCallContext? context = null)
    {
        activity.SetTag("rpc.system", "grpc");
        activity.SetTag("rpc.service", "SupacryptGrpcService");
        activity.SetTag("rpc.method", method);
        
        if (context != null)
        {
            activity.SetTag("rpc.grpc.status_code", (int)context.Status.StatusCode);
            
            // Add peer information
            if (!string.IsNullOrEmpty(context.Peer))
            {
                activity.SetTag("net.peer.name", ExtractHostFromPeer(context.Peer));
            }
            
            // Add metadata
            if (context.RequestHeaders.Any())
            {
                var userAgent = context.RequestHeaders.FirstOrDefault(h => 
                    h.Key.Equals("user-agent", StringComparison.OrdinalIgnoreCase))?.Value;
                
                if (!string.IsNullOrEmpty(userAgent))
                {
                    activity.SetTag("http.user_agent", userAgent);
                }
            }
        }
        
        activity.SetTag("service.component", "grpc");
    }

    public static void EnrichAuthentication(Activity activity, X509Certificate2? clientCertificate, bool success)
    {
        activity.SetTag("auth.method", "certificate");
        activity.SetTag("auth.success", success);
        
        if (clientCertificate != null)
        {
            activity.SetTag("auth.cert.subject", clientCertificate.Subject);
            activity.SetTag("auth.cert.issuer", clientCertificate.Issuer);
            activity.SetTag("auth.cert.thumbprint", clientCertificate.Thumbprint[..8] + "...");
            activity.SetTag("auth.cert.expires", clientCertificate.NotAfter.ToString("yyyy-MM-dd"));
            
            // Extract user ID from certificate CN
            var cn = ExtractCommonName(clientCertificate.Subject);
            if (!string.IsNullOrEmpty(cn))
            {
                activity.SetTag("enduser.id", cn);
            }
        }
        
        activity.SetTag("service.component", "authentication");
    }

    public static void EnrichHealthCheck(Activity activity, string checkName, string status, TimeSpan duration)
    {
        activity.SetTag("health.check.name", checkName);
        activity.SetTag("health.check.status", status);
        activity.SetTag("health.check.duration_ms", duration.TotalMilliseconds);
        activity.SetTag("service.component", "health-check");
    }

    public static void RecordException(Activity activity, Exception exception)
    {
        activity.RecordException(exception);
        activity.SetStatus(ActivityStatusCode.Error, exception.Message);
        
        // Add custom exception attributes
        activity.SetTag("exception.type", exception.GetType().FullName);
        activity.SetTag("exception.message", exception.Message);
        
        if (exception.InnerException != null)
        {
            activity.SetTag("exception.inner_type", exception.InnerException.GetType().FullName);
            activity.SetTag("exception.inner_message", exception.InnerException.Message);
        }
    }

    public static void RecordOperationEvent(Activity activity, string eventName, string? description = null, 
        Dictionary<string, object>? attributes = null)
    {
        var tags = new ActivityTagsCollection();
        
        if (!string.IsNullOrEmpty(description))
        {
            tags.Add("event.description", description);
        }
        
        if (attributes != null)
        {
            foreach (var attr in attributes)
            {
                tags.Add(attr.Key, attr.Value);
            }
        }
        
        activity.AddEvent(new ActivityEvent(eventName, DateTimeOffset.UtcNow, tags));
    }

    public static void SetCorrelationContext(Activity activity, string correlationId, string? requestId = null)
    {
        activity.SetTag("correlation.id", correlationId);
        
        if (!string.IsNullOrEmpty(requestId))
        {
            activity.SetTag("request.id", requestId);
        }
        
        // Set baggage for propagation
        activity.SetBaggage("correlation.id", correlationId);
        
        if (!string.IsNullOrEmpty(requestId))
        {
            activity.SetBaggage("request.id", requestId);
        }
    }

    public static void SetCustomAttributes(Activity activity, Dictionary<string, object> attributes)
    {
        foreach (var attribute in attributes)
        {
            activity.SetTag(attribute.Key, attribute.Value);
        }
    }

    private static string SanitizeKeyId(string keyId)
    {
        if (string.IsNullOrEmpty(keyId) || keyId.Length <= 8)
            return keyId;
            
        return $"{keyId[..4]}...{keyId[^4..]}";
    }

    private static string ExtractHostFromPeer(string peer)
    {
        // Extract host from gRPC peer string (e.g., "ipv4:127.0.0.1:54321")
        var parts = peer.Split(':');
        return parts.Length >= 2 ? parts[1] : peer;
    }

    private static string? ExtractCommonName(string subject)
    {
        // Extract CN from certificate subject
        var parts = subject.Split(',', StringSplitOptions.RemoveEmptyEntries);
        var cnPart = parts.FirstOrDefault(p => p.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
        return cnPart?.Substring(3).Trim();
    }
}