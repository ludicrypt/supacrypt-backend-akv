using Azure;
using Polly.CircuitBreaker;
using Supacrypt.Backend.Exceptions;
using Supacrypt.V1;
using System.Net;

namespace Supacrypt.Backend.Services.Azure;

public static class AzureKeyVaultErrorHandler
{
    public static Exception HandleAzureKeyVaultException(Exception exception, string? keyId = null, string? operation = null)
    {
        return exception switch
        {
            RequestFailedException azureEx => MapRequestFailedException(azureEx, keyId, operation),
            BrokenCircuitException circuitEx => MapCircuitBreakerException(circuitEx, keyId, operation),
            TaskCanceledException or OperationCanceledException => 
                new CryptographicOperationException(ErrorCode.Timeout, "Operation timed out", keyId, operation, exception),
            KeyNotFoundException => exception,
            InvalidOperationException => exception,
            _ => new CryptographicOperationException(ErrorCode.InternalError, "An unexpected error occurred", keyId, operation, exception)
        };
    }

    private static Exception MapRequestFailedException(RequestFailedException azureException, string? keyId, string? operation)
    {
        var (errorCode, message) = azureException.Status switch
        {
            404 => (ErrorCode.KeyNotFound, $"Key '{keyId}' not found"),
            401 => (ErrorCode.AuthenticationFailed, "Authentication failed with Azure Key Vault"),
            403 => (ErrorCode.AuthorizationFailed, "Authorization failed for Azure Key Vault operation"),
            409 => (ErrorCode.KeyAlreadyExists, $"Key '{keyId}' already exists"),
            429 => (ErrorCode.RateLimited, "Rate limit exceeded for Azure Key Vault operations"),
            >= 500 => (ErrorCode.ServiceUnavailable, "Azure Key Vault service is temporarily unavailable"),
            408 => (ErrorCode.Timeout, "Request to Azure Key Vault timed out"),
            _ => (ErrorCode.AzureKvError, $"Azure Key Vault error: {azureException.Message}")
        };

        return operation switch
        {
            "generate" or "delete" or "list" or "get" => 
                new KeyManagementException(errorCode, message, keyId, azureException),
            "sign" or "verify" or "encrypt" or "decrypt" => 
                new CryptographicOperationException(errorCode, message, keyId, operation, azureException),
            _ => new CryptographicOperationException(errorCode, message, keyId, operation, azureException)
        };
    }

    private static Exception MapCircuitBreakerException(BrokenCircuitException circuitException, string? keyId, string? operation)
    {
        const string message = "Azure Key Vault service is temporarily unavailable due to circuit breaker activation";
        
        return operation switch
        {
            "generate" or "delete" or "list" or "get" => 
                new KeyManagementException(ErrorCode.ServiceUnavailable, message, keyId, circuitException),
            "sign" or "verify" or "encrypt" or "decrypt" => 
                new CryptographicOperationException(ErrorCode.ServiceUnavailable, message, keyId, operation, circuitException),
            _ => new CryptographicOperationException(ErrorCode.ServiceUnavailable, message, keyId, operation, circuitException)
        };
    }

    public static bool IsTransientAzureError(Exception exception)
    {
        return exception switch
        {
            RequestFailedException azureEx => IsTransientStatusCode(azureEx.Status),
            TaskCanceledException or OperationCanceledException => true,
            HttpRequestException => true,
            _ => false
        };
    }

    public static bool IsCircuitBreakerError(Exception exception)
    {
        return exception switch
        {
            RequestFailedException azureEx => IsCircuitBreakerStatusCode(azureEx.Status),
            TaskCanceledException or OperationCanceledException => true,
            HttpRequestException => true,
            _ => false
        };
    }

    private static bool IsTransientStatusCode(int statusCode)
    {
        return statusCode switch
        {
            429 => true, // Rate limited
            408 => true, // Request timeout
            >= 500 => true, // Server errors
            _ => false
        };
    }

    private static bool IsCircuitBreakerStatusCode(int statusCode)
    {
        return statusCode switch
        {
            429 => true, // Rate limited
            408 => true, // Request timeout
            >= 500 => true, // Server errors
            _ => false
        };
    }
}