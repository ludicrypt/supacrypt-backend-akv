using Azure;
using Grpc.Core;
using Polly.CircuitBreaker;
using Supacrypt.V1;
using Supacrypt.Backend.Exceptions;

namespace Supacrypt.Backend.ErrorHandling;

public static class ErrorMapper
{
    private const int BackendErrorBaseCode = 1000;

    public static Status MapToGrpcStatus(Exception exception, string correlationId)
    {
        return exception switch
        {
            Supacrypt.Backend.Exceptions.ValidationException validationEx => new Status(StatusCode.InvalidArgument, validationEx.Message),
            KeyManagementException keyEx => MapKeyManagementException(keyEx),
            CryptographicOperationException cryptoEx => MapCryptographicException(cryptoEx),
            RequestFailedException azureEx => MapAzureException(azureEx),
            BrokenCircuitException circuitEx => new Status(StatusCode.Unavailable, "Service temporarily unavailable due to circuit breaker"),
            ArgumentNullException => new Status(StatusCode.InvalidArgument, "Required parameter is missing"),
            ArgumentException => new Status(StatusCode.InvalidArgument, "Invalid request parameters"),
            TimeoutException => new Status(StatusCode.DeadlineExceeded, "Operation timed out"),
            TaskCanceledException => new Status(StatusCode.DeadlineExceeded, "Operation timed out"),
            OperationCanceledException => new Status(StatusCode.DeadlineExceeded, "Operation was cancelled"),
            UnauthorizedAccessException => new Status(StatusCode.Unauthenticated, "Authentication failed"),
            _ => new Status(StatusCode.Internal, "An internal error occurred")
        };
    }

    public static ErrorDetails MapToErrorDetails(Exception exception, string correlationId)
    {
        var errorDetails = new ErrorDetails
        {
            Context = { ["correlation_id"] = correlationId }
        };

        switch (exception)
        {
            case Supacrypt.Backend.Exceptions.ValidationException validationEx:
                errorDetails.Code = ErrorCode.InvalidRequest;
                errorDetails.Message = validationEx.Message;
                errorDetails.Details = string.Join(", ", validationEx.Errors.SelectMany(kvp => kvp.Value));
                break;

            case KeyManagementException keyEx:
                errorDetails.Code = keyEx.ErrorCode;
                errorDetails.Message = keyEx.Message;
                if (keyEx.KeyId != null)
                    errorDetails.Context["key_id"] = keyEx.KeyId;
                break;

            case CryptographicOperationException cryptoEx:
                errorDetails.Code = cryptoEx.ErrorCode;
                errorDetails.Message = cryptoEx.Message;
                if (cryptoEx.KeyId != null)
                    errorDetails.Context["key_id"] = cryptoEx.KeyId;
                if (cryptoEx.Operation != null)
                    errorDetails.Context["operation"] = cryptoEx.Operation;
                break;

            case RequestFailedException azureEx:
                (errorDetails.Code, errorDetails.Message) = MapAzureExceptionToError(azureEx);
                errorDetails.Context["azure_status"] = azureEx.Status.ToString();
                if (!string.IsNullOrEmpty(azureEx.ErrorCode))
                    errorDetails.Context["azure_error_code"] = azureEx.ErrorCode;
                break;

            case BrokenCircuitException circuitEx:
                errorDetails.Code = ErrorCode.ServiceUnavailable;
                errorDetails.Message = "Service temporarily unavailable due to circuit breaker";
                errorDetails.Details = circuitEx.Message;
                break;

            case TaskCanceledException or OperationCanceledException:
                errorDetails.Code = ErrorCode.Timeout;
                errorDetails.Message = "Operation timed out";
                break;

            default:
                errorDetails.Code = ErrorCode.InternalError;
                errorDetails.Message = "An internal error occurred";
                errorDetails.Details = GetSafeErrorMessage(exception);
                break;
        }

        return errorDetails;
    }

    private static Status MapKeyManagementException(KeyManagementException exception)
    {
        return exception.ErrorCode switch
        {
            ErrorCode.KeyNotFound => new Status(StatusCode.NotFound, exception.Message),
            ErrorCode.KeyAlreadyExists => new Status(StatusCode.AlreadyExists, exception.Message),
            ErrorCode.UnsupportedAlgorithm => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.KeySizeNotSupported => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.AuthenticationFailed => new Status(StatusCode.Unauthenticated, exception.Message),
            ErrorCode.AuthorizationFailed => new Status(StatusCode.PermissionDenied, exception.Message),
            _ => new Status(StatusCode.Internal, exception.Message)
        };
    }

    private static Status MapCryptographicException(CryptographicOperationException exception)
    {
        return exception.ErrorCode switch
        {
            ErrorCode.KeyNotFound => new Status(StatusCode.NotFound, exception.Message),
            ErrorCode.InvalidSignature => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.UnsupportedAlgorithm => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.EncryptionFailed => new Status(StatusCode.Internal, exception.Message),
            ErrorCode.DecryptionFailed => new Status(StatusCode.Internal, exception.Message),
            ErrorCode.OperationNotSupported => new Status(StatusCode.Unimplemented, exception.Message),
            _ => new Status(StatusCode.Internal, exception.Message)
        };
    }

    private static string GetSafeErrorMessage(Exception exception)
    {
        return exception.Message;
    }

    public static int GetBackendErrorCode(ErrorCode errorCode)
    {
        return BackendErrorBaseCode + (int)errorCode;
    }

    private static Status MapAzureException(RequestFailedException azureException)
    {
        return azureException.Status switch
        {
            404 => new Status(StatusCode.NotFound, "Resource not found"),
            401 => new Status(StatusCode.Unauthenticated, "Authentication failed"),
            403 => new Status(StatusCode.PermissionDenied, "Authorization failed"),
            409 => new Status(StatusCode.AlreadyExists, "Resource already exists"),
            429 => new Status(StatusCode.ResourceExhausted, "Rate limit exceeded"),
            >= 500 => new Status(StatusCode.Unavailable, "Service temporarily unavailable"),
            408 => new Status(StatusCode.DeadlineExceeded, "Request timed out"),
            _ => new Status(StatusCode.Internal, azureException.Message)
        };
    }

    private static (ErrorCode, string) MapAzureExceptionToError(RequestFailedException azureException)
    {
        return azureException.Status switch
        {
            404 => (ErrorCode.KeyNotFound, "Key not found"),
            401 => (ErrorCode.Unauthorized, "Authentication failed"),
            403 => (ErrorCode.AuthorizationFailed, "Authorization failed"),
            409 => (ErrorCode.KeyAlreadyExists, "Key already exists"),
            429 => (ErrorCode.RateLimited, "Rate limit exceeded"),
            >= 500 => (ErrorCode.ServiceUnavailable, "Azure Key Vault service temporarily unavailable"),
            408 => (ErrorCode.Timeout, "Request to Azure Key Vault timed out"),
            _ => (ErrorCode.AzureKvError, $"Azure Key Vault error: {azureException.Message}")
        };
    }
}