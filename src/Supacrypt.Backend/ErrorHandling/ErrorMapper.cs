using Grpc.Core;
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
            ArgumentException => new Status(StatusCode.InvalidArgument, "Invalid request parameters"),
            ArgumentNullException => new Status(StatusCode.InvalidArgument, "Required parameter is missing"),
            TimeoutException => new Status(StatusCode.DeadlineExceeded, "Operation timed out"),
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
                errorDetails.Code = ErrorCode.ErrorCodeInvalidRequest;
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

            default:
                errorDetails.Code = ErrorCode.ErrorCodeInternalError;
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
            ErrorCode.ErrorCodeKeyNotFound => new Status(StatusCode.NotFound, exception.Message),
            ErrorCode.ErrorCodeKeyAlreadyExists => new Status(StatusCode.AlreadyExists, exception.Message),
            ErrorCode.ErrorCodeUnsupportedAlgorithm => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.ErrorCodeKeySizeNotSupported => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.ErrorCodeAuthenticationFailed => new Status(StatusCode.Unauthenticated, exception.Message),
            ErrorCode.ErrorCodeAuthorizationFailed => new Status(StatusCode.PermissionDenied, exception.Message),
            _ => new Status(StatusCode.Internal, exception.Message)
        };
    }

    private static Status MapCryptographicException(CryptographicOperationException exception)
    {
        return exception.ErrorCode switch
        {
            ErrorCode.ErrorCodeKeyNotFound => new Status(StatusCode.NotFound, exception.Message),
            ErrorCode.ErrorCodeInvalidSignature => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.ErrorCodeUnsupportedAlgorithm => new Status(StatusCode.InvalidArgument, exception.Message),
            ErrorCode.ErrorCodeEncryptionFailed => new Status(StatusCode.Internal, exception.Message),
            ErrorCode.ErrorCodeDecryptionFailed => new Status(StatusCode.Internal, exception.Message),
            ErrorCode.ErrorCodeOperationNotSupported => new Status(StatusCode.Unimplemented, exception.Message),
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
}