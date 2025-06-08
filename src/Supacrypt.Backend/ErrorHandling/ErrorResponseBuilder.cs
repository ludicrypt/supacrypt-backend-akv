using Supacrypt.V1;

namespace Supacrypt.Backend.ErrorHandling;

public static class ErrorResponseBuilder
{
    public static GenerateKeyResponse BuildGenerateKeyError(ErrorDetails errorDetails)
    {
        return new GenerateKeyResponse { Error = errorDetails };
    }

    public static SignDataResponse BuildSignDataError(ErrorDetails errorDetails)
    {
        return new SignDataResponse { Error = errorDetails };
    }

    public static VerifySignatureResponse BuildVerifySignatureError(ErrorDetails errorDetails)
    {
        return new VerifySignatureResponse { Error = errorDetails };
    }

    public static GetKeyResponse BuildGetKeyError(ErrorDetails errorDetails)
    {
        return new GetKeyResponse { Error = errorDetails };
    }

    public static ListKeysResponse BuildListKeysError(ErrorDetails errorDetails)
    {
        return new ListKeysResponse { Error = errorDetails };
    }

    public static DeleteKeyResponse BuildDeleteKeyError(ErrorDetails errorDetails)
    {
        return new DeleteKeyResponse { Error = errorDetails };
    }

    public static EncryptDataResponse BuildEncryptDataError(ErrorDetails errorDetails)
    {
        return new EncryptDataResponse { Error = errorDetails };
    }

    public static DecryptDataResponse BuildDecryptDataError(ErrorDetails errorDetails)
    {
        return new DecryptDataResponse { Error = errorDetails };
    }
}