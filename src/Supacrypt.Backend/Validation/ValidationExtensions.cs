using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public static class ValidationExtensions
{
    public static IRuleBuilder<T, string> ValidKeyId<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        return ruleBuilder
            .NotEmpty().WithMessage("Key ID is required")
            .Length(1, 255).WithMessage("Key ID must be between 1 and 255 characters")
            .Matches(@"^[a-zA-Z0-9\-_]+$").WithMessage("Key ID can only contain alphanumeric characters, hyphens, and underscores");
    }

    public static IRuleBuilder<T, string> ValidKeyName<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        return ruleBuilder
            .NotEmpty().WithMessage("Key name is required")
            .Length(1, 255).WithMessage("Key name must be between 1 and 255 characters");
    }

    public static IRuleBuilder<T, KeyAlgorithm> ValidKeyAlgorithm<T>(this IRuleBuilder<T, KeyAlgorithm> ruleBuilder)
    {
        return ruleBuilder
            .Must(algorithm => algorithm != KeyAlgorithm.Unspecified)
            .WithMessage("Key algorithm must be specified")
            .Must(algorithm => Enum.IsDefined(typeof(KeyAlgorithm), algorithm))
            .WithMessage("Invalid key algorithm");
    }

    public static IRuleBuilder<T, RSAKeySize> ValidRsaKeySize<T>(this IRuleBuilder<T, RSAKeySize> ruleBuilder)
    {
        return ruleBuilder
            .Must(size => size != RSAKeySize.Unspecified)
            .WithMessage("RSA key size must be specified")
            .Must(size => size == RSAKeySize._2048 || size == RSAKeySize._3072 || size == RSAKeySize._4096)
            .WithMessage("RSA key size must be 2048, 3072, or 4096 bits");
    }

    public static IRuleBuilder<T, ECCCurve> ValidEccCurve<T>(this IRuleBuilder<T, ECCCurve> ruleBuilder)
    {
        return ruleBuilder
            .Must(curve => curve != ECCCurve.Unspecified)
            .WithMessage("ECC curve must be specified")
            .Must(curve => curve == ECCCurve.P256 || curve == ECCCurve.P384 || curve == ECCCurve.P521)
            .WithMessage("ECC curve must be P-256, P-384, or P-521");
    }

    public static IRuleBuilder<T, HashAlgorithm> ValidHashAlgorithm<T>(this IRuleBuilder<T, HashAlgorithm> ruleBuilder)
    {
        return ruleBuilder
            .Must(hash => hash != HashAlgorithm.Unspecified)
            .WithMessage("Hash algorithm must be specified")
            .Must(hash => hash == HashAlgorithm.Sha256 || hash == HashAlgorithm.Sha384 || hash == HashAlgorithm.Sha512)
            .WithMessage("Hash algorithm must be SHA-256, SHA-384, or SHA-512");
    }

    public static IRuleBuilder<T, Google.Protobuf.ByteString> ValidDataSize<T>(this IRuleBuilder<T, Google.Protobuf.ByteString> ruleBuilder, int maxSizeBytes = 1024 * 1024)
    {
        return ruleBuilder
            .NotNull().WithMessage("Data is required")
            .Must(data => data.Length > 0).WithMessage("Data cannot be empty")
            .Must(data => data.Length <= maxSizeBytes).WithMessage($"Data size cannot exceed {maxSizeBytes} bytes");
    }

    public static IRuleBuilder<T, uint> ValidPageSize<T>(this IRuleBuilder<T, uint> ruleBuilder, uint maxPageSize = 1000)
    {
        return ruleBuilder
            .Must(size => size <= maxPageSize).WithMessage($"Page size cannot exceed {maxPageSize}");
    }

    public static bool IsValidKeyParametersForAlgorithm(KeyAlgorithm algorithm, KeyParameters? parameters)
    {
        return algorithm switch
        {
            KeyAlgorithm.Rsa => parameters?.RsaParams != null,
            KeyAlgorithm.Ecc or KeyAlgorithm.Ecdsa => parameters?.EccParams != null,
            _ => false
        };
    }
}