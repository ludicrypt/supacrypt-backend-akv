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
            .Must(algorithm => algorithm != KeyAlgorithm.KeyAlgorithmUnspecified)
            .WithMessage("Key algorithm must be specified")
            .Must(algorithm => Enum.IsDefined(typeof(KeyAlgorithm), algorithm))
            .WithMessage("Invalid key algorithm");
    }

    public static IRuleBuilder<T, RSAKeySize> ValidRsaKeySize<T>(this IRuleBuilder<T, RSAKeySize> ruleBuilder)
    {
        return ruleBuilder
            .Must(size => size != RSAKeySize.RsaKeySizeUnspecified)
            .WithMessage("RSA key size must be specified")
            .Must(size => size == RSAKeySize.RsaKeySize2048 || size == RSAKeySize.RsaKeySize3072 || size == RSAKeySize.RsaKeySize4096)
            .WithMessage("RSA key size must be 2048, 3072, or 4096 bits");
    }

    public static IRuleBuilder<T, ECCCurve> ValidEccCurve<T>(this IRuleBuilder<T, ECCCurve> ruleBuilder)
    {
        return ruleBuilder
            .Must(curve => curve != ECCCurve.EccCurveUnspecified)
            .WithMessage("ECC curve must be specified")
            .Must(curve => curve == ECCCurve.EccCurveP256 || curve == ECCCurve.EccCurveP384 || curve == ECCCurve.EccCurveP521)
            .WithMessage("ECC curve must be P-256, P-384, or P-521");
    }

    public static IRuleBuilder<T, HashAlgorithm> ValidHashAlgorithm<T>(this IRuleBuilder<T, HashAlgorithm> ruleBuilder)
    {
        return ruleBuilder
            .Must(hash => hash != HashAlgorithm.HashAlgorithmUnspecified)
            .WithMessage("Hash algorithm must be specified")
            .Must(hash => hash == HashAlgorithm.HashAlgorithmSha256 || hash == HashAlgorithm.HashAlgorithmSha384 || hash == HashAlgorithm.HashAlgorithmSha512)
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
            KeyAlgorithm.KeyAlgorithmRsa => parameters?.RsaParams != null,
            KeyAlgorithm.KeyAlgorithmEcc or KeyAlgorithm.KeyAlgorithmEcdsa => parameters?.EccParams != null,
            _ => false
        };
    }
}