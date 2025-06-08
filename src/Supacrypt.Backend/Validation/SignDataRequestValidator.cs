using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public class SignDataRequestValidator : AbstractValidator<SignDataRequest>
{
    public SignDataRequestValidator()
    {
        RuleFor(x => x.Version)
            .GreaterThan(0u).WithMessage("Protocol version must be greater than 0");

        RuleFor(x => x.KeyId)
            .ValidKeyId();

        RuleFor(x => x.Data)
            .ValidDataSize(maxSizeBytes: 1024 * 64);

        RuleFor(x => x.Parameters)
            .NotNull().WithMessage("Signing parameters are required");

        RuleFor(x => x.Parameters.HashAlgorithm)
            .ValidHashAlgorithm();

        When(x => x.Parameters?.RsaParams != null, () =>
        {
            RuleFor(x => x.Parameters.RsaParams.PaddingScheme)
                .Must(scheme => scheme == RSAPaddingScheme.RsaPaddingPkcs1 || scheme == RSAPaddingScheme.RsaPaddingPss)
                .WithMessage("RSA padding scheme must be PKCS#1 or PSS for signing");

            When(x => x.Parameters.RsaParams.PaddingScheme == RSAPaddingScheme.RsaPaddingPss, () =>
            {
                RuleFor(x => x.Parameters.RsaParams.SaltLength)
                    .GreaterThanOrEqualTo(0u)
                    .WithMessage("PSS salt length must be non-negative");
            });
        });

        When(x => x.IsPrehashed && x.Data.Length > 64, () =>
        {
            RuleFor(x => x.Data.Length)
                .LessThanOrEqualTo(64)
                .WithMessage("Pre-hashed data should not exceed 64 bytes (SHA-512 hash size)");
        });
    }
}