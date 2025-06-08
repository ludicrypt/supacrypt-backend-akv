using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public class DecryptDataRequestValidator : AbstractValidator<DecryptDataRequest>
{
    public DecryptDataRequestValidator()
    {
        RuleFor(x => x.Version)
            .GreaterThan(0u).WithMessage("Protocol version must be greater than 0");

        RuleFor(x => x.KeyId)
            .ValidKeyId();

        RuleFor(x => x.Ciphertext)
            .NotNull().WithMessage("Ciphertext is required")
            .Must(data => data.Length > 0).WithMessage("Ciphertext cannot be empty")
            .Must(data => data.Length <= 1024 * 1024).WithMessage("Ciphertext size cannot exceed 1MB");

        RuleFor(x => x.Parameters)
            .NotNull().WithMessage("Decryption parameters are required");

        When(x => x.Parameters?.RsaParams != null, () =>
        {
            RuleFor(x => x.Parameters.RsaParams.PaddingScheme)
                .Must(scheme => scheme == RSAPaddingScheme.RsaPaddingPkcs1 || scheme == RSAPaddingScheme.RsaPaddingOaep)
                .WithMessage("RSA padding scheme must be PKCS#1 or OAEP for decryption");

            When(x => x.Parameters.RsaParams.PaddingScheme == RSAPaddingScheme.RsaPaddingOaep, () =>
            {
                RuleFor(x => x.Parameters.RsaParams.OaepHash)
                    .Must(hash => hash == HashAlgorithm.HashAlgorithmSha256 || hash == HashAlgorithm.HashAlgorithmSha384 || hash == HashAlgorithm.HashAlgorithmSha512)
                    .WithMessage("OAEP hash algorithm must be SHA-256, SHA-384, or SHA-512");
            });
        });

        When(x => x.Parameters?.EccParams != null, () =>
        {
            RuleFor(x => x.Parameters.EccParams.KdfHash)
                .Must(hash => hash == HashAlgorithm.HashAlgorithmSha256 || hash == HashAlgorithm.HashAlgorithmSha384 || hash == HashAlgorithm.HashAlgorithmSha512)
                .WithMessage("ECC KDF hash algorithm must be SHA-256, SHA-384, or SHA-512");
        });
    }
}