using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public class GenerateKeyRequestValidator : AbstractValidator<GenerateKeyRequest>
{
    public GenerateKeyRequestValidator()
    {
        RuleFor(x => x.Version)
            .GreaterThan(0u).WithMessage("Protocol version must be greater than 0");

        RuleFor(x => x.Name)
            .ValidKeyName();

        RuleFor(x => x.Algorithm)
            .ValidKeyAlgorithm();

        RuleFor(x => x.Parameters)
            .NotNull().WithMessage("Key parameters are required")
            .Must((request, parameters) => ValidationExtensions.IsValidKeyParametersForAlgorithm(request.Algorithm, parameters))
            .WithMessage("Key parameters must match the specified algorithm");

        When(x => x.Algorithm == KeyAlgorithm.KeyAlgorithmRsa, () =>
        {
            RuleFor(x => x.Parameters.RsaParams.KeySize)
                .ValidRsaKeySize();

            RuleFor(x => x.Parameters.RsaParams.PublicExponent)
                .Must(exp => exp == 0 || exp == 65537 || exp == 3)
                .WithMessage("RSA public exponent must be 0 (default), 3, or 65537");
        });

        When(x => x.Algorithm == KeyAlgorithm.KeyAlgorithmEcc || x.Algorithm == KeyAlgorithm.KeyAlgorithmEcdsa, () =>
        {
            RuleFor(x => x.Parameters.EccParams.Curve)
                .ValidEccCurve();
        });

        RuleFor(x => x.Operations)
            .NotEmpty().WithMessage("At least one operation must be specified")
            .Must(ops => ops.All(op => IsValidOperation(op)))
            .WithMessage("Invalid operation specified. Valid operations are: sign, verify, encrypt, decrypt");

        RuleFor(x => x.Tags)
            .Must(tags => tags.Count <= 50)
            .WithMessage("Maximum of 50 tags allowed")
            .Must(tags => tags.All(kvp => !string.IsNullOrWhiteSpace(kvp.Key) && kvp.Key.Length <= 128))
            .WithMessage("Tag keys must be non-empty and not exceed 128 characters")
            .Must(tags => tags.All(kvp => kvp.Value.Length <= 256))
            .WithMessage("Tag values must not exceed 256 characters");
    }

    private static bool IsValidOperation(string operation)
    {
        return operation is "sign" or "verify" or "encrypt" or "decrypt";
    }
}