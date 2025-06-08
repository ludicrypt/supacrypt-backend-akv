using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public class DeleteKeyRequestValidator : AbstractValidator<DeleteKeyRequest>
{
    public DeleteKeyRequestValidator()
    {
        RuleFor(x => x.Version)
            .GreaterThan(0u).WithMessage("Protocol version must be greater than 0");

        RuleFor(x => x.KeyId)
            .ValidKeyId();
    }
}