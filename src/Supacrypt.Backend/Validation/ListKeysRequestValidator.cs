using FluentValidation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Validation;

public class ListKeysRequestValidator : AbstractValidator<ListKeysRequest>
{
    public ListKeysRequestValidator()
    {
        RuleFor(x => x.Version)
            .GreaterThan(0u).WithMessage("Protocol version must be greater than 0");

        RuleFor(x => x.PageSize)
            .ValidPageSize();

        RuleFor(x => x.Filter)
            .Must(filter => string.IsNullOrEmpty(filter) || filter.Length <= 1000)
            .WithMessage("Filter expression cannot exceed 1000 characters");

        RuleFor(x => x.PageToken)
            .Must(token => string.IsNullOrEmpty(token) || IsValidBase64(token))
            .WithMessage("Page token must be a valid base64 string");
    }

    private static bool IsValidBase64(string value)
    {
        try
        {
            Convert.FromBase64String(value);
            return true;
        }
        catch
        {
            return false;
        }
    }
}