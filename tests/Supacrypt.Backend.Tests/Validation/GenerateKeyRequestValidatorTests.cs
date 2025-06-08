using FluentAssertions;
using Supacrypt.Backend.Validation;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.Validation;

public class GenerateKeyRequestValidatorTests
{
    private readonly GenerateKeyRequestValidator _validator = new();

    [Fact]
    public async Task ValidateAsync_WithValidRequest_ReturnsSuccess()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName("valid-key-name")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .WithKeySize(RSAKeySize.Rsa2048)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task ValidateAsync_WithInvalidName_ReturnsValidationError(string name)
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName(name)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.Name));
    }

    [Fact]
    public async Task ValidateAsync_WithNameTooLong_ReturnsValidationError()
    {
        var longName = new string('a', 256); // Assuming max length is 255
        var request = new GenerateKeyRequestBuilder()
            .WithName(longName)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.Name));
    }

    [Fact]
    public async Task ValidateAsync_WithUnsupportedAlgorithm_ReturnsValidationError()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(KeyAlgorithm.Unspecified)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.Algorithm));
    }

    [Theory]
    [InlineData(KeyAlgorithm.RsaPkcs1V2048, RSAKeySize.Rsa1024)] // Key size too small for algorithm
    [InlineData(KeyAlgorithm.RsaPkcs1V4096, RSAKeySize.Rsa2048)] // Key size smaller than algorithm suggests
    public async Task ValidateAsync_WithIncompatibleRsaKeySize_ReturnsValidationError(KeyAlgorithm algorithm, RSAKeySize keySize)
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(algorithm)
            .WithKeySize(keySize)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.RsaKeySize) || 
                                            e.PropertyName == nameof(GenerateKeyRequest.Algorithm));
    }

    [Fact]
    public async Task ValidateAsync_WithEcAlgorithmAndRsaKeySize_ReturnsValidationError()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(KeyAlgorithm.EcdsaP256)
            .WithKeySize(RSAKeySize.Rsa2048) // RSA key size with EC algorithm
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.RsaKeySize));
    }

    [Fact]
    public async Task ValidateAsync_WithPastExpiryDate_ReturnsValidationError()
    {
        var pastDate = DateTime.UtcNow.AddDays(-1);
        var request = new GenerateKeyRequestBuilder()
            .WithExpiryDate(pastDate)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.ExpiryDate));
    }

    [Fact]
    public async Task ValidateAsync_WithExpiryDateTooFarInFuture_ReturnsValidationError()
    {
        var farFutureDate = DateTime.UtcNow.AddYears(11); // Assuming max is 10 years
        var request = new GenerateKeyRequestBuilder()
            .WithExpiryDate(farFutureDate)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(GenerateKeyRequest.ExpiryDate));
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidTagKey_ReturnsValidationError()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithTag("", "value") // Empty tag key
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName.Contains("Tags"));
    }

    [Fact]
    public async Task ValidateAsync_WithTooManyTags_ReturnsValidationError()
    {
        var request = new GenerateKeyRequestBuilder().Build();
        
        // Add too many tags (assuming limit is 15)
        for (int i = 0; i < 16; i++)
        {
            request.Tags[$"tag{i}"] = $"value{i}";
        }

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName.Contains("Tags"));
    }

    [Theory]
    [InlineData(KeyAlgorithm.RsaPkcs1V2048)]
    [InlineData(KeyAlgorithm.RsaPkcs1V3072)]
    [InlineData(KeyAlgorithm.RsaPkcs1V4096)]
    [InlineData(KeyAlgorithm.EcdsaP256)]
    [InlineData(KeyAlgorithm.EcdsaP384)]
    [InlineData(KeyAlgorithm.EcdsaP521)]
    public async Task ValidateAsync_WithSupportedAlgorithms_ReturnsSuccess(KeyAlgorithm algorithm)
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(algorithm)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_WithValidTags_ReturnsSuccess()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithTag("Environment", "Production")
            .WithTag("Owner", "TeamA")
            .WithTag("CostCenter", "12345")
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
    }
}