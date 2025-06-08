using FluentAssertions;
using Google.Protobuf;
using Supacrypt.Backend.Validation;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.Validation;

public class SignDataRequestValidatorTests
{
    private readonly SignDataRequestValidator _validator = new();

    [Fact]
    public async Task ValidateAsync_WithValidRequest_ReturnsSuccess()
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(TestConstants.TestKeyId)
            .WithData(TestConstants.TestData)
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task ValidateAsync_WithInvalidKeyId_ReturnsValidationError(string keyId)
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(keyId)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.KeyId));
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyData_ReturnsValidationError()
    {
        var request = new SignDataRequestBuilder()
            .WithData(Array.Empty<byte>())
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.Data));
    }

    [Fact]
    public async Task ValidateAsync_WithNullData_ReturnsValidationError()
    {
        var request = new SignDataRequestBuilder().Build();
        request.Data = null;

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.Data));
    }

    [Fact]
    public async Task ValidateAsync_WithDataTooLarge_ReturnsValidationError()
    {
        var largeData = new byte[1024 * 1024 + 1]; // 1MB + 1 byte (assuming max is 1MB)
        var request = new SignDataRequestBuilder()
            .WithData(largeData)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.Data));
    }

    [Fact]
    public async Task ValidateAsync_WithUnsupportedAlgorithm_ReturnsValidationError()
    {
        var request = new SignDataRequestBuilder()
            .WithAlgorithm(SignatureAlgorithm.Unspecified)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.Algorithm));
    }

    [Theory]
    [InlineData(SignatureAlgorithm.RsaPkcs1V15Sha256)]
    [InlineData(SignatureAlgorithm.RsaPkcs1V15Sha384)]
    [InlineData(SignatureAlgorithm.RsaPkcs1V15Sha512)]
    [InlineData(SignatureAlgorithm.RsaPssV2048Sha256)]
    [InlineData(SignatureAlgorithm.RsaPssV3072Sha384)]
    [InlineData(SignatureAlgorithm.RsaPssV4096Sha512)]
    [InlineData(SignatureAlgorithm.EcdsaP256Sha256)]
    [InlineData(SignatureAlgorithm.EcdsaP384Sha384)]
    [InlineData(SignatureAlgorithm.EcdsaP521Sha512)]
    public async Task ValidateAsync_WithSupportedAlgorithms_ReturnsSuccess(SignatureAlgorithm algorithm)
    {
        var request = new SignDataRequestBuilder()
            .WithAlgorithm(algorithm)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_WithMaximumAllowedDataSize_ReturnsSuccess()
    {
        var maxData = new byte[1024 * 1024]; // 1MB (assuming this is the max)
        var request = new SignDataRequestBuilder()
            .WithData(maxData)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_WithValidKeyIdFormat_ReturnsSuccess()
    {
        var validKeyIds = new[]
        {
            "key-123",
            "my_key_456",
            "Key789",
            "test-key-with-dashes",
            "key_with_underscores"
        };

        foreach (var keyId in validKeyIds)
        {
            var request = new SignDataRequestBuilder()
                .WithKeyId(keyId)
                .Build();

            var result = await _validator.ValidateAsync(request);

            result.IsValid.Should().BeTrue($"KeyId '{keyId}' should be valid");
        }
    }

    [Theory]
    [InlineData("key with spaces")]
    [InlineData("key@with@symbols")]
    [InlineData("key/with/slashes")]
    [InlineData("key\\with\\backslashes")]
    public async Task ValidateAsync_WithInvalidKeyIdFormat_ReturnsValidationError(string invalidKeyId)
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(invalidKeyId)
            .Build();

        var result = await _validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == nameof(SignDataRequest.KeyId));
    }
}