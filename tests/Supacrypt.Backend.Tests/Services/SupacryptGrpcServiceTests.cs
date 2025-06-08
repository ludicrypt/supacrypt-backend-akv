using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Moq;
using Supacrypt.Backend.Observability.Metrics;
using Supacrypt.Backend.Services;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.Telemetry;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.Services;

public class SupacryptGrpcServiceTests
{
    private readonly Mock<IKeyManagementService> _keyManagementService;
    private readonly Mock<ICryptographicOperations> _cryptographicOperations;
    private readonly Mock<ILogger<SupacryptGrpcService>> _logger;
    private readonly Mock<PerformanceTracker> _performanceTracker;
    private readonly Mock<CryptoMetrics> _cryptoMetrics;
    private readonly Mock<IValidator<GenerateKeyRequest>> _generateKeyValidator;
    private readonly Mock<IValidator<SignDataRequest>> _signDataValidator;
    private readonly Mock<IValidator<VerifySignatureRequest>> _verifySignatureValidator;
    private readonly Mock<IValidator<GetKeyRequest>> _getKeyValidator;
    private readonly Mock<IValidator<ListKeysRequest>> _listKeysValidator;
    private readonly Mock<IValidator<DeleteKeyRequest>> _deleteKeyValidator;
    private readonly Mock<IValidator<EncryptDataRequest>> _encryptDataValidator;
    private readonly Mock<IValidator<DecryptDataRequest>> _decryptDataValidator;
    private readonly Mock<ServerCallContext> _serverCallContext;
    private readonly SupacryptGrpcService _service;

    public SupacryptGrpcServiceTests()
    {
        _keyManagementService = MockFactories.CreateKeyManagementService();
        _cryptographicOperations = MockFactories.CreateCryptographicOperations();
        _logger = MockFactories.CreateLogger<SupacryptGrpcService>();
        _performanceTracker = MockFactories.CreatePerformanceTracker();
        _cryptoMetrics = MockFactories.CreateCryptoMetrics();
        _generateKeyValidator = new Mock<IValidator<GenerateKeyRequest>>();
        _signDataValidator = new Mock<IValidator<SignDataRequest>>();
        _verifySignatureValidator = new Mock<IValidator<VerifySignatureRequest>>();
        _getKeyValidator = new Mock<IValidator<GetKeyRequest>>();
        _listKeysValidator = new Mock<IValidator<ListKeysRequest>>();
        _deleteKeyValidator = new Mock<IValidator<DeleteKeyRequest>>();
        _encryptDataValidator = new Mock<IValidator<EncryptDataRequest>>();
        _decryptDataValidator = new Mock<IValidator<DecryptDataRequest>>();
        _serverCallContext = new Mock<ServerCallContext>();

        SetupServerCallContext();
        SetupValidators();

        _service = new SupacryptGrpcService(
            _keyManagementService.Object,
            _cryptographicOperations.Object,
            _logger.Object,
            _performanceTracker.Object,
            _cryptoMetrics.Object,
            _generateKeyValidator.Object,
            _signDataValidator.Object,
            _verifySignatureValidator.Object,
            _getKeyValidator.Object,
            _listKeysValidator.Object,
            _deleteKeyValidator.Object,
            _encryptDataValidator.Object,
            _decryptDataValidator.Object);
    }

    private void SetupServerCallContext()
    {
        var headers = new Metadata
        {
            { "correlation-id", TestConstants.TestCorrelationId }
        };
        var trailers = new Metadata();
        
        _serverCallContext.Setup(x => x.RequestHeaders).Returns(headers);
        _serverCallContext.Setup(x => x.ResponseTrailers).Returns(trailers);
        _serverCallContext.Setup(x => x.CancellationToken).Returns(CancellationToken.None);
    }

    private void SetupValidators()
    {
        _generateKeyValidator.Setup(x => x.ValidateAsync(It.IsAny<GenerateKeyRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _signDataValidator.Setup(x => x.ValidateAsync(It.IsAny<SignDataRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _verifySignatureValidator.Setup(x => x.ValidateAsync(It.IsAny<VerifySignatureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _getKeyValidator.Setup(x => x.ValidateAsync(It.IsAny<GetKeyRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _listKeysValidator.Setup(x => x.ValidateAsync(It.IsAny<ListKeysRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _deleteKeyValidator.Setup(x => x.ValidateAsync(It.IsAny<DeleteKeyRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _encryptDataValidator.Setup(x => x.ValidateAsync(It.IsAny<EncryptDataRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
        _decryptDataValidator.Setup(x => x.ValidateAsync(It.IsAny<DecryptDataRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
    }

    [Fact]
    public async Task GenerateKey_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new GenerateKeyRequestBuilder().Build();

        var result = await _service.GenerateKey(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.KeyId.Should().Be(TestConstants.TestKeyId);
        _keyManagementService.Verify(x => x.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task GenerateKey_WithValidationErrors_ThrowsRpcException()
    {
        var request = new GenerateKeyRequestBuilder().Build();
        var validationResult = new ValidationResult(new[]
        {
            new ValidationFailure("Name", TestConstants.ErrorMessages.ValidationFailed)
        });
        
        _generateKeyValidator.Setup(x => x.ValidateAsync(request, CancellationToken.None))
            .ReturnsAsync(validationResult);

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _service.GenerateKey(request, _serverCallContext.Object));

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain(TestConstants.ErrorMessages.ValidationFailed);
    }

    [Fact]
    public async Task SignData_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new SignDataRequestBuilder().Build();

        var result = await _service.SignData(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Signature.Should().NotBeEmpty();
        _cryptographicOperations.Verify(x => x.SignDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task SignData_WithValidationErrors_ThrowsRpcException()
    {
        var request = new SignDataRequestBuilder().Build();
        var validationResult = new ValidationResult(new[]
        {
            new ValidationFailure("Data", TestConstants.ErrorMessages.ValidationFailed)
        });
        
        _signDataValidator.Setup(x => x.ValidateAsync(request, CancellationToken.None))
            .ReturnsAsync(validationResult);

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _service.SignData(request, _serverCallContext.Object));

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain(TestConstants.ErrorMessages.ValidationFailed);
    }

    [Fact]
    public async Task VerifySignature_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new VerifySignatureRequestBuilder().Build();

        var result = await _service.VerifySignature(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.IsValid.Should().BeTrue();
        _cryptographicOperations.Verify(x => x.VerifySignatureAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task VerifySignature_WithValidationErrors_ThrowsRpcException()
    {
        var request = new VerifySignatureRequestBuilder().Build();
        var validationResult = new ValidationResult(new[]
        {
            new ValidationFailure("Signature", TestConstants.ErrorMessages.InvalidSignature)
        });
        
        _verifySignatureValidator.Setup(x => x.ValidateAsync(request, CancellationToken.None))
            .ReturnsAsync(validationResult);

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _service.VerifySignature(request, _serverCallContext.Object));

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain(TestConstants.ErrorMessages.InvalidSignature);
    }

    [Fact]
    public async Task GetKey_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new GetKeyRequestBuilder().Build();
        
        _keyManagementService.Setup(x => x.GetKeyAsync(It.IsAny<GetKeyRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetKeyResponse
            {
                Success = new KeyInfo
                {
                    Metadata = new KeyMetadata
                    {
                        KeyId = TestConstants.TestKeyId,
                        Name = TestConstants.TestKeyName,
                        Algorithm = KeyAlgorithm.RsaPkcs1V2048
                    }
                }
            });

        var result = await _service.GetKey(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Metadata.KeyId.Should().Be(TestConstants.TestKeyId);
        _keyManagementService.Verify(x => x.GetKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task ListKeys_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new ListKeysRequestBuilder().Build();
        
        _keyManagementService.Setup(x => x.ListKeysAsync(It.IsAny<ListKeysRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ListKeysResponse
            {
                Success = new KeyList
                {
                    Keys = { new KeyMetadata { KeyId = TestConstants.TestKeyId, Name = TestConstants.TestKeyName } }
                }
            });

        var result = await _service.ListKeys(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Keys.Should().HaveCount(1);
        _keyManagementService.Verify(x => x.ListKeysAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task DeleteKey_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new DeleteKeyRequestBuilder().Build();
        
        _keyManagementService.Setup(x => x.DeleteKeyAsync(It.IsAny<DeleteKeyRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeleteKeyResponse
            {
                Success = new Google.Protobuf.WellKnownTypes.Empty()
            });

        var result = await _service.DeleteKey(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        _keyManagementService.Verify(x => x.DeleteKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task EncryptData_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new EncryptDataRequestBuilder().Build();
        
        _cryptographicOperations.Setup(x => x.EncryptDataAsync(It.IsAny<EncryptDataRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new EncryptDataResponse
            {
                Success = new EncryptResult
                {
                    Ciphertext = Google.Protobuf.ByteString.CopyFrom(TestConstants.TestCiphertext)
                }
            });

        var result = await _service.EncryptData(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Ciphertext.Should().NotBeEmpty();
        _cryptographicOperations.Verify(x => x.EncryptDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task DecryptData_WithValidRequest_ReturnsSuccessResponse()
    {
        var request = new DecryptDataRequestBuilder().Build();
        
        _cryptographicOperations.Setup(x => x.DecryptDataAsync(It.IsAny<DecryptDataRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DecryptDataResponse
            {
                Success = new DecryptResult
                {
                    Plaintext = Google.Protobuf.ByteString.CopyFrom(TestConstants.TestData)
                }
            });

        var result = await _service.DecryptData(request, _serverCallContext.Object);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Plaintext.Should().NotBeEmpty();
        _cryptographicOperations.Verify(x => x.DecryptDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task SignData_ServiceThrowsException_MapsToRpcException()
    {
        var request = new SignDataRequestBuilder().Build();
        var innerException = new InvalidOperationException("Service error");
        
        _cryptographicOperations.Setup(x => x.SignDataAsync(It.IsAny<SignDataRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(innerException);

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _service.SignData(request, _serverCallContext.Object));

        exception.Should().NotBeNull();
        exception.StatusCode.Should().NotBe(StatusCode.OK);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task Service_WithoutCorrelationId_GeneratesCorrelationId(string correlationId)
    {
        var headers = new Metadata();
        if (!string.IsNullOrEmpty(correlationId))
        {
            headers.Add("correlation-id", correlationId);
        }
        
        _serverCallContext.Setup(x => x.RequestHeaders).Returns(headers);
        
        var request = new GenerateKeyRequestBuilder().Build();

        await _service.GenerateKey(request, _serverCallContext.Object);

        _keyManagementService.Verify(x => x.GenerateKeyAsync(
            request, 
            It.Is<string>(c => !string.IsNullOrEmpty(c)), 
            CancellationToken.None), Times.Once);
    }
}