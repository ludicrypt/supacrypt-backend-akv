using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Grpc.Core;
using Moq;
using Supacrypt.Backend.Observability.Tracing;
using Xunit;

namespace Supacrypt.Backend.Tests.Observability;

public class TracingEnricherTests : IDisposable
{
    private readonly ActivitySource _activitySource;
    private readonly ActivityListener _activityListener;
    private readonly List<Activity> _activities;

    public TracingEnricherTests()
    {
        _activitySource = new ActivitySource("Supacrypt.Backend.Tests");
        _activities = new List<Activity>();
        
        _activityListener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllData,
            ActivityStarted = activity => _activities.Add(activity)
        };
        
        ActivitySource.AddActivityListener(_activityListener);
    }

    [Fact]
    public void EnrichCryptoOperation_ShouldSetCorrectTags()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var operation = "sign";
        var keyId = "test-key-123";
        var algorithm = "RS256";

        // Act
        TracingEnricher.EnrichCryptoOperation(activity!, operation, keyId, algorithm);

        // Assert
        Assert.Equal(operation, activity!.GetTagItem("crypto.operation.type"));
        Assert.Equal("test...123", activity.GetTagItem("crypto.key.id")); // Sanitized
        Assert.Equal(algorithm, activity.GetTagItem("crypto.algorithm"));
        Assert.Equal("crypto", activity.GetTagItem("service.component"));
    }

    [Fact]
    public void EnrichCryptoOperation_WithShortKeyId_ShouldNotSanitize()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var operation = "sign";
        var keyId = "short";
        var algorithm = "ES256";

        // Act
        TracingEnricher.EnrichCryptoOperation(activity!, operation, keyId, algorithm);

        // Assert
        Assert.Equal(keyId, activity!.GetTagItem("crypto.key.id")); // Not sanitized
    }

    [Fact]
    public void EnrichAzureKeyVaultOperation_ShouldSetAkvTags()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var operation = "get-key";
        var vaultName = "test-vault";
        var keyName = "test-key-name";

        // Act
        TracingEnricher.EnrichAzureKeyVaultOperation(activity!, operation, vaultName, keyName);

        // Assert
        Assert.Equal(operation, activity!.GetTagItem("akv.operation"));
        Assert.Equal(vaultName, activity.GetTagItem("akv.vault.name"));
        Assert.Equal("test...name", activity.GetTagItem("akv.key.name")); // Sanitized
        Assert.Equal("azure-key-vault", activity.GetTagItem("service.component"));
        Assert.Equal("azure", activity.GetTagItem("cloud.provider"));
        Assert.Equal("key-vault", activity.GetTagItem("cloud.service"));
    }

    [Fact]
    public void EnrichGrpcOperation_ShouldSetGrpcTags()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var method = "SignData";
        var contextMock = new Mock<ServerCallContext>();
        contextMock.Setup(x => x.Status).Returns(new Status(StatusCode.OK, "Success"));
        contextMock.Setup(x => x.Peer).Returns("ipv4:127.0.0.1:12345");

        // Act
        TracingEnricher.EnrichGrpcOperation(activity!, method, contextMock.Object);

        // Assert
        Assert.Equal("grpc", activity!.GetTagItem("rpc.system"));
        Assert.Equal("SupacryptGrpcService", activity.GetTagItem("rpc.service"));
        Assert.Equal(method, activity.GetTagItem("rpc.method"));
        Assert.Equal((int)StatusCode.OK, activity.GetTagItem("rpc.grpc.status_code"));
        Assert.Equal("127.0.0.1", activity.GetTagItem("net.peer.name"));
        Assert.Equal("grpc", activity.GetTagItem("service.component"));
    }

    [Fact]
    public void EnrichAuthentication_WithValidCertificate_ShouldSetAuthTags()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        
        // Create a test certificate
        using var rsa = System.Security.Cryptography.RSA.Create();
        var request = new CertificateRequest("CN=TestUser,O=TestOrg", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        // Act
        TracingEnricher.EnrichAuthentication(activity!, certificate, true);

        // Assert
        Assert.Equal("certificate", activity!.GetTagItem("auth.method"));
        Assert.Equal(true, activity.GetTagItem("auth.success"));
        Assert.Equal("CN=TestUser,O=TestOrg", activity.GetTagItem("auth.cert.subject"));
        Assert.Equal("TestUser", activity.GetTagItem("enduser.id"));
        Assert.Equal("authentication", activity.GetTagItem("service.component"));
        
        // Check thumbprint is truncated
        var thumbprint = activity.GetTagItem("auth.cert.thumbprint") as string;
        Assert.NotNull(thumbprint);
        Assert.EndsWith("...", thumbprint);
    }

    [Fact]
    public void EnrichHealthCheck_ShouldSetHealthCheckTags()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var checkName = "keyvault";
        var status = "healthy";
        var duration = TimeSpan.FromMilliseconds(50);

        // Act
        TracingEnricher.EnrichHealthCheck(activity!, checkName, status, duration);

        // Assert
        Assert.Equal(checkName, activity!.GetTagItem("health.check.name"));
        Assert.Equal(status, activity.GetTagItem("health.check.status"));
        Assert.Equal(50.0, activity.GetTagItem("health.check.duration_ms"));
        Assert.Equal("health-check", activity.GetTagItem("service.component"));
    }

    [Fact]
    public void RecordException_ShouldSetErrorStatus()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var exception = new InvalidOperationException("Test error", new ArgumentException("Inner error"));

        // Act
        TracingEnricher.RecordException(activity!, exception);

        // Assert
        Assert.Equal(ActivityStatusCode.Error, activity!.Status);
        Assert.Equal("Test error", activity.StatusDescription);
        Assert.Equal("System.InvalidOperationException", activity.GetTagItem("exception.type"));
        Assert.Equal("Test error", activity.GetTagItem("exception.message"));
        Assert.Equal("System.ArgumentException", activity.GetTagItem("exception.inner_type"));
        Assert.Equal("Inner error", activity.GetTagItem("exception.inner_message"));
    }

    [Fact]
    public void RecordOperationEvent_ShouldAddEventWithAttributes()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var eventName = "key-rotation-detected";
        var description = "Key rotation event occurred";
        var attributes = new Dictionary<string, object>
        {
            ["key.id"] = "rotated-key",
            ["rotation.type"] = "automatic"
        };

        // Act
        TracingEnricher.RecordOperationEvent(activity!, eventName, description, attributes);

        // Assert
        Assert.NotEmpty(activity!.Events);
        var activityEvent = activity.Events.First();
        Assert.Equal(eventName, activityEvent.Name);
        Assert.Contains(activityEvent.Tags, tag => tag.Key == "event.description" && tag.Value?.ToString() == description);
        Assert.Contains(activityEvent.Tags, tag => tag.Key == "key.id" && tag.Value?.ToString() == "rotated-key");
        Assert.Contains(activityEvent.Tags, tag => tag.Key == "rotation.type" && tag.Value?.ToString() == "automatic");
    }

    [Fact]
    public void SetCorrelationContext_ShouldSetTagsAndBaggage()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var correlationId = "test-correlation-123";
        var requestId = "test-request-456";

        // Act
        TracingEnricher.SetCorrelationContext(activity!, correlationId, requestId);

        // Assert
        Assert.Equal(correlationId, activity!.GetTagItem("correlation.id"));
        Assert.Equal(requestId, activity.GetTagItem("request.id"));
        
        // Check baggage
        Assert.Equal(correlationId, activity.GetBaggageItem("correlation.id"));
        Assert.Equal(requestId, activity.GetBaggageItem("request.id"));
    }

    [Fact]
    public void SetCustomAttributes_ShouldSetAllAttributes()
    {
        // Arrange
        using var activity = _activitySource.StartActivity("TestOperation");
        var attributes = new Dictionary<string, object>
        {
            ["custom.string"] = "test-value",
            ["custom.number"] = 42,
            ["custom.boolean"] = true
        };

        // Act
        TracingEnricher.SetCustomAttributes(activity!, attributes);

        // Assert
        Assert.Equal("test-value", activity!.GetTagItem("custom.string"));
        Assert.Equal(42, activity.GetTagItem("custom.number"));
        Assert.Equal(true, activity.GetTagItem("custom.boolean"));
    }

    public void Dispose()
    {
        _activityListener?.Dispose();
        _activitySource?.Dispose();
    }
}