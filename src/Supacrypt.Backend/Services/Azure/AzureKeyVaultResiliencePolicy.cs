using Azure;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using Supacrypt.Backend.Configuration;
using System.Net;

namespace Supacrypt.Backend.Services.Azure;

public interface IAzureKeyVaultResiliencePolicy
{
    ResiliencePipeline<T> GetPipeline<T>();
}

public class AzureKeyVaultResiliencePolicy : IAzureKeyVaultResiliencePolicy
{
    private readonly AzureKeyVaultOptions _options;
    private readonly ILogger<AzureKeyVaultResiliencePolicy> _logger;

    public AzureKeyVaultResiliencePolicy(
        IOptions<AzureKeyVaultOptions> options,
        ILogger<AzureKeyVaultResiliencePolicy> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public ResiliencePipeline<T> GetPipeline<T>()
    {
        return CreateResiliencePipeline<T>();
    }

    private ResiliencePipeline<T> CreateResiliencePipeline<T>()
    {
        var pipelineBuilder = new ResiliencePipelineBuilder<T>();

        // Add retry strategy
        pipelineBuilder.AddRetry(new RetryStrategyOptions<T>
        {
            ShouldHandle = new PredicateBuilder<T>()
                .Handle<RequestFailedException>(IsTransientError)
                .Handle<TaskCanceledException>()
                .Handle<HttpRequestException>()
                .Handle<OperationCanceledException>(),
            BackoffType = DelayBackoffType.Exponential,
            UseJitter = true,
            MaxRetryAttempts = _options.RetryOptions.MaxRetries,
            Delay = _options.RetryOptions.Delay,
            MaxDelay = _options.RetryOptions.MaxDelay,
            OnRetry = args =>
            {
                _logger.LogWarning("Retrying Azure Key Vault operation. Attempt: {Attempt}, Exception: {Exception}",
                    args.AttemptNumber, args.Outcome.Exception?.Message);
                return ValueTask.CompletedTask;
            }
        });

        // Add circuit breaker strategy
        pipelineBuilder.AddCircuitBreaker(new CircuitBreakerStrategyOptions<T>
        {
            ShouldHandle = new PredicateBuilder<T>()
                .Handle<RequestFailedException>(IsCircuitBreakerError)
                .Handle<TaskCanceledException>()
                .Handle<HttpRequestException>(),
            FailureRatio = 0.5,
            SamplingDuration = TimeSpan.FromSeconds(30),
            MinimumThroughput = _options.CircuitBreaker.HandledEventsAllowedBeforeBreaking,
            BreakDuration = _options.CircuitBreaker.DurationOfBreak,
            OnOpened = args =>
            {
                _logger.LogError("Azure Key Vault circuit breaker opened. Exception: {Exception}",
                    args.Outcome.Exception?.Message);
                return ValueTask.CompletedTask;
            },
            OnClosed = args =>
            {
                _logger.LogInformation("Azure Key Vault circuit breaker closed");
                return ValueTask.CompletedTask;
            },
            OnHalfOpened = args =>
            {
                _logger.LogInformation("Azure Key Vault circuit breaker half-opened");
                return ValueTask.CompletedTask;
            }
        });

        return pipelineBuilder.Build();
    }

    private static bool IsTransientError(RequestFailedException exception)
    {
        return exception.Status switch
        {
            429 => true, // Rate limited
            >= 500 => true, // Server errors
            408 => true, // Request timeout
            _ => false
        };
    }

    private static bool IsCircuitBreakerError(RequestFailedException exception)
    {
        return exception.Status switch
        {
            >= 500 => true, // Server errors
            429 => true, // Rate limited
            408 => true, // Request timeout
            _ => false
        };
    }
}