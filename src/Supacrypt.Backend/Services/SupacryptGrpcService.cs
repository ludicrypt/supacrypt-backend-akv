using FluentValidation;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Supacrypt.V1;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.ErrorHandling;
using Supacrypt.Backend.Logging;
using Supacrypt.Backend.Telemetry;
using Supacrypt.Backend.Observability.Metrics;
using Supacrypt.Backend.Observability.Tracing;
using System.Diagnostics;

namespace Supacrypt.Backend.Services;

[Authorize(Policy = "RequireValidCertificate")]
public class SupacryptGrpcService : SupacryptService.SupacryptServiceBase
{
    private readonly IKeyManagementService _keyManagementService;
    private readonly ICryptographicOperations _cryptographicOperations;
    private readonly ILogger<SupacryptGrpcService> _logger;
    private readonly PerformanceTracker _performanceTracker;
    private readonly CryptoMetrics _cryptoMetrics;
    
    private readonly IValidator<GenerateKeyRequest> _generateKeyValidator;
    private readonly IValidator<SignDataRequest> _signDataValidator;
    private readonly IValidator<VerifySignatureRequest> _verifySignatureValidator;
    private readonly IValidator<GetKeyRequest> _getKeyValidator;
    private readonly IValidator<ListKeysRequest> _listKeysValidator;
    private readonly IValidator<DeleteKeyRequest> _deleteKeyValidator;
    private readonly IValidator<EncryptDataRequest> _encryptDataValidator;
    private readonly IValidator<DecryptDataRequest> _decryptDataValidator;

    public SupacryptGrpcService(
        IKeyManagementService keyManagementService,
        ICryptographicOperations cryptographicOperations,
        ILogger<SupacryptGrpcService> logger,
        PerformanceTracker performanceTracker,
        CryptoMetrics cryptoMetrics,
        IValidator<GenerateKeyRequest> generateKeyValidator,
        IValidator<SignDataRequest> signDataValidator,
        IValidator<VerifySignatureRequest> verifySignatureValidator,
        IValidator<GetKeyRequest> getKeyValidator,
        IValidator<ListKeysRequest> listKeysValidator,
        IValidator<DeleteKeyRequest> deleteKeyValidator,
        IValidator<EncryptDataRequest> encryptDataValidator,
        IValidator<DecryptDataRequest> decryptDataValidator)
    {
        _keyManagementService = keyManagementService;
        _cryptographicOperations = cryptographicOperations;
        _logger = logger;
        _performanceTracker = performanceTracker;
        _cryptoMetrics = cryptoMetrics;
        _generateKeyValidator = generateKeyValidator;
        _signDataValidator = signDataValidator;
        _verifySignatureValidator = verifySignatureValidator;
        _getKeyValidator = getKeyValidator;
        _listKeysValidator = listKeysValidator;
        _deleteKeyValidator = deleteKeyValidator;
        _encryptDataValidator = encryptDataValidator;
        _decryptDataValidator = decryptDataValidator;
    }

    public override async Task<GenerateKeyResponse> GenerateKey(
        GenerateKeyRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("GenerateKey", correlationId);
        using var operationLogger = new OperationLogger(_logger, "GenerateKey", correlationId);

        try
        {
            operationLogger.LogInformation("Starting key generation: KeyName={KeyName}, Algorithm={Algorithm}", 
                request.Name, request.Algorithm);

            var validationResult = await _generateKeyValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _keyManagementService.GenerateKeyAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { KeyId = result.Success.Metadata.KeyId });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Key generation completed: KeyId={KeyId}", 
                    result.Success.Metadata.KeyId);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<SignDataResponse> SignData(
        SignDataRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var activity = ActivitySources.GrpcService.StartActivity("SignData");
        using var performanceTracker = _performanceTracker.BeginOperation("SignData", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "SignData", correlationId, request.KeyId);

        // Enrich activity with request context
        if (activity != null)
        {
            TracingEnricher.EnrichGrpcOperation(activity, "SignData", context);
            TracingEnricher.EnrichCryptoOperation(activity, "sign", request.KeyId, request.Algorithm.ToString());
            TracingEnricher.SetCorrelationContext(activity, correlationId);
        }

        var stopwatch = Stopwatch.StartNew();
        _cryptoMetrics.RecordActiveOperationStart("sign");

        try
        {
            operationLogger.LogInformation("Starting data signing: KeyId={KeyId}, DataSize={DataSize}bytes", 
                request.KeyId, request.Data.Length);

            var validationResult = await _signDataValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                
                if (activity != null)
                {
                    activity.SetStatus(ActivityStatusCode.Error, "Validation failed");
                    activity.SetTag("validation.error", errors);
                }
                
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _cryptographicOperations.SignDataAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            stopwatch.Stop();
            var success = result.Success != null;

            // Record metrics
            _cryptoMetrics.RecordSignOperation(
                request.KeyId, 
                request.Algorithm.ToString(), 
                stopwatch.Elapsed, 
                success,
                request.Data.Length,
                result.Success?.Signature.Length);

            if (success)
            {
                operationLogger.LogSuccess(new { SignatureSize = result.Success!.Signature.Length });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Data signing completed: SignatureSize={SignatureSize}bytes", 
                    result.Success.Signature.Length);
                
                if (activity != null)
                {
                    activity.SetTag("signature.size", result.Success.Signature.Length);
                    activity.SetStatus(ActivityStatusCode.Ok);
                }
            }

            return result;
        }
        catch (RpcException ex)
        {
            stopwatch.Stop();
            _cryptoMetrics.RecordSignOperation(request.KeyId, request.Algorithm.ToString(), stopwatch.Elapsed, false, request.Data.Length);
            
            if (activity != null)
            {
                TracingEnricher.RecordException(activity, ex);
            }
            
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _cryptoMetrics.RecordSignOperation(request.KeyId, request.Algorithm.ToString(), stopwatch.Elapsed, false, request.Data.Length);
            
            if (activity != null)
            {
                TracingEnricher.RecordException(activity, ex);
            }
            
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
        finally
        {
            _cryptoMetrics.RecordActiveOperationEnd("sign");
        }
    }

    public override async Task<VerifySignatureResponse> VerifySignature(
        VerifySignatureRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("VerifySignature", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "VerifySignature", correlationId, request.KeyId);

        try
        {
            operationLogger.LogInformation("Starting signature verification: KeyId={KeyId}, DataSize={DataSize}bytes, SignatureSize={SignatureSize}bytes", 
                request.KeyId, request.Data.Length, request.Signature.Length);

            var validationResult = await _verifySignatureValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _cryptographicOperations.VerifySignatureAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { IsValid = result.Success.IsValid });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Signature verification completed: IsValid={IsValid}", 
                    result.Success.IsValid);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<GetKeyResponse> GetKey(
        GetKeyRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("GetKey", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "GetKey", correlationId, request.KeyId);

        try
        {
            operationLogger.LogInformation("Starting key retrieval: KeyId={KeyId}, IncludePublicKey={IncludePublicKey}", 
                request.KeyId, request.IncludePublicKey);

            var validationResult = await _getKeyValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _keyManagementService.GetKeyAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { KeyName = result.Success.Metadata.Name });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Key retrieval completed: KeyName={KeyName}", 
                    result.Success.Metadata.Name);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<ListKeysResponse> ListKeys(
        ListKeysRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("ListKeys", correlationId);
        using var operationLogger = new OperationLogger(_logger, "ListKeys", correlationId);

        try
        {
            operationLogger.LogInformation("Starting key listing: PageSize={PageSize}, Filter={Filter}, IncludeDisabled={IncludeDisabled}", 
                request.PageSize, request.Filter ?? "None", request.IncludeDisabled);

            var validationResult = await _listKeysValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _keyManagementService.ListKeysAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { KeyCount = result.Success.Keys.Count });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Key listing completed: KeyCount={KeyCount}", 
                    result.Success.Keys.Count);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<DeleteKeyResponse> DeleteKey(
        DeleteKeyRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("DeleteKey", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "DeleteKey", correlationId, request.KeyId);

        try
        {
            operationLogger.LogInformation("Starting key deletion: KeyId={KeyId}, Force={Force}", 
                request.KeyId, request.Force);

            var validationResult = await _deleteKeyValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _keyManagementService.DeleteKeyAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess();
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Key deletion completed");
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<EncryptDataResponse> EncryptData(
        EncryptDataRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("EncryptData", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "EncryptData", correlationId, request.KeyId);

        try
        {
            operationLogger.LogInformation("Starting data encryption: KeyId={KeyId}, PlaintextSize={PlaintextSize}bytes", 
                request.KeyId, request.Plaintext.Length);

            var validationResult = await _encryptDataValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _cryptographicOperations.EncryptDataAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { CiphertextSize = result.Success.Ciphertext.Length });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Data encryption completed: CiphertextSize={CiphertextSize}bytes", 
                    result.Success.Ciphertext.Length);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    public override async Task<DecryptDataResponse> DecryptData(
        DecryptDataRequest request,
        ServerCallContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        using var performanceTracker = _performanceTracker.BeginOperation("DecryptData", correlationId, request.KeyId);
        using var operationLogger = new OperationLogger(_logger, "DecryptData", correlationId, request.KeyId);

        try
        {
            operationLogger.LogInformation("Starting data decryption: KeyId={KeyId}, CiphertextSize={CiphertextSize}bytes", 
                request.KeyId, request.Ciphertext.Length);

            var validationResult = await _decryptDataValidator.ValidateAsync(request, context.CancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
                operationLogger.LogValidationFailure(errors);
                throw new RpcException(new Status(StatusCode.InvalidArgument, errors));
            }

            var result = await _cryptographicOperations.DecryptDataAsync(
                request,
                correlationId,
                context.CancellationToken)
                .ConfigureAwait(false);

            if (result.Success != null)
            {
                operationLogger.LogSuccess(new { PlaintextSize = result.Success.Plaintext.Length });
                performanceTracker.MarkSuccess();
                operationLogger.LogInformation("Data decryption completed: PlaintextSize={PlaintextSize}bytes", 
                    result.Success.Plaintext.Length);
            }

            return result;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            operationLogger.LogFailure(ex);
            var status = ErrorMapper.MapToGrpcStatus(ex, correlationId);
            throw new RpcException(status);
        }
    }

    private static string GetOrCreateCorrelationId(ServerCallContext context)
    {
        const string correlationIdKey = "correlation-id";
        
        var headers = context.RequestHeaders;
        var correlationIdHeader = headers.FirstOrDefault(h => 
            string.Equals(h.Key, correlationIdKey, StringComparison.OrdinalIgnoreCase));

        if (correlationIdHeader != null && !string.IsNullOrEmpty(correlationIdHeader.Value))
        {
            return correlationIdHeader.Value;
        }

        var correlationId = Activity.Current?.Id ?? Guid.NewGuid().ToString();
        
        context.ResponseTrailers.Add(correlationIdKey, correlationId);
        
        return correlationId;
    }
}