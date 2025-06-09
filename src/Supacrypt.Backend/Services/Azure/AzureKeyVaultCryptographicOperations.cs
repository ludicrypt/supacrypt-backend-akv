using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Google.Protobuf;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.V1;
using System.Diagnostics;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;
using AzureEncryptionAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm;

namespace Supacrypt.Backend.Services.Azure;

public class AzureKeyVaultCryptographicOperations(
    IAzureKeyVaultClientFactory clientFactory,
    IAzureKeyVaultResiliencePolicy resiliencePolicy,
    IKeyRepository keyRepository,
    IAzureKeyVaultMetrics metrics,
    ILogger<AzureKeyVaultCryptographicOperations> logger) : ICryptographicOperations
{
    private readonly IAzureKeyVaultClientFactory _clientFactory = clientFactory;
    private readonly IAzureKeyVaultResiliencePolicy _resiliencePolicy = resiliencePolicy;
    private readonly IKeyRepository _keyRepository = keyRepository;
    private readonly IAzureKeyVaultMetrics _metrics = metrics;
    private readonly ILogger<AzureKeyVaultCryptographicOperations> _logger = logger;

    private static string GetAlgorithmFromSigningParameters(SigningParameters? parameters)
    {
        if (parameters == null) return "Unknown";
        
        return parameters.AlgorithmParamsCase switch
        {
            SigningParameters.AlgorithmParamsOneofCase.RsaParams => "RSA",
            SigningParameters.AlgorithmParamsOneofCase.EccParams => "ECC",
            _ => "Unknown"
        };
    }

    private static string GetAlgorithmFromEncryptionParameters(EncryptionParameters? parameters)
    {
        if (parameters == null) return "Unknown";
        
        return parameters.AlgorithmParamsCase switch
        {
            EncryptionParameters.AlgorithmParamsOneofCase.RsaParams => "RSA",
            EncryptionParameters.AlgorithmParamsOneofCase.EccParams => "ECC",
            _ => "Unknown"
        };
    }

    public async Task<SignDataResponse> SignDataAsync(
        SignDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            _logger.LogInformation("Starting signing operation for key {KeyId} with algorithm {Algorithm} [CorrelationId: {CorrelationId}]",
                request.KeyId, GetAlgorithmFromSigningParameters(request.Parameters), correlationId);

            // Validate key exists and supports signing
            await ValidateKeyForOperation(request.KeyId, "sign", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (context) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: cancellationToken), cancellationToken);

            if (keyResponse?.Value is null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);

            // Map the signature algorithm
            var signatureAlgorithm = MapSignatureAlgorithm(request.Parameters, keyResponse.Value.KeyType);

            // Perform the signing operation with basic retry logic
            SignResult signResult;
            try
            {
                signResult = await cryptoClient.SignAsync(signatureAlgorithm, request.Data.ToByteArray(), cancellationToken);
            }
            catch (RequestFailedException ex) when (ex.Status == 429 || ex.Status >= 500)
            {
                // Simple retry for transient errors
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                signResult = await cryptoClient.SignAsync(signatureAlgorithm, request.Data.ToByteArray(), cancellationToken);
            }

            if (signResult is null)
            {
                throw new InvalidOperationException("Signing operation failed");
            }

            _logger.LogInformation("Successfully signed data for key {KeyId} in {Duration}ms [CorrelationId: {CorrelationId}]",
                request.KeyId, stopwatch.ElapsedMilliseconds, correlationId);

            _metrics.RecordOperation("sign", request.KeyId, stopwatch.Elapsed, true);

            return new SignDataResponse
            {
                Success = new SignDataSuccess
                {
                    Signature = ByteString.CopyFrom(signResult.Signature),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign data for key {KeyId} after {Duration}ms [CorrelationId: {CorrelationId}]",
                request.KeyId, stopwatch.ElapsedMilliseconds, correlationId);
            
            _metrics.RecordOperation("sign", request.KeyId, stopwatch.Elapsed, false, ex.GetType().Name);
            throw;
        }
    }

    public async Task<VerifySignatureResponse> VerifySignatureAsync(
        VerifySignatureRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            _logger.LogInformation("Starting signature verification for key {KeyId} with algorithm {Algorithm}",
                request.KeyId, GetAlgorithmFromSigningParameters(request.Parameters));

            // Validate key exists and supports verification
            await ValidateKeyForOperation(request.KeyId, "verify", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (context) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: cancellationToken), cancellationToken);

            if (keyResponse?.Value is null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);

            // Map the signature algorithm
            var signatureAlgorithm = MapSignatureAlgorithm(request.Parameters, keyResponse.Value.KeyType);

            // Perform the verification operation with basic retry logic
            VerifyResult verifyResult;
            try
            {
                verifyResult = await cryptoClient.VerifyAsync(signatureAlgorithm, request.Data.ToByteArray(), request.Signature.ToByteArray(), cancellationToken);
            }
            catch (RequestFailedException ex) when (ex.Status == 429 || ex.Status >= 500)
            {
                // Simple retry for transient errors
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                verifyResult = await cryptoClient.VerifyAsync(signatureAlgorithm, request.Data.ToByteArray(), request.Signature.ToByteArray(), cancellationToken);
            }

            var isValid = verifyResult?.IsValid ?? false;

            _logger.LogInformation("Signature verification for key {KeyId} completed with result {IsValid} in {Duration}ms",
                request.KeyId, isValid, stopwatch.ElapsedMilliseconds);

            return new VerifySignatureResponse
            {
                Success = new VerifySignatureSuccess
                {
                    IsValid = isValid,
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify signature for key {KeyId} after {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    public async Task<EncryptDataResponse> EncryptDataAsync(
        EncryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            _logger.LogInformation("Starting encryption operation for key {KeyId} with algorithm {Algorithm}",
                request.KeyId, GetAlgorithmFromEncryptionParameters(request.Parameters));

            // Validate key exists and supports encryption
            await ValidateKeyForOperation(request.KeyId, "encrypt", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (context) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: cancellationToken), cancellationToken);

            if (keyResponse?.Value is null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Ensure it's an RSA key (only RSA supports encryption/decryption in Azure Key Vault)
            if (keyResponse.Value.KeyType != KeyType.Rsa && keyResponse.Value.KeyType != KeyType.RsaHsm)
            {
                throw new InvalidOperationException($"Encryption is only supported for RSA keys, but key {request.KeyId} is {keyResponse.Value.KeyType}");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);

            // Map the encryption algorithm
            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Parameters);

            // Perform the encryption operation with basic retry logic
            EncryptResult encryptResult;
            try
            {
                encryptResult = await cryptoClient.EncryptAsync(encryptionAlgorithm, request.Plaintext.ToByteArray(), cancellationToken);
            }
            catch (RequestFailedException ex) when (ex.Status == 429 || ex.Status >= 500)
            {
                // Simple retry for transient errors
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                encryptResult = await cryptoClient.EncryptAsync(encryptionAlgorithm, request.Plaintext.ToByteArray(), cancellationToken);
            }

            if (encryptResult is null)
            {
                throw new InvalidOperationException("Encryption operation failed");
            }

            _logger.LogInformation("Successfully encrypted data for key {KeyId} in {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);

            return new EncryptDataResponse
            {
                Success = new EncryptDataSuccess
                {
                    Ciphertext = ByteString.CopyFrom(encryptResult.Ciphertext),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt data for key {KeyId} after {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    public async Task<DecryptDataResponse> DecryptDataAsync(
        DecryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            _logger.LogInformation("Starting decryption operation for key {KeyId} with algorithm {Algorithm}",
                request.KeyId, GetAlgorithmFromEncryptionParameters(request.Parameters));

            // Validate key exists and supports decryption
            await ValidateKeyForOperation(request.KeyId, "decrypt", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (context) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: cancellationToken), cancellationToken);

            if (keyResponse?.Value is null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Ensure it's an RSA key (only RSA supports encryption/decryption in Azure Key Vault)
            if (keyResponse.Value.KeyType != KeyType.Rsa && keyResponse.Value.KeyType != KeyType.RsaHsm)
            {
                throw new InvalidOperationException($"Decryption is only supported for RSA keys, but key {request.KeyId} is {keyResponse.Value.KeyType}");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);

            // Map the encryption algorithm
            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Parameters);

            // Perform the decryption operation with basic retry logic
            DecryptResult decryptResult;
            try
            {
                decryptResult = await cryptoClient.DecryptAsync(encryptionAlgorithm, request.Ciphertext.ToByteArray(), cancellationToken);
            }
            catch (RequestFailedException ex) when (ex.Status == 429 || ex.Status >= 500)
            {
                // Simple retry for transient errors
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                decryptResult = await cryptoClient.DecryptAsync(encryptionAlgorithm, request.Ciphertext.ToByteArray(), cancellationToken);
            }

            if (decryptResult is null)
            {
                throw new InvalidOperationException("Decryption operation failed");
            }

            _logger.LogInformation("Successfully decrypted data for key {KeyId} in {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);

            return new DecryptDataResponse
            {
                Success = new DecryptDataSuccess
                {
                    Plaintext = ByteString.CopyFrom(decryptResult.Plaintext),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt data for key {KeyId} after {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    private async Task ValidateKeyForOperation(string keyId, string operation, CancellationToken cancellationToken)
    {
        var metadata = await _keyRepository.GetKeyMetadataAsync(keyId, cancellationToken);
        
        if (metadata is null)
        {
            throw new KeyNotFoundException($"Key {keyId} not found");
        }

        if (!metadata.Enabled)
        {
            throw new InvalidOperationException($"Key {keyId} is disabled");
        }

        if (!metadata.Operations.Contains(operation, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Key {keyId} does not support operation: {operation}");
        }
    }

    private static AzureSignatureAlgorithm MapSignatureAlgorithm(SigningParameters parameters, KeyType keyType)
    {
        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            var paddingScheme = parameters.RsaParams?.PaddingScheme ?? RSAPaddingScheme.RsaPaddingPkcs1;
            
            if (paddingScheme == RSAPaddingScheme.RsaPaddingPkcs1)
            {
                return parameters.HashAlgorithm switch
                {
                    HashAlgorithm.Sha256 => AzureSignatureAlgorithm.RS256,
                    HashAlgorithm.Sha384 => AzureSignatureAlgorithm.RS384,
                    HashAlgorithm.Sha512 => AzureSignatureAlgorithm.RS512,
                    _ => AzureSignatureAlgorithm.RS256
                };
            }
            else if (paddingScheme == RSAPaddingScheme.RsaPaddingPss)
            {
                return parameters.HashAlgorithm switch
                {
                    HashAlgorithm.Sha256 => AzureSignatureAlgorithm.PS256,
                    HashAlgorithm.Sha384 => AzureSignatureAlgorithm.PS384,
                    HashAlgorithm.Sha512 => AzureSignatureAlgorithm.PS512,
                    _ => AzureSignatureAlgorithm.PS256
                };
            }
            
            return AzureSignatureAlgorithm.RS256;
        }
        else if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            return parameters.HashAlgorithm switch
            {
                HashAlgorithm.Sha256 => AzureSignatureAlgorithm.ES256,
                HashAlgorithm.Sha384 => AzureSignatureAlgorithm.ES384,
                HashAlgorithm.Sha512 => AzureSignatureAlgorithm.ES512,
                _ => AzureSignatureAlgorithm.ES256
            };
        }
        
        throw new ArgumentException($"Unsupported key type for signing: {keyType}");
    }

    private static AzureEncryptionAlgorithm MapEncryptionAlgorithm(EncryptionParameters parameters)
    {
        return parameters.RsaParams?.PaddingScheme switch
        {
            RSAPaddingScheme.RsaPaddingOaep => parameters.RsaParams.OaepHash switch
            {
                HashAlgorithm.Sha256 => AzureEncryptionAlgorithm.RsaOaep256,
                _ => AzureEncryptionAlgorithm.RsaOaep
            },
            RSAPaddingScheme.RsaPaddingPkcs1 => AzureEncryptionAlgorithm.Rsa15,
            _ => AzureEncryptionAlgorithm.RsaOaep256
        };
    }
}