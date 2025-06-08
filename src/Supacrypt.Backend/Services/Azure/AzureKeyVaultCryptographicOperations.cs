using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Google.Protobuf;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.V1;
using System.Diagnostics;

namespace Supacrypt.Backend.Services.Azure;

public class AzureKeyVaultCryptographicOperations : ICryptographicOperations
{
    private readonly IAzureKeyVaultClientFactory _clientFactory;
    private readonly IAzureKeyVaultResiliencePolicy _resiliencePolicy;
    private readonly IKeyRepository _keyRepository;
    private readonly IAzureKeyVaultMetrics _metrics;
    private readonly ILogger<AzureKeyVaultCryptographicOperations> _logger;

    public AzureKeyVaultCryptographicOperations(
        IAzureKeyVaultClientFactory clientFactory,
        IAzureKeyVaultResiliencePolicy resiliencePolicy,
        IKeyRepository keyRepository,
        IAzureKeyVaultMetrics metrics,
        ILogger<AzureKeyVaultCryptographicOperations> logger)
    {
        _clientFactory = clientFactory;
        _resiliencePolicy = resiliencePolicy;
        _keyRepository = keyRepository;
        _metrics = metrics;
        _logger = logger;
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
                request.KeyId, request.Algorithm, correlationId);

            // Validate key exists and supports signing
            await ValidateKeyForOperation(request.KeyId, "sign", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (ct) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: ct), cancellationToken);

            if (keyResponse?.Value == null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);
            var cryptoPipeline = _resiliencePolicy.GetPipeline<Response<SignResult>>();

            // Map the signature algorithm
            var signatureAlgorithm = MapSignatureAlgorithm(request.Algorithm, keyResponse.Value.KeyType);

            // Perform the signing operation
            var signResult = await cryptoPipeline.ExecuteAsync(async (ct) =>
                await cryptoClient.SignAsync(signatureAlgorithm, request.Data.ToByteArray(), ct), cancellationToken);

            if (signResult?.Value == null)
            {
                throw new InvalidOperationException("Signing operation failed");
            }

            _logger.LogInformation("Successfully signed data for key {KeyId} in {Duration}ms [CorrelationId: {CorrelationId}]",
                request.KeyId, stopwatch.ElapsedMilliseconds, correlationId);

            _metrics.RecordOperation("sign", request.KeyId, stopwatch.Elapsed, true);

            return new SignDataResponse
            {
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                Signature = ByteString.CopyFrom(signResult.Value.Signature)
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
                request.KeyId, request.Algorithm);

            // Validate key exists and supports verification
            await ValidateKeyForOperation(request.KeyId, "verify", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (ct) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: ct), cancellationToken);

            if (keyResponse?.Value == null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            // Create cryptography client for the key
            var cryptoClient = keyClient.GetCryptographyClient(request.KeyId);
            var cryptoPipeline = _resiliencePolicy.GetPipeline<Response<VerifyResult>>();

            // Map the signature algorithm
            var signatureAlgorithm = MapSignatureAlgorithm(request.Algorithm, keyResponse.Value.KeyType);

            // Perform the verification operation
            var verifyResult = await cryptoPipeline.ExecuteAsync(async (ct) =>
                await cryptoClient.VerifyAsync(signatureAlgorithm, request.Data.ToByteArray(), request.Signature.ToByteArray(), ct), cancellationToken);

            var isValid = verifyResult?.Value?.IsValid ?? false;

            _logger.LogInformation("Signature verification for key {KeyId} completed with result {IsValid} in {Duration}ms",
                request.KeyId, isValid, stopwatch.ElapsedMilliseconds);

            return new VerifySignatureResponse
            {
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                IsValid = isValid
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
                request.KeyId, request.Algorithm);

            // Validate key exists and supports encryption
            await ValidateKeyForOperation(request.KeyId, "encrypt", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (ct) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: ct), cancellationToken);

            if (keyResponse?.Value == null)
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
            var cryptoPipeline = _resiliencePolicy.GetPipeline<Response<EncryptResult>>();

            // Map the encryption algorithm
            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Algorithm);

            // Perform the encryption operation
            var encryptResult = await cryptoPipeline.ExecuteAsync(async (ct) =>
                await cryptoClient.EncryptAsync(encryptionAlgorithm, request.Data.ToByteArray(), ct), cancellationToken);

            if (encryptResult?.Value == null)
            {
                throw new InvalidOperationException("Encryption operation failed");
            }

            _logger.LogInformation("Successfully encrypted data for key {KeyId} in {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);

            return new EncryptDataResponse
            {
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                EncryptedData = ByteString.CopyFrom(encryptResult.Value.Ciphertext)
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
                request.KeyId, request.Algorithm);

            // Validate key exists and supports decryption
            await ValidateKeyForOperation(request.KeyId, "decrypt", cancellationToken);

            var keyClient = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Get the key
            var keyResponse = await pipeline.ExecuteAsync(async (ct) =>
                await keyClient.GetKeyAsync(request.KeyId, cancellationToken: ct), cancellationToken);

            if (keyResponse?.Value == null)
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
            var cryptoPipeline = _resiliencePolicy.GetPipeline<Response<DecryptResult>>();

            // Map the encryption algorithm
            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Algorithm);

            // Perform the decryption operation
            var decryptResult = await cryptoPipeline.ExecuteAsync(async (ct) =>
                await cryptoClient.DecryptAsync(encryptionAlgorithm, request.EncryptedData.ToByteArray(), ct), cancellationToken);

            if (decryptResult?.Value == null)
            {
                throw new InvalidOperationException("Decryption operation failed");
            }

            _logger.LogInformation("Successfully decrypted data for key {KeyId} in {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);

            return new DecryptDataResponse
            {
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                DecryptedData = ByteString.CopyFrom(decryptResult.Value.Plaintext)
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
        
        if (metadata == null)
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

    private static SignatureAlgorithm MapSignatureAlgorithm(SignatureAlgorithm algorithm, KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Rsa or KeyType.RsaHsm => algorithm switch
            {
                V1.SignatureAlgorithm.RsaPkcs1Sha256 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS256,
                V1.SignatureAlgorithm.RsaPkcs1Sha384 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS384,
                V1.SignatureAlgorithm.RsaPkcs1Sha512 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS512,
                V1.SignatureAlgorithm.RsaPssSha256 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS256,
                V1.SignatureAlgorithm.RsaPssSha384 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS384,
                V1.SignatureAlgorithm.RsaPssSha512 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS512,
                _ => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS256
            },
            KeyType.Ec or KeyType.EcHsm => algorithm switch
            {
                V1.SignatureAlgorithm.EcdsaSha256 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.ES256,
                V1.SignatureAlgorithm.EcdsaSha384 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.ES384,
                V1.SignatureAlgorithm.EcdsaSha512 => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.ES512,
                _ => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.ES256
            },
            _ => throw new ArgumentException($"Unsupported key type for signing: {keyType}")
        };
    }

    private static EncryptionAlgorithm MapEncryptionAlgorithm(EncryptionAlgorithm algorithm)
    {
        return algorithm switch
        {
            V1.EncryptionAlgorithm.RsaOaepSha1 => Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.RsaOaep,
            V1.EncryptionAlgorithm.RsaOaepSha256 => Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.RsaOaep256,
            V1.EncryptionAlgorithm.RsaPkcs1 => Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.Rsa15,
            _ => Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.RsaOaep256
        };
    }
}