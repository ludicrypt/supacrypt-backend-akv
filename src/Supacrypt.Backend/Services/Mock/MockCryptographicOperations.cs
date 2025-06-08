using Microsoft.Extensions.Logging;
using Supacrypt.V1;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.ErrorHandling;
using Supacrypt.Backend.Exceptions;
using System.Security.Cryptography;

namespace Supacrypt.Backend.Services.Mock;

public class MockCryptographicOperations : ICryptographicOperations
{
    private readonly IKeyRepository _keyRepository;
    private readonly ILogger<MockCryptographicOperations> _logger;
    private readonly Random _random = new();

    public MockCryptographicOperations(IKeyRepository keyRepository, ILogger<MockCryptographicOperations> logger)
    {
        _keyRepository = keyRepository;
        _logger = logger;
    }

    public async Task<SignDataResponse> SignDataAsync(
        SignDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(100, 300, cancellationToken).ConfigureAwait(false);

            var keyMetadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (keyMetadata == null)
            {
                throw new CryptographicOperationException(
                    ErrorCode.ErrorCodeKeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    "SignData",
                    correlationId,
                    request.KeyId);
            }

            if (!keyMetadata.Operations.Contains("sign"))
            {
                throw new CryptographicOperationException(
                    ErrorCode.ErrorCodeOperationNotSupported,
                    $"Key '{request.KeyId}' does not support signing operations",
                    "SignData",
                    correlationId,
                    request.KeyId);
            }

            var signature = GenerateMockSignature(keyMetadata.Algorithm, request.Data.ToByteArray());

            return new SignDataResponse
            {
                Success = new SignDataSuccess
                {
                    Signature = Google.Protobuf.ByteString.CopyFrom(signature),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock sign data failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildSignDataError(errorDetails);
        }
    }

    public async Task<VerifySignatureResponse> VerifySignatureAsync(
        VerifySignatureRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(80, 250, cancellationToken).ConfigureAwait(false);

            var keyMetadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (keyMetadata == null)
            {
                throw new CryptographicOperationException(
                    ErrorCode.KeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    "VerifySignature",
                    correlationId,
                    request.KeyId);
            }

            if (!keyMetadata.Operations.Contains("verify"))
            {
                throw new CryptographicOperationException(
                    ErrorCode.ErrorCodeOperationNotSupported,
                    $"Key '{request.KeyId}' does not support verification operations",
                    "VerifySignature",
                    correlationId,
                    request.KeyId);
            }

            var isValid = MockVerifySignature(request.Data.ToByteArray(), request.Signature.ToByteArray());

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
            _logger.LogError(ex, "Mock verify signature failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildVerifySignatureError(errorDetails);
        }
    }

    public async Task<EncryptDataResponse> EncryptDataAsync(
        EncryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(100, 300, cancellationToken).ConfigureAwait(false);

            var keyMetadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (keyMetadata == null)
            {
                throw new CryptographicOperationException(
                    ErrorCode.KeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    "EncryptData",
                    correlationId,
                    request.KeyId);
            }

            if (!keyMetadata.Operations.Contains("encrypt"))
            {
                throw new CryptographicOperationException(
                    ErrorCode.ErrorCodeOperationNotSupported,
                    $"Key '{request.KeyId}' does not support encryption operations",
                    "EncryptData",
                    correlationId,
                    request.KeyId);
            }

            var ciphertext = GenerateMockEncryption(request.Plaintext.ToByteArray());

            return new EncryptDataResponse
            {
                Success = new EncryptDataSuccess
                {
                    Ciphertext = Google.Protobuf.ByteString.CopyFrom(ciphertext),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock encrypt data failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildEncryptDataError(errorDetails);
        }
    }

    public async Task<DecryptDataResponse> DecryptDataAsync(
        DecryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(100, 300, cancellationToken).ConfigureAwait(false);

            var keyMetadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (keyMetadata == null)
            {
                throw new CryptographicOperationException(
                    ErrorCode.KeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    "DecryptData",
                    correlationId,
                    request.KeyId);
            }

            if (!keyMetadata.Operations.Contains("decrypt"))
            {
                throw new CryptographicOperationException(
                    ErrorCode.ErrorCodeOperationNotSupported,
                    $"Key '{request.KeyId}' does not support decryption operations",
                    "DecryptData",
                    correlationId,
                    request.KeyId);
            }

            var plaintext = MockDecryptData(request.Ciphertext.ToByteArray());

            return new DecryptDataResponse
            {
                Success = new DecryptDataSuccess
                {
                    Plaintext = Google.Protobuf.ByteString.CopyFrom(plaintext),
                    Parameters = request.Parameters,
                    KeyId = request.KeyId
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock decrypt data failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildDecryptDataError(errorDetails);
        }
    }

    private async Task SimulateDelay(int minMs, int maxMs, CancellationToken cancellationToken)
    {
        var delay = _random.Next(minMs, maxMs);
        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private byte[] GenerateMockSignature(KeyAlgorithm algorithm, byte[] data)
    {
        var hashBytes = SHA256.HashData(data);
        var signatureSize = algorithm switch
        {
            KeyAlgorithm.KeyAlgorithmRsa => 256,
            KeyAlgorithm.KeyAlgorithmEcc or KeyAlgorithm.KeyAlgorithmEcdsa => 64,
            _ => 64
        };

        var signature = new byte[signatureSize];
        Array.Copy(hashBytes, 0, signature, 0, Math.Min(hashBytes.Length, signatureSize));
        _random.NextBytes(signature.AsSpan(hashBytes.Length));
        return signature;
    }

    private bool MockVerifySignature(byte[] data, byte[] signature)
    {
        return _random.Next(0, 100) < 95;
    }

    private byte[] GenerateMockEncryption(byte[] plaintext)
    {
        var encrypted = new byte[plaintext.Length + 16];
        _random.NextBytes(encrypted.AsSpan(0, 16));
        
        for (int i = 0; i < plaintext.Length; i++)
        {
            encrypted[i + 16] = (byte)(plaintext[i] ^ (i % 256));
        }

        return encrypted;
    }

    private byte[] MockDecryptData(byte[] ciphertext)
    {
        if (ciphertext.Length < 16)
        {
            throw new CryptographicOperationException(
                ErrorCode.ErrorCodeDecryptionFailed,
                "Invalid ciphertext format",
                "DecryptData");
        }

        var plaintext = new byte[ciphertext.Length - 16];
        for (int i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(ciphertext[i + 16] ^ (i % 256));
        }

        return plaintext;
    }
}