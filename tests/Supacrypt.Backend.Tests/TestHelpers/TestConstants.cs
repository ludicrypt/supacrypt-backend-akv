using System.Text;

namespace Supacrypt.Backend.Tests.TestHelpers;

public static class TestConstants
{
    public const string TestKeyId = "test-key-12345678";
    public const string TestKeyName = "test-key-name";
    public const string TestVaultUri = "https://test-vault.vault.azure.net/";
    public const string TestCorrelationId = "test-correlation-123";
    public static readonly byte[] TestData = Encoding.UTF8.GetBytes("test data for cryptographic operations");
    public static readonly byte[] TestSignature = Convert.FromBase64String("VGVzdFNpZ25hdHVyZURhdGE=");
    public static readonly byte[] TestCiphertext = Convert.FromBase64String("VGVzdENpcGhlcnRleHREYXRh");
    
    public const string TestSubject = "CN=Test Client Certificate";
    public const string TestIssuer = "CN=Test CA";
    
    public static class ErrorMessages
    {
        public const string InvalidKeyAlgorithm = "Unsupported key algorithm";
        public const string KeyNotFound = "Key not found";
        public const string InvalidSignature = "Invalid signature format";
        public const string ValidationFailed = "Validation failed";
        public const string UnauthorizedAccess = "Unauthorized access";
        public const string InvalidKeySize = "Invalid key size";
    }
    
    public static class MetricNames
    {
        public const string SignOperations = "crypto_sign_operations_total";
        public const string VerifyOperations = "crypto_verify_operations_total";
        public const string EncryptOperations = "crypto_encrypt_operations_total";
        public const string DecryptOperations = "crypto_decrypt_operations_total";
        public const string KeyGenerations = "crypto_key_generations_total";
    }
}