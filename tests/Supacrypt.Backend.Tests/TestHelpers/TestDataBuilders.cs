using Google.Protobuf;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.TestHelpers;

public class GenerateKeyRequestBuilder
{
    private readonly GenerateKeyRequest _request = new();
    
    public GenerateKeyRequestBuilder()
    {
        _request.Name = TestConstants.TestKeyName;
        _request.Algorithm = KeyAlgorithm.RsaPkcs1V2048;
        _request.Tags.Add("Environment", "Test");
    }
    
    public GenerateKeyRequestBuilder WithName(string name)
    {
        _request.Name = name;
        return this;
    }
    
    public GenerateKeyRequestBuilder WithAlgorithm(KeyAlgorithm algorithm)
    {
        _request.Algorithm = algorithm;
        return this;
    }
    
    public GenerateKeyRequestBuilder WithKeySize(RSAKeySize size)
    {
        _request.RsaKeySize = size;
        return this;
    }
    
    public GenerateKeyRequestBuilder WithTag(string key, string value)
    {
        _request.Tags[key] = value;
        return this;
    }
    
    public GenerateKeyRequestBuilder WithExpiryDate(DateTime expiry)
    {
        _request.ExpiryDate = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(expiry.ToUniversalTime());
        return this;
    }
    
    public GenerateKeyRequest Build() => _request;
}

public class SignDataRequestBuilder
{
    private readonly SignDataRequest _request = new();
    
    public SignDataRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.Data = ByteString.CopyFrom(TestConstants.TestData);
        _request.Algorithm = SignatureAlgorithm.RsaPkcs1V15Sha256;
    }
    
    public SignDataRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public SignDataRequestBuilder WithData(byte[] data)
    {
        _request.Data = ByteString.CopyFrom(data);
        return this;
    }
    
    public SignDataRequestBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        _request.Algorithm = algorithm;
        return this;
    }
    
    public SignDataRequest Build() => _request;
}

public class VerifySignatureRequestBuilder
{
    private readonly VerifySignatureRequest _request = new();
    
    public VerifySignatureRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.Data = ByteString.CopyFrom(TestConstants.TestData);
        _request.Signature = ByteString.CopyFrom(TestConstants.TestSignature);
        _request.Algorithm = SignatureAlgorithm.RsaPkcs1V15Sha256;
    }
    
    public VerifySignatureRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public VerifySignatureRequestBuilder WithData(byte[] data)
    {
        _request.Data = ByteString.CopyFrom(data);
        return this;
    }
    
    public VerifySignatureRequestBuilder WithSignature(byte[] signature)
    {
        _request.Signature = ByteString.CopyFrom(signature);
        return this;
    }
    
    public VerifySignatureRequestBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        _request.Algorithm = algorithm;
        return this;
    }
    
    public VerifySignatureRequest Build() => _request;
}

public class GetKeyRequestBuilder
{
    private readonly GetKeyRequest _request = new();
    
    public GetKeyRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.IncludePublicKey = true;
    }
    
    public GetKeyRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public GetKeyRequestBuilder WithIncludePublicKey(bool include)
    {
        _request.IncludePublicKey = include;
        return this;
    }
    
    public GetKeyRequest Build() => _request;
}

public class ListKeysRequestBuilder
{
    private readonly ListKeysRequest _request = new();
    
    public ListKeysRequestBuilder()
    {
        _request.PageSize = 10;
        _request.IncludeDisabled = false;
    }
    
    public ListKeysRequestBuilder WithPageSize(int pageSize)
    {
        _request.PageSize = pageSize;
        return this;
    }
    
    public ListKeysRequestBuilder WithFilter(string filter)
    {
        _request.Filter = filter;
        return this;
    }
    
    public ListKeysRequestBuilder WithIncludeDisabled(bool include)
    {
        _request.IncludeDisabled = include;
        return this;
    }
    
    public ListKeysRequestBuilder WithPageToken(string token)
    {
        _request.PageToken = token;
        return this;
    }
    
    public ListKeysRequest Build() => _request;
}

public class DeleteKeyRequestBuilder
{
    private readonly DeleteKeyRequest _request = new();
    
    public DeleteKeyRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.Force = false;
    }
    
    public DeleteKeyRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public DeleteKeyRequestBuilder WithForce(bool force)
    {
        _request.Force = force;
        return this;
    }
    
    public DeleteKeyRequest Build() => _request;
}

public class EncryptDataRequestBuilder
{
    private readonly EncryptDataRequest _request = new();
    
    public EncryptDataRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.Plaintext = ByteString.CopyFrom(TestConstants.TestData);
        _request.Algorithm = EncryptionAlgorithm.RsaOaep256;
    }
    
    public EncryptDataRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public EncryptDataRequestBuilder WithPlaintext(byte[] plaintext)
    {
        _request.Plaintext = ByteString.CopyFrom(plaintext);
        return this;
    }
    
    public EncryptDataRequestBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        _request.Algorithm = algorithm;
        return this;
    }
    
    public EncryptDataRequest Build() => _request;
}

public class DecryptDataRequestBuilder
{
    private readonly DecryptDataRequest _request = new();
    
    public DecryptDataRequestBuilder()
    {
        _request.KeyId = TestConstants.TestKeyId;
        _request.Ciphertext = ByteString.CopyFrom(TestConstants.TestCiphertext);
        _request.Algorithm = EncryptionAlgorithm.RsaOaep256;
    }
    
    public DecryptDataRequestBuilder WithKeyId(string keyId)
    {
        _request.KeyId = keyId;
        return this;
    }
    
    public DecryptDataRequestBuilder WithCiphertext(byte[] ciphertext)
    {
        _request.Ciphertext = ByteString.CopyFrom(ciphertext);
        return this;
    }
    
    public DecryptDataRequestBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        _request.Algorithm = algorithm;
        return this;
    }
    
    public DecryptDataRequest Build() => _request;
}