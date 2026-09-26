using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace XlsxRsaLock;

public enum CipherMode : byte
{
    /// <summary>Every 190/318/446-byte slice of the file is encrypted directly with RSA-OAEP. No symmetric cipher.</summary>
    PureRsa = 0,
    /// <summary>RSA-OAEP wraps a random AES-256-GCM key that encrypts the file (the usual industry approach, much faster).</summary>
    Hybrid = 1,
}

public sealed record FileHeader(CipherMode Mode, int KeyBits, byte[] Sha256, byte[] KeyId, string OriginalName, long OriginalLength);

/// <summary>
/// Encrypts any file (e.g. .xlsx) with an RSA public key and restores it bit-for-bit with the private key.
/// Container layout (little endian):
///   "XRSA" | version:u8 | mode:u8 | keyBits:u16 | sha256[32] | keyId[8] | nameLen:u16 | name(utf8) | originalLength:i64 | payload
///   PureRsa payload: ceil(len / chunk) RSA-OAEP-SHA256 blocks of keyBits/8 bytes
///   Hybrid payload : wrappedKey[keyBits/8] | nonce[12] | tag[16] | ciphertext[len]
/// </summary>
public static class RsaFileCrypto
{
    private static readonly byte[] Magic = "XRSA"u8.ToArray();
    private const byte Version = 1;
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public static int ChunkSize(int keyBits) => keyBits / 8 - 2 * 32 - 2; // OAEP-SHA256 overhead

    /// <summary>First 8 bytes of SHA-256 over the public key, so decryption can tell a wrong key immediately.</summary>
    public static byte[] KeyId(RSA rsa) => SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())[..8];

    // ---------- keys ----------

    public static (string publicPem, string privatePem) CreateKeyPair(int bits, string? password)
    {
        using var rsa = RSA.Create(bits);
        string pub = rsa.ExportSubjectPublicKeyInfoPem();
        string priv = string.IsNullOrEmpty(password)
            ? rsa.ExportPkcs8PrivateKeyPem()
            : rsa.ExportEncryptedPkcs8PrivateKeyPem(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
        return (pub, priv);
    }

    public static RSA LoadKey(string pem, string? password = null)
    {
        var rsa = RSA.Create();
        if (pem.Contains("ENCRYPTED PRIVATE KEY"))
        {
            if (string.IsNullOrEmpty(password)) throw new CryptographicException("This private key is password protected.");
            rsa.ImportFromEncryptedPem(pem, password);
        }
        else rsa.ImportFromPem(pem);
        return rsa;
    }

    public static bool IsPasswordProtected(string pem) => pem.Contains("ENCRYPTED PRIVATE KEY");

    // ---------- encrypt ----------

    public static void Encrypt(string inputPath, string outputPath, RSA publicKey, CipherMode mode, IProgress<double>? progress = null)
    {
        byte[] data = File.ReadAllBytes(inputPath);
        int keyBits = publicKey.KeySize;
        using var output = File.Create(outputPath);
        WriteHeader(output, new FileHeader(mode, keyBits, SHA256.HashData(data), KeyId(publicKey), Path.GetFileName(inputPath), data.LongLength));

        if (mode == CipherMode.Hybrid)
        {
            byte[] key = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12), tag = new byte[16];
            byte[] cipher = new byte[data.Length];
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, data, cipher, tag);
            output.Write(publicKey.Encrypt(key, Padding));
            output.Write(nonce); output.Write(tag); output.Write(cipher);
            CryptographicOperations.ZeroMemory(key);
            progress?.Report(1);
            return;
        }

        int chunk = ChunkSize(keyBits), blockLen = keyBits / 8;
        int blocks = (int)((data.LongLength + chunk - 1) / chunk);
        var result = new byte[(long)blocks * blockLen];
        byte[] spki = publicKey.ExportSubjectPublicKeyInfo();
        int done = 0;
        // RSA objects are not thread-safe, so each worker imports its own copy of the public key.
        Parallel.For(0, blocks, () => { var r = RSA.Create(); r.ImportSubjectPublicKeyInfo(spki, out _); return r; }, (i, _, rsa) =>
        {
            int off = i * chunk, len = Math.Min(chunk, data.Length - off);
            rsa.Encrypt(new ReadOnlySpan<byte>(data, off, len), result.AsSpan(i * blockLen, blockLen), Padding);
            if (Interlocked.Increment(ref done) % 256 == 0) progress?.Report((double)done / blocks);
            return rsa;
        }, rsa => rsa.Dispose());
        output.Write(result);
        progress?.Report(1);
    }

    // ---------- decrypt ----------

    public static FileHeader ReadHeader(string path)
    {
        using var input = File.OpenRead(path);
        return ReadHeader(input);
    }

    /// <summary>Decrypts and verifies the SHA-256 of the result. Throws if the key is wrong or the file was altered.</summary>
    public static FileHeader Decrypt(string inputPath, string outputPath, RSA privateKey, IProgress<double>? progress = null)
    {
        using var input = File.OpenRead(inputPath);
        var h = ReadHeader(input);
        if (!h.KeyId.AsSpan().SequenceEqual(KeyId(privateKey)))
            throw new CryptographicException("This private key does not match the public key the file was encrypted with.");
        if (privateKey.KeySize != h.KeyBits) throw new CryptographicException("Key size does not match the file.");

        byte[] rest = new byte[input.Length - input.Position];
        input.ReadExactly(rest);
        byte[] plain = new byte[h.OriginalLength];
        int blockLen = h.KeyBits / 8;

        if (h.Mode == CipherMode.Hybrid)
        {
            byte[] key = privateKey.Decrypt(rest.AsSpan(0, blockLen).ToArray(), Padding);
            var nonce = rest.AsSpan(blockLen, 12); var tag = rest.AsSpan(blockLen + 12, 16);
            using (var aes = new AesGcm(key, 16)) aes.Decrypt(nonce, rest.AsSpan(blockLen + 28), tag, plain);
            CryptographicOperations.ZeroMemory(key);
        }
        else
        {
            int chunk = ChunkSize(h.KeyBits);
            int blocks = rest.Length / blockLen;
            if ((long)blocks * blockLen != rest.Length) throw new CryptographicException("The encrypted file is truncated or damaged.");
            byte[] pkcs8 = privateKey.ExportPkcs8PrivateKey();
            int done = 0;
            try
            {
                Parallel.For(0, blocks, () => { var r = RSA.Create(); r.ImportPkcs8PrivateKey(pkcs8, out _); return r; }, (i, _, rsa) =>
                {
                    byte[] part = rsa.Decrypt(rest.AsSpan(i * blockLen, blockLen).ToArray(), Padding);
                    Buffer.BlockCopy(part, 0, plain, i * chunk, part.Length);
                    if (Interlocked.Increment(ref done) % 256 == 0) progress?.Report((double)done / blocks);
                    return rsa;
                }, rsa => rsa.Dispose());
            }
            finally { CryptographicOperations.ZeroMemory(pkcs8); }
        }

        if (!SHA256.HashData(plain).AsSpan().SequenceEqual(h.Sha256))
            throw new CryptographicException("Integrity check failed: the decrypted file does not match the original SHA-256.");
        File.WriteAllBytes(outputPath, plain);
        progress?.Report(1);
        return h;
    }

    // ---------- header ----------

    private static void WriteHeader(Stream s, FileHeader h)
    {
        byte[] name = Encoding.UTF8.GetBytes(h.OriginalName);
        Span<byte> b2 = stackalloc byte[2]; Span<byte> b8 = stackalloc byte[8];
        s.Write(Magic); s.WriteByte(Version); s.WriteByte((byte)h.Mode);
        BinaryPrimitives.WriteUInt16LittleEndian(b2, (ushort)h.KeyBits); s.Write(b2);
        s.Write(h.Sha256); s.Write(h.KeyId);
        BinaryPrimitives.WriteUInt16LittleEndian(b2, (ushort)name.Length); s.Write(b2); s.Write(name);
        BinaryPrimitives.WriteInt64LittleEndian(b8, h.OriginalLength); s.Write(b8);
    }

    private static FileHeader ReadHeader(Stream s)
    {
        Span<byte> head = stackalloc byte[4 + 1 + 1 + 2];
        s.ReadExactly(head);
        if (!head[..4].SequenceEqual(Magic)) throw new InvalidDataException("Not an XlsxRsaLock file.");
        if (head[4] != Version) throw new InvalidDataException($"Unsupported file version {head[4]}.");
        var mode = (CipherMode)head[5];
        int bits = BinaryPrimitives.ReadUInt16LittleEndian(head[6..]);
        byte[] sha = new byte[32]; s.ReadExactly(sha);
        byte[] id = new byte[8]; s.ReadExactly(id);
        Span<byte> b2 = stackalloc byte[2]; s.ReadExactly(b2);
        byte[] name = new byte[BinaryPrimitives.ReadUInt16LittleEndian(b2)]; s.ReadExactly(name);
        Span<byte> b8 = stackalloc byte[8]; s.ReadExactly(b8);
        return new FileHeader(mode, bits, sha, id, Encoding.UTF8.GetString(name), BinaryPrimitives.ReadInt64LittleEndian(b8));
    }
}
