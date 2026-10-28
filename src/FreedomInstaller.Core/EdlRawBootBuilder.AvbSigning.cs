// Fixed AOSP AVB SHA256_RSA4096 candidate authentication.
//
// The private material is embedded at build time from a mandatory MSBuild input
// outside the source tree. This file carries no key material: it validates the
// loaded key against public facts and refuses anything else. There is no
// generated key, default key, or unsigned fallback.
using System;
using System.Buffers.Binary;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    private const int AvbAuthBlockBytes = 576;
    private const int AvbHashBytes = 32;
    private const int AvbSignatureBytes = 512;
    private const int AvbPublicKeyBytes = 1032;
    private const uint AvbAlgorithmRsa4096 = 2;
    private const int AvbRsaModulusBytes = 512;

    private const string AvbSigningKeyResourceName = "FreedomInstaller.AvbTestKey.pem";

    // Public facts about the AOSP AVB public test RSA4096 key. They pin the key
    // without exposing any private component.
    private const string AvbModulusSha256 = "36949B827927C883836897AB67EB01360795186CB81FACA37EF7DE583A1B65B1";
    private const string AvbPublicKeySha256 = "7728E30F50BFA5CEA165F473175A08803F6A8346642B5AA10913E9D9E6DEFEF6";

    // Loads and validates the RSA private key from a PEM stream. The caller owns
    // and must dispose the returned instance; there is no shared mutable cache.
    private static RSA LoadAvbSigningKey(Stream input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        string pem;
        using (StreamReader reader = new(input, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true))
        {
            pem = reader.ReadToEnd();
        }

        if (pem.Length == 0)
        {
            throw new InvalidDataException("the AVB test signing material is empty");
        }

        RSA key = RSA.Create();
        try
        {
            key.ImportFromPem(pem);

            RSAParameters parameters;
            try
            {
                parameters = key.ExportParameters(includePrivateParameters: true);
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException("the AVB test signing material is not a private RSA key");
            }

            if (parameters.Modulus is null
                || parameters.D is null
                || parameters.P is null
                || parameters.Q is null
                || parameters.DP is null
                || parameters.DQ is null
                || parameters.InverseQ is null)
            {
                throw new InvalidDataException("the AVB test signing material is not a complete private RSA key");
            }

            if (key.KeySize != 4096 || parameters.Modulus.Length != AvbRsaModulusBytes)
            {
                throw new InvalidDataException("the AVB test signing material is not a 4096-bit RSA key");
            }

            if (!IsRsaExponent65537(parameters.Exponent))
            {
                throw new InvalidDataException("the AVB test signing material does not use RSA exponent 65537");
            }

            if (!IsPinnedModulus(parameters.Modulus))
            {
                throw new InvalidDataException("the AVB test signing material does not match the fixed AOSP test key");
            }

            return key;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            key.Dispose();
            throw new InvalidDataException("the AVB test signing material is not a usable RSA private key", exception);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    // Derives the 1032-byte avbtool public key blob:
    // BE32(4096) || BE32(n0inv) || modulus[512] || rr[512].
    private static byte[] CreateAvbPublicKey(RSA key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        RSAParameters parameters = key.ExportParameters(includePrivateParameters: false);
        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            throw new InvalidDataException("the AVB test key has no public parameters");
        }

        if (!IsRsaExponent65537(parameters.Exponent))
        {
            throw new InvalidDataException("the AVB test key does not use RSA exponent 65537");
        }

        byte[] modulus = LeftPad(parameters.Modulus, AvbRsaModulusBytes, "modulus");
        if (!IsPinnedModulus(modulus))
        {
            throw new InvalidDataException("the AVB test key does not match the fixed AOSP test key");
        }

        uint n0Inverse = ComputeAvbN0Inverse(modulus);

        BigInteger n = new(modulus, isUnsigned: true, isBigEndian: true);
        BigInteger rr = BigInteger.ModPow(new BigInteger(2), 8192, n);
        byte[] rrBytes = LeftPad(rr.ToByteArray(isUnsigned: true, isBigEndian: true), AvbRsaModulusBytes, "RR");

        byte[] blob = new byte[AvbPublicKeyBytes];
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(0, 4), 4096);
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(4, 4), n0Inverse);
        Buffer.BlockCopy(modulus, 0, blob, 8, AvbRsaModulusBytes);
        Buffer.BlockCopy(rrBytes, 0, blob, 8 + AvbRsaModulusBytes, AvbRsaModulusBytes);

        if (!string.Equals(Convert.ToHexString(SHA256.HashData(blob)), AvbPublicKeySha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("the derived AVB public key blob does not match the fixed AOSP test key");
        }

        return blob;
    }

    // n0inv = -n^-1 mod 2^32, computed with a bounded extended Euclid over the
    // low 32 bits of the positive big-endian modulus.
    private static uint ComputeAvbN0Inverse(byte[] modulus)
    {
        uint low = BinaryPrimitives.ReadUInt32BigEndian(modulus.AsSpan(modulus.Length - 4, 4));
        if ((low & 1u) == 0)
        {
            throw new InvalidDataException("the AVB RSA modulus is not odd");
        }

        BigInteger modulus32 = BigInteger.One << 32;
        BigInteger oldR = modulus32;
        BigInteger r = low;
        BigInteger oldT = BigInteger.Zero;
        BigInteger t = BigInteger.One;

        while (!r.IsZero)
        {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - (quotient * r));
            (oldT, t) = (t, oldT - (quotient * t));
        }

        if (oldR != BigInteger.One)
        {
            throw new InvalidDataException("the AVB RSA modulus has no inverse modulo 2^32");
        }

        if (oldT.Sign < 0)
        {
            oldT += modulus32;
        }

        uint inverse = (uint)(oldT & 0xFFFF_FFFFU);
        return unchecked(0u - inverse);
    }

    // Pure verifier for the candidate vbmeta block. It enforces the fixed
    // SHA256_RSA4096 layout, re-hashes the header and full auxiliary block,
    // compares the authentication hash in constant time, and authenticates the
    // signature with the candidate public modulus and exponent 65537 / PKCS#1.
    private static void VerifyCandidateVbmetaSignature(byte[] vbmeta)
    {
        if (vbmeta is null)
        {
            throw new ArgumentNullException(nameof(vbmeta));
        }

        const int HeaderBytes = VbmetaHeaderBytes;
        const int AuthStart = HeaderBytes;
        const int AuxStart = HeaderBytes + AvbAuthBlockBytes;

        if (vbmeta.Length < AuxStart)
        {
            throw new InvalidDataException("candidate vbmeta is shorter than its fixed header and authentication block");
        }

        if (!vbmeta.AsSpan(0, 4).SequenceEqual(AvbVbmetaMagic))
        {
            throw new InvalidDataException("candidate vbmeta magic is not AVB0");
        }

        if (ReadBeU32(vbmeta, 4) != 1)
        {
            throw new InvalidDataException("candidate vbmeta major version is not 1");
        }

        ulong authSize = ReadBeU64(vbmeta, 12);
        ulong auxSize = ReadBeU64(vbmeta, 20);
        ulong hashOffset = ReadBeU64(vbmeta, 32);
        ulong hashSize = ReadBeU64(vbmeta, 40);
        ulong signatureOffset = ReadBeU64(vbmeta, 48);
        ulong signatureSize = ReadBeU64(vbmeta, 56);
        ulong publicKeyOffset = ReadBeU64(vbmeta, 64);
        ulong publicKeySize = ReadBeU64(vbmeta, 72);
        ulong publicKeyMetadataOffset = ReadBeU64(vbmeta, 80);
        ulong publicKeyMetadataSize = ReadBeU64(vbmeta, 88);
        ulong descriptorsOffset = ReadBeU64(vbmeta, 96);
        ulong descriptorsLength = ReadBeU64(vbmeta, 104);

        if (authSize != AvbAuthBlockBytes
            || ReadBeU32(vbmeta, 28) != AvbAlgorithmRsa4096
            || ReadBeU32(vbmeta, 120) != 0)
        {
            throw new InvalidDataException("candidate vbmeta does not use the fixed SHA256_RSA4096 layout");
        }

        if (hashOffset != 0
            || hashSize != AvbHashBytes
            || signatureOffset != AvbHashBytes
            || signatureSize != AvbSignatureBytes)
        {
            throw new InvalidDataException("candidate vbmeta authentication offsets are not the fixed layout");
        }

        if (descriptorsLength > int.MaxValue - AvbPublicKeyBytes)
        {
            throw new InvalidDataException("candidate vbmeta descriptor length is out of range");
        }

        if (descriptorsOffset != 0
            || publicKeyOffset != descriptorsLength
            || publicKeySize != AvbPublicKeyBytes
            || publicKeyMetadataOffset != descriptorsLength + AvbPublicKeyBytes
            || publicKeyMetadataSize != 0)
        {
            throw new InvalidDataException("candidate vbmeta public key ranges are not the fixed layout");
        }

        ulong expectedAuxSize = (ulong)Align((long)descriptorsLength + AvbPublicKeyBytes, 64);
        if (auxSize != expectedAuxSize || auxSize > int.MaxValue - AuxStart)
        {
            throw new InvalidDataException("candidate vbmeta auxiliary block size is not the fixed layout");
        }

        if (vbmeta.Length != AuxStart + (int)auxSize)
        {
            throw new InvalidDataException("candidate vbmeta length does not match its declared blocks");
        }

        for (int i = AvbHashBytes + AvbSignatureBytes; i < AvbAuthBlockBytes; i++)
        {
            if (vbmeta[AuthStart + i] != 0)
            {
                throw new InvalidDataException("candidate vbmeta authentication padding is nonzero");
            }
        }

        for (long i = (long)descriptorsLength + AvbPublicKeyBytes; i < (long)auxSize; i++)
        {
            if (vbmeta[AuxStart + (int)i] != 0)
            {
                throw new InvalidDataException("candidate vbmeta auxiliary padding is nonzero");
            }
        }

        byte[] digest;
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            hash.AppendData(vbmeta, 0, HeaderBytes);
            hash.AppendData(vbmeta, AuxStart, (int)auxSize);
            digest = hash.GetHashAndReset();
        }

        if (!CryptographicOperations.FixedTimeEquals(digest, vbmeta.AsSpan(AuthStart, AvbHashBytes)))
        {
            throw new InvalidDataException("candidate vbmeta authentication hash does not match its signed contents");
        }

        byte[] publicKey = new byte[AvbPublicKeyBytes];
        Buffer.BlockCopy(vbmeta, AuxStart + (int)descriptorsLength, publicKey, 0, AvbPublicKeyBytes);
        if (BinaryPrimitives.ReadUInt32BigEndian(publicKey.AsSpan(0, 4)) != 4096)
        {
            throw new InvalidDataException("candidate vbmeta public key size field is not 4096 bits");
        }

        if (!string.Equals(Convert.ToHexString(SHA256.HashData(publicKey)), AvbPublicKeySha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("candidate vbmeta public key is not the fixed AOSP test key");
        }

        byte[] modulus = new byte[AvbRsaModulusBytes];
        Buffer.BlockCopy(publicKey, 8, modulus, 0, AvbRsaModulusBytes);
        if (!IsPinnedModulus(modulus))
        {
            throw new InvalidDataException("candidate vbmeta public modulus is not the fixed AOSP test key");
        }

        byte[] signature = new byte[AvbSignatureBytes];
        Buffer.BlockCopy(vbmeta, AuthStart + AvbHashBytes, signature, 0, AvbSignatureBytes);

        using RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus,
            Exponent = new byte[] { 0x01, 0x00, 0x01 },
        });

        if (!rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            throw new InvalidDataException("candidate vbmeta signature does not authenticate its signed contents");
        }
    }

    private static bool IsPinnedModulus(byte[] modulus)
    {
        return modulus.Length == AvbRsaModulusBytes
            && string.Equals(
                Convert.ToHexString(SHA256.HashData(modulus)),
                AvbModulusSha256,
                StringComparison.Ordinal);
    }

    private static bool IsRsaExponent65537(byte[] exponent)
    {
        return exponent is not null
            && exponent.Length == 3
            && exponent[0] == 0x01
            && exponent[1] == 0x00
            && exponent[2] == 0x01;
    }

    private static byte[] LeftPad(byte[] value, int length, string what)
    {
        if (value.Length == length)
        {
            return value;
        }

        if (value.Length > length)
        {
            throw new InvalidDataException("the AVB " + what + " is larger than " + length.ToString() + " bytes");
        }

        byte[] padded = new byte[length];
        Buffer.BlockCopy(value, 0, padded, length - value.Length, value.Length);
        return padded;
    }
}
