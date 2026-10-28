// SPDX-License-Identifier: GPL-3.0-or-later
//
// focused facts for the Core efisp detector scaffold. The synthetic
// vectors are the simple public ones from EfispLoadDetector.10green.Tests.cs
// (LTBox a278647, crates/ltbox-patch/src/efisp_load.rs); no real firmware bytes are
// embedded. All helper bytes are synthetic: one .text section at RVA 0x1000 with
// PointerToRawData 0x200, so raw offset X maps to RVA X + 0xE00.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    public sealed class GblEfispLoadDetectorTests
    {
        private const int DefaultTextRva = 0x1000;
        private const int TextRawOffset = 0x200;
        private const int TextRawSize = 0x5E00;
        private const int ImageSize = 0x6000;
        private const int SectionTableOffset = 0xF8;
        private const int SectionRawSizeOffset = SectionTableOffset + 0x10;
        private const int SectionCharacteristicsOffset = SectionTableOffset + 0x24;

        private const int EfispRaw = 0x5000;
        private const int LoadRaw = 0x5100;
        private const int StartRaw = 0x5200;

        private const long PublicAblLength = 270136;
        private const long PublicPeLength = 679952;
        private const string PublicAblSha256 = "A7B278E11E6C7AA2A930C69E0811F3C0C3DADFE066F5753A7C975B4BACF991BA";
        private const string PublicPeSha256 = "948BB29740CDC04D40F58B276AC849CDE277D55D8EAAFF4A0C3730DC3AC4C654";

        private static readonly byte[] EfispUtf16Le =
        {
            0x65, 0x00, 0x66, 0x00, 0x69, 0x00, 0x73, 0x00, 0x70, 0x00,
        };

        private static readonly byte[] LoadAscii = Encoding.ASCII.GetBytes("Loading GBL app");
        private static readonly byte[] StartAscii = Encoding.ASCII.GetBytes("Starting GBL app");
        private static readonly byte[] SecureBootAscii = Encoding.ASCII.GetBytes("SecureBoot");

        [Fact]
        public void FullChain_IsYes()
        {
            object result = Detect(Fixture());

            Assert.Equal("Yes", Status(result));
            Assert.Contains(0x5E00L, Rvas(result, "EfispMarkerRvas"));
            Assert.Contains(0x5F00L, Rvas(result, "LoadMarkerRvas"));
            Assert.Contains(0x6000L, Rvas(result, "StartMarkerRvas"));
            Assert.Contains(0x1220L, Rvas(result, "LoadXrefRvas"));
            Assert.Contains(0x1240L, Rvas(result, "StartXrefRvas"));

            object chain = SelectedChain(result);
            Assert.Equal(0x1200L, Long(chain, "FirstRva"));
            Assert.Equal(0x1240L, Long(chain, "LastRva"));
        }

        [Fact]
        public void SecureBootGate_IsUndetermined()
        {
            byte[] data = Fixture();
            WriteBytes(data, 0x5300, SecureBootAscii);
            Adr(data, 0x840, 0x5300); // xref RVA 0x1640 == last chain xref + 0x400

            object result = Detect(data);

            Assert.Equal("Undetermined", Status(result));
            Assert.Contains(0x1640L, Rvas(result, "SecureBootXrefRvas"));

            object chain = SelectedChain(result);
            Assert.Equal(0x1200L, Long(chain, "FirstRva"));
            Assert.Equal(0x1240L, Long(chain, "LastRva"));
        }

        [PublicAblFact]
        public void PublicAblWrapper_DecodesReviewedPe()
        {
            string? path = Environment.GetEnvironmentVariable("G5_PUBLIC_ABL_PATH");
            if (string.IsNullOrEmpty(path))
            {
                return;
            }

            Assert.True(File.Exists(path), "G5_PUBLIC_ABL_PATH must point at the reviewed public ABL file.");
            Assert.Equal(PublicAblLength, new FileInfo(path!).Length);

            byte[] abl = File.ReadAllBytes(path!);
            Assert.Equal((int)PublicAblLength, abl.Length);
            Assert.Equal(PublicAblSha256, Sha256Hex(abl));

            Type loader = typeof(InternalSlotMaterialReader).Assembly
                .GetType("FreedomInstaller.Core.InternalSlotLoaderStructure", throwOnError: true)!;
            MethodInfo wrapper = loader.GetMethod(
                "TryDecodeAblForGbl",
                BindingFlags.Static | BindingFlags.NonPublic,
                binder: null,
                types: new[] { typeof(byte[]), typeof(CancellationToken), typeof(byte[]).MakeByRefType() },
                modifiers: null)!;
            Assert.NotNull(wrapper);

            object?[] arguments = { abl, CancellationToken.None, null! };
            object? decoded = wrapper.Invoke(null, arguments);

            Assert.True(decoded is true, "TryDecodeAblForGbl must decode the public ABL image.");
            byte[] pe = Assert.IsType<byte[]>(arguments[2]);
            Assert.Equal((int)PublicPeLength, pe.Length);
            Assert.Equal((byte)'M', pe[0]);
            Assert.Equal((byte)'Z', pe[1]);
            Assert.Equal(PublicPeSha256, Sha256Hex(pe));
        }

        private static object Detect(byte[] data)
        {
            Type detector = typeof(InternalSlotMaterialReader).Assembly
                .GetType("FreedomInstaller.Core.Gbl.EfispLoadDetector", throwOnError: true)!;
            MethodInfo method = detector.GetMethod(
                "Detect",
                BindingFlags.Static | BindingFlags.NonPublic,
                binder: null,
                types: new[] { typeof(byte[]) },
                modifiers: null)!;
            Assert.NotNull(method);
            return method.Invoke(null, new object?[] { data })!;
        }

        private static string Status(object result) => Member(result, "Status").ToString()!;

        private static object SelectedChain(object result)
        {
            object? chain = Member(result, "SelectedChain");
            Assert.NotNull(chain);
            return chain!;
        }

        private static long Long(object target, string name) => Assert.IsType<long>(Member(target, name));

        private static IReadOnlyList<long> Rvas(object result, string name)
            => Assert.IsAssignableFrom<IReadOnlyList<long>>(Member(result, name));

        private static object Member(object target, string name)
        {
            PropertyInfo? property = target.GetType().GetProperty(
                name,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.NotNull(property);
            object? value = property!.GetValue(target);
            Assert.NotNull(value);
            return value!;
        }

        private static string Sha256Hex(byte[] data)
        {
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", string.Empty);
        }

        private static byte[] Fixture()
        {
            byte[] data = BuildImage(DefaultTextRva);
            WriteBytes(data, EfispRaw, EfispUtf16Le);
            WriteBytes(data, LoadRaw, LoadAscii);
            WriteBytes(data, StartRaw, StartAscii);
            Adr(data, 0x400, EfispRaw);
            Adr(data, 0x420, LoadRaw);
            Adr(data, 0x440, StartRaw);
            return data;
        }

        private static byte[] BuildImage(int textRva)
        {
            var data = new byte[ImageSize];
            data[0] = (byte)'M';
            data[1] = (byte)'Z';
            PutU32(data, 0x3C, 0x80);

            WriteAscii(data, 0x80, "PE");
            PutU16(data, 0x86, 1); // NumberOfSections
            PutU16(data, 0x94, 0x60); // SizeOfOptionalHeader
            PutU16(data, 0x98, 0x20B); // PE32+ magic
            PutU32(data, 0xD4, TextRawOffset); // SizeOfHeaders

            WriteAscii(data, SectionTableOffset, ".text");
            PutU32(data, SectionTableOffset + 0x0C, (uint)textRva);
            PutU32(data, SectionRawSizeOffset, TextRawSize);
            PutU32(data, SectionTableOffset + 0x14, TextRawOffset);
            PutU32(data, SectionCharacteristicsOffset, 0x2000_0000); // IMAGE_SCN_MEM_EXECUTE
            return data;
        }

        /// <summary>Single ADR instruction; both offsets live in the same section.</summary>
        private static void Adr(byte[] data, int atRaw, int targetRaw)
        {
            var immediate = (uint)((targetRaw - atRaw) & 0x1F_FFFF);
            var word = 0x1000_0000u | ((immediate & 0x3) << 29) | ((immediate >> 2) << 5);
            PutU32(data, atRaw, word);
        }

        private static void WriteBytes(byte[] data, int offset, byte[] bytes)
            => Array.Copy(bytes, 0, data, offset, bytes.Length);

        private static void WriteAscii(byte[] data, int offset, string value)
            => WriteBytes(data, offset, Encoding.ASCII.GetBytes(value));

        private static void PutU16(byte[] data, int offset, ushort value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
        }

        private static void PutU32(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        /// <summary>
        /// Discovery gate for the single public-fixture fact: skipped only when the
        /// explicit G5_PUBLIC_ABL_PATH environment variable is unset.
        /// </summary>
        private sealed class PublicAblFactAttribute : FactAttribute
        {
            public PublicAblFactAttribute()
            {
                if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("G5_PUBLIC_ABL_PATH")))
                {
                    Skip = "G5_PUBLIC_ABL_PATH is not set.";
                }
            }
        }
    }
}
