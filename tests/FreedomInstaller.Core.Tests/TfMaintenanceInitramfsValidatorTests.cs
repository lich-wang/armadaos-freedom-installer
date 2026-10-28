#nullable enable

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    public sealed class TfMaintenanceInitramfsValidatorTests : IDisposable
    {
        private const string KernelSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private const long DefaultCap = 1024 * 1024;

        private readonly string root;

        public TfMaintenanceInitramfsValidatorTests()
        {
            root = Path.Combine(TestArtifactRoot.Resolve(), "tf-initramfs-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
        }

        public void Dispose()
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, true);
            }
        }

        [Theory]
        [InlineData("TB322FC")]
        [InlineData("TB323FU")]
        public async Task ValidArchive_Succeeds(string model)
        {
            VerifiedEdlFile artifact = WriteVerified(BuildArchive(ValidEntries(model)));

            await TfMaintenanceInitramfsValidator.ValidateAsync(artifact, model, KernelSha, DefaultCap);
        }

        [Theory]
        [InlineData("TB322FC")]
        [InlineData("TB323FU")]
        public async Task DeferredHardlinkBodies_Succeed(string model)
        {
            var entries = new List<Entry>();
            AddDirectories(entries);
            entries.Add(new Entry { Ino = 100, Mode = 0x81ED, Name = "init", Nlink = 2 });
            entries.Add(new Entry { Ino = 101, Mode = 0x81ED, Name = "bin/busybox", Nlink = 2 });
            entries.Add(new Entry
            {
                Ino = 102,
                Mode = 0x81A4,
                Name = "etc/armada/tf-maintenance.json",
                Nlink = 2
            });
            entries.Add(new Entry { Ino = 8, Mode = 0x41ED, Name = "var" });
            entries.Add(new Entry { Ino = 100, Mode = 0x81ED, Name = "var/init.body", Nlink = 2, Data = InitScript() });
            entries.Add(new Entry { Ino = 101, Mode = 0x81ED, Name = "var/busybox.body", Nlink = 2, Data = ElfImage() });
            entries.Add(new Entry
            {
                Ino = 102,
                Mode = 0x81A4,
                Name = "var/marker.body",
                Nlink = 2,
                Data = Marker(model, KernelSha)
            });
            entries.Add(Trailer());

            VerifiedEdlFile artifact = WriteVerified(BuildArchive(entries));

            await TfMaintenanceInitramfsValidator.ValidateAsync(artifact, model, KernelSha, DefaultCap);
        }

        [Theory]
        [InlineData("TB322FC")]
        [InlineData("TB323FU")]
        public async Task MultipleTrailingNameNuls_Succeed(string model)
        {
            var entries = ValidEntries(model);
            foreach (Entry entry in entries)
            {
                if (entry.Name == "init" || entry.Name == "bin/busybox" || entry.Name == "TRAILER!!!")
                {
                    entry.ExtraNuls = 3;
                }
            }

            VerifiedEdlFile artifact = WriteVerified(BuildArchive(entries));

            await TfMaintenanceInitramfsValidator.ValidateAsync(artifact, model, KernelSha, DefaultCap);
        }

        [Fact]
        public async Task InteriorNameNul_Rejects()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "bin/busybox")!.Name = "bin/busy\0box";

            VerifiedEdlFile artifact = WriteVerified(BuildArchive(entries));

            await AssertRejects(artifact, "TB322FC", KernelSha, DefaultCap, "interior NUL");
        }

        [Fact]
        public async Task InitWithoutShebang_Rejects()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "init")!.Data = Encoding.UTF8.GetBytes("echo synthetic\n");

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "'init'");
        }

        [Fact]
        public async Task InitWithEmptyInterpreter_Rejects()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "init")!.Data = Encoding.UTF8.GetBytes("#!   \techo synthetic\n");

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "'init'");
        }

        [Fact]
        public async Task InitWithoutTrailingNewline_Succeeds()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "init")!.Data = Encoding.UTF8.GetBytes("#!/bin/busybox sh");

            await TfMaintenanceInitramfsValidator.ValidateAsync(
                WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap);
        }

        [Fact]
        public async Task EmptyInit_Rejects()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "init")!.Data = Array.Empty<byte>();

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "'init'");
        }

        [Fact]
        public async Task NonExecutableInit_Rejects()
        {
            var entries = ValidEntries();
            entries.Find(e => e.Name == "init")!.Mode = 0x81A4;

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "must be executable");
        }

        [Theory]
        [InlineData("model")]
        [InlineData("kernel")]
        [InlineData("missing")]
        [InlineData("transport")]
        public async Task InvalidMarker_Rejects(string variant)
        {
            var entries = ValidEntries();
            Entry marker = entries.Find(e => e.Name == "etc/armada/tf-maintenance.json")!;
            marker.Data = variant switch
            {
                "model" => Marker("TB323FU", KernelSha),
                "kernel" => Marker("TB322FC", new string('b', 64)),
                "missing" => Encoding.UTF8.GetBytes(
                    "{\"schema\":1,\"expectedModel\":\"TB322FC\",\"kernelSha256\":\"" + KernelSha + "\"}"),
                _ => Encoding.UTF8.GetBytes(
                    "{\"schema\":1,\"expectedModel\":\"TB322FC\",\"kernelSha256\":\"" + KernelSha +
                    "\",\"transportProtocol\":\"tf-card-v2\"}")
            };

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "marker");
        }

        [Theory]
        [InlineData("machine")]
        [InlineData("class")]
        public async Task InvalidElf_Rejects(string variant)
        {
            var entries = ValidEntries();
            byte[] elf = ElfImage();
            if (variant == "machine")
            {
                BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(18, 2), 62);
            }
            else
            {
                elf[4] = 1;
            }

            entries.Find(e => e.Name == "bin/busybox")!.Data = elf;

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "'bin/busybox'");
        }

        [Fact]
        public async Task TruncatedCpio_Rejects()
        {
            byte[] expanded = BuildArchive(ValidEntries());
            byte[] truncated = new byte[expanded.Length - 12];
            Array.Copy(expanded, truncated, truncated.Length);

            await AssertRejects(WriteVerified(truncated), "TB322FC", KernelSha, DefaultCap);
        }

        [Fact]
        public async Task ExpansionBeyondSmallCap_Rejects()
        {
            VerifiedEdlFile artifact = WriteVerified(BuildArchive(ValidEntries()));

            await AssertRejects(artifact, "TB322FC", KernelSha, 64);
        }

        [Fact]
        public async Task MissingRequiredEntry_Rejects()
        {
            var entries = ValidEntries();
            entries.RemoveAll(e => e.Name == "bin/busybox");

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap, "bin/busybox");
        }

        [Fact]
        public async Task DuplicateCanonicalPath_Rejects()
        {
            var entries = ValidEntries();
            entries.Insert(entries.Count - 1, new Entry { Ino = 40, Mode = 0x81ED, Name = "./init", Data = InitScript() });

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap);
        }

        [Fact]
        public async Task ParentEscapePath_Rejects()
        {
            var entries = ValidEntries();
            entries.Insert(entries.Count - 1, new Entry { Ino = 41, Mode = 0x81A4, Name = "../evil", Data = new byte[] { 1 } });

            await AssertRejects(WriteVerified(BuildArchive(entries)), "TB322FC", KernelSha, DefaultCap);
        }

        [Fact]
        public async Task WrongCompressedShaClaim_Rejects()
        {
            VerifiedEdlFile artifact = WriteVerified(BuildArchive(ValidEntries()), new string('b', 64));

            await AssertRejects(artifact, "TB322FC", KernelSha, DefaultCap, "SHA-256");
        }

        private static async Task AssertRejects(
            VerifiedEdlFile artifact,
            string model,
            string kernel,
            long cap,
            string? messageContains = null)
        {
            InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(
                () => TfMaintenanceInitramfsValidator.ValidateAsync(artifact, model, kernel, cap));

            if (messageContains != null)
            {
                Assert.Contains(messageContains, error.Message);
            }
        }

        private VerifiedEdlFile WriteVerified(byte[] archiveBytes, string? claimedSha = null)
        {
            byte[] gzipBytes;
            using (var buffer = new MemoryStream())
            {
                using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
                {
                    gzip.Write(archiveBytes, 0, archiveBytes.Length);
                }

                gzipBytes = buffer.ToArray();
            }

            string path = Path.Combine(root, "artifact-" + Guid.NewGuid().ToString("N") + ".gz");
            File.WriteAllBytes(path, gzipBytes);

            string sha = claimedSha ?? Convert.ToHexString(SHA256.HashData(gzipBytes));
            return new VerifiedEdlFile(path, gzipBytes.LongLength, sha);
        }

        private static List<Entry> ValidEntries(string model = "TB322FC", string kernel = KernelSha)
        {
            var entries = new List<Entry>();
            AddDirectories(entries);
            entries.Add(new Entry { Ino = 5, Mode = 0x81ED, Name = "init", Data = InitScript() });
            entries.Add(new Entry { Ino = 6, Mode = 0x81ED, Name = "bin/busybox", Data = ElfImage() });
            entries.Add(new Entry
            {
                Ino = 7,
                Mode = 0x81A4,
                Name = "etc/armada/tf-maintenance.json",
                Data = Marker(model, kernel)
            });
            entries.Add(Trailer());
            return entries;
        }

        private static void AddDirectories(List<Entry> entries)
        {
            entries.Add(new Entry { Ino = 1, Mode = 0x41ED, Name = "." });
            entries.Add(new Entry { Ino = 2, Mode = 0x41ED, Name = "bin" });
            entries.Add(new Entry { Ino = 3, Mode = 0x41ED, Name = "etc" });
            entries.Add(new Entry { Ino = 4, Mode = 0x41ED, Name = "etc/armada" });
        }

        private static Entry Trailer()
        {
            return new Entry { Ino = 900, Mode = 0, Name = "TRAILER!!!" };
        }

        private static byte[] InitScript()
        {
            return Encoding.UTF8.GetBytes("#!/bin/busybox sh\necho synthetic\n");
        }

        private static byte[] ElfImage()
        {
            byte[] bytes = new byte[64];
            bytes[0] = 0x7F;
            bytes[1] = (byte)'E';
            bytes[2] = (byte)'L';
            bytes[3] = (byte)'F';
            bytes[4] = 2;
            bytes[5] = 1;
            bytes[6] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(16, 2), 2);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(18, 2), 183);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20, 4), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(52, 2), 64);
            return bytes;
        }

        private static byte[] Marker(string model, string kernel)
        {
            return Encoding.UTF8.GetBytes(
                "{\"schema\":1,\"expectedModel\":\"" + model + "\",\"kernelSha256\":\"" + kernel +
                "\",\"transportProtocol\":\"tf-card-v1\"}");
        }

        private static byte[] BuildArchive(List<Entry> entries)
        {
            using var archive = new MemoryStream();
            foreach (Entry entry in entries)
            {
                byte[] name = Encoding.UTF8.GetBytes(entry.Name);
                int nameSize = name.Length + entry.ExtraNuls;
                int namePadding = (4 - ((110 + nameSize) & 3)) & 3;
                int dataPadding = (4 - (entry.Data.Length & 3)) & 3;

                WriteAscii(archive, "070701");
                WriteField(archive, entry.Ino);
                WriteField(archive, entry.Mode);
                WriteField(archive, 0);
                WriteField(archive, 0);
                WriteField(archive, entry.Nlink);
                WriteField(archive, 0);
                WriteField(archive, (uint)entry.Data.Length);
                WriteField(archive, entry.DevMajor);
                WriteField(archive, entry.DevMinor);
                WriteField(archive, 0);
                WriteField(archive, 0);
                WriteField(archive, (uint)nameSize);
                WriteField(archive, 0);
                archive.Write(name, 0, name.Length);
                archive.Write(new byte[entry.ExtraNuls], 0, entry.ExtraNuls);
                archive.Write(new byte[namePadding], 0, namePadding);
                archive.Write(entry.Data, 0, entry.Data.Length);
                archive.Write(new byte[dataPadding], 0, dataPadding);
            }

            return archive.ToArray();
        }

        private static void WriteAscii(Stream stream, string value)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        private static void WriteField(Stream stream, uint value)
        {
            WriteAscii(stream, value.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
        }

        private sealed class Entry
        {
            public uint Ino { get; set; }

            public uint Mode { get; set; }

            public string Name { get; set; } = string.Empty;

            public byte[] Data { get; set; } = Array.Empty<byte>();

            public uint Nlink { get; set; } = 1;

            public uint DevMajor { get; set; }

            public uint DevMinor { get; set; }

            public int ExtraNuls { get; set; } = 1;
        }
    }
}
