// SPDX-License-Identifier: GPL-3.0-or-later
//
// Source attribution:
//   LTBox https://github.com/miner7222/LTBox
//   commit a278647284eee120efd7ca48c413ff236c0d17ca
//   crates/ltbox-patch/src/efisp_load.rs
//   SHA-256 051D23B424090BA18E857486B98BB4484DC890D475053CA8C322821D2DD6074E
//
// Mechanical port of the standalone detector into the Core
// Gbl namespace. The input is already a decoded raw MZ PE image at offset 0. There is
// no decompression, ELF or embedded-container handling. Section parsing is deliberately
// permissive (optional-header size only needs to cover 0x60 bytes, PE32 and PE32+
// magic both accepted). Every failure path returns an explicit Undetermined verdict;
// default(EfispLoad) is Yes and is never used as a fallback. Contract member names,
// types and enum order are unchanged from the standalone source.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace FreedomInstaller.Core.Gbl
{
    /// <summary>
    /// Static verdict for an ungated efisp execution chain in a decoded raw MZ PE.
    /// </summary>
    /// <remarks>
    /// Unlike the Rust reference's <c>Default</c>, <c>default(EfispLoad)</c> is <see cref="Yes"/>,
    /// so detection code always returns an explicit member and never falls back to a
    /// zero-initialized value.
    /// </remarks>
    internal enum EfispLoad
    {
        /// <summary>An ordered, ungated efisp -&gt; load -&gt; start chain was found.</summary>
        Yes,

        /// <summary>No LOAD or START marker string and no EFISP cross-reference exist at all.</summary>
        No,

        /// <summary>Incomplete chain, authentication gate, malformed input, or unusable input.</summary>
        Undetermined,
    }

    /// <summary>First ordered chain selected by the detector, in RVAs.</summary>
    /// <param name="FirstRva">Cross-reference RVA of the EFISP marker.</param>
    /// <param name="LastRva">Cross-reference RVA of the START marker.</param>
    internal readonly record struct ChainBounds(long FirstRva, long LastRva)
    {
        /// <summary>Distance between the first and last cross-reference.</summary>
        internal long Span => LastRva - FirstRva;
    }

    /// <summary>
    /// Reviewable evidence for one static verdict.
    /// </summary>
    /// <remarks>
    /// All RVAs are section-mapped values, never raw file offsets.
    /// </remarks>
    internal sealed class DetectionResult
    {
        /// <summary>Tri-state verdict.</summary>
        internal required EfispLoad Status { get; init; }

        /// <summary>RVAs of every UTF-16LE <c>efisp</c> marker occurrence.</summary>
        internal IReadOnlyList<long> EfispMarkerRvas { get; init; } = Array.Empty<long>();

        /// <summary>RVAs of every ASCII <c>Loading GBL app</c> occurrence.</summary>
        internal IReadOnlyList<long> LoadMarkerRvas { get; init; } = Array.Empty<long>();

        /// <summary>RVAs of every ASCII <c>Starting GBL app</c> occurrence.</summary>
        internal IReadOnlyList<long> StartMarkerRvas { get; init; } = Array.Empty<long>();

        /// <summary>RVAs of every SecureBoot marker occurrence (UTF-16LE or ASCII).</summary>
        internal IReadOnlyList<long> SecureBootMarkerRvas { get; init; } = Array.Empty<long>();

        /// <summary>Sorted, deduplicated cross-reference RVAs for the EFISP marker.</summary>
        internal IReadOnlyList<long> EfispXrefRvas { get; init; } = Array.Empty<long>();

        /// <summary>Sorted, deduplicated cross-reference RVAs for the LOAD marker.</summary>
        internal IReadOnlyList<long> LoadXrefRvas { get; init; } = Array.Empty<long>();

        /// <summary>Sorted, deduplicated cross-reference RVAs for the START marker.</summary>
        internal IReadOnlyList<long> StartXrefRvas { get; init; } = Array.Empty<long>();

        /// <summary>Sorted, deduplicated cross-reference RVAs for the SecureBoot marker.</summary>
        internal IReadOnlyList<long> SecureBootXrefRvas { get; init; } = Array.Empty<long>();

        /// <summary>The first ordered chain, when one was selected.</summary>
        internal ChainBounds? SelectedChain { get; init; }

        /// <summary>Human-readable explanation of the verdict or of the parsing failure.</summary>
        internal string Reason { get; init; } = string.Empty;
    }

    /// <summary>
    /// Raw-PE efisp loader detector.
    /// </summary>
    internal static class EfispLoadDetector
    {
        /// <summary>Legacy scaffold text, retained for source compatibility; never returned.</summary>
        internal const string StubReason = "RED scaffold: raw-PE detection not implemented";

        private const long EfispMargin = 64;
        private const long SecureMargin = 64;
        private const long MarkerSpan = 0x4000;
        private const long SecureBefore = 0x200;
        private const long SecureAfter = 0x400;

        private static readonly byte[] EfispMarker = { (byte)'e', 0, (byte)'f', 0, (byte)'i', 0, (byte)'s', 0, (byte)'p', 0 };

        private static readonly byte[] LoadMarker = Encoding.ASCII.GetBytes("Loading GBL app");

        private static readonly byte[] StartMarker = Encoding.ASCII.GetBytes("Starting GBL app");

        private static readonly byte[] SecureMarker = { (byte)'S', 0, (byte)'e', 0, (byte)'c', 0, (byte)'u', 0, (byte)'r', 0, (byte)'e', 0, (byte)'B', 0, (byte)'o', 0, (byte)'o', 0, (byte)'t', 0 };

        private static readonly byte[] SecureAsciiMarker = Encoding.ASCII.GetBytes("SecureBoot");

        /// <summary>
        /// Inspects a decoded raw MZ PE image for an ungated efisp execution chain.
        /// </summary>
        /// <param name="data">Complete raw PE bytes; the input must start with <c>MZ</c>.</param>
        /// <returns>
        /// <see cref="EfispLoad.Yes"/> only for a complete ungated ordered chain,
        /// <see cref="EfispLoad.No"/> only when no reference exists at all, and
        /// <see cref="EfispLoad.Undetermined"/> for partial chains, gates, or
        /// inputs that cannot be parsed.
        /// </returns>
        internal static DetectionResult Detect(byte[] data)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (!TryParseImage(data, out PeImage? image, out string? failure) || image is null)
            {
                return Build(
                    EfispLoad.Undetermined,
                    failure ?? "Input is not a usable raw MZ PE image.",
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    null);
            }

            List<long> loadMarkers = FindMarkerRvas(image, data, LoadMarker);
            List<long> startMarkers = FindMarkerRvas(image, data, StartMarker);
            List<long> efispMarkers = FindMarkerRvas(image, data, EfispMarker);

            List<long>? efispXrefs = CollectXrefs(image, data, efispMarkers, EfispMargin);
            if (efispXrefs is null)
            {
                return Build(
                    EfispLoad.Undetermined,
                    "An instruction word could not be read while scanning code.",
                    efispMarkers,
                    loadMarkers,
                    startMarkers,
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    null);
            }

            if (loadMarkers.Count == 0 && startMarkers.Count == 0 && efispXrefs.Count == 0)
            {
                return Build(
                    EfispLoad.No,
                    "No efisp cross-reference and no LOAD or START marker string is present.",
                    efispMarkers,
                    loadMarkers,
                    startMarkers,
                    Array.Empty<long>(),
                    efispXrefs,
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    Array.Empty<long>(),
                    null);
            }

            List<long>? loadXrefs = CollectXrefs(image, data, loadMarkers, LoadMarker.Length);
            List<long>? startXrefs = loadXrefs is null ? null : CollectXrefs(image, data, startMarkers, StartMarker.Length);
            if (loadXrefs is null || startXrefs is null)
            {
                IReadOnlyList<long> loadEvidence = loadXrefs is null ? Array.Empty<long>() : loadXrefs;
                IReadOnlyList<long> startEvidence = startXrefs is null ? Array.Empty<long>() : startXrefs;
                return Build(
                    EfispLoad.Undetermined,
                    "An instruction word could not be read while scanning code.",
                    efispMarkers,
                    loadMarkers,
                    startMarkers,
                    Array.Empty<long>(),
                    efispXrefs,
                    loadEvidence,
                    startEvidence,
                    Array.Empty<long>(),
                    null);
            }

            ChainBounds? chain = null;
            foreach (long efisp in efispXrefs)
            {
                bool selected = false;
                foreach (long load in loadXrefs)
                {
                    if (load <= efisp)
                    {
                        continue;
                    }

                    foreach (long start in startXrefs)
                    {
                        if (start <= load)
                        {
                            continue;
                        }

                        if (start - efisp > MarkerSpan)
                        {
                            break;
                        }

                        chain = new ChainBounds(efisp, start);
                        selected = true;
                        break;
                    }

                    if (selected)
                    {
                        break;
                    }
                }

                if (selected)
                {
                    break;
                }
            }

            if (chain is null)
            {
                return Build(
                    EfispLoad.Undetermined,
                    "Markers are present, but no ordered efisp -> load -> start chain within 0x4000 bytes exists.",
                    efispMarkers,
                    loadMarkers,
                    startMarkers,
                    Array.Empty<long>(),
                    efispXrefs,
                    loadXrefs,
                    startXrefs,
                    Array.Empty<long>(),
                    null);
            }

            List<long> secureMarkers = FindMarkerRvas(image, data, SecureMarker);
            secureMarkers.AddRange(FindMarkerRvas(image, data, SecureAsciiMarker));

            List<long>? secureXrefs = CollectXrefs(image, data, secureMarkers, SecureMargin);
            if (secureXrefs is null)
            {
                return Build(
                    EfispLoad.Undetermined,
                    "An instruction word could not be read while scanning code.",
                    efispMarkers,
                    loadMarkers,
                    startMarkers,
                    secureMarkers,
                    efispXrefs,
                    loadXrefs,
                    startXrefs,
                    Array.Empty<long>(),
                    chain);
            }

            long windowStart = chain.Value.FirstRva - SecureBefore;
            long windowEnd = chain.Value.LastRva + SecureAfter;
            bool gated = false;
            foreach (long secure in secureXrefs)
            {
                if (windowStart <= secure && secure <= windowEnd)
                {
                    gated = true;
                    break;
                }
            }

            return Build(
                gated ? EfispLoad.Undetermined : EfispLoad.Yes,
                gated
                    ? "A SecureBoot reference overlaps the selected chain window; static gate detected."
                    : "Static cross-references form an ordered, ungated efisp -> load -> start chain.",
                efispMarkers,
                loadMarkers,
                startMarkers,
                secureMarkers,
                efispXrefs,
                loadXrefs,
                startXrefs,
                secureXrefs,
                chain);
        }

        private static DetectionResult Build(
            EfispLoad status,
            string reason,
            IReadOnlyList<long> efispMarkers,
            IReadOnlyList<long> loadMarkers,
            IReadOnlyList<long> startMarkers,
            IReadOnlyList<long> secureMarkers,
            IReadOnlyList<long> efispXrefs,
            IReadOnlyList<long> loadXrefs,
            IReadOnlyList<long> startXrefs,
            IReadOnlyList<long> secureXrefs,
            ChainBounds? chain)
        {
            return new DetectionResult
            {
                Status = status,
                EfispMarkerRvas = efispMarkers,
                LoadMarkerRvas = loadMarkers,
                StartMarkerRvas = startMarkers,
                SecureBootMarkerRvas = secureMarkers,
                EfispXrefRvas = efispXrefs,
                LoadXrefRvas = loadXrefs,
                StartXrefRvas = startXrefs,
                SecureBootXrefRvas = secureXrefs,
                SelectedChain = chain,
                Reason = reason,
            };
        }

        private static bool TryParseImage(byte[] data, out PeImage? image, out string? failure)
        {
            image = null;

            if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z')
            {
                failure = "Input does not start with a complete DOS MZ header.";
                return false;
            }

            if (!TryReadU32(data, 0x3c, out uint eLfanewValue))
            {
                failure = "The PE header offset cannot be read.";
                return false;
            }

            long peHeader = eLfanewValue;
            if (peHeader + 24 > data.Length)
            {
                failure = "The PE header lies outside the input.";
                return false;
            }

            if (data[peHeader] != (byte)'P' || data[peHeader + 1] != (byte)'E' || data[peHeader + 2] != 0 || data[peHeader + 3] != 0)
            {
                failure = "The PE signature is missing at the DOS header offset.";
                return false;
            }

            TryReadU32(data, peHeader + 6, out uint sectionCountValue);
            TryReadU32(data, peHeader + 20, out uint optionalSizeValue);
            long sectionCount = sectionCountValue & 0xFFFF;
            long optionalSize = optionalSizeValue & 0xFFFF;

            if (sectionCount < 1 || sectionCount > 96 || optionalSize < 0x60)
            {
                failure = "The section count or optional-header size is unusable.";
                return false;
            }

            long optional = peHeader + 24;
            long optionalEnd = optional + optionalSize;
            if (optionalEnd > data.Length || optionalEnd < optional)
            {
                failure = "The optional header lies outside the input.";
                return false;
            }

            TryReadU32(data, optional, out uint magicValue);
            if ((magicValue & 0xFFFF) != 0x10b && (magicValue & 0xFFFF) != 0x20b)
            {
                failure = "The optional-header magic is neither PE32 nor PE32+.";
                return false;
            }

            long sectionTable = optionalEnd;
            long tableEnd = sectionTable + sectionCount * 40;
            if (tableEnd > data.Length || tableEnd < sectionTable)
            {
                failure = "The section table lies outside the input.";
                return false;
            }

            TryReadU32(data, optional + 60, out uint sizeOfHeadersValue);
            long realSize = Math.Max(sizeOfHeadersValue, tableEnd);
            var sections = new Section[sectionCount];

            for (int index = 0; index < sections.Length; index++)
            {
                long entry = sectionTable + index * 40L;
                TryReadU32(data, entry + 16, out uint rawSizeValue);
                TryReadU32(data, entry + 20, out uint rawOffsetValue);
                TryReadU32(data, entry + 12, out uint virtualAddressValue);
                TryReadU32(data, entry + 36, out uint characteristicsValue);

                long rawOffset = rawOffsetValue;
                long rawSize = rawSizeValue;
                long rawEnd = rawOffset + rawSize;
                if (rawSize != 0 && (rawEnd > data.Length || rawEnd < rawOffset))
                {
                    failure = "A section raw range lies outside the input.";
                    return false;
                }

                realSize = Math.Max(realSize, rawEnd);
                sections[index] = new Section(Name(data, entry), virtualAddressValue, rawOffset, rawSize, (characteristicsValue & 0x2000_0000u) != 0);
            }

            if (realSize == 0 || realSize > data.Length)
            {
                failure = "The image extent is empty or exceeds the input.";
                return false;
            }

            image = new PeImage((int)realSize, sections);
            failure = null;
            return true;
        }

        private static string Name(byte[] data, long entry)
        {
            int length = 0;
            while (length < 8 && entry + length < data.Length && data[entry + length] != 0)
            {
                length++;
            }

            return Encoding.UTF8.GetString(data, (int)entry, length);
        }

        private static List<long> FindMarkerRvas(PeImage image, byte[] data, byte[] needle)
        {
            var rvas = new List<long>();
            long limit = image.Length - needle.Length;
            for (long raw = 0; raw <= limit; raw++)
            {
                int offset = (int)raw;
                bool match = true;
                for (int i = 0; i < needle.Length; i++)
                {
                    if (data[offset + i] != needle[i])
                    {
                        match = false;
                        break;
                    }
                }

                if (match && TryRawToRva(image, raw, out long rva))
                {
                    rvas.Add(rva);
                }
            }

            return rvas;
        }

        private static bool TryRawToRva(PeImage image, long raw, out long rva)
        {
            foreach (Section section in image.Sections)
            {
                if (raw >= section.RawOffset && raw < section.RawOffset + section.RawSize)
                {
                    rva = section.VirtualAddress + (raw - section.RawOffset);
                    return true;
                }
            }

            rva = 0;
            return false;
        }

        private static List<long>? CollectXrefs(PeImage image, byte[] data, List<long> targets, long margin)
        {
            var hits = new List<long>();
            foreach (long target in targets)
            {
                List<long>? found = CodeXrefsTo(image, data, target, margin);
                if (found is null)
                {
                    return null;
                }

                hits.AddRange(found);
            }

            hits.Sort();
            Deduplicate(hits);
            return hits;
        }

        private static List<long>? CodeXrefsTo(PeImage image, byte[] data, long targetRva, long margin)
        {
            var hits = new List<long>();
            foreach (TextRange range in TextRanges(image))
            {
                long first = range.RawStart + ((4 - (range.RawStart & 3)) & 3);
                for (long instruction = first; instruction + 4 <= range.RawEnd; instruction += 4)
                {
                    if (!TryReadU32(data, instruction, out uint word))
                    {
                        return null;
                    }

                    long pc = range.SectionRva + (instruction - range.RawStart);
                    uint encoded = (((word >> 5) & 0x7FFFFu) << 2) | ((word >> 29) & 3u);
                    long immediate = encoded - ((encoded & (1u << 20)) != 0 ? 1 << 21 : 0);
                    long instrRva = pc;
                    long? target = null;

                    switch (word & 0x9F00_0000u)
                    {
                        case 0x1000_0000u:
                            target = pc + immediate;
                            break;

                        case 0x9000_0000u:
                            long page = (pc & ~0xFFFL) + (immediate << 12);
                            long lookEnd = Math.Min(instruction + 20, range.RawEnd);
                            for (long addOffset = instruction + 4; addOffset < lookEnd; addOffset += 4)
                            {
                                if (!TryReadU32(data, addOffset, out uint add))
                                {
                                    return null;
                                }

                                if ((add & 0x7F00_0000u) != 0x1100_0000u
                                    || (add & 0x8000_0000u) == 0
                                    || ((add >> 5) & 0x1Fu) != (word & 0x1Fu))
                                {
                                    continue;
                                }

                                long addImmediate = (long)((add >> 10) & 0xFFFu) << (((add >> 22) & 1u) != 0 ? 12 : 0);
                                target = page + addImmediate;
                                instrRva = range.SectionRva + (addOffset - range.RawStart);
                                break;
                            }

                            break;

                        default:
                            break;
                    }

                    if (target is long resolved && targetRva <= resolved && resolved < targetRva + margin)
                    {
                        hits.Add(instrRva);
                    }
                }
            }

            hits.Sort();
            Deduplicate(hits);
            return hits;
        }

        private static List<TextRange> TextRanges(PeImage image)
        {
            var text = new List<Section>();
            var executable = new List<Section>();
            foreach (Section section in image.Sections)
            {
                if (string.Equals(section.Name, ".text", StringComparison.Ordinal))
                {
                    text.Add(section);
                }

                if (section.Executable)
                {
                    executable.Add(section);
                }
            }

            List<Section> chosen = text.Count > 0 ? text : executable.Count > 0 ? executable : new List<Section>(image.Sections);

            var ranges = new List<TextRange>(chosen.Count);
            foreach (Section section in chosen)
            {
                long end = Math.Min(section.RawOffset + section.RawSize, image.Length);
                if (end < section.RawOffset)
                {
                    end = section.RawOffset;
                }

                ranges.Add(new TextRange(section.RawOffset, end, section.VirtualAddress));
            }

            return ranges;
        }

        private static void Deduplicate(List<long> values)
        {
            int write = 0;
            for (int read = 0; read < values.Count; read++)
            {
                if (write == 0 || values[read] != values[write - 1])
                {
                    values[write++] = values[read];
                }
            }

            if (write < values.Count)
            {
                values.RemoveRange(write, values.Count - write);
            }
        }

        private static bool TryReadU32(byte[] data, long offset, out uint value)
        {
            if (offset < 0 || offset + 4 > data.Length)
            {
                value = 0;
                return false;
            }

            int start = (int)offset;
            value = (uint)(data[start] | (data[start + 1] << 8) | (data[start + 2] << 16) | (data[start + 3] << 24));
            return true;
        }

        private readonly struct Section
        {
            public Section(string name, long virtualAddress, long rawOffset, long rawSize, bool executable)
            {
                Name = name;
                VirtualAddress = virtualAddress;
                RawOffset = rawOffset;
                RawSize = rawSize;
                Executable = executable;
            }

            public string Name { get; }

            public long VirtualAddress { get; }

            public long RawOffset { get; }

            public long RawSize { get; }

            public bool Executable { get; }
        }

        private readonly struct TextRange
        {
            public TextRange(long rawStart, long rawEnd, long sectionRva)
            {
                RawStart = rawStart;
                RawEnd = rawEnd;
                SectionRva = sectionRva;
            }

            public long RawStart { get; }

            public long RawEnd { get; }

            public long SectionRva { get; }
        }

        private sealed class PeImage
        {
            public PeImage(int length, Section[] sections)
            {
                Length = length;
                Sections = sections;
            }

            public int Length { get; }

            public Section[] Sections { get; }
        }
    }
}

namespace FreedomInstaller.Core
{
    internal static partial class InternalSlotLoaderStructure
    {
        /// <summary>
        /// Direct pass-through to the existing bounded-container decoder so the GBL
        /// efisp detector can consume a decoded ABL PE image.
        /// </summary>
        internal static bool TryDecodeAblForGbl(byte[] abl, CancellationToken token, out byte[] pe)
            => ContainerTryDecodeBoundedImage(abl, token, out pe);
    }
}
