using System;

namespace FreedomInstaller.Core
{
    internal static partial class InternalSlotLoaderStructure
    {
        // AArch64 CS/HS condition code; the shared branch constants stop at
        // NE/LO/LS, so this family keeps its own value instead of widening them.
        private const int Arm64Gen5CondHs = 2;

        // Gen5 prefix: dual GetVariable success relation plus gzip detector.
        private static bool Arm64Gen5Variables(Arm64PeView view, long p, out long q)
        {
            q = p + 0xC4L;

            // p-0x14: x22 global page; both loads must bind to [x22+0x1C8].
            if (!Arm64TryAdrp(view, p - 0x14L, 22, out long globalPage))
            {
                return false;
            }

            if (!view.Arm64TryMapRva(globalPage + 0x1C8L, 8, false, out _))
            {
                return false;
            }

            if (!Arm64Words(view, p + 0x8L, 0xF940E6C8u) ||
                !Arm64Words(view, p + 0x28L, 0xF940E6C8u))
            {
                return false;
            }

            // p-0x10/p-0xC: x25 points at the expected EFI_GUID.
            if (!Arm64TryAddress(view, p - 0x10L, p - 0xCL, 25, out long guidRva) ||
                !Arm64BytesAt(view, guidRva, new Guid(Arm64PrefixGuid).ToByteArray()))
            {
                return false;
            }

            // p/p+4 and p+0x34/p+0x38: x0 points at the two UTF-16 names.
            if (!Arm64TryAddress(view, p, p + 0x4L, 0, out long baseName) ||
                !Arm64Utf16(view, baseName, Arm64PrefixKernelBase) ||
                !Arm64TryAddress(view, p + 0x34L, p + 0x38L, 0, out long sizeName) ||
                !Arm64Utf16(view, sizeName, Arm64PrefixKernelSize))
            {
                return false;
            }

            // Fixed operand words for stack outs, size pointer, attributes, GUID,
            // runtime call, first return save and the success ORR.
            if (!Arm64Words(view, p - 0x8L,
                    0x914007E4u, 0x52800115u) ||
                !Arm64Words(view, p + 0x8L,
                    0xF940E6C8u, 0x911AC3E3u, 0x91230084u,
                    0xAA1903E1u, 0xAA1F03E2u, 0xF9035BF5u,
                    0xF9402508u, 0xD63F0100u) ||
                !Arm64Words(view, p + 0x28L,
                    0xF940E6C8u, 0x914007E4u, 0xAA0003FAu) ||
                !Arm64Words(view, p + 0x3CL,
                    0x911AC3E3u, 0x91168084u, 0xAA1903E1u,
                    0xF9402508u, 0xAA1F03E2u, 0xF9035BF5u,
                    0xD63F0100u, 0xAA000348u))
            {
                return false;
            }

            if (!Arm64TryBranch(view, p + 0x5CL, Arm64BranchKind.CbzX, 8, out long success) ||
                success != q)
            {
                return false;
            }

            return Arm64Gen5GzipFlag(view, p);
        }

        // Gzip format detector p-0xAC..p-0x50; every reject path must reach p-0x4C.
        private static bool Arm64Gen5GzipFlag(Arm64PeView view, long p)
        {
            long start = p - 0xACL;
            long fail = p - 0x4CL;

            if (!Arm64Words(view, start,
                    0xF94297E8u, 0xB945A3E9u, 0xB90103FDu, 0x528A483Du,
                    0x72AC89BDu, 0x3917E3FFu, 0xB9010FF6u, 0x8B090119u))
            {
                return false;
            }

            if (!Arm64TryBranch(view, start + 0x20L, Arm64BranchKind.CbzX, 8, out long target) ||
                target != fail)
            {
                return false;
            }

            if (!Arm64Words(view, start + 0x24L, 0xB945A7E8u, 0x7100291Fu) ||
                !Arm64TryBranch(view, start + 0x2CL, Arm64BranchKind.BCond, Arm64CondLo, out target) ||
                target != fail)
            {
                return false;
            }

            if (!Arm64Words(view, start + 0x30L, 0x39400328u, 0x71007D1Fu) ||
                !Arm64TryBranch(view, start + 0x38L, Arm64BranchKind.BCond, Arm64CondNe, out target) ||
                target != fail)
            {
                return false;
            }

            if (!Arm64Words(view, start + 0x3CL, 0x39400728u, 0x71022D1Fu) ||
                !Arm64TryBranch(view, start + 0x44L, Arm64BranchKind.BCond, Arm64CondNe, out target) ||
                target != fail)
            {
                return false;
            }

            if (!Arm64Words(view, start + 0x48L, 0x39400B28u, 0x7100211Fu) ||
                !Arm64TryBranch(view, start + 0x50L, Arm64BranchKind.BCond, Arm64CondNe, out target) ||
                target != fail)
            {
                return false;
            }

            if (!Arm64Words(view, start + 0x54L, 0x52800028u, 0x3917EBE8u))
            {
                return false;
            }

            return Arm64TryBranch(view, start + 0x5CL, Arm64BranchKind.B, 0, out target) &&
                target == p - 0x14L;
        }

        // V4 source metadata and both linked header helpers; h coexists with q+0x28.
        private static bool Arm64Gen5HeaderSources(Arm64PeView view, long p, out long h)
        {
            h = p + 0xECL;

            if (!Arm64Words(view, h,
                    0xF9433BE8u, 0xF94AD3E9u, 0xF902ABE8u, 0xF902AFE9u, 0x3840CD09u))
            {
                return false;
            }

            if (!Arm64TryBranch(view, h + 0x14L, Arm64BranchKind.Bl, 0, out long leInit) ||
                !Arm64Gen5LinkedLeInit(view, leInit))
            {
                return false;
            }

            if (!Arm64Words(view, h + 0x18L, 0xF94CEBE9u))
            {
                return false;
            }

            if (!Arm64TryBranch(view, h + 0x1CL, Arm64BranchKind.Bl, 0, out long bootHeader) ||
                !Arm64Gen5LinkedBootHeader(view, bootHeader))
            {
                return false;
            }

            return Arm64Words(view, h + 0x20L,
                0xB948412Bu, 0x2A080148u, 0xB948352Au, 0xB905AFE8u,
                0xB9401928u, 0xB905CBE8u, 0xB9400D28u, 0xB9484D29u,
                0xB905BFEAu, 0xB905C3EBu, 0xB905A3E8u, 0xB905C7E9u);
        }

        // Success gzip flow, finite non-gzip fallback and exact capacity arithmetic.
        private static bool Arm64Gen5SourceFlow(Arm64PeView view, long p, long q, out long m)
        {
            m = p + 0x1F8L;
            if (q != p + 0xC4L)
            {
                return false;
            }

            if (!Arm64Gen5HeaderSources(view, p, out long h) || h != q + 0x28L)
            {
                return false;
            }

            if (!Arm64Words(view, q, 0xF94C63E9u, 0x3957E3E8u, 0xF902B3E9u))
            {
                return false;
            }

            if (!Arm64TryBranch(view, q + 0xCL, Arm64BranchKind.CbzW, 8, out long target) ||
                target != q + 0x18L)
            {
                return false;
            }

            if (!Arm64Words(view, q + 0x10L, 0x91402128u) ||
                !Arm64TryBranch(view, q + 0x14L, Arm64BranchKind.B, 0, out target) ||
                target != m)
            {
                return false;
            }

            if (!Arm64Words(view, q + 0x18L, 0x3957EBE8u) ||
                !Arm64TryBranch(view, q + 0x1CL, Arm64BranchKind.CbzW, 8, out target) ||
                target != m - 0x1CL)
            {
                return false;
            }

            if (!Arm64Words(view, q + 0x20L, 0x91420128u) ||
                !Arm64TryBranch(view, q + 0x24L, Arm64BranchKind.B, 0, out target) ||
                target != m)
            {
                return false;
            }

            // Non-gzip u body: reload base/boot size, store D/E, then R/A/U/L.
            long u = m - 0x1CL;
            if (!Arm64Words(view, u, 0xF94297E8u, 0xB945A3EAu, 0x8B0A0108u, 0xF940090Au))
            {
                return false;
            }

            if (!Arm64TryBranch(view, u + 0x10L, Arm64BranchKind.CbzX, 10, out target) ||
                target != q + 0x20L)
            {
                return false;
            }

            if (!Arm64Words(view, u + 0x14L,
                    0xF9400508u, 0x8B090108u, 0xF94AD3EAu, 0xF902B3E8u,
                    0x8B090149u, 0xF902B7E9u, 0xB945CBEAu, 0xB945CFEBu,
                    0xB945AFECu, 0xB945A3EDu, 0x0B0A018Au, 0x0B0D016Bu,
                    0x0B0B014Au, 0x4B0D03EBu, 0x5100054Au, 0x0A0B014Au,
                    0x0B0D014Au, 0xCB0A0129u, 0x114801AAu, 0xCB0A012Au,
                    0xEB08015Fu, 0xF902BBE9u, 0xF902BFEAu))
            {
                return false;
            }

            return Arm64TryBranch(view, u + 0x70L, Arm64BranchKind.BCond, Arm64CondLs, out target) &&
                target == m + 0xECL;
        }

        // init_boot+0xC little-endian init-size helper.
        private static bool Arm64Gen5LinkedLeInit(Arm64PeView view, long at)
        {
            return Arm64Words(view, at,
                0xD503245Fu, 0x3940050Au, 0x39400D0Bu, 0x39400908u, 0x2A0A2129u,
                0x53103D08u, 0x2A0B6108u, 0x2A090108u, 0xD65F03C0u);
        }

        // Main boot header-tail helper: kernel size, ramdisk and its stores.
        private static bool Arm64Gen5LinkedBootHeader(Arm64PeView view, long at)
        {
            return Arm64Words(view, at,
                0xD503245Fu, 0xF9435BEAu, 0xB905CFE8u, 0xAA1503E8u,
                0xF902A3E9u, 0xF902A7EAu, 0x38408D0Bu, 0x39400D0Cu,
                0x39400908u, 0x394026AAu, 0x53103D08u, 0x2A0A216Au,
                0x2A0C6108u, 0x2A0A0108u, 0xB905A7E8u, 0x3840CEA8u,
                0x394006AAu, 0x39400AACu, 0x39400EABu, 0x2A0A2108u,
                0x53103D8Au, 0x2A0B614Au, 0xD65F03C0u);
        }

        // Full Gen5 family link: Variables -> SourceFlow -> inline inflate Output.
        private static bool Arm64Gen5Matches(Arm64PeView view, long p)
        {
            return Arm64Gen5Variables(view, p, out long q) &&
                Arm64Gen5SourceFlow(view, p, q, out long m) &&
                Arm64Gen5Output(view, p, m);
        }

        // Failure edges may not land inside the admitted positive range that the
        // Gen5 success chain occupies: [p-0xAC, g+0x1C0).
        private static bool Arm64Gen5OutsideAdmitted(long p, long g, long target)
        {
            return target < p - 0xACL || target >= g + 0x1C0L;
        }

        // Complete finite state initialisation between the fresh z_stream and the
        // inline inflater handoff: g+0x70..g+0x138 with no unknown word inside.
        // x26 is fixed by g+0x5C and this gap never writes it, so the state
        // pointer stored at [x26,0x38] is the same qword the handoff reloads.
        private static bool Arm64Gen5StreamState(Arm64PeView view, long p, long g)
        {
            // gzip flag byte, then TBNZ bit3 into the relative reject block. The
            // displacement is decoded from the verified word instead of naming
            // any absolute image address.
            if (!Arm64Words(view, g + 0x70L, 0x39400F08u) ||
                !Arm64TryReadWord(view, g + 0x74L, out uint flagTest) ||
                flagTest != 0x371A0C48u)
            {
                return false;
            }

            long flagImm = (long)((flagTest >> 5) & 0x3FFFu);
            if ((flagImm & 0x2000L) != 0L)
            {
                flagImm -= 0x4000L;
            }

            long flagReject = g + 0x74L + flagImm * 4L;
            if (flagReject != g + 0x41FCL ||
                !Arm64Gen5OutsideAdmitted(p, g, flagReject) ||
                !view.Arm64TryMapRva(flagReject, 4, true, out _))
            {
                return false;
            }

            // zalloc callback from stream+0x50, items=1, size=7152, reserved
            // cleared, and the BL must reach the same allocCb that g+0x40/0x44
            // decode; the null result leaves the admitted chain.
            if (!Arm64Words(view, g + 0x78L,
                    0xF9402B40u, 0x52800021u, 0x52837E02u, 0xF9001B5Fu) ||
                !Arm64TryBranch(view, g + 0x88L, Arm64BranchKind.Bl, 0, out long stateAllocator) ||
                !Arm64TryAddress(view, g + 0x40L, g + 0x44L, 8, out long streamAllocator) ||
                stateAllocator != streamAllocator ||
                !Arm64TryBranch(view, g + 0x8CL, Arm64BranchKind.CbzX, 0, out long stateAllocFail) ||
                !Arm64Gen5OutsideAdmitted(p, g, stateAllocFail))
            {
                return false;
            }

            // internal state goes back into [x26,0x38]; x25 keeps the allocation
            // result (never the stream), and the free callback clears +0x40.
            if (!Arm64Words(view, g + 0x90L,
                    0xF9001F40u, 0xAA0003F9u, 0xF900201Fu, 0xF9401F55u) ||
                !Arm64TryBranch(view, g + 0xA0L, Arm64BranchKind.CbzX, 21, out long stateMissing) ||
                !Arm64Gen5OutsideAdmitted(p, g, stateMissing) ||
                !Arm64Words(view, g + 0xA4L, 0xF94022A1u) ||
                !Arm64TryBranch(view, g + 0xA8L, Arm64BranchKind.CbzX, 1, out long freeJoin) ||
                freeJoin != g + 0xC4L ||
                !Arm64Words(view, g + 0xACL, 0xB94032A8u, 0x71003D1Fu) ||
                !Arm64TryBranch(view, g + 0xB4L, Arm64BranchKind.BCond, 0, out long usedJoin) ||
                usedJoin != g + 0xC4L ||
                !Arm64Words(view, g + 0xB8L, 0xA9448348u, 0xD63F0100u, 0xF90022BFu))
            {
                return false;
            }

            // Initialiser: x8 is the internal state loaded from [x26,0x38], so its
            // +0x20 write is state+0x20 and not the stream avail_out field. The
            // stream itself is only written at +0x10, +0x28..0x30 and +0x60.
            if (!Arm64Words(view, g + 0xC4L,
                    0x528001E8u, 0xB9000ABFu, 0xB90032A8u, 0xF9401F48u) ||
                !Arm64TryBranch(view, g + 0xD4L, Arm64BranchKind.CbzX, 8, out long firstMissing) ||
                !Arm64Gen5OutsideAdmitted(p, g, firstMissing) ||
                !Arm64Words(view, g + 0xD8L, 0x2906FD1Fu, 0xB9003D1Fu, 0xF9401F48u) ||
                !Arm64TryBranch(view, g + 0xE4L, Arm64BranchKind.CbzX, 8, out long secondMissing) ||
                !Arm64Gen5OutsideAdmitted(p, g, secondMissing) ||
                !Arm64Words(view, g + 0xE8L,
                    0xF900111Fu, 0xF9000B5Fu, 0xA902FF5Fu, 0xB9400909u, 0xF9005FF8u) ||
                !Arm64TryBranch(view, g + 0xFCL, Arm64BranchKind.CbzW, 9, out long flagJoin) ||
                flagJoin != g + 0x108L ||
                !Arm64Words(view, g + 0x100L, 0x92400129u, 0xF9003349u))
            {
                return false;
            }

            // Internal state words, then the dynamic read-only data page whose
            // +0x8B8 qword is the vector constant loaded into d0 and copied to
            // state+0x1BE0.
            if (!Arm64Words(view, g + 0x108L,
                    0x52900009u, 0x29007D1Fu, 0xB9000D1Fu, 0xF900151Fu, 0xB9001509u) ||
                !Arm64TryAdrp(view, g + 0x11CL, 9, out long statePage) ||
                !view.Arm64TryMapRva(statePage + 0x8B8L, 8, false, out _) ||
                !Arm64Words(view, g + 0x120L, 0xF900251Fu, 0xB900511Fu, 0xFD445D20u) ||
                !Arm64Words(view, g + 0x12CL,
                    0x91154109u, 0xF9004509u, 0xA9062509u, 0xFD0DF100u))
            {
                return false;
            }

            // The bounded segment ends at g+0x13C, where the handoff reloads the
            // same [x26,0x38] slot written at g+0x90.
            return true;
        }

        // Capacity guard, post-limit variables, room bind and stream handoff.
        // Gen5 inlines inflate, so there is no standalone BL inflate to follow.
        private static bool Arm64Gen5Output(Arm64PeView view, long p, long m)
        {
            if (m != p + 0x1F8L)
            {
                return false;
            }

            long k = m + 0x58L;
            long err = m + 0xECL;
            long o = m + 0x128L;
            long g = o + 0xD8L;

            // m+0x54 (n+0x44): L<=D must leave for err, never fall into output.
            if (!Arm64TryBranch(view, m + 0x54L, Arm64BranchKind.BCond, Arm64CondLs, out long target) ||
                target != err)
            {
                return false;
            }

            // Error return shape: -0x80000000, log, cookie, check, frame restore.
            // err+0/+4 debug text is build-dependent; decode only, never compare.
            if (!Arm64TryAddress(view, err, err + 0x4L, 1, out long errText) ||
                !view.Arm64TryMapRva(errText, 1, false, out _) ||
                !Arm64Words(view, err + 0x8L, 0x52B00000u) ||
                !Arm64TryBranch(view, err + 0xCL, Arm64BranchKind.Bl, 0, out _) ||
                !Arm64TryAdrp(view, err + 0x10L, 9, out _) ||
                !Arm64Words(view, err + 0x14L, 0xF94D67E8u) ||
                !Arm64TryBranch(view, err + 0x18L, Arm64BranchKind.Bl, 0, out _) ||
                !Arm64TryBranch(view, err + 0x1CL, Arm64BranchKind.BCond, Arm64CondNe, out long abort) ||
                !Arm64Words(view, err + 0x20L, 0x914007FFu, 0x912B43FFu) ||
                !Arm64TryBranch(view, err + 0x28L, Arm64BranchKind.Bl, 0, out _) ||
                !Arm64Words(view, err + 0x2CL, 0xA9417BFDu, 0xFC4707E8u, 0xD50323BFu, 0xD65F03C0u))
            {
                return false;
            }

            // A failing check must leave the whole admitted chain, not rejoin it.
            if (!Arm64Gen5OutsideAdmitted(p, g, abort))
            {
                return false;
            }

            // k: two 8-byte GetVariable calls, same GUID, out sp19D0/sp1A48
            // (disjoint from D/U/L). Extra variables may not rewrite capacity
            // slots: both admit paths rejoin o and the miss goes err+8.
            if (!Arm64Words(view, k, 0xF940E6C8u) ||
                !Arm64TryAddress(view, k + 0x4L, k + 0x8L, 25, out long guidRva) ||
                !Arm64BytesAt(view, guidRva, new Guid(Arm64PrefixGuid).ToByteArray()) ||
                !Arm64Words(view, k + 0xCL, 0x914007E4u, 0x52800115u) ||
                !Arm64TryAddress(view, k + 0x14L, k + 0x18L, 0, out long nameRva) ||
                !view.Arm64TryMapRva(nameRva, 2, false, out _) ||
                !Arm64Words(view, k + 0x1CL,
                    0x911AC3E3u, 0xF9402508u, 0x91274084u, 0xAA1903E1u,
                    0xAA1F03E2u, 0xF9035BF5u, 0xD63F0100u, 0xF940E6C8u,
                    0x914007E4u, 0xAA0003FAu) ||
                !Arm64TryAddress(view, k + 0x44L, k + 0x48L, 0, out nameRva) ||
                !view.Arm64TryMapRva(nameRva, 2, false, out _) ||
                !Arm64Words(view, k + 0x4CL,
                    0x911AC3E3u, 0x91292084u, 0xAA1903E1u, 0xF9402508u,
                    0xAA1F03E2u, 0xF9035BF5u, 0xD63F0100u, 0xAA000348u) ||
                !Arm64Gen5TryCbnzX(view, k + 0x6CL, 8, out long extraJoined) ||
                extraJoined != o ||
                !Arm64Words(view, k + 0x70L,
                    0xB945DBE8u, 0xF94D27E9u, 0xF94CEBEAu, 0xEB08013Fu,
                    0xF902C3EAu) ||
                !Arm64TryBranch(view, k + 0x84L, Arm64BranchKind.BCond, Arm64Gen5CondHs, out target) ||
                target != o ||
                !Arm64TryBranch(view, k + 0x90L, Arm64BranchKind.B, 0, out target) ||
                target != err + 0x8L)
            {
                return false;
            }

            // o: D sp560, U sp570, gzip flag sp5FA, published D/U pair, then
            // room = L - D via x25 with the 32-bit range reject into err.
            long gzipFlag;
            if (!Arm64Words(view, o, 0xF942B3E8u) ||
                !Arm64TryAddress(view, o + 0x4L, o + 0x8L, 11, out gzipFlag) ||
                !view.Arm64TryMapRva(gzipFlag, 16, false, out _) ||
                !Arm64Words(view, o + 0xCL, 0xF942BBE9u, 0x3957EBEAu) ||
                !Arm64TryAdrp(view, o + 0x14L, 22, out _) ||
                !Arm64Words(view, o + 0x18L, 0xA9002568u) ||
                !Arm64TryBranch(view, o + 0x1CL, Arm64BranchKind.CbzW, 10, out long nonGzip) ||
                nonGzip != o + 0x44L ||
                !Arm64Words(view, o + 0x20L, 0xF942BFE9u, 0xCB080139u, 0xD360FF28u) ||
                !Arm64TryBranch(view, o + 0x2CL, Arm64BranchKind.CbzX, 8, out target) ||
                target != g)
            {
                return false;
            }

            // g: fresh 112-byte z_stream, callbacks, next_out=D, avail_out=room.
            // Every reject edge has to land outside the admitted chain.
            if (!Arm64Words(view, g, 0xF9006BF8u) ||
                !Arm64TryBranch(view, g + 0x4L, Arm64BranchKind.Bl, 0, out _) ||
                !Arm64Words(view, g + 0x8L, 0xF94297F8u) ||
                !Arm64TryBranch(view, g + 0xCL, Arm64BranchKind.CbzX, 24, out long inputNull) ||
                !Arm64Gen5OutsideAdmitted(p, g, inputNull) ||
                !Arm64Words(view, g + 0x10L, 0xB945A7FCu, 0x71002B95u) ||
                !Arm64TryBranch(view, g + 0x18L, Arm64BranchKind.BCond, Arm64CondLs, out long shortInput) ||
                !Arm64Gen5OutsideAdmitted(p, g, shortInput) ||
                !Arm64Words(view, g + 0x1CL, 0x6B19039Fu) ||
                !Arm64TryBranch(view, g + 0x20L, Arm64BranchKind.BCond, Arm64Gen5CondHs, out long longInput) ||
                !Arm64Gen5OutsideAdmitted(p, g, longInput) ||
                !Arm64Words(view, g + 0x24L,
                    0xF9007FE0u, 0x52800E00u, 0xF90067FBu, 0xB945A3FBu,
                    0xF942B3FAu) ||
                !Arm64TryBranch(view, g + 0x38L, Arm64BranchKind.Bl, 0, out _) ||
                !Arm64TryBranch(view, g + 0x3CL, Arm64BranchKind.CbzX, 0, out long shortStream) ||
                !Arm64Gen5OutsideAdmitted(p, g, shortStream) ||
                !Arm64TryAddress(view, g + 0x40L, g + 0x44L, 8, out long allocCb) ||
                !view.Arm64TryMapRva(allocCb, 4, true, out _) ||
                !Arm64TryAddress(view, g + 0x48L, g + 0x4CL, 9, out long freeCb) ||
                !view.Arm64TryMapRva(freeCb, 4, true, out _) ||
                !Arm64Words(view, g + 0x50L, 0x8B1B0318u) ||
                !Arm64Words(view, g + 0x54L,
                    0xF9000C1Au, 0xB9002019u, 0xAA0003FAu, 0xA9042408u) ||
                !Arm64Words(view, g + 0x64L,
                    0x91002B08u, 0xB9000815u, 0xF9000008u))
            {
                return false;
            }

            // Stream/state initialisation g+0x70..g+0x138 is consumed whole by
            // the handoff; x26 must still be the producer z_stream pointer.
            if (!Arm64Gen5StreamState(view, p, g))
            {
                return false;
            }

            // Actual inline inflater handoff: the same stream pointer (x26/x9)
            // reloads next_out+0x18 and avail_out+0x20 written at g+0x54/0x58,
            // then stages that avail_out as the output bound in its own loop.
            long handoff = g + 0x13CL;
            if (!Arm64Words(view, handoff, 0xF9401F48u, 0xA90EA3FAu) ||
                !Arm64TryBranch(view, handoff + 0x8L, Arm64BranchKind.CbzX, 8, out long stateNull) ||
                !Arm64Gen5OutsideAdmitted(p, g, stateNull) ||
                !Arm64Words(view, handoff + 0xCL, 0xF94077E8u, 0xF9400D18u) ||
                !Arm64TryBranch(view, handoff + 0x14L, Arm64BranchKind.CbzX, 24, out long inputStateNull) ||
                !Arm64Gen5OutsideAdmitted(p, g, inputStateNull) ||
                !Arm64Words(view, handoff + 0x18L,
                    0xF94077E8u, 0xF9400108u, 0xAA0803F6u) ||
                !Arm64TryBranch(view, handoff + 0x24L, Arm64BranchKind.CbzX, 8, out long outputStateNull) ||
                !Arm64Gen5OutsideAdmitted(p, g, outputStateNull) ||
                !Arm64Words(view, handoff + 0x28L,
                    0xF9407BE8u, 0xB9400108u, 0x71002D1Fu) ||
                !Arm64TryBranch(view, handoff + 0x34L, Arm64BranchKind.BCond, Arm64CondNe, out long modeJoin) ||
                modeJoin != handoff + 0x4CL ||
                !Arm64Words(view, handoff + 0x38L,
                    0xA94EABE9u, 0x52800188u, 0xB9000148u, 0xF9400D38u,
                    0xF9400136u, 0xA94EAFE9u, 0xB900ABFFu, 0xB940212Cu,
                    0xB940093Au, 0x91024169u, 0xF940257Cu, 0xB940517Bu,
                    0xF90073E9u, 0x91154169u, 0xB900B7FAu, 0xB900DBECu,
                    0xF9004BE9u) ||
                !Arm64TryAdrp(view, handoff + 0x7CL, 9, out _) ||
                !Arm64Words(view, handoff + 0x80L, 0xB900C3ECu))
            {
                return false;
            }

            return true;
        }

        // CBNZ X only; the existing branch enum has no CBNZ X kind.
        private static bool Arm64Gen5TryCbnzX(Arm64PeView view, long at, int reg, out long target)
        {
            target = 0L;
            if (reg < 0 || reg > 31 ||
                !Arm64TryReadWord(view, at, out uint word) ||
                (word & 0xFF00001Fu) != (0xB5000000u | (uint)reg))
            {
                return false;
            }

            long imm19 = (long)((word >> 5) & 0x7FFFFu);
            if ((imm19 & 0x40000L) != 0L)
            {
                imm19 -= 0x80000L;
            }

            target = at + imm19 * 4L;
            return view.Arm64TryMapRva(target, 4, true, out _);
        }
    }
}
