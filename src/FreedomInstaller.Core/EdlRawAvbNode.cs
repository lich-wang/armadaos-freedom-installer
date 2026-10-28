using System.Collections.Generic;

namespace FreedomInstaller.Core;

internal enum EdlRawAvbNodeKind
{
    Recovery,
    VbmetaSystem,
    Vbmeta
}

internal sealed record EdlRawResignedAvbNode(
    VerifiedEdlFile Original,
    VerifiedEdlFile Candidate,
    EdlRawAvbNodeKind Kind,
    string OriginalPublicKeySha256,
    string PublicKeySha256,
    IReadOnlyDictionary<string, string> ChainPublicKeySha256,
    long VbmetaOffset,
    long VbmetaBytes,
    ulong RollbackIndex,
    uint RollbackIndexLocation,
    uint Flags,
    uint RequiredMajor,
    uint RequiredMinor,
    string NonChainDescriptorsSha256);
