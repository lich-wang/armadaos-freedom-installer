using System.IO;
using System.Text;
using System.Threading;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>Which models must carry the mirrored-policy runtime marker (Freedom's MIRROR_POLICY_MODELS).</summary>
public sealed class LinuxRuntimeContractModelTests
{
    [Theory]
    [InlineData("TB322FC", true)]
    [InlineData("TB323FU", true)]
    [InlineData("TB710FU", true)]
    [InlineData("tb710fu", false)]
    [InlineData("TB320FC", false)]
    [InlineData(null, false)]
    public void Mirrored_policy_models_require_the_marker(string? model, bool expected) =>
        Assert.Equal(expected, LinuxRuntimeContract.RequiresMirrorMarker(model));

    [Fact]
    public void A_tb710fu_runtime_without_the_marker_is_refused()
    {
        using var unmarked = new MemoryStream(Encoding.ASCII.GetBytes("kshim runtime without the contract"));
        var ex = Assert.Throws<InvalidDataException>(() =>
            LinuxRuntimeContract.RequireMirrorMarker(unmarked, "TB710FU", "runtime", CancellationToken.None));
        Assert.Contains(LinuxRuntimeContract.MirrorMarkerText, ex.Message);

        using var marked = new MemoryStream(Encoding.ASCII.GetBytes("prefix " + LinuxRuntimeContract.MirrorMarkerText + " suffix"));
        LinuxRuntimeContract.RequireMirrorMarker(marked, "TB710FU", "runtime", CancellationToken.None);
    }
}
