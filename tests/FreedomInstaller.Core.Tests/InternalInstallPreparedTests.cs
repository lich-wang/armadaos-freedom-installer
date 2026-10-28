using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Narrow gate tests for <see cref="InternalInstallBackend.CreatePreparedAsync"/>. They define the concrete
/// refusals the real preparation must produce, in the order it must produce them, and nothing else.
/// <para>
/// This is the actual guard suite of the implemented factory: each test drives a concrete refusal through the
/// production gate before any source is read, and none of them constructs a prepared instance, a Sahara proof or
/// a readiness flag.
/// </para>
/// <para>
/// There is deliberately no positive "Prepared" test. A successful preparation needs the frozen compiled
/// install-support pin plus the real backup, artifact, package and asset files, which the manager supplies
/// later; fabricating them here would fake exactly what these guards exist to protect. The real positive device
/// integration remains pending.
/// </para>
/// <para>
/// The negative fixtures use sentinel references created by <see cref="RuntimeHelpers.GetUninitializedObject(Type)"/>
/// for resources the gate under test must reject BEFORE reading: they are never valid
/// <see cref="InternalBackupSet"/>, <see cref="InternalArtifactSet"/>, <see cref="ImportedPackage"/>,
/// <see cref="InternalInstallAssets"/>, <see cref="InternalInstallServices"/> or <see cref="EdlClient"/>
/// instances, hold no leases, no proof and no Sahara evidence, and are never installed or claimed as prepared.
/// The EdlClient sentinel is used only because its public <see cref="EdlClient.HasInitialSaharaProof"/> is
/// false without any private state being touched: no proof bit is set or fabricated. Any code that dereferences
/// those sentinels would surface as a NullReferenceException and fail the test, which is exactly the intended
/// signal.
/// </para>
/// </summary>
public sealed class InternalInstallPreparedTests
{
    /// <summary>Stable refusal identities, restated here independently of the production code.</summary>
    private const string UnsupportedSlotCode = "unsupported-current-slot";

    private const string IncompleteDeviceCheckCode = "device-check-incomplete";

    private const string InitialProofCode = "edl-initial-proof-required";

    private const string UnsupportedProfileCode = "unsupported-install-profile";

    private const string Serial = "HA1B2C3D4";

    private const string SocSerial = "3251823604";

    private const string G4Product = "elden_prc_wifi";

    private const string G5Model = "TB323FU";

    private const string DisplayId = MaintenanceProfiles.AndroidBuild;

    /// <summary>A 258 build: close to the supported 259 build, and never an accepted profile by substring.</summary>
    private const string WrongDisplayId =
        "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.258_ST_260601";

    private const string BuildFingerprint =
        "Lenovo/TB322FC/elden_prc_wifi:15/AQ3A.250601.001/20260611.000000:user/release-keys";

    /// <summary>
    /// Evidence parent used by the guard fixtures: a unique, deliberately absent child of the ticket's
    /// <see cref="TestArtifactRoot"/>. It is never created and never deleted, so every refusal under test must
    /// happen before any output directory is touched. There is no system temporary-directory fallback.
    /// </summary>
    private static readonly string EvidenceParent =
        Path.Combine(TestArtifactRoot.Resolve(), "ibp001-guard-evidence-" + Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData("b")]
    [InlineData(null)]
    [InlineData("c")]
    [InlineData("")]
    public async Task CreatePrepared_WithUnsupportedCurrentSlot_IsRefusedWithTheStableSlotCode(string? slot)
    {
        // A completely verified Step 1 result with slot b still opens no route: the maintenance boot is fixed to
        // A, so only an observed slot a can ever be prepared.
        var step1 = Step1(slot);
        Assert.Equal(slot is "a" or "b", step1.Succeeded);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreatePrepared(step1));

        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Contains(UnsupportedSlotCode, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("lock")]
    [InlineData("ota")]
    [InlineData("return")]
    public async Task CreatePrepared_WithIncompleteStep1Result_IsRefusedWithTheDeviceCheckCode(string gap)
    {
        var step1 = gap switch
        {
            "lock" => Step1("a", lockState: BootloaderState.Unknown),
            "ota" => Step1("a", otaState: OtaUpdateState.Unknown),
            "return" => Step1("a", androidReturn: AndroidReturnState.Unconfirmed),
            _ => throw new ArgumentOutOfRangeException(nameof(gap), gap, "unknown gap"),
        };
        Assert.False(step1.Succeeded);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreatePrepared(step1));

        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Contains(IncompleteDeviceCheckCode, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(BootloaderState.Locked)]
    [InlineData(BootloaderState.Unlocked)]
    public async Task CreatePrepared_WithUnprovenInitialEdl_IsRefusedWithTheInitialProofCode(BootloaderState lockState)
    {
        // Both real lock states must get past the lock gate: there is no blanket "must be unlocked" rule, and the
        // refusal below has to come from the missing EDL proof, not from a lock policy.
        var step1 = Step1("a", lockState: lockState);
        Assert.True(step1.Succeeded);

        var initialEdl = NeverValid<EdlClient>();
        Assert.False(initialEdl.HasInitialSaharaProof);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePrepared(step1, initialEdl));

        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Contains(InitialProofCode, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(G5Model, DisplayId)]
    [InlineData(MaintenanceProfiles.Model, WrongDisplayId)]
    public async Task CreatePrepared_WithUnsupportedProfile_IsRefusedWithTheProfileCode(string model, string displayId)
    {
        // Step 1 has no profile gate of its own, so this result is fully verified while the install profile is
        // not a supported G4 / exact 259 one. The factory must refuse by profile before it looks at any opaque
        // client metadata: model spoofing and substring build matching are both rejected.
        var step1 = Step1("a", model: model, displayId: displayId);
        Assert.True(step1.Succeeded);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreatePrepared(step1));

        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Contains(UnsupportedProfileCode, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreatePrepared_WithPreCancelledToken_CancelsBeforeAnySourceIsRead()
    {
        var step1 = Step1("a");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var exception = await Record.ExceptionAsync(() => CreatePrepared(step1, token: cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(exception);
        Assert.IsNotType<NotImplementedException>(exception);
        Assert.False(step1.Cancelled);
    }

    [Theory]
    [InlineData("deviceCheck")]
    [InlineData("initialEdl")]
    [InlineData("backup")]
    [InlineData("artifacts")]
    [InlineData("package")]
    [InlineData("installAssets")]
    [InlineData("services")]
    [InlineData("evidenceParent")]
    public async Task CreatePrepared_WithMissingOrBlankArgument_IsRejectedBeforeAnyRead(string argument)
    {
        var step1 = Step1("a");
        var initialEdl = NeverValid<EdlClient>();
        var backup = NeverValid<InternalBackupSet>();
        var artifacts = NeverValid<InternalArtifactSet>();
        var package = NeverValid<ImportedPackage>();
        var installAssets = NeverValid<InternalInstallAssets>();
        var services = NeverValid<InternalInstallServices>();

        Func<Task<InternalInstallBackend>> call = argument switch
        {
            "deviceCheck" => () => Create(
                null, initialEdl, backup, artifacts, package, installAssets, services, EvidenceParent),
            "initialEdl" => () => Create(
                step1, null, backup, artifacts, package, installAssets, services, EvidenceParent),
            "backup" => () => Create(
                step1, initialEdl, null, artifacts, package, installAssets, services, EvidenceParent),
            "artifacts" => () => Create(
                step1, initialEdl, backup, null, package, installAssets, services, EvidenceParent),
            "package" => () => Create(
                step1, initialEdl, backup, artifacts, null, installAssets, services, EvidenceParent),
            "installAssets" => () => Create(
                step1, initialEdl, backup, artifacts, package, null, services, EvidenceParent),
            "services" => () => Create(
                step1, initialEdl, backup, artifacts, package, installAssets, null, EvidenceParent),
            "evidenceParent" => () => Create(
                step1, initialEdl, backup, artifacts, package, installAssets, services, "   "),
            _ => throw new ArgumentOutOfRangeException(nameof(argument), argument, "unknown argument"),
        };

        var exception = await Record.ExceptionAsync(call);

        Assert.IsNotType<NotImplementedException>(exception);

        if (string.Equals(argument, "evidenceParent", StringComparison.Ordinal))
        {
            // A whitespace evidence parent is a bad value, not a missing object.
            Assert.IsType<ArgumentException>(exception);
        }
        else
        {
            Assert.IsType<ArgumentNullException>(exception);
        }
    }

    [Fact]
    public void PublicSurface_StaysImmutableAndExposesNoReadinessSwitch()
    {
        var backend = typeof(InternalInstallBackend);

        Assert.True(backend.IsSealed);
        Assert.Empty(backend.GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        // The backend is a disposable single-use object and implements no other contract: no IInstallBackend, no
        // generic workflow interface and no simulation surface.
        Assert.Equal(new[] { typeof(IDisposable) }, backend.GetInterfaces());

        // State is getter-only: the prepared data, its snapshot and the last result are read, never replaced.
        AssertGetterOnly(backend, nameof(InternalInstallBackend.Prepared), typeof(InternalInstallPrepared));
        AssertGetterOnly(backend, nameof(InternalInstallBackend.Snapshot), typeof(InternalInstallSnapshot));

        var lastResult = backend.GetProperty(
            nameof(InternalInstallBackend.LastResult),
            BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(lastResult);

        // InternalInstallResult is a nullable *reference* class: the nullability is an annotation, not a runtime
        // type, so the property type is the class itself and Nullable.GetUnderlyingType is always null here.
        Assert.Equal(typeof(InternalInstallResult), lastResult!.PropertyType);
        Assert.Null(lastResult.SetMethod);

        // The frozen legacy factory keeps its exact public signature; only its body was implemented in P2. The
        // approved Direct overload differs only in its sixth parameter, so this lookup names the legacy types.
        var factory = backend.GetMethod(
            nameof(InternalInstallBackend.CreatePreparedAsync),
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: new[]
            {
                typeof(InternalDeviceCheckResult),
                typeof(EdlClient),
                typeof(InternalBackupSet),
                typeof(InternalArtifactSet),
                typeof(ImportedPackage),
                typeof(InternalInstallAssets),
                typeof(InternalInstallServices),
                typeof(string),
                typeof(CancellationToken),
            },
            modifiers: null);
        Assert.NotNull(factory);
        Assert.Equal(typeof(Task<InternalInstallBackend>), factory!.ReturnType);

        var parameters = factory.GetParameters();
        Assert.Equal(9, parameters.Length);
        Assert.Equal(typeof(InternalDeviceCheckResult), parameters[0].ParameterType);
        Assert.Equal(typeof(EdlClient), parameters[1].ParameterType);
        Assert.Equal(typeof(InternalBackupSet), parameters[2].ParameterType);
        Assert.Equal(typeof(InternalArtifactSet), parameters[3].ParameterType);
        Assert.Equal(typeof(ImportedPackage), parameters[4].ParameterType);
        Assert.Equal(typeof(InternalInstallAssets), parameters[5].ParameterType);
        Assert.Equal(typeof(InternalInstallServices), parameters[6].ParameterType);
        Assert.Equal(typeof(string), parameters[7].ParameterType);
        Assert.Equal(typeof(CancellationToken), parameters[8].ParameterType);
        Assert.True(parameters[8].HasDefaultValue);

        foreach (var type in new[]
                 {
                     typeof(InternalInstallPrepared),
                     typeof(InternalInstallSnapshot),
                     typeof(InternalInstallResult),
                 })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.NotEmpty(type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance));

            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.Null(property.SetMethod);
                Assert.False(property.CanWrite, $"{type.Name}.{property.Name} must not be writable.");
            }
        }

        // The approved BootTrustMode property is a metadata-only read projection of the observed trust state: it
        // is declared on the prepared record itself, returns the immutable enum and has no setter. Only this exact
        // property and its exact getter are exempt from the filter below; nothing else gains an exemption.
        var bootTrustProperty = typeof(InternalInstallPrepared).GetProperty(
            nameof(InternalInstallPrepared.BootTrustMode),
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        Assert.NotNull(bootTrustProperty);
        Assert.Equal(typeof(InternalInstallPrepared), bootTrustProperty!.DeclaringType);
        Assert.Equal(typeof(InternalInstallBootTrustMode), bootTrustProperty.PropertyType);
        Assert.Empty(bootTrustProperty.GetIndexParameters());
        Assert.Null(bootTrustProperty.SetMethod);
        Assert.False(bootTrustProperty.CanWrite);

        var bootTrustGetter = bootTrustProperty.GetMethod;
        Assert.NotNull(bootTrustGetter);
        Assert.Equal(typeof(InternalInstallPrepared), bootTrustGetter!.DeclaringType);
        Assert.True(bootTrustGetter.IsPublic);
        Assert.False(bootTrustGetter.IsStatic);
        Assert.Empty(bootTrustGetter.GetParameters());
        Assert.Equal(typeof(InternalInstallBootTrustMode), bootTrustGetter.ReturnType);

        // No readiness, trust or simulation switch may exist on the public surface.
        foreach (var type in new[] { backend, typeof(InternalInstallPrepared) })
        {
            var suspicious = type
                .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .Where(member => member.Name.Contains("Ready", StringComparison.OrdinalIgnoreCase)
                    || member.Name.Contains("Simulat", StringComparison.OrdinalIgnoreCase)
                    || member.Name.Contains("Trust", StringComparison.OrdinalIgnoreCase))
                .Where(member => !(type == typeof(InternalInstallPrepared)
                    && (bootTrustProperty!.Equals(member) || bootTrustGetter!.Equals(member))))
                .ToArray();

            Assert.Empty(suspicious);
        }
    }

    [Fact]
    public void InternalInstallServices_KeepsTheFourReferenceContractAndHasNoBootstrap()
    {
        // The maintenance console does not exist while the device is prepared in 9008, so the services record must
        // not carry a MaintenanceBootstrap at all; the execution owner builds the real one after the normal reset.
        var entry = NeverValid<EdlEntry>();
        var runner = new StubRunner();
        var discovery = new StubEndpointDiscovery();

        Assert.Throws<ArgumentNullException>(() => new InternalInstallServices(null!, runner, discovery, "adb.exe"));
        Assert.Throws<ArgumentNullException>(() => new InternalInstallServices(entry, null!, discovery, "adb.exe"));
        Assert.Throws<ArgumentNullException>(() => new InternalInstallServices(entry, runner, null!, "adb.exe"));
        Assert.Throws<ArgumentException>(() => new InternalInstallServices(entry, runner, discovery, "   "));

        var services = new InternalInstallServices(entry, runner, discovery, "adb.exe");

        Assert.Same(entry, services.EdlEntry);
        Assert.Same(runner, services.CommandRunner);
        Assert.Same(discovery, services.EndpointDiscovery);
        Assert.Equal("adb.exe", services.AdbPath);

        Assert.Equal(4, typeof(InternalInstallServices).GetConstructors().Single().GetParameters().Length);
        Assert.Null(typeof(InternalInstallServices).GetProperty("MaintenanceBootstrap"));
    }

    private static void AssertGetterOnly(Type type, string name, Type propertyType)
    {
        var property = type.GetProperty(name, BindingFlags.Public | BindingFlags.Instance);

        Assert.NotNull(property);
        Assert.Equal(propertyType, property!.PropertyType);
        Assert.Empty(property.GetIndexParameters());
        Assert.NotNull(property.GetMethod);
        Assert.Null(property.SetMethod);
        Assert.False(property.CanWrite);
    }

    /// <summary>
    /// Builds a Step 1 result through its actual internal constructor (ten parameters, the last one the observed
    /// current slot). The values are the real observed shape of the supported G4 259 device; a test only ever
    /// varies the one fact under test.
    /// </summary>
    private static InternalDeviceCheckResult Step1(
        string? slot,
        BootloaderState lockState = BootloaderState.Locked,
        OtaUpdateState otaState = OtaUpdateState.Completed,
        AndroidReturnState androidReturn = AndroidReturnState.Verified,
        string model = MaintenanceProfiles.Model,
        string displayId = DisplayId)
    {
        var firmware = new FirmwareSnapshot(
            displayId,
            BuildFingerprint,
            "15",
            "2026-06-01",
            BootloaderState.Locked);

        var android = new AndroidMaintenanceIdentity(
            new DeviceIdentity(Serial, model, lockState) { Firmware = firmware },
            SocSerial);

        var constructor = typeof(InternalDeviceCheckResult).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(AndroidMaintenanceIdentity),
                typeof(string),
                typeof(string),
                typeof(BootloaderState),
                typeof(OtaUpdateState),
                typeof(AndroidReturnState),
                typeof(bool),
                typeof(InternalDeviceCheckStage?),
                typeof(string),
                typeof(string),
            },
            modifiers: null)
            ?? throw new InvalidOperationException(
                "InternalDeviceCheckResult no longer exposes the ten-parameter internal constructor this fixture "
                + "drives.");

        return (InternalDeviceCheckResult)constructor.Invoke(new object?[]
        {
            android,
            Serial,
            G4Product,
            lockState,
            otaState,
            androidReturn,
            false,
            null,
            null,
            slot,
        });
    }

    /// <summary>
    /// A reference that was never constructed: no constructor ran, so it has no leases, no proof, no
    /// configuration and no device. It exists only so a gate that must refuse before reading a resource can be
    /// driven without producing real backup, artifact, package or asset data.
    /// </summary>
    private static T NeverValid<T>()
        where T : class
        => (T)RuntimeHelpers.GetUninitializedObject(typeof(T));

    private static Task<InternalInstallBackend> CreatePrepared(
        InternalDeviceCheckResult step1,
        EdlClient? initialEdl = null,
        CancellationToken token = default)
        => Create(
            step1,
            initialEdl ?? NeverValid<EdlClient>(),
            NeverValid<InternalBackupSet>(),
            NeverValid<InternalArtifactSet>(),
            NeverValid<ImportedPackage>(),
            NeverValid<InternalInstallAssets>(),
            NeverValid<InternalInstallServices>(),
            EvidenceParent,
            token);

    private static Task<InternalInstallBackend> Create(
        InternalDeviceCheckResult? deviceCheck,
        EdlClient? initialEdl,
        InternalBackupSet? backup,
        InternalArtifactSet? artifacts,
        ImportedPackage? package,
        InternalInstallAssets? installAssets,
        InternalInstallServices? services,
        string? evidenceParent,
        CancellationToken token = default)
        => InternalInstallBackend.CreatePreparedAsync(
            deviceCheck!,
            initialEdl!,
            backup!,
            artifacts!,
            package!,
            installAssets!,
            services!,
            evidenceParent!,
            token);

    /// <summary>A runner that exists only so the services guard can pass a real implementation.</summary>
    private sealed class StubRunner : ICommandRunner
    {
        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("The guard fixtures never start a process.");
    }

    /// <summary>An endpoint source with no devices; it is never read by the guard fixtures.</summary>
    private sealed class StubEndpointDiscovery : IEdlEndpointDiscovery
    {
        public IReadOnlyList<EdlEndpoint> ReadPresent() => Array.Empty<EdlEndpoint>();
    }
}
