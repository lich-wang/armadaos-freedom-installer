using System;

namespace FreedomInstaller.Core;

/// <summary>
/// Result of a completed RAM install bootstrap: the identity the device proved in this fresh session
/// plus the console and bearer token the install request layer uses for later fixed commands.
/// </summary>
/// <remarks>
/// The constructor is internal so a client cannot fabricate a session that was never proven against a
/// live RAM device. <see cref="SocSerial"/> is the normalized decimal serial that matched the expected
/// Android identity. The token is a secret: it is not a public property and never appears in
/// <see cref="ToString"/> or in an error message.
/// </remarks>
public sealed class RamInstallSession
{
    internal RamInstallSession(
        string model,
        string soc,
        string socSerial,
        string bootId,
        IMaintenanceConsole console,
        string token)
    {
        Model = model;
        Soc = soc;
        SocSerial = socSerial;
        BootId = bootId;
        Console = console;
        Token = token;
    }

    public string Model { get; }

    public string Soc { get; }

    /// <summary>The normalized decimal SoC serial proven for this session.</summary>
    public string SocSerial { get; }

    /// <summary>The fresh RAM <c>boot_id</c> of this session.</summary>
    public string BootId { get; }

    internal IMaintenanceConsole Console { get; }

    internal string Token { get; }

    public override string ToString() =>
        nameof(RamInstallSession)
        + " { Model = " + Model
        + ", Soc = " + Soc
        + ", SocSerial = " + SocSerial
        + ", BootId = " + BootId
        + " }";
}
