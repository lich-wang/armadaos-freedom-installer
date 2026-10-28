using System;

namespace FreedomInstaller.Core;

/// <summary>The three exact diagnostic outcomes of a finish attempt.</summary>
public enum RamInstallFinishAttemptState
{
    /// <summary>The finish command returned a normal running job envelope.</summary>
    Requested = 0,

    /// <summary>The command was attempted but its console acknowledgement was lost.</summary>
    AcknowledgementUnknown = 1,

    /// <summary>The helper reported that RESTART2 returned; this is always a failure.</summary>
    Restart2Returned = 2,
}

/// <summary>
/// The outcome of one finish attempt. It is deliberately not a success record: no RAM-side finish
/// success can be read back after the reset, so a real reset must still be proven by the backend's own
/// USB/EDL evidence.
/// </summary>
public sealed class RamInstallFinishAttempt
{
    internal RamInstallFinishAttempt(RamInstallFinishAttemptState state, int? errno, long? returnCode)
    {
        if (!Enum.IsDefined(typeof(RamInstallFinishAttemptState), state))
        {
            throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown finish attempt state.");
        }

        if (state == RamInstallFinishAttemptState.Restart2Returned)
        {
            if (errno is null || errno < 0 || returnCode is null)
            {
                throw new ArgumentException("A RESTART2 diagnostic requires errno and returnCode.");
            }
        }
        else if (errno is not null || returnCode is not null)
        {
            throw new ArgumentException("Only a RESTART2 diagnostic carries errno and returnCode.");
        }

        State = state;
        Errno = errno;
        ReturnCode = returnCode;
    }

    /// <summary>The exact attempt state.</summary>
    public RamInstallFinishAttemptState State { get; }

    /// <summary>The sanitized positive RESTART2 errno, or null for the other outcomes.</summary>
    public int? Errno { get; }

    /// <summary>The sanitized RESTART2 return code, or null for the other outcomes.</summary>
    public long? ReturnCode { get; }
}
