# Prepare an existing backup for launcher settings

This offline tool validates a complete 2 GiB v2 board-recovery image with the installer recovery verifier and prepares the two bounded regions needed for v3. It does not open any device for writing, invoke fastboot, or deploy its output.

Build the project with the same .NET 10 and BundledAvbSigningKey input as FreedomInstaller.Core. Run the resulting BackupSettingsUpgrade.dll with four arguments:

1. Absolute path to the captured v2 image.
2. Actual device model: TB322FC or TB323FU.
3. ARMADA_BACKUP partition UUID read from the current target GPT.
4. A new absolute output directory below an existing parent.

The output contains upgrade-plan.json and before/after copies of the 64 KiB header and 64 KiB tail. The plan records partition/installation identity, compressed backup SHA-256 and SHA-256 for every region. The compressed recovery member is unchanged. Wrong-partition images, corrupt backups, v3 images and nonzero legacy tails are rejected.

Deployment is a separate operation. Keep the captured source and original regions, recheck the live partition/geometry and original bytes, apply only the declared regions, flush and verify the complete v3 recovery image before using launcher settings. Two separate region writes are not power-loss atomic; a failed/interrupted deployment requires restoring and verifying the original regions before retrying. The preparation tool makes no on-device completion claim.