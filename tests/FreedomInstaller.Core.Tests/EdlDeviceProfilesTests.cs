using System;
using System.Collections.Generic;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    /// <summary>
    /// Behavioral contract for the trusted static EDL profile table. All expected values are independent
    /// literals of the frozen API, never read back from production constants.
    /// </summary>
    public class EdlDeviceProfilesTests
    {
        private const string G4ProfileId = "g4-9008-259";
        private const string G4Model = "TB322FC";
        private const string G4Soc = "SM8750";
        private const string G4FullHardwareId = "0028D0E100400000";
        private const string G4DisplayId = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
        private const string G4UserFirmware = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
        private const string G4ArchiveName = "FreedomInstaller.EdlTools.zip";
        private const string G4FirehosePath = "tools/firehose.melf";
        private const long G4FirehoseBytes = 1697740L;
        private const string G4FirehoseSha = "a38993803139d881f47adfa66309f8d5e545c2e33eb4576d0a585afae9cd3da0";

        private const string G5ProfileId = "g5-9008-y7005";
        private const string G5Model = "TB323FU";
        private const string G5Soc = "SM8850";
        private const string G5FullHardwareId = "002B40E100400000";
        private const string G5LoaderSourceBuild = "QCTool-2026.3.21-1/lenovo/devprg_legion-y700-5";
        private const string G5ArchiveName = "FreedomInstaller.EdlTools.G5.zip";
        private const string G5LoaderEntryPath = "tools/g5/qsahara_device_programmer.xml";

        // Synthetic, non-blank actual-firmware value. The live 043 observation is only evidence that a
        // non-blank device build is accepted; no firmware literal is pinned here.
        private const string G5ActualDisplayId = "TB323FU_SYNTHETIC_ACTUAL_FIRMWARE";

        private const string AndroidSerial = "HA1B2C3D4";

        private static readonly (string Role, uint? ImageId, string RelativePath, long Bytes, string Sha256)[]
            G5Materials =
            {
                (
                    "firehose",
                    null,
                    "tools/g5/qsahara_device_programmer.xml",
                    564L,
                    "433749ae084aa0f1b4016b29619b0b0c377d4b2cd22d8a48b423ca6d9cbc83ca"),
                (
                    "image36",
                    36u,
                    "tools/g5/multi_image_qti.mbn",
                    12088L,
                    "a98c7ae167f5d0daf947dc707e3c3679ea438f30ea6ebc510edf15655a14d223"),
                (
                    "image37",
                    37u,
                    "tools/g5/multi_image.mbn",
                    12088L,
                    "9dd679f3b38e59af6a7e22598ed85a1918cad41a0af84eac2c33e1b02d6166f8"),
                (
                    "image21",
                    21u,
                    "tools/g5/xbl_sc.elf",
                    1174496L,
                    "5d277384cac8fb1512562028ca30c67b2314810ad26b2546a6c8653119a056d4"),
                (
                    "image60",
                    60u,
                    "tools/g5/signed_firmware_soc_view.elf",
                    203840L,
                    "dbfdf2602cadb02fe8272abbce55f3f804ad1e98a8481586bf40fa1cbe2960e3"),
                (
                    "image59",
                    59u,
                    "tools/g5/sequencer_ram.elf",
                    4864L,
                    "d7dc67ddd77332e558d14b7acb82bc42e1be66a07786403c96b655f46d019636"),
                (
                    "image61",
                    61u,
                    "tools/g5/tme_config.elf",
                    43760L,
                    "91f17966306617d1a47336ada238865d4faea014a12edc92f08ea79a773e667a"),
                (
                    "image13",
                    13u,
                    "tools/g5/prog_firehose_ddr.elf",
                    315384L,
                    "109338f05b2597b1238f8b724f400f6753a393f6d84c5c534ff36294bbc2da3e"),
                (
                    "image38",
                    38u,
                    "tools/g5/xbl_config_devprg.elf",
                    180928L,
                    "199e60752d9f0db398bbc3524839a627f3ae32ab47fb58b90df124b3e0affbbb")
            };

        // ---------------------------------------------------------------- G4 default

        [Fact]
        public void Default_is_the_exact_g4_static_profile()
        {
            var profile = EdlDeviceProfiles.Default;

            Assert.Equal(G4ProfileId, profile.ProfileId);
            Assert.Equal(G4Model, profile.Model);
            Assert.Equal(G4Soc, profile.Soc);
            Assert.Equal(G4FullHardwareId, profile.FullHardwareId);
            Assert.Equal(new[] { G4DisplayId }, profile.AllowedDisplayIds);
            Assert.Equal(EdlLoaderKind.Single, profile.LoaderKind);
            Assert.Equal(G4FirehosePath, profile.LoaderEntryPath);
            Assert.Equal(G4ArchiveName, profile.ArchiveLogicalName);
            Assert.True(profile.IsComplete);
        }

        [Fact]
        public void Default_carries_the_single_reviewed_firehose_material()
        {
            var material = Assert.Single(EdlDeviceProfiles.Default.Materials);

            Assert.Equal("firehose", material.Role);
            Assert.Equal(13u, material.ImageId.Value);
            Assert.Equal(G4FirehosePath, material.RelativePath);
            Assert.Equal(G4FirehoseBytes, material.Bytes);
            Assert.Equal(G4FirehoseSha, material.Sha256);
        }

        // ---------------------------------------------------------------- G5 static profile

        [Fact]
        public void G5_is_the_complete_static_profile_with_exact_metadata()
        {
            var profile = EdlDeviceProfiles.FindById(G5ProfileId);

            Assert.NotNull(profile);
            Assert.Equal(G5ProfileId, profile!.ProfileId);
            Assert.Equal(G5Model, profile.Model);
            Assert.Equal(G5Soc, profile.Soc);
            Assert.Equal(G5FullHardwareId, profile.FullHardwareId);
            Assert.Equal(new[] { G5LoaderSourceBuild }, profile.AllowedDisplayIds);
            Assert.Equal(EdlLoaderKind.SaharaXml, profile.LoaderKind);
            Assert.Equal(G5LoaderEntryPath, profile.LoaderEntryPath);
            Assert.Equal(G5ArchiveName, profile.ArchiveLogicalName);
            Assert.True(profile.IsComplete);
        }

        [Fact]
        public void G5_is_not_reachable_through_the_old_incomplete_id()
        {
            Assert.Null(EdlDeviceProfiles.FindById("g5-9008-092"));
        }

        [Fact]
        public void G5_materials_are_exactly_the_nine_reviewed_payloads()
        {
            var profile = EdlDeviceProfiles.FindById(G5ProfileId);

            Assert.NotNull(profile);
            Assert.Equal(G5Materials.Length, profile!.Materials.Count);

            for (var index = 0; index < G5Materials.Length; index++)
            {
                var expected = G5Materials[index];
                var actual = profile.Materials[index];

                Assert.Equal(expected.Role, actual.Role);
                Assert.Equal(expected.ImageId, actual.ImageId);
                Assert.Equal(expected.RelativePath, actual.RelativePath);
                Assert.Equal(expected.Bytes, actual.Bytes);
                Assert.Equal(expected.Sha256, actual.Sha256);
            }

            Assert.Null(profile.Materials[0].ImageId);
        }

        // ---------------------------------------------------------------- lookup and immutability

        [Fact]
        public void Models_are_the_two_supported_models_in_order()
        {
            Assert.Equal(new[] { "TB322FC", "TB323FU" }, EdlDeviceProfiles.Models);
        }

        [Fact]
        public void FindById_is_exact_ordinal()
        {
            Assert.Same(EdlDeviceProfiles.Default, EdlDeviceProfiles.FindById(G4ProfileId));
            Assert.Equal(G5ProfileId, EdlDeviceProfiles.FindById(G5ProfileId)!.ProfileId);

            Assert.Null(EdlDeviceProfiles.FindById(null));
            Assert.Null(EdlDeviceProfiles.FindById(string.Empty));
            Assert.Null(EdlDeviceProfiles.FindById("g4-9008-999"));
            Assert.Null(EdlDeviceProfiles.FindById("G4-9008-259"));
            Assert.Null(EdlDeviceProfiles.FindById(" " + G4ProfileId));
        }

        [Fact]
        public void FindByModel_is_canonical_ignore_case_only()
        {
            Assert.Same(EdlDeviceProfiles.Default, EdlDeviceProfiles.FindByModel(G4Model));
            Assert.Same(EdlDeviceProfiles.Default, EdlDeviceProfiles.FindByModel("tb322fc"));
            Assert.Equal(G5ProfileId, EdlDeviceProfiles.FindByModel("tb323fu")!.ProfileId);

            Assert.Null(EdlDeviceProfiles.FindByModel(null));
            Assert.Null(EdlDeviceProfiles.FindByModel(string.Empty));
            Assert.Null(EdlDeviceProfiles.FindByModel("TB322F"));
            Assert.Null(EdlDeviceProfiles.FindByModel("TB322FCX"));
            Assert.Null(EdlDeviceProfiles.FindByModel(" " + G4Model));
        }

        [Fact]
        public void Collections_are_read_only_wrappers()
        {
            var allowed = Assert.IsAssignableFrom<IList<string>>(EdlDeviceProfiles.Default.AllowedDisplayIds);
            var materials = Assert.IsAssignableFrom<IList<EdlLoaderMaterial>>(EdlDeviceProfiles.Default.Materials);
            var models = Assert.IsAssignableFrom<IList<string>>(EdlDeviceProfiles.Models);

            Assert.Throws<NotSupportedException>(() => allowed.Add("TB322FC_EXTRA"));
            Assert.Throws<NotSupportedException>(() => materials.Clear());
            Assert.Throws<NotSupportedException>(() => models.Add("TB999XX"));
        }

        // ---------------------------------------------------------------- identity gate

        [Fact]
        public void SupportsIdentity_accepts_the_exact_complete_g4_identity()
        {
            Assert.True(EdlDeviceProfiles.Default.SupportsIdentity(Android(G4Model, G4DisplayId)));
        }

        [Fact]
        public void FW01_Profile_accepts_actual_firmware_without_changing_loader_provenance()
        {
            Assert.True(EdlDeviceProfiles.Default.SupportsIdentity(Android(G4Model, G4UserFirmware)));

            Assert.Equal(G4ProfileId, EdlDeviceProfiles.Default.ProfileId);
            Assert.Equal(new[] { G4DisplayId }, EdlDeviceProfiles.Default.AllowedDisplayIds);
            Assert.DoesNotContain(G4UserFirmware, EdlDeviceProfiles.Default.AllowedDisplayIds);
        }

        [Theory]
        [InlineData("TB322F", G4DisplayId)]
        [InlineData("TB322FCX", G4DisplayId)]
        [InlineData("tb322fc", G4DisplayId)]
        [InlineData(G4Model + " ", G4DisplayId)]
        [InlineData("TB323FU", G4DisplayId)]
        [InlineData(G4Model, " ")]
        [InlineData(G4Model, "\t")]
        [InlineData(G4Model, "")]
        public void SupportsIdentity_rejects_non_exact_identity(string model, string displayId)
        {
            Assert.False(EdlDeviceProfiles.Default.SupportsIdentity(Android(model, displayId)));
        }

        [Fact]
        public void SupportsIdentity_is_false_without_a_firmware_snapshot()
        {
            var identity = new DeviceIdentity(AndroidSerial, G4Model, BootloaderState.Unknown);

            Assert.False(EdlDeviceProfiles.Default.SupportsIdentity(identity));
        }

        [Fact]
        public void G5_SupportsIdentity_accepts_the_actual_model_with_nonblank_firmware()
        {
            var profile = EdlDeviceProfiles.FindByModel(G5Model);

            Assert.NotNull(profile);
            Assert.True(profile!.IsComplete);
            Assert.True(profile.SupportsIdentity(Android(G5Model, G5ActualDisplayId)));
        }

        [Theory]
        [InlineData(G4Model)]
        [InlineData("TB323F")]
        [InlineData("TB323FUX")]
        [InlineData("tb323fu")]
        [InlineData(G5Model + " ")]
        public void G5_SupportsIdentity_rejects_wrong_or_noncanonical_model(string model)
        {
            var profile = EdlDeviceProfiles.FindByModel(G5Model);

            Assert.NotNull(profile);
            Assert.False(profile!.SupportsIdentity(Android(model, G5ActualDisplayId)));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("\t")]
        public void G5_SupportsIdentity_rejects_blank_actual_firmware(string displayId)
        {
            var profile = EdlDeviceProfiles.FindByModel(G5Model);

            Assert.NotNull(profile);
            Assert.False(profile!.SupportsIdentity(Android(G5Model, displayId)));
        }

        [Fact]
        public void RequireComplete_succeeds_for_both_complete_builtin_profiles()
        {
            EdlDeviceProfiles.Default.RequireComplete();

            var g5 = EdlDeviceProfiles.FindById(G5ProfileId);
            Assert.NotNull(g5);

            g5!.RequireComplete();
            Assert.True(g5.IsComplete);
        }

        private static DeviceIdentity Android(string model, string? displayId) =>
            new(AndroidSerial, model, BootloaderState.Unknown)
            {
                Firmware = displayId == null
                    ? null
                    : new FirmwareSnapshot(displayId, "google/fingerprint", "16", "2026-06-01", BootloaderState.Unknown),
            };
    }
}
