#!/usr/bin/env python3
"""Fork helper: build the TB710FU EDL toolchain ZIP with package_edl.py.

Same nine roles and layout as the TB322FC archive; only the identity, the
firehose path (tools/tb710fu/firehose.melf) and the pins change. The pins
match EdlToolchain.cs (client) and EdlDeviceProfiles.cs (TB710FU loader).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import package_edl  # noqa: E402

package_edl.PROFILE_ID = "tb710fu-9008-495"
package_edl.MODEL = "TB710FU"
package_edl.ANDROID_BUILD = "TB710FU/ZUXOS_1.5.04.495_WITHOUT_UBL/EDL/xbl_s_devprg_ns.melf"
package_edl.HARDWARE_ID = "003050E100400000"
package_edl.ROLES = tuple(
    (role, "tools/tb710fu/firehose.melf" if role == "firehose" else arcname)
    for role, arcname in package_edl.ROLES
)
package_edl.PINS = {
    "client": (12014576, "ad3e133f464f8fcdb5f5999bed92b4f7ac415391b10cbe003ca116d0485bebbe"),
    "firehose": (1573224, "ad4689b1c52458250d46829ee46a89ec974e69f8e82eee8d4950427919e0b9eb"),
    "python": (12601679, "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"),
}

if __name__ == "__main__":
    sys.exit(package_edl.main())
