#!/bin/sh
# RH001/a2 fixed RAM install bootstrap. No arguments, no configurable paths.
# Every external command outside the chroot uses an explicit busybox prefix;
# only shell builtins (printf/test/[ /case/set) are invoked bare.
# The toolbox and the install-support archive were already SHA-verified and
# usb0+DHCP already configured by C#. This script only: prove RAM filesystems,
# check the fixed inputs, create the fixed root, extract the pinned toolbox
# exactly once, bind mount, and stage the canonical install files. It never
# starts a helper, server or background job, never mounts target partitions and
# never writes GPT/Android/boot.
set -eu
umask 077

incoming=/tmp/freedom-maintenance/incoming
toolbox=$incoming/installer-toolbox198.tar.gz
support=$incoming/install-support
token=$incoming/token
root=/tmp/armada-installer-tools
run=/run/freedom-maintenance

fail() {
	printf 'RH001-INSTALL-BOOTSTRAP-FAIL %s\n' "$1" >&2
	exit 1
}

check_input() {
	[ ! -h "$1" ] || fail "$2_LINK"
	[ -f "$1" ] || fail "$2_MISSING"
	[ -r "$1" ] || fail "$2_UNREADABLE"
}

check_dir() {
	[ ! -h "$1" ] || fail "$2_LINK"
	[ -d "$1" ] || fail "$2_MISSING"
}

check_ram_fs() {
	fs=$(busybox stat -f -c %T "$1" 2>/dev/null) || fail "$2_STATFS"
	case $fs in
	rootfs | ramfs | tmpfs) ;;
	*) fail "$2_TYPE" ;;
	esac
}

[ "$#" -eq 0 ] || fail E_ARGS

check_ram_fs / E_FS_ROOT
check_ram_fs /tmp E_FS_TMP
check_ram_fs /run E_FS_RUN

check_dir "$incoming" E_INCOMING
check_input "$toolbox" E_TOOLBOX
check_dir "$support" E_SUPPORT
check_input "$support/install_bootstrap.sh" E_SUPPORT_LAUNCHER
check_input "$support/armada_install.py" E_SUPPORT_HELPER
check_input "$support/armada-installer" E_SUPPORT_CANONICAL
check_input "$support/kshim-build-boot.py" E_SUPPORT_KSHIM_BUILD
check_input "$support/kshim_slot_material.py" E_SUPPORT_KSHIM_MATERIAL
check_dir "$support/tools" E_SUPPORT_TOOLS

# The support archive carries these seven fixed tool files. "7packtools" was only a descriptive
# name; each real file is checked as a regular, readable, non-link input.
for tool in \
	MultiBootKernelPatcher \
	UnpackTool \
	repack_boot_v4.py \
	avbtool.py \
	dtc \
	fdtget \
	fdtput; do
	check_input "$support/tools/$tool" "E_TOOL_$tool"
done

check_input "$token" E_TOKEN

bytes=$(( $(busybox wc -c <"$token") ))
[ "$bytes" -eq 64 ] || fail E_TOKEN_SIZE
tok=$(busybox cat "$token")
case $tok in
*[!0123456789abcdef]*) fail E_TOKEN_CHARSET ;;
esac
[ "${#tok}" -eq 64 ] || fail E_TOKEN_LENGTH
tok=
unset tok

# A prior fixed root or prior install state means this is not a fresh RAM session.
[ ! -e "$root" ] || fail E_ROOT_EXISTS
[ ! -h "$root" ] || fail E_ROOT_LINK
[ ! -e "$run/install.lock" ] || fail E_LOCK
[ ! -h "$run/install.lock" ] || fail E_LOCK_LINK

busybox mkdir -p "$run" || fail E_RUN_MKDIR
busybox mkdir "$run/install.lock" || fail E_LOCK
busybox mkdir "$root" || fail E_ROOT_CREATE

busybox tar -xzf "$toolbox" -C "$root" || fail E_EXTRACT
[ -f "$root/usr/bin/python3" ] || fail E_PYTHON_MISSING

for d in dev proc sys run tmp; do
	busybox mkdir -p "$root/$d" || fail E_PREP_DIR
done
[ ! -h "$root/tmp" ] || fail E_ROOT_TMP_LINK
[ -d "$root/tmp" ] || fail E_ROOT_TMP

busybox mount -o bind "$root" "$root" || fail E_MOUNT_SELF
busybox mount -o rbind /dev "$root/dev" || fail E_MOUNT_DEV
busybox mount -o bind /proc "$root/proc" || fail E_MOUNT_PROC
busybox mount -o bind /sys "$root/sys" || fail E_MOUNT_SYS
busybox mount -o bind /run "$root/run" || fail E_MOUNT_RUN

# Fixed stage directory inside the chroot: /tmp/freedom-install.
idir=$root/tmp/freedom-install
busybox mkdir -p "$idir" || fail E_INSIDE_MKDIR

# The two canonical kshim Python siblings are staged next to the helper for a later explicit
# python3 invocation; this launcher never executes them.
busybox cp "$support/armada_install.py" "$idir/armada_install.py" || fail E_COPY_HELPER
busybox cp "$support/armada-installer" "$idir/armada-installer" || fail E_COPY_CANONICAL
busybox cp "$support/kshim-build-boot.py" "$idir/kshim-build-boot.py" || fail E_COPY_KSHIM_BUILD
busybox cp "$support/kshim_slot_material.py" "$idir/kshim_slot_material.py" || fail E_COPY_KSHIM_MATERIAL
busybox cp "$token" "$idir/token" || fail E_COPY_TOKEN
busybox chmod 644 "$idir/armada_install.py" || fail E_CHMOD_HELPER
busybox chmod 755 "$idir/armada-installer" || fail E_CHMOD_CANONICAL
busybox chmod 644 "$idir/kshim-build-boot.py" "$idir/kshim_slot_material.py" || fail E_CHMOD_KSHIM
busybox chmod 600 "$idir/token" || fail E_CHMOD_TOKEN

# Fixed tool directory inside the chroot: /tmp/freedom-install/tools (never /tools). Only the seven
# literal files are copied; nothing is downloaded and no tool is executed here. The root builder
# invokes them by explicit path, and the future CLI PATH starts with this directory.
tools=$idir/tools
busybox mkdir -p "$tools" || fail E_TOOLS_MKDIR
for tool in \
	MultiBootKernelPatcher \
	UnpackTool \
	repack_boot_v4.py \
	avbtool.py \
	dtc \
	fdtget \
	fdtput; do
	busybox cp "$support/tools/$tool" "$tools/$tool" || fail "E_COPY_TOOL_$tool"
done

# Binaries are executable 0755; the two Python scripts stay readable 0644 because they are only
# used through an explicit python3.
busybox chmod 755 \
	"$tools/MultiBootKernelPatcher" \
	"$tools/UnpackTool" \
	"$tools/dtc" \
	"$tools/fdtget" \
	"$tools/fdtput" || fail E_CHMOD_BINARIES
busybox chmod 644 "$tools/repack_boot_v4.py" "$tools/avbtool.py" || fail E_CHMOD_SCRIPTS

# The optional support lib directory must be a real non-link directory; its fixed contents are
# staged at /tmp/freedom-install/lib inside the chroot. No other path is consulted.
if [ -e "$support/lib" ] || [ -h "$support/lib" ]; then
	check_dir "$support/lib" E_SUPPORT_LIB
	busybox mkdir -p "$idir/lib" || fail E_LIB_MKDIR
	busybox cp -a "$support/lib/." "$idir/lib/" || fail E_LIB_COPY
fi

# request.json and state/ are deliberately not created here: the install helper owns them.
printf 'FREEDOM_INSTALL_BOOTSTRAP_READY\n'
