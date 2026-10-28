#!/bin/sh
# MB005/a2 fixed RAM launcher. No arguments, no configurable paths.
# Every external command outside the chroot uses an explicit busybox prefix;
# only shell builtins (printf/test/[ /case/set/read/wait/kill/umask/unset) are
# invoked bare. /usr/bin/env is resolved inside the original toolbox chroot.
# Assets were already SHA-verified and usb0+DHCP already configured by C#.
# This script only: prove RAM filesystems, check inputs, create root,
# unzip pinned toolbox, bind mount, stage helper files, start helper.
set -eu
umask 077

incoming=/tmp/freedom-maintenance/incoming
toolbox=$incoming/installer-toolbox198.tar.gz
helper=$incoming/armada_uninstall.py
avb=$incoming/avb_stock.py
token=$incoming/token
root=/tmp/armada-installer-tools
run=/run/freedom-maintenance

fail() {
	printf 'MB005-BOOTSTRAP-FAIL %s\n' "$1" >&2
	exit 1
}

check_input() {
	[ ! -h "$1" ] || fail "$2_LINK"
	[ -f "$1" ] || fail "$2_MISSING"
	[ -r "$1" ] || fail "$2_UNREADABLE"
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

[ -d "$incoming" ] || fail E_INCOMING_MISSING
[ ! -h "$incoming" ] || fail E_INCOMING_LINK
check_input "$toolbox" E_TOOLBOX
check_input "$helper" E_HELPER
check_input "$avb" E_AVB
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

[ ! -e "$root" ] || fail E_ROOT_EXISTS
[ ! -h "$root" ] || fail E_ROOT_LINK
[ ! -e "$run/helper.pid" ] || fail E_PID_MARKER
[ ! -h "$run/helper.pid" ] || fail E_PID_MARKER_LINK
[ ! -e "$run/launcher.lock" ] || fail E_LOCK

busybox mkdir -p "$run" || fail E_RUN_MKDIR
busybox mkdir "$run/launcher.lock" || fail E_LOCK
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

idir=$root/tmp/freedom-maintenance
busybox mkdir -p "$idir" || fail E_INSIDE_MKDIR

busybox cp "$helper" "$idir/armada_uninstall.py" || fail E_COPY_HELPER
busybox cp "$avb" "$idir/avb_stock.py" || fail E_COPY_AVB
busybox cp "$token" "$idir/token" || fail E_COPY_TOKEN
busybox chmod 600 "$idir/token" || fail E_CHMOD_TOKEN
busybox chmod 644 "$idir/armada_uninstall.py" "$idir/avb_stock.py" || fail E_CHMOD_FILES
busybox mkdir "$idir/state" || fail E_STATE_DIR

busybox nohup busybox chroot "$root" /usr/bin/env -i \
	PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
	/usr/bin/python3 /tmp/freedom-maintenance/armada_uninstall.py serve \
	--bind 192.168.77.1 --port 8202 \
	--token-file /tmp/freedom-maintenance/token \
	--state-dir /tmp/freedom-maintenance/state \
	</dev/null >"$idir/helper.log" 2>&1 &
hpid=$!
[ -n "$hpid" ] || fail E_SPAWN

( set -C; printf '%s\n' "$hpid" >"$run/helper.pid" ) 2>/dev/null || fail E_PID_WRITE

busybox sleep 1
kill -0 "$hpid" 2>/dev/null || fail E_HELPER_EXITED

printf 'FREEDOM_MAINT_HELPER_STARTED\n'
