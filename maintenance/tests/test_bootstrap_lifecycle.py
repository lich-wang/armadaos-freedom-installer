#!/usr/bin/env python3
"""TF bootstrap cleanup.sh lifecycle harness (TF-RAM-BOOTSTRAP-TEST-01).

Executes the ACTUAL generated cleanup.sh with the ACTUAL public ARM64 BusyBox
inside the CI disposable Docker container only. Stdlib only.

Required environment (checked before anything else):
  TF_BOOTSTRAP_CONTAINER_TEST=1   plus /.dockerenv present
  TF_BOOTSTRAP_FIXTURE_EXPORT_DIR existing dir with launcher.sh / cleanup.sh
                                  exported by the C# test
  TF_BOOTSTRAP_REAL_BUSYBOX       existing executable real BusyBox
  TF_BOOTSTRAP_TEST_WORK          own fresh /evidence subdirectory

Nine runtime cases exercise the actual shell: syntax check (sh -n), ownership
guards, foreign/own process handling, umount success/failure loops and the
residual mount guard. Cases 7-9 need CAP_SYS_ADMIN (explicit root approval);
without it they are reported BLOCKED, never passed or skipped silently.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

CONTAINER_TEST = os.environ.get("TF_BOOTSTRAP_CONTAINER_TEST") == "1"
IN_CONTAINER = os.path.exists("/.dockerenv")

SUPPORT_DIR = "/tmp/freedom-maintenance/incoming/tf-support"
STATE_DIR = "/run/freedom-maintenance"
TOOLS_DIR = "/tmp/armada-tf-tools"
RUN_DIR = "/run/freedom-tf"
FIXED_DIRS = (SUPPORT_DIR, RUN_DIR, TOOLS_DIR)
HELPER_PID = STATE_DIR + "/tf-helper.pid"
DHCP_PID = STATE_DIR + "/udhcpd.pid"
CREATED_MARKER = STATE_DIR + "/tf-created"
SUCCESS_MARKER = "FREEDOM_TF_CLEANUP_V1_OK"
HELPER_CMDLINE = "/usr/bin/python3 /tmp/freedom-tf/armada_tf.py serve"
DHCP_CONF = "/tmp/freedom-maintenance/udhcpd.conf"
MOUNTINFO = "/proc/self/mountinfo"
OUTSIDE_SENTINEL = "/tmp/freedom-tf-harness-outside-sentinel"


def fail_fast_env():
    if not CONTAINER_TEST or not IN_CONTAINER:
        print("refusing to run outside the CI disposable container", file=sys.stderr)
        return False
    for name in ("TF_BOOTSTRAP_FIXTURE_EXPORT_DIR", "TF_BOOTSTRAP_REAL_BUSYBOX",
                 "TF_BOOTSTRAP_TEST_WORK"):
        value = os.environ.get(name)
        if not value:
            print("missing required env %s" % name, file=sys.stderr)
            return False
    work = os.environ["TF_BOOTSTRAP_TEST_WORK"]
    if os.path.commonpath([os.path.realpath(work), "/evidence"]) != "/evidence":
        print("TF_BOOTSTRAP_TEST_WORK must be beneath /evidence", file=sys.stderr)
        return False
    busybox = os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"]
    if not (os.path.isfile(busybox) and os.access(busybox, os.X_OK)):
        print("TF_BOOTSTRAP_REAL_BUSYBOX must be an existing executable", file=sys.stderr)
        return False
    export = os.environ["TF_BOOTSTRAP_FIXTURE_EXPORT_DIR"]
    for name in ("launcher.sh", "cleanup.sh"):
        if not os.path.isfile(os.path.join(export, name)):
            print("missing exported fixture %s" % name, file=sys.stderr)
            return False
    return True


class Shim:
    """PATH shim named busybox: delegates every call to the real BusyBox via
    exec, except the two explicit injection modes configured per case. Never
    fakes /proc, pid identity, mountinfo, file tests or a successful Ready."""

    def __init__(self, bin_dir, real_busybox):
        self.bin_dir = bin_dir
        self.real = real_busybox
        self.trace = []
        self.fail_kill_pid = None      # case 6: nonzero for non-probe kill of this pid
        self.fail_umount_target = None  # case 7: nonzero for umount of this target
        self.ack_umount_target = None  # case 9: exit 0 WITHOUT performing the umount
        self.script = os.path.join(bin_dir, "busybox")

    def write(self):
        body = r'''#!/bin/sh
trace="$TF_SHIM_TRACE"
printf '%s\n' "$*" >> "$trace"
applet="$1"; shift
case "$applet" in
  kill)
    # probe (kill -0) always delegates to the real BusyBox
    if [ "${1:-}" != "-0" ] && [ -n "$TF_FAIL_KILL_PID" ] && [ "$1" = "$TF_FAIL_KILL_PID" ]; then
      exit 111
    fi
    ;;
  umount)
    if [ -n "$TF_ACK_UMOUNT_TARGET" ] && [ "$1" = "$TF_ACK_UMOUNT_TARGET" ]; then
      exit 0
    fi
    if [ -n "$TF_FAIL_UMOUNT_TARGET" ] && [ "$1" = "$TF_FAIL_UMOUNT_TARGET" ]; then
      exit 112
    fi
    ;;
esac
exec "$TF_REAL_BUSYBOX" "$applet" "$@"
'''
        with open(self.script, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(self.script, 0o755)

    def env(self):
        environment = dict(os.environ)
        environment.update({
            "TF_SHIM_TRACE": os.path.join(self.bin_dir, "trace.log"),
            "TF_REAL_BUSYBOX": self.real,
            "TF_FAIL_KILL_PID": self.fail_kill_pid or "",
            "TF_FAIL_UMOUNT_TARGET": self.fail_umount_target or "",
            "TF_ACK_UMOUNT_TARGET": self.ack_umount_target or "",
        })
        return environment

    def read_trace(self):
        path = os.path.join(self.bin_dir, "trace.log")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().splitlines()
        except FileNotFoundError:
            return []


class Process:
    """Tracks one fixture child by exact (pid, start time) identity."""

    def __init__(self, child):
        self.child = child
        self.pid = child.pid
        self.start = self._start_time(self.pid)

    @staticmethod
    def _start_time(pid):
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
        return fields[19]  # starttime, 22nd field

    def alive(self):
        if self.child.poll() is not None:
            return False
        try:
            return self._start_time(self.pid) == self.start
        except (FileNotFoundError, ProcessLookupError, IndexError):
            return False

    def reap(self):
        if self.alive():
            try:
                os.kill(self.pid, 9)
            except ProcessLookupError:
                pass
        try:
            code = self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise AssertionError("fixture pid %d could not be reaped" % self.pid)
        if code != 0:
            print("TEARDOWN: fixture pid %d exited with %r" % (self.pid, code),
                  file=sys.stderr)


def start_sleeper(args):
    return Process(subprocess.Popen(args))


def mounts():
    with open(MOUNTINFO, "r", encoding="utf-8") as handle:
        return [line.split()[4] for line in handle if line.strip()]


def subtree_mounted(target):
    return any(m == target or m.startswith(target + "/") for m in mounts())


def write_marker_record(created_lines):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(CREATED_MARKER, "w", encoding="utf-8") as handle:
        handle.write("\n".join(created_lines) + "\n")


def reject_preexisting():
    """Fail before setup if any fixed path or its parent chain is unexpectedly
    preexisting with wrong ownership; the harness must own everything it touches."""
    problems = []
    for path in FIXED_DIRS:
        if os.path.lexists(path):
            problems.append("preexisting fixed path %s" % path)
    for path in (STATE_DIR, os.path.dirname(SUPPORT_DIR), "/tmp/freedom-tf"):
        if os.path.lexists(path) and os.stat(path).st_uid != 0:
            problems.append("unexpected non-root owner on %s" % path)
    if os.path.lexists(HELPER_PID) or os.path.lexists(DHCP_PID) or os.path.lexists(CREATED_MARKER):
        problems.append("preexisting pid/marker records in %s" % STATE_DIR)
    if problems:
        raise AssertionError("; ".join(problems))


class LifecycleCase(unittest.TestCase):
    """Base: one fresh fixture per case, strict teardown ordering."""

    def setUp(self):
        if not fail_fast_env():
            raise AssertionError("refusing to run outside the CI disposable container")
        reject_preexisting()
        self.work = tempfile.mkdtemp(dir=os.environ["TF_BOOTSTRAP_TEST_WORK"], prefix="case-")
        self.bin_dir = os.path.join(self.work, "bin")
        os.makedirs(self.bin_dir)
        self.shim = Shim(self.bin_dir, os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"])
        self.shim.write()
        self.environment = self.shim.env()
        self.environment["PATH"] = self.bin_dir + ":" + self.environment.get("PATH", "")
        self.processes = []
        self.mount_targets = []  # own mount targets, innermost first
        self.export = os.environ["TF_BOOTSTRAP_FIXTURE_EXPORT_DIR"]
        self.cleanup_sh = os.path.join(self.export, "cleanup.sh")
        self.launcher_sh = os.path.join(self.export, "launcher.sh")

    def run_cleanup(self):
        environment = self.shim.env()
        environment["PATH"] = self.bin_dir + ":" + environment.get("PATH", "")
        result = subprocess.run(
            [os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"], "sh", self.cleanup_sh],
            env=environment, capture_output=True, text=True, timeout=120)
        # capture evidence immediately, before any later assertion or teardown
        # unmount failure can lose it
        with open(os.path.join(self.work, "cleanup-out.log"), "w", encoding="utf-8") as out:
            out.write(result.stdout)
        with open(os.path.join(self.work, "cleanup-err.log"), "w", encoding="utf-8") as err:
            err.write(result.stderr)
        with open(os.path.join(self.work, "cleanup-exit.txt"), "w", encoding="utf-8") as code:
            code.write("%d\n" % result.returncode)
        self.last_cleanup_result = result
        return result

    def make_dirs(self):
        for path in (os.path.dirname(SUPPORT_DIR), STATE_DIR, RUN_DIR, TOOLS_DIR):
            os.makedirs(path, exist_ok=True)
        with open(OUTSIDE_SENTINEL, "w", encoding="utf-8") as handle:
            handle.write("outside\n")
        os.makedirs(SUPPORT_DIR + "/tools/run", exist_ok=True)

    def remove_dirs(self):
        for path in (SUPPORT_DIR, RUN_DIR, TOOLS_DIR, "/tmp/freedom-tf", STATE_DIR,
                     os.path.dirname(SUPPORT_DIR)):
            if os.path.islink(path):
                os.unlink(path)  # never traverse a fixture symlink
            elif os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.lexists(path):
                os.unlink(path)
        try:
            os.unlink(OUTSIDE_SENTINEL)
        except FileNotFoundError:
            pass

    def unmount_own_targets(self):
        failures = []
        for target in reversed(self.mount_targets):
            # a successful production cleanup already unmounted its own targets;
            # only attempt targets still present in REAL mountinfo
            if target not in mounts():
                continue
            done = subprocess.run(
                [os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"], "umount", target],
                capture_output=True, text=True)
            if done.returncode != 0:
                failures.append((target, done.returncode, done.stderr))
        if failures:
            raise AssertionError("teardown umount failures: %r" % (failures,))

    def tearDown(self):
        # 1) reap only exact tracked fixture processes
        for proc in self.processes:
            proc.reap()
        # 2) unmount own known targets in reverse creation order; the list is
        #    retained until real mountinfo proves every target is gone.
        self.unmount_own_targets()
        residual = [t for t in self.mount_targets if subtree_mounted(t)]
        if residual:
            raise AssertionError(
                "TEARDOWN FAILURE: residual mounts %r; fixture trees, marker and "
                "work evidence kept untouched" % residual)
        # 3) nothing of ours remains mounted: delete fixture trees;
        #    a symlink is always unlinked, never traversed.
        self.remove_dirs()
        # 4) self.work is CI evidence and is never removed by the harness;
        #    cleanup evidence is captured immediately in run_cleanup.

    # --- shared assertions -------------------------------------------------

    def assert_all_dirs_gone_except_outside(self):
        for path in (SUPPORT_DIR, RUN_DIR, TOOLS_DIR):
            self.assertFalse(os.path.lexists(path), path)
        for path in (HELPER_PID, DHCP_PID, CREATED_MARKER):
            self.assertFalse(os.path.lexists(path), path)
        self.assertTrue(os.path.isfile(OUTSIDE_SENTINEL))

    def assert_all_dirs_and_records_present(self):
        for path in FIXED_DIRS:
            self.assertTrue(os.path.lexists(path), path)
        self.assertTrue(os.path.lexists(CREATED_MARKER))


class SyntaxAndCase1(LifecycleCase):

    def test_01_no_processes_cleanup_succeeds_and_removes_own_dirs(self):
        for path in (self.launcher_sh, self.cleanup_sh):
            checked = subprocess.run(
                [os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"], "sh", "-n", path],
                capture_output=True, text=True)
            self.assertEqual(0, checked.returncode, checked.stderr)
        self.make_dirs()
        write_marker_record(["tf-support", "run", "tools"])
        result = self.run_cleanup()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, result.stdout.count(SUCCESS_MARKER))
        self.assert_all_dirs_gone_except_outside()
        # its own helper/created records are gone; nothing else was touched
        self.assertFalse(subtree_mounted(TOOLS_DIR))


class SymlinkGuardCases(LifecycleCase):
    """Cases 2-4: a symlinked fixed path must stop cleanup before any
    non-probe kill, umount or rm. The teardown unlinks the link itself."""

    def guard_case(self, link_path, created_lines):
        self.make_dirs()
        # replace exactly one fixed dir with a symlink to an owned sentinel
        # beneath self.work; the sentinel file content is asserted post-failure.
        target = os.path.join(self.work, "link-target")
        os.makedirs(target, exist_ok=True)
        sentinel = os.path.join(target, "sentinel")
        with open(sentinel, "w", encoding="utf-8") as handle:
            handle.write("harness-link-target-sentinel\n")
        if os.path.isdir(link_path):
            shutil.rmtree(link_path)
        os.symlink(target, link_path)
        self.assertTrue(os.path.islink(link_path))
        write_marker_record(created_lines)
        result = self.run_cleanup()
        self.assertNotEqual(0, result.returncode)
        # link, target dir and exact sentinel content remain
        self.assertTrue(os.path.islink(link_path))
        self.assertTrue(os.path.isdir(target))
        with open(sentinel, "r", encoding="utf-8") as handle:
            self.assertEqual("harness-link-target-sentinel\n", handle.read())
        self.assertTrue(os.path.lexists(CREATED_MARKER))
        trace = self.shim.read_trace()
        self.assertFalse(any(t.startswith("umount") for t in trace), trace)
        self.assertFalse(any(t.startswith("rm") for t in trace), trace)
        self.assertFalse(any(t.startswith("kill") and not t.startswith("kill -0")
                             for t in trace), trace)

    def test_02_support_symlink_stops_cleanup(self):
        self.guard_case(SUPPORT_DIR, ["tf-support", "run", "tools"])

    def test_03_run_symlink_stops_cleanup(self):
        self.guard_case(RUN_DIR, ["tf-support", "run", "tools"])

    def test_04_tools_symlink_stops_cleanup(self):
        self.guard_case(TOOLS_DIR, ["tf-support", "run", "tools"])


class ProcessGuardCases(LifecycleCase):

    def test_05_foreign_helper_pid_stops_cleanup_and_process_survives(self):
        self.make_dirs()
        proc = start_sleeper([sys.executable, "-c", "import time; time.sleep(300)"])
        self.processes.append(proc)
        with open(HELPER_PID, "w", encoding="utf-8") as handle:
            handle.write("%d\n" % proc.pid)
        write_marker_record(["tf-support", "run", "tools"])
        # real /proc identity differs from the production helper identity
        with open("/proc/%d/cmdline" % proc.pid, "rb") as handle:
            self.assertNotIn(b"armada_tf.py", handle.read())
        self.assertNotEqual(TOOLS_DIR, os.readlink("/proc/%d/root" % proc.pid)
                            if os.path.islink("/proc/%d/root" % proc.pid) else "")
        result = self.run_cleanup()
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(proc.alive())
        self.assert_all_dirs_and_records_present()
        self.assertFalse(subtree_mounted(TOOLS_DIR))
        trace = self.shim.read_trace()
        self.assertFalse(any(t.startswith("umount") for t in trace), trace)
        self.assertFalse(any(t.startswith("rm") for t in trace), trace)
        self.assertFalse(any(t.startswith("kill") and not t.startswith("kill -0")
                             for t in trace), trace)

    def test_06_owned_dhcp_argv_with_failed_stop_stops_cleanup(self):
        self.make_dirs()
        script = os.path.join(self.work, "udhcpd")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("import time; time.sleep(300)\n")
        os.chmod(script, 0o755)
        proc = start_sleeper([sys.executable, script, DHCP_CONF])
        self.processes.append(proc)
        expected_argv = os.path.basename(script).encode() + b"\0" + DHCP_CONF.encode()
        argv = b""
        deadline = time.monotonic() + 5.0
        while proc.alive() and time.monotonic() < deadline:
            with open("/proc/%d/cmdline" % proc.pid, "rb") as handle:
                argv = handle.read()
            if expected_argv in argv:
                break
            time.sleep(0.01)
        self.assertIn(expected_argv, argv)
        self.assertTrue(proc.alive())
        with open(DHCP_PID, "w", encoding="utf-8") as handle:
            handle.write("%d\n" % proc.pid)
        write_marker_record(["tf-support", "run", "tools"])
        # kill-0 probes delegate to the real BusyBox; only the real stop fails
        self.shim.fail_kill_pid = str(proc.pid)
        result = self.run_cleanup()
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(proc.alive())
        self.assert_all_dirs_and_records_present()
        self.assertFalse(subtree_mounted(TOOLS_DIR))
        trace = self.shim.read_trace()
        self.assertFalse(any(t.startswith("umount") for t in trace), trace)
        self.assertFalse(any(t.startswith("rm") for t in trace), trace)


def have_cap_sys_admin():
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return (int(line.split()[1], 16) >> 21) & 1 == 1
    except OSError:
        pass
    return False


def mount_owned_tmpfs(target):
    os.makedirs(target, exist_ok=True)
    done = subprocess.run(
        [os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"], "mount", "-t", "tmpfs", "tmpfs", target],
        capture_output=True, text=True)
    if done.returncode != 0:
        raise AssertionError("own tmpfs mount denied at %s: %s" % (target, done.stderr))


class MountCases(LifecycleCase):

    def setUp(self):
        super().setUp()
        if not have_cap_sys_admin():
            raise AssertionError(
                "BLOCKED: CAP_SYS_ADMIN not root-approved; mount cases must "
                "fail/blocked, never pass or skip")

    def test_07_mounted_tools_with_failed_umount_stops_cleanup(self):
        self.make_dirs()
        target = TOOLS_DIR + "/dev"
        mount_owned_tmpfs(target)
        self.mount_targets.append(target)
        self.assertIn(target, mounts())
        write_marker_record(["tf-support", "run", "tools"])
        self.shim.fail_umount_target = target
        result = self.run_cleanup()
        self.assertNotEqual(0, result.returncode)
        self.assertIn(target, mounts())
        self.assert_all_dirs_and_records_present()
        trace = self.shim.read_trace()
        self.assertFalse(any(t.startswith("rm") for t in trace), trace)

    def test_08_nested_own_mounts_cleanup_unmounts_child_then_parent(self):
        self.make_dirs()
        child = TOOLS_DIR + "/dev"
        # own bind mount of tools onto itself first (parent), then the child
        # tmpfs on top; cleanup must unmount child before parent.
        parent_done = subprocess.run(
            [os.environ["TF_BOOTSTRAP_REAL_BUSYBOX"], "mount", "--bind", TOOLS_DIR, TOOLS_DIR],
            capture_output=True, text=True)
        self.assertEqual(0, parent_done.returncode, parent_done.stderr)
        self.mount_targets.append(TOOLS_DIR)
        mount_owned_tmpfs(child)
        self.mount_targets.append(child)
        self.assertTrue(subtree_mounted(TOOLS_DIR))
        write_marker_record(["tf-support", "run", "tools"])
        result = self.run_cleanup()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(SUCCESS_MARKER, result.stdout)
        self.assertFalse(subtree_mounted(TOOLS_DIR))
        self.assert_all_dirs_gone_except_outside()
        trace = self.shim.read_trace()
        umounts = [t for t in trace if t.startswith("umount")]
        self.assertGreaterEqual(len(umounts), 2, trace)
        first_rm = next((i for i, t in enumerate(trace) if t.startswith("rm")), len(trace))
        # exact trace lines, computed in the FULL trace list; "TOOLS_DIR in t"
        # would also match the child line and yield child==parent
        child_umount = next((i for i, t in enumerate(trace) if t == "umount " + child), None)
        parent_umount = next((i for i, t in enumerate(trace) if t == "umount " + TOOLS_DIR), None)
        self.assertIsNotNone(child_umount, trace)
        self.assertIsNotNone(parent_umount, trace)
        self.assertLess(child_umount, parent_umount, trace)
        self.assertLess(parent_umount, first_rm, trace)

    def test_09_residual_mount_guard_reaches_final_rejection(self):
        self.make_dirs()
        target = TOOLS_DIR + "/dev"
        mount_owned_tmpfs(target)
        self.mount_targets.append(target)
        write_marker_record(["tf-support", "run", "tools"])
        # shim ACKs the exact umount with exit 0 without performing it
        self.shim.ack_umount_target = target
        result = self.run_cleanup()
        self.assertNotEqual(0, result.returncode)
        self.assertIn(target, mounts())          # real mountinfo still shows it
        self.assert_all_dirs_and_records_present()
        trace = self.shim.read_trace()
        self.assertFalse(any(t.startswith("rm") for t in trace), trace)


def main():
    if not fail_fast_env():
        return 2
    unittest.main(verbosity=2, argv=[sys.argv[0]] + sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
