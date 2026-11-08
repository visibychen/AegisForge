"""Irreversible child-only restrictions on known cross-process attack channels (Linux)."""

import ctypes
import ctypes.util
import errno
import os
import resource

DENIED = (
    "kill",
    "tkill",
    "tgkill",
    "pidfd_send_signal",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "pidfd_open",
    "pidfd_getfd",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "process_madvise",
    "setpriority",
    "sched_setattr",
    "sched_setscheduler",
    "sched_setparam",
    "ioprio_set",
    "migrate_pages",
    "move_pages",
)


class Comparison(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_uint),
        ("a", ctypes.c_uint64),
        ("b", ctypes.c_uint64),
    ]


def apply_guard():
    try:
        # Raising one's score is unprivileged and cannot subsequently be lowered without caps.
        with open("/proc/self/oom_score_adj", "w") as stream:
            stream.write("1000")
        library = ctypes.util.find_library("seccomp")
        if not library:
            raise RuntimeError
        lib = ctypes.CDLL(library, use_errno=True)
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_attr_set.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint32,
        ]
        lib.seccomp_rule_add_array.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(Comparison),
        ]
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
        context = lib.seccomp_init(0x7FFF0000)  # ALLOW; this augments Docker's default filter.
        if not context:
            raise RuntimeError
        try:
            # ACT_BADARCH=2; CTL_TSYNC=4. Fail closed rather than silently losing protection.
            if lib.seccomp_attr_set(context, 2, 0x80000000) or lib.seccomp_attr_set(context, 4, 1):
                raise RuntimeError
            action = 0x00050000 | errno.EPERM
            for name in DENIED:
                number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
                if number >= 0 and lib.seccomp_rule_add_array(context, action, number, 0, None):
                    raise RuntimeError
            number = lib.seccomp_syscall_resolve_name(b"prlimit64")
            rule = Comparison(0, 1, 0, 0)  # SCMP_CMP_NE: only pid=0 (self) remains available.
            if number >= 0 and lib.seccomp_rule_add_array(
                context, action, number, 1, ctypes.byref(rule)
            ):
                raise RuntimeError
            if lib.seccomp_load(context):
                raise RuntimeError
        finally:
            lib.seccomp_release(context)
        try:
            os.kill(os.getpid(), 0)
        except PermissionError:
            pass
        else:
            raise RuntimeError
        resource.getrlimit(resource.RLIMIT_CPU)  # libc's pid=0 prlimit must still work.
    except Exception:
        raise SystemExit(3) from None


if __name__ == "__main__":
    apply_guard()
