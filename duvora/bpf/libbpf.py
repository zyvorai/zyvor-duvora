# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

"""Thin ctypes bindings to the system libbpf (1.3 or later, for TCX links)."""
import ctypes
import ctypes.util
import os
import struct

BPF_ANY, BPF_NOEXIST, BPF_EXIST = 0, 1, 2
BPF_F_BEFORE = 1 << 3


class BpfError(OSError):
    pass


class TcxOpts(ctypes.Structure):
    _fields_ = [("sz", ctypes.c_size_t), ("flags", ctypes.c_uint32), ("relative_fd", ctypes.c_uint32),
                ("relative_id", ctypes.c_uint32), ("expected_revision", ctypes.c_uint64)]


class TestRunOpts(ctypes.Structure):
    _fields_ = [("sz", ctypes.c_size_t), ("data_in", ctypes.c_void_p), ("data_out", ctypes.c_void_p),
                ("data_size_in", ctypes.c_uint32), ("data_size_out", ctypes.c_uint32),
                ("ctx_in", ctypes.c_void_p), ("ctx_out", ctypes.c_void_p),
                ("ctx_size_in", ctypes.c_uint32), ("ctx_size_out", ctypes.c_uint32),
                ("retval", ctypes.c_uint32), ("repeat", ctypes.c_int), ("duration", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("cpu", ctypes.c_uint32), ("batch_size", ctypes.c_uint32)]


def _fail(what, code=None):
    code = code if code is not None else ctypes.get_errno()
    code = abs(code) or 1
    return BpfError(code, f"{what}: {os.strerror(code)}")


def percpu_size(value_size):
    """Bytes per CPU for a per-CPU map value: rounded up to 8."""
    return (value_size + 7) & ~7


def sum_percpu(raw, value_size, fmt):
    """Sum a per-CPU value buffer field by field; `fmt` describes one CPU's value."""
    step = percpu_size(value_size)
    total = [0] * len(struct.unpack(fmt, bytes(struct.calcsize(fmt))))
    for offset in range(0, len(raw) - step + 1, step):
        total = [a + b for a, b in zip(total, struct.unpack_from(fmt, raw, offset))]
    return tuple(total)


class Libbpf:
    def __init__(self, path=None):
        path = path or os.environ.get("DUVORA_LIBBPF") or ctypes.util.find_library("bpf") or "libbpf.so.1"
        self.lib = lib = ctypes.CDLL(path, use_errno=True)
        vp, i, u32 = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32
        for name, res, args in (
                ("bpf_object__open_file", vp, [ctypes.c_char_p, vp]),
                ("bpf_object__load", i, [vp]),
                ("bpf_object__close", None, [vp]),
                ("bpf_object__find_program_by_name", vp, [vp, ctypes.c_char_p]),
                ("bpf_object__find_map_fd_by_name", i, [vp, ctypes.c_char_p]),
                ("bpf_program__fd", i, [vp]),
                ("bpf_program__attach", vp, [vp]),
                ("bpf_program__attach_tcx", vp, [vp, i, ctypes.POINTER(TcxOpts)]),
                ("bpf_link__destroy", i, [vp]),
                ("bpf_map_lookup_elem", i, [i, vp, vp]),
                ("bpf_map_update_elem", i, [i, vp, vp, ctypes.c_uint64]),
                ("bpf_map_delete_elem", i, [i, vp]),
                ("bpf_map_get_next_key", i, [i, vp, vp]),
                ("bpf_prog_test_run_opts", i, [i, ctypes.POINTER(TestRunOpts)]),
                ("libbpf_num_possible_cpus", i, []),
                ("libbpf_major_version", u32, []),
                ("libbpf_minor_version", u32, [])):
            fn = getattr(lib, name)
            fn.restype, fn.argtypes = res, args
        self.cpus = max(1, lib.libbpf_num_possible_cpus())

    def version(self):
        return (self.lib.libbpf_major_version(), self.lib.libbpf_minor_version())

    def open(self, path):
        return BpfObject(self, path)

    # Map access by fd. Keys and values are bytes; per-CPU values come back for every CPU.
    def lookup(self, fd, key, value_size):
        buf = ctypes.create_string_buffer(value_size)
        rc = self.lib.bpf_map_lookup_elem(fd, key, buf)
        if rc < 0:
            if abs(rc) == 2:  # ENOENT
                return None
            raise _fail("map lookup", rc)
        return buf.raw

    def update(self, fd, key, value, flags=BPF_ANY):
        rc = self.lib.bpf_map_update_elem(fd, key, value, flags)
        if rc < 0:
            raise _fail("map update", rc)

    def delete(self, fd, key):
        rc = self.lib.bpf_map_delete_elem(fd, key)
        if rc < 0 and abs(rc) != 2:
            raise _fail("map delete", rc)

    def keys(self, fd, key_size):
        out, prev = [], None
        nxt = ctypes.create_string_buffer(key_size)
        while True:
            rc = self.lib.bpf_map_get_next_key(fd, prev, nxt)
            if rc < 0:
                if abs(rc) == 2:
                    return out
                raise _fail("map iterate", rc)
            out.append(nxt.raw)
            prev = ctypes.create_string_buffer(nxt.raw, key_size)
            if len(out) > 1 << 16:
                return out

    def items(self, fd, key_size, value_size):
        out = []
        for k in self.keys(fd, key_size):
            v = self.lookup(fd, k, value_size)
            if v is not None:
                out.append((k, v))
        return out

    def test_run(self, prog_fd, data, repeat=1):
        """Run a program once over `data` (BPF_PROG_TEST_RUN). Returns (retval, data_out)."""
        inp = ctypes.create_string_buffer(data, len(data))
        out = ctypes.create_string_buffer(len(data) + 256)
        opts = TestRunOpts(sz=ctypes.sizeof(TestRunOpts), data_in=ctypes.cast(inp, ctypes.c_void_p),
                           data_out=ctypes.cast(out, ctypes.c_void_p), data_size_in=len(data),
                           data_size_out=len(out), repeat=repeat)
        rc = self.lib.bpf_prog_test_run_opts(prog_fd, ctypes.byref(opts))
        if rc < 0:
            raise _fail("test run", rc)
        return opts.retval, out.raw[:opts.data_size_out]


class BpfObject:
    """An opened and loaded object file; links are destroyed on close."""

    def __init__(self, bpf, path):
        self.bpf, self.path, self.links = bpf, str(path), []
        lib = bpf.lib
        self.obj = lib.bpf_object__open_file(self.path.encode(), None)
        if not self.obj:
            raise _fail(f"open {os.path.basename(self.path)}")
        rc = lib.bpf_object__load(self.obj)
        if rc < 0:
            lib.bpf_object__close(self.obj)
            self.obj = None
            raise _fail(f"load {os.path.basename(self.path)}", rc)

    def program(self, name):
        prog = self.bpf.lib.bpf_object__find_program_by_name(self.obj, name.encode())
        if not prog:
            raise BpfError(2, f"program {name} not found in {os.path.basename(self.path)}")
        return prog

    def prog_fd(self, name):
        return self.bpf.lib.bpf_program__fd(self.program(name))

    def map_fd(self, name):
        fd = self.bpf.lib.bpf_object__find_map_fd_by_name(self.obj, name.encode())
        if fd < 0:
            raise BpfError(2, f"map {name} not found in {os.path.basename(self.path)}")
        return fd

    def attach(self, name):
        link = self.bpf.lib.bpf_program__attach(self.program(name))
        if not link:
            raise _fail(f"attach {name}")
        self.links.append(link)
        return link

    def attach_tcx(self, name, ifindex, first=False):
        """Attach to an interface's TCX hook (ingress or egress by section); `first` puts it at the head."""
        opts = TcxOpts(sz=ctypes.sizeof(TcxOpts), flags=BPF_F_BEFORE if first else 0)
        link = self.bpf.lib.bpf_program__attach_tcx(self.program(name), ifindex, ctypes.byref(opts))
        if not link:
            raise _fail(f"attach {name} to ifindex {ifindex}")
        self.links.append(link)
        return link

    def detach(self, link):
        if link in self.links:
            self.links.remove(link)
            self.bpf.lib.bpf_link__destroy(link)

    def close(self):
        for link in self.links:
            self.bpf.lib.bpf_link__destroy(link)
        self.links = []
        if self.obj:
            self.bpf.lib.bpf_object__close(self.obj)
            self.obj = None
