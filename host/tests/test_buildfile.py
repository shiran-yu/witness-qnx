"""buildfile.file_digests on a synthetic mkqnximage system.build."""
import hashlib

from witness.buildfile import file_digests


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_file_digests(tmp_path):
    image = tmp_path / "image"
    outside = tmp_path / "sdp"
    write(image / "first/bin/sshd", b"sshd from first search dir")
    write(outside / "bin/sshd", b"sshd shadowed")
    write(outside / "lib/libc.so", b"libc from absolute search dir")
    write(image / "first/bin/tool", b"tool")
    write(image / "local/sshd_config", b"PermitRootLogin no\n")
    write(image / "motd.txt", b"welcome\n")
    write(tmp_path / "abs/file", b"absolute source")
    buildfile = write(image / "output/build/system.build", f"""\
# comment line
[search=first:{outside}]

[uid=0 gid=0]
bin/sshd
lib/libc.so
[perms=0555] bin/tool
[uid=0 gid=0] [perms=0444] etc/motd=motd.txt
etc/ssh/sshd_config=local/sshd_config
/etc/abs={tmp_path / "abs/file"}
[perms=0644] etc/hosts={{
127.0.0.1 localhost
  ::1 localhost
}}
[type=dir] var/log
[type=link] bin/sh=/proc/boot/ksh
bin/optional
etc/also_missing=nowhere/file
etc/after=motd.txt
""".encode())

    digests = file_digests(str(buildfile), str(image))
    assert digests == {
        "/system/bin/sshd": sha(b"sshd from first search dir"),
        "/system/lib/libc.so": sha(b"libc from absolute search dir"),
        "/system/bin/tool": sha(b"tool"),
        "/system/etc/motd": sha(b"welcome\n"),
        "/system/etc/ssh/sshd_config": sha(b"PermitRootLogin no\n"),
        "/system/etc/abs": sha(b"absolute source"),
        "/system/etc/hosts": sha(b"127.0.0.1 localhost\n  ::1 localhost\n"),
        "/system/etc/after": sha(b"welcome\n"),
    }


def test_mount_point_and_later_search_line(tmp_path):
    image = tmp_path / "image"
    write(image / "a/x", b"from a")
    write(image / "b/x", b"from b")
    buildfile = write(tmp_path / "data.build", b"[search=a]\nx\n[search=b]\ny=x\n")
    assert file_digests(str(buildfile), str(image), "/data") == {"/data/x": sha(b"from a"), "/data/y": sha(b"from b")}


def test_empty_inline_block(tmp_path):
    buildfile = write(tmp_path / "s.build", b"etc/empty={\n}\n")
    assert file_digests(str(buildfile), str(tmp_path)) == {"/system/etc/empty": sha(b"\n")}
