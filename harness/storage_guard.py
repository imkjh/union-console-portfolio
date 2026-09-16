"""One bounded, volatile filesystem for CLI HOME, cwd and temporary files.

Only synthetic fixture files are mounted here. Authentication mounts, if separately
authorized, remain the caller's responsibility. Default to read-only; the approved
agy no-question refresh harness may mount its one existing cache writable.
"""
from pathlib import Path

STORAGE_BYTES = 128 * 1024 * 1024
TEST_STORAGE_BYTES = 8 * 1024 * 1024
RUNTIME_HOME = '/runtime/home'
PROC_SYSTEM_PATHS = ('/proc/sys', '/proc/sysrq-trigger', '/proc/irq', '/proc/bus')

# Run inside the namespace before mounting real authentication or sharing network.
def storage_check(*, sandbox_uid_maps=False):
    readonly = ('/', '/dev', *PROC_SYSTEM_PATHS) if sandbox_uid_maps else ('/', '/dev', '/proc')
    return '''
import os
_folders=[os.environ['HOME'],'/work','/tmp']
_volumes=[os.statvfs(p) for p in _folders]
if (len({os.stat(p).st_dev for p in _folders}) != 1
    or any(v.f_blocks*v.f_frsize != 134217728 for v in _volumes)
    or any(not (os.statvfs(p).f_flag & os.ST_RDONLY) for p in READONLY_PATHS)):
    raise SystemExit(2)
'''.replace('READONLY_PATHS', repr(readonly))


STORAGE_CHECK = storage_check()


def namespace(root, home, *, storage_bytes=STORAGE_BYTES, sandbox_uid_maps=False):
    if storage_bytes not in (STORAGE_BYTES, TEST_STORAGE_BYTES):
        raise ValueError('unsupported_storage_limit')
    if (not home.startswith('/home/') or Path(home).parts != ('/', 'home', Path(home).name)
            or Path(home).name in ('.', '..') or str(Path(home)) != home):
        raise ValueError('unsupported_home')
    root = Path(root)
    args = [
        '/usr/bin/bwrap', '--unshare-all', '--hostname', 'localhost', '--die-with-parent', '--new-session',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
        '--proc', '/proc', '--dev', '/dev',
        '--size', str(storage_bytes), '--tmpfs', '/runtime',
        '--dir', RUNTIME_HOME, '--dir', '/runtime/work', '--dir', '/runtime/tmp',
        '--symlink', RUNTIME_HOME, home, '--symlink', '/runtime/work', '/work',
        '--symlink', '/runtime/tmp', '/tmp', '--ro-bind', str(root / 'etc'), '/etc',
        '--clearenv', '--setenv', 'HOME', home,
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '--chdir', '/work',
    ]
    if sandbox_uid_maps:
        # Keep kernel controls read-only while allowing the trusted CLI to set
        # up its child user namespace via the private procfs uid/gid maps.
        for path in PROC_SYSTEM_PATHS:
            args += ['--ro-bind', path, path]
    # These are newly created synthetic fixture trees, never a real user HOME.
    for folder in ('home', 'work'):
        if (root / folder).is_symlink():
            raise ValueError('fixture_symlink_forbidden')
        for path in sorted((root / folder).rglob('*')):
            if path.is_symlink():
                raise ValueError('fixture_symlink_forbidden')
            if path.is_file():
                relative = path.relative_to(root / folder).as_posix()
                args += ['--ro-bind', str(path), '/runtime/' + folder + '/' + relative]
    return args


def seal(*, sandbox_uid_maps=False):
    # Append after the caller's final mount and before its executable.
    # /runtime is a separate mount and remains writable with one shared quota.
    return (['--remount-ro', '/dev'] + ([] if sandbox_uid_maps else ['--remount-ro', '/proc'])
            + ['--remount-ro', '/'])
