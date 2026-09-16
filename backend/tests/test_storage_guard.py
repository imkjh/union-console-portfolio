from pathlib import Path
import pytest
from harness.storage_guard import namespace


@pytest.mark.parametrize('home', ['/root', '/home/u/../../tmp', '/home/u/cache', '/home/', '/home/..', '/home//u'])
def test_reject_home_outside_fixed_layout(tmp_path, home):
    with pytest.raises(ValueError, match='unsupported_home'):
        namespace(tmp_path, home)


def test_reject_fixture_symlink_to_external_tree(tmp_path):
    (tmp_path / 'home').mkdir()
    (tmp_path / 'work').mkdir()
    (tmp_path / 'home' / 'unexpected').symlink_to(Path('/usr'))
    with pytest.raises(ValueError, match='fixture_symlink_forbidden'):
        namespace(tmp_path, '/home/union')


def test_reject_unbounded_storage_size(tmp_path):
    with pytest.raises(ValueError, match='unsupported_storage_limit'):
        namespace(tmp_path, '/home/union', storage_bytes=0)


def test_reject_fixture_root_symlink(tmp_path):
    (tmp_path / 'home').symlink_to(Path('/usr'))
    with pytest.raises(ValueError, match='fixture_symlink_forbidden'):
        namespace(tmp_path, '/home/union')


def test_namespace_uses_private_resolvable_hostname(tmp_path):
    command = namespace(tmp_path, '/home/union')
    assert command[command.index('--hostname') + 1] == 'localhost'
    assert '--unshare-all' in command
