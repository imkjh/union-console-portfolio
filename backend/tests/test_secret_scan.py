import subprocess
from harness.secret_scan import scan


def git(root, *args):
    return subprocess.run(['git', '-c', 'user.name=Union Test',
                           '-c', 'user.email=test@example.invalid',
                           '-c', 'commit.gpgsign=false', *args], cwd=root,
                          capture_output=True, check=True)


def test_clean_committed_history_is_scanned(tmp_path):
    git(tmp_path, 'init')
    (tmp_path / 'file.txt').write_text('clean')
    git(tmp_path, 'add', 'file.txt')
    git(tmp_path, 'commit', '-m', 'clean fixture')
    report = scan(tmp_path)
    assert not report['findings']
    assert not report['incomplete']
    assert report['counts']['history'] == 1
    assert report['counts']['index'] == 1


def test_deleted_historical_secret_is_found_without_value(tmp_path):
    git(tmp_path, 'init')
    marker = 'sk-' + 'SYNTHETIC' * 4
    (tmp_path / 'old.txt').write_text(marker)
    git(tmp_path, 'add', 'old.txt')
    git(tmp_path, 'commit', '-m', 'synthetic fixture')
    git(tmp_path, 'rm', 'old.txt')
    git(tmp_path, 'commit', '-m', 'remove synthetic fixture')
    report = scan(tmp_path)
    assert report['findings'] == [{'path': 'old.txt', 'kind': 'api_key', 'area': 'history'}]
    assert marker not in str(report)


def test_index_differs_from_worktree_and_ignored_files_excluded(tmp_path):
    git(tmp_path, 'init')
    (tmp_path / '.gitignore').write_text('ignored.txt\n')
    marker = 'sk-' + 'SYNTHETIC' * 4
    (tmp_path / 'file.txt').write_text(marker)
    (tmp_path / 'ignored.txt').write_text(marker)
    git(tmp_path, 'add', 'file.txt')
    (tmp_path / 'file.txt').write_text('clean now')
    report = scan(tmp_path)
    assert report['findings'] == [{'path': 'file.txt', 'kind': 'api_key', 'area': 'index'}]
    assert report['history'].startswith('N/A')


def test_large_text_is_incomplete_not_silent_pass(tmp_path, monkeypatch):
    import harness.secret_scan as scanner
    git(tmp_path, 'init')
    (tmp_path / 'large.txt').write_text('text' * 30)
    monkeypatch.setattr(scanner, 'MAX_BYTES', 100)
    report = scan(tmp_path)
    assert report['incomplete'] == [{'path': 'large.txt', 'kind': 'size_limit', 'area': 'working_tree'}]
