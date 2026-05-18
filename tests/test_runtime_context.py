from src.runtime_context import ensure_directory, set_private_permissions


def test_ensure_directory_tolerates_chmod_permission_error(monkeypatch, tmp_path):
    path = tmp_path / "mounted-context"

    monkeypatch.setattr(
        "pathlib.Path.chmod",
        lambda _path, _mode: (_ for _ in ()).throw(PermissionError("mounted filesystem")),
    )

    assert ensure_directory(path) == path
    assert path.exists()


def test_set_private_permissions_reports_permission_error(monkeypatch, tmp_path):
    path = tmp_path / "note.md"
    path.write_text("content", encoding="utf-8")
    monkeypatch.setattr(
        "pathlib.Path.chmod",
        lambda _path, _mode: (_ for _ in ()).throw(PermissionError("mounted filesystem")),
    )

    assert set_private_permissions(path, 0o600) is False
