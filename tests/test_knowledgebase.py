from src.knowledgebase import ensure_knowledgebase, update_inventory


def test_ensure_knowledgebase_creates_expected_directories(tmp_path):
    root = ensure_knowledgebase(tmp_path)

    assert root == tmp_path
    assert (tmp_path / "inventory" / "hosts" / "README.md").exists()
    assert (tmp_path / "inventory" / "networks" / "README.md").exists()
    assert (tmp_path / "incidents" / "README.md").exists()
    assert (tmp_path / "notes" / "README.md").exists()
    assert (tmp_path / "skills" / "README.md").exists()


def test_update_inventory_writes_bounded_host_profile(tmp_path):
    command = {"function": "ping", "args": {"host": "192.168.1.10"}}
    result = {"success": True, "stdout": "PING 192.168.1.10"}

    path = update_inventory(command, result, tmp_path)

    assert path == tmp_path / "inventory" / "hosts" / "192.168.1.10.md"
    content = path.read_text(encoding="utf-8")
    assert "# 192.168.1.10" in content
    assert "## Admin Notes" in content
    assert "`ping` success: PING 192.168.1.10" in content
    assert "nca:metadata" not in content


def test_update_inventory_preserves_admin_notes_and_caps_observations(tmp_path):
    command = {"function": "ping", "args": {"host": "192.168.1.10"}}
    result = {"success": True, "stdout": "PING 192.168.1.10"}
    path = update_inventory(command, result, tmp_path)
    content = path.read_text(encoding="utf-8")
    content = content.replace("_Add durable human-maintained knowledge here._", "Router lives in rack A.")
    path.write_text(content, encoding="utf-8")

    for _ in range(25):
        update_inventory(command, result, tmp_path)

    updated = path.read_text(encoding="utf-8")
    assert "Router lives in rack A." in updated
    assert updated.count("`ping` success") == 20
