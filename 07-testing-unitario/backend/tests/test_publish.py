from app.rules import can_publish


def test_can_publish_dueño_puede():
    assert can_publish(owner_id=5, user_id=5, role="editor") is True


def test_can_publish_admin_puede_sobre_ajeno():
    assert can_publish(owner_id=5, user_id=9, role="admin") is True


def test_can_publish_editor_no_puede_sobre_ajeno():
    assert can_publish(owner_id=5, user_id=9, role="editor") is False