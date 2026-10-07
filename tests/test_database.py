from reconforge.database import Database


def test_database_creates_tables_and_stores_scan(tmp_path):
    db_path = tmp_path / "scan.db"
    db = Database(str(db_path))
    db.create_tables()
    scan_id = db.insert_scan(target="example.com", summary="demo")
    assert scan_id > 0
    assert db.get_scan(scan_id)["target"] == "example.com"
