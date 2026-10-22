import sqlite3
import sqlite_vec


def test_sqlite_vec_loads():
    con = sqlite3.connect(":memory:")
    con.enable_load_extension(True)
    sqlite_vec.load(con)
    assert con.execute("select vec_version()").fetchone()[0].startswith("v")
