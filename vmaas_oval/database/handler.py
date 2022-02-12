import sqlite3


class SqliteConnection:
    def __init__(self, db_file_name: str):
        self.db_file_name = db_file_name
        self.con = None

    def __enter__(self) -> sqlite3.Connection:
        self.con = sqlite3.connect(self.db_file_name)
        self.con.execute("PRAGMA foreign_keys = ON")  # Enforce foreign keys
        return self.con

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.con is not None:
            self.con.close()
            self.con = None


class SqliteCursor:
    def __init__(self, sqlite_connection: SqliteConnection):
        self.con = sqlite_connection
        self.cur = None

    def __enter__(self) -> sqlite3.Cursor:
        self.cur = sqlite3.Cursor(self.con)
        return self.cur

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.cur is not None:
            self.cur.close()
            self.cur = None
