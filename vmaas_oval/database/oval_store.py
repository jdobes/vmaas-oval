from datetime import datetime
import sqlite3
from typing import Optional

from vmaas_oval.common.dateutils import parse_datetime_sqlite
from vmaas_oval.common.logger import get_logger
from vmaas_oval.database.handler import SqliteConnection, SqliteCursor
from vmaas_oval.database.utils import prepare_table_map
from vmaas_oval.parsers.oval_stream import OvalStream

LOGGER = get_logger(__name__)


class OvalStore:
    def __init__(self, con: SqliteConnection):
        self.con = con
        self.arch_map = prepare_table_map(self.con, "arch", ["name"])

    def _save_oval_stream_updated(self, oval_id: str, updated: datetime, force: bool = False) -> Optional[int]:
        with SqliteCursor(self.con) as cur:
            try:
                cur.execute("SELECT id, updated FROM oval_stream WHERE oval_id = ?", (oval_id,))
                row = cur.fetchone()
                if row is None:  # New stream
                    cur.execute("INSERT INTO oval_stream (oval_id, updated) VALUES (?, ?)", (oval_id, updated))
                    self.con.commit()
                    cur.execute("SELECT id, updated FROM oval_stream WHERE oval_id = ?", (oval_id,))
                    row = cur.fetchone()
                    row_id = row[0]
                elif updated > parse_datetime_sqlite(row[1]) or force:  # Updated stream
                    row_id = row[0]
                    cur.execute("UPDATE oval_stream SET updated = ? WHERE oval_id = ?", (updated, oval_id))
                    self.con.commit()
                else:  # Unchanged
                    row_id = None
            except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during storing OVAL stream: \"%s\"", e)
                    row_id = None
        return row_id

    def store(self, oval_stream: OvalStream, force: bool = False):
        oval_stream_id = self._save_oval_stream_updated(oval_stream.oval_id, oval_stream.updated, force=force)
        if oval_stream_id:
            pass
        else:
            LOGGER.debug("OVAL stream is unchanged, skipping store")
