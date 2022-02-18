import sqlite3
from typing import Optional

from vmaas_oval.common.logger import get_logger
from vmaas_oval.database.handler import SqliteConnection, SqliteCursor

LOGGER = get_logger(__name__)


def fetch_data(db_file_name: str, table_name: str, columns: list) -> list:
    data = []
    with SqliteConnection(db_file_name) as con:
        with SqliteCursor(con) as cur:
            try:
                data = list(cur.execute(f"SELECT {', '.join(columns)} FROM {table_name}"))
            except sqlite3.DatabaseError as e:
                LOGGER.error("Error occured during fetching data from DB: \"%s\"", e)
    return data


def prepare_table_map(con: SqliteConnection, table_name: str, columns: list, to_columns: list = None,
                      where: str = None, one_to_many: bool = False):
    """Create map from table map[columns] -> or(column, tuple(columns))."""
    if not to_columns:
        to_columns = ["id"]
    cols_len = len(columns)
    to_cols_len = len(to_columns)

    table_map = {}
    with SqliteCursor(con) as cur:
        sql = "SELECT %s, %s FROM %s" % (", ".join(columns), ", ".join(to_columns), table_name)
        if where:
            sql = f"{sql} WHERE {where}"
        try:
            cur.execute(sql)
            for row in cur.fetchall():
                if cols_len == 1:
                    key = row[0]
                else:
                    key = tuple(row[:cols_len])
                if to_cols_len == 1:
                    value = row[-1]
                else:
                    value = tuple(row[cols_len:])
                if one_to_many:
                    table_map.setdefault(key, set()).add(value)
                else:
                    table_map[key] = value
        except sqlite3.DatabaseError as e:
            LOGGER.error("Error occured during fetching data from DB: \"%s\"", e)
    return table_map


def populate_table(con: SqliteConnection, table_name: str, columns: list, data: set, current_data: Optional[dict] = None,
                   update_current_data: bool = False):
    cols_len = len(columns)
    if current_data is None:
        current_data = prepare_table_map(con, table_name, columns)
    if cols_len == 1:
        to_insert = [item for item in data if item[0] not in current_data]  # key is not tuple, rows are
    else:
        to_insert = [item for item in data if item not in current_data]

    LOGGER.debug("Inserting %s items to %s", len(to_insert), table_name)
    if to_insert:
        with SqliteCursor(con) as cur:
            try:
                cur.executemany("INSERT INTO %s (%s) VALUES (%s)" % (table_name,
                                                                     ", ".join(columns),
                                                                     ", ".join(["?" for _ in columns])),
                                to_insert)
                con.commit()
                if update_current_data:
                    cur.execute("SELECT %s, id FROM %s" % (", ".join(columns), table_name))
                    for row in cur.fetchall():
                        if cols_len == 1:
                            key = row[0]
                        else:
                            key = tuple(row[:cols_len])
                        if key not in current_data:
                            current_data[key] = row[-1]
            except sqlite3.DatabaseError as e:
                con.rollback()
                LOGGER.error("Error occured during inserting to %s: \"%s\"", table_name, e)
