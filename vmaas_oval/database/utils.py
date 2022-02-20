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
                      where: str = None, one_to_many: bool = False) -> dict:
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


def insert_table(con: SqliteConnection, table_name: str, columns: list, to_insert: set):
    LOGGER.debug("Inserting %s items to %s", len(to_insert), table_name)
    if to_insert:
        with SqliteCursor(con) as cur:
            try:
                cur.executemany("INSERT INTO %s (%s) VALUES (%s)" % (table_name,
                                                                     ", ".join(columns),
                                                                     ", ".join(["?" for _ in columns])),
                                to_insert)
                con.commit()
            except sqlite3.DatabaseError as e:
                con.rollback()
                LOGGER.error("Error occured during inserting to %s: \"%s\"", table_name, e)


def update_table(con: SqliteConnection, table_name: str, to_update_columns: list, where_columns: list, to_update: set):
    LOGGER.debug("Updating %s items in %s", len(to_update), table_name)
    if to_update:
        with SqliteCursor(con) as cur:
            try:
                cur.executemany("UPDATE %s SET %s WHERE %s" % (table_name,
                                                               ", ".join([f"{col} = ?" for col in to_update_columns]),
                                                               " AND ".join([f"{col} = ?" for col in where_columns])),
                                to_update)
                con.commit()
            except sqlite3.DatabaseError as e:
                con.rollback()
                LOGGER.error("Error occured during updating %s: \"%s\"", table_name, e)
