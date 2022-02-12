import sqlite3

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


def prepare_table_map(con: SqliteConnection, table_name: str, columns: list, to_columns: list=None,
                      where: str=None, one_to_many: bool=False):
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
