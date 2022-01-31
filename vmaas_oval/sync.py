from vmaas_oval.database_handler import SqliteConnection, SqliteCursor
from vmaas_oval.utils import get_logger

LOGGER = get_logger(__name__)


def sync_data(db_file_name: str) -> None:
    LOGGER.info("Downloading and synchronizing data in sqlite DB file: %s", db_file_name)
    with SqliteConnection(db_file_name) as con:
        with SqliteCursor(con) as cur:
            pass
