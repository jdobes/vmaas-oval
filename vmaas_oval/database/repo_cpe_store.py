from platform import release
import sqlite3

from vmaas_oval.common.logger import get_logger
from vmaas_oval.database.handler import SqliteConnection, SqliteCursor
from vmaas_oval.database.utils import prepare_table_map
from vmaas_oval.parsers.repo_cpe_map import RepoCpeMap

LOGGER = get_logger(__name__)


class RepoCpeStore:
    def __init__(self, con: SqliteConnection):
        self.con = con
        self.arch_map = prepare_table_map(self.con, "arch", ["name"])
        self.cpe_map = prepare_table_map(self.con, "cpe", ["name"])
        self.content_set_map = prepare_table_map(self.con, "content_set", ["name"])
        self.repo_map = prepare_table_map(self.con, "repo", ["name", "basearch_id", "releasever"])

    def _store_cpes(self, cpes: set):
        to_insert = [(cpe,) for cpe in cpes if cpe not in self.cpe_map]
        LOGGER.debug("Inserting %s CPEs", len(to_insert))
        if not to_insert:
            return
        with SqliteCursor(self.con) as cur:
            try:
                cur.executemany("INSERT INTO cpe (name) VALUES (?)", to_insert)
                self.con.commit()
                # Refresh cache
                cur.execute("SELECT id, name FROM cpe")
                for idx, name in cur.fetchall():
                    if name not in self.cpe_map:
                        self.cpe_map[name] = idx
            except sqlite3.DatabaseError as e:
                self.con.rollback()
                LOGGER.error("Error occured during inserting CPEs: \"%s\"", e)

    def _store_content_sets(self, content_sets: set):
        to_insert = [(content_set,) for content_set in content_sets if content_set not in self.content_set_map]
        LOGGER.debug("Inserting %s content sets", len(to_insert))
        if not to_insert:
            return
        with SqliteCursor(self.con) as cur:
            try:
                cur.executemany("INSERT INTO content_set (name) VALUES (?)", to_insert)
                self.con.commit()
                # Refresh cache
                cur.execute("SELECT id, name FROM content_set")
                for idx, name in cur.fetchall():
                    if name not in self.content_set_map:
                        self.content_set_map[name] = idx
            except sqlite3.DatabaseError as e:
                self.con.rollback()
                LOGGER.error("Error occured during inserting content sets: \"%s\"", e)

    def _store_repos(self, repos: set):
        to_insert = [(content_set_label, self.arch_map.get(basearch), releasever)
                     for content_set_label, basearch, releasever in repos
                     if (content_set_label, self.arch_map.get(basearch), releasever) not in self.repo_map]
        LOGGER.debug("Inserting %s repositories", len(to_insert))
        if not to_insert:
            return
        with SqliteCursor(self.con) as cur:
            try:
                cur.executemany("INSERT INTO repo (name, basearch_id, releasever) VALUES (?, ?, ?)", to_insert)
                self.con.commit()
                # Refresh cache
                cur.execute("SELECT id, name, basearch_id, releasever FROM repo")
                for idx, name, basearch_id, releasever in cur.fetchall():
                    if (name, basearch_id, releasever) not in self.repo_map:
                        self.repo_map[(name, basearch_id, releasever)] = idx
            except sqlite3.DatabaseError as e:
                self.con.rollback()
                LOGGER.error("Error occured during inserting repositories: \"%s\"", e)

    def store(self, repo_cpe_map: RepoCpeMap):
        self._store_cpes(repo_cpe_map.cpes)
        self._store_content_sets(repo_cpe_map.content_sets)
        self._store_repos(repo_cpe_map.repos)
