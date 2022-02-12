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

    def _store_cpes(self, cpes: set):
        cpe_map = prepare_table_map(self.con, "cpe", ["name"])
        to_insert = [(cpe,) for cpe in cpes if cpe not in cpe_map]
        LOGGER.debug("Inserting %s CPEs", len(to_insert))
        if to_insert:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("INSERT INTO cpe (name) VALUES (?)", to_insert)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting CPEs: \"%s\"", e)

    def _store_content_sets(self, content_sets: set):
        content_set_map = prepare_table_map(self.con, "content_set", ["name"])
        to_insert = [(content_set,) for content_set in content_sets if content_set not in content_set_map]
        LOGGER.debug("Inserting %s content sets", len(to_insert))
        if to_insert:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("INSERT INTO content_set (name) VALUES (?)", to_insert)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting content sets: \"%s\"", e)

    def _store_repos(self, repos: set):
        repo_map = prepare_table_map(self.con, "repo", ["name", "basearch_id", "releasever"])
        to_insert = [(content_set_label, self.arch_map.get(basearch), releasever)
                     for content_set_label, basearch, releasever in repos
                     if (content_set_label, self.arch_map.get(basearch), releasever) not in repo_map]
        LOGGER.debug("Inserting %s repositories", len(to_insert))
        if to_insert:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("INSERT INTO repo (name, basearch_id, releasever) VALUES (?, ?, ?)", to_insert)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting repositories: \"%s\"", e)

    def _store_content_set_to_cpes(self, content_set_to_cpes: dict):
        cpe_map = prepare_table_map(self.con, "cpe", ["name"])
        content_set_map = prepare_table_map(self.con, "content_set", ["name"])

        current_associations = prepare_table_map(self.con, "cpe_content_set", ["content_set_id"],
                                                 to_columns=["cpe_id"], one_to_many=True)

        to_insert = []
        to_delete = []

        for content_set, cpes in content_set_to_cpes.items():
            content_set_id = content_set_map[content_set]
            for cpe in cpes:
                cpe_id = cpe_map[cpe]
                if cpe_id not in current_associations.get(content_set_id, []):
                    to_insert.append((cpe_id, content_set_id))
                else:
                    current_associations[content_set_id].remove(cpe_id)

        for content_set_id, cpe_ids in current_associations.items():
            for cpe_id in cpe_ids:
                to_delete.append((cpe_id, content_set_id))

        LOGGER.debug("Inserting %s CPE - content set pairs", len(to_insert))
        LOGGER.debug("Deleting %s CPE - content set pairs", len(to_delete))
        if to_insert:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("INSERT INTO cpe_content_set (cpe_id, content_set_id) VALUES (?, ?)", to_insert)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting CPE - content set pairs: \"%s\"", e)
        if to_delete:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("DELETE FROM cpe_content_set WHERE cpe_id = ? AND content_set_id = ?", to_delete)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during deleting CPE - content set pairs: \"%s\"", e)

    def _store_repo_to_cpes(self, repo_to_cpes: dict):
        cpe_map = prepare_table_map(self.con, "cpe", ["name"])
        repo_map = prepare_table_map(self.con, "repo", ["name", "basearch_id", "releasever"])

        current_associations = prepare_table_map(self.con, "cpe_repo", ["repo_id"],
                                                 to_columns=["cpe_id"], one_to_many=True)

        to_insert = []
        to_delete = []

        for (content_set_label, basearch, releasever), cpes in repo_to_cpes.items():
            repo_id = repo_map[(content_set_label, self.arch_map.get(basearch), releasever)]
            for cpe in cpes:
                cpe_id = cpe_map[cpe]
                if cpe_id not in current_associations.get(repo_id, []):
                    to_insert.append((cpe_id, repo_id))
                else:
                    current_associations[repo_id].remove(cpe_id)

        for repo_id, cpe_ids in current_associations.items():
            for cpe_id in cpe_ids:
                to_delete.append((cpe_id, repo_id))

        LOGGER.debug("Inserting %s CPE - repo pairs", len(to_insert))
        LOGGER.debug("Deleting %s CPE - repo pairs", len(to_delete))
        if to_insert:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("INSERT INTO cpe_repo (cpe_id, repo_id) VALUES (?, ?)", to_insert)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting CPE - repo pairs: \"%s\"", e)
        if to_delete:
            with SqliteCursor(self.con) as cur:
                try:
                    cur.executemany("DELETE FROM cpe_repo WHERE cpe_id = ? AND repo_id = ?", to_delete)
                    self.con.commit()
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during deleting CPE - repo pairs: \"%s\"", e)

    def store(self, repo_cpe_map: RepoCpeMap):
        self._store_cpes(repo_cpe_map.cpes)
        self._store_content_sets(repo_cpe_map.content_sets)
        self._store_repos(repo_cpe_map.repos)
        self._store_content_set_to_cpes(repo_cpe_map.content_set_to_cpes)
        self._store_repo_to_cpes(repo_cpe_map.repo_to_cpes)
