from datetime import datetime
import sqlite3
from typing import Optional

from vmaas_oval.common.dateutils import parse_datetime_sqlite
from vmaas_oval.common.logger import get_logger
from vmaas_oval.common.rpm import parse_evr
from vmaas_oval.database.handler import SqliteConnection, SqliteCursor
from vmaas_oval.database.utils import delete_table, prepare_table_map, insert_table, update_table
from vmaas_oval.parsers.oval_stream import OvalStream

LOGGER = get_logger(__name__)


class OvalStore:
    def __init__(self, con: SqliteConnection):
        self.con = con
        # Persistent caches
        self.arch_map = prepare_table_map(self.con, "arch", ["name"])
        self.package_name_map = prepare_table_map(self.con, "package_name", ["name"])
        self.evr_map = prepare_table_map(self.con, "evr", ["epoch", "version", "release"])
        self.cve_map = prepare_table_map(self.con, "cve", ["name"])

        # Caches for single stream
        self.oval_rpminfo_object_map = {}

    def _get_oval_stream_id(self, oval_id: str, updated: datetime, force: bool = False) -> Optional[int]:
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
    
    def _populate_objects(self, oval_stream_id: int, objects: list):
        # Insert new package names
        to_insert_package_name = set()
        for obj in objects:
            if obj["name"] not in self.package_name_map:
                to_insert_package_name.add((obj["name"],))
        insert_table(self.con, "package_name", ["name"], to_insert_package_name)
        if to_insert_package_name:
            self.package_name_map = prepare_table_map(self.con, "package_name", ["name"])

        # Insert OVAL rpminfo objects
        oval_rpminfo_object_map = prepare_table_map(self.con, "oval_rpminfo_object", ["stream_id", "oval_id"],
                                                    to_columns=["id", "package_name_id", "version"],
                                                    where=f"stream_id = {oval_stream_id}")
        to_insert_oval_rpminfo_object = set()
        to_update_oval_rpminfo_object = set()
        for obj in objects:
            if (oval_stream_id, obj["id"]) not in oval_rpminfo_object_map:
                to_insert_oval_rpminfo_object.add((oval_stream_id, obj["id"], self.package_name_map[obj["name"]], obj["version"]))
            elif obj["version"] > oval_rpminfo_object_map[(oval_stream_id, obj["id"])][2]:  # Version increased -> update
                to_update_oval_rpminfo_object.add((self.package_name_map[obj["name"]], obj["version"], oval_stream_id, obj["id"]))
            oval_rpminfo_object_map.pop((oval_stream_id, obj["id"]), None)  # Pop out visited items
        
        to_delete_oval_rpminfo_object = set(oval_rpminfo_object_map)  # Delete items in DB which are not in current data

        insert_table(self.con, "oval_rpminfo_object", ["stream_id", "oval_id", "package_name_id", "version"], to_insert_oval_rpminfo_object)
        update_table(self.con, "oval_rpminfo_object", ["package_name_id", "version"], ["stream_id", "oval_id"], to_update_oval_rpminfo_object)
        delete_table(self.con, "oval_rpminfo_object", ["stream_id", "oval_id"], to_delete_oval_rpminfo_object)

        # Refresh cache for future lookups
        self.oval_rpminfo_object_map = prepare_table_map(self.con, "oval_rpminfo_object", ["stream_id", "oval_id"],
                                                         to_columns=["id", "package_name_id", "version"],
                                                         where=f"stream_id = {oval_stream_id}")

    def _populate_states(self, oval_stream_id: int, states: list):
        # Insert new EVRs
        to_insert_evr = set()
        for state in states:
            if state["evr"]:
                evr = parse_evr(state["evr"])
                if evr not in self.evr_map:
                    to_insert_evr.add(evr)
        if to_insert_evr:
            insert_table(self.con, "evr", ["epoch", "version", "release"], to_insert_evr)
            self.evr_map = prepare_table_map(self.con, "evr", ["epoch", "version", "release"])

    def _populate_definitions(self, oval_stream_id: int, definitions: list):
        # Insert new CVEs
        to_insert = {(cve,) for definition in definitions for cve in definition["cves"] if cve not in self.cve_map}
        if to_insert:
            insert_table(self.con, "cve", ["name"], to_insert)
            self.cve_map = prepare_table_map(self.con, "cve", ["name"])

    def store(self, oval_stream: OvalStream, force: bool = False):
        oval_stream_id = self._get_oval_stream_id(oval_stream.oval_id, oval_stream.updated, force=force)
        if oval_stream_id:
            self._populate_objects(oval_stream_id, oval_stream.objects)
            self._populate_states(oval_stream_id, oval_stream.states)
            self._populate_definitions(oval_stream_id, oval_stream.definitions)
        else:
            LOGGER.debug("OVAL stream is unchanged, skipping store")
