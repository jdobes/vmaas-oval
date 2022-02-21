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

# Not in DB table like other operations because we don't need this information further
SUPPORTED_ARCH_OPERATIONS = ["equals", "pattern match"]


class OvalStore:
    def __init__(self, con: SqliteConnection):
        self.con = con
        # Persistent caches
        self.arch_map = prepare_table_map(self.con, "arch", ["name"])
        self.package_name_map = prepare_table_map(self.con, "package_name", ["name"])
        self.evr_map = prepare_table_map(self.con, "evr", ["epoch", "version", "release"])
        self.cve_map = prepare_table_map(self.con, "cve", ["name"])
        self.oval_operation_evr_map = prepare_table_map(self.con, "oval_operation_evr", ["name"])
        self.oval_check_rpminfo_map = prepare_table_map(self.con, "oval_check_rpminfo", ["name"])
        self.oval_check_existence_rpminfo_map = prepare_table_map(self.con, "oval_check_existence_rpminfo", ["name"])

        # Caches for all streams (items are continuosly deleted)
        self.oval_rpminfo_state_arch_map = prepare_table_map(self.con, "oval_rpminfo_state_arch", ["rpminfo_state_id"],
                                                             to_columns=["arch_id"], one_to_many=True)
        self.oval_rpminfo_test_state_map = prepare_table_map(self.con, "oval_rpminfo_test_state", ["rpminfo_test_id"],
                                                             to_columns=["rpminfo_state_id"], one_to_many=True)

        # Caches for single stream
        self.oval_rpminfo_object_map = {}
        self.oval_rpminfo_state_map = {}
        self.oval_rpminfo_test_map = {}
        self.oval_module_test_map = {}

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
        if to_insert_package_name:  # Refresh cache
            self.package_name_map = prepare_table_map(self.con, "package_name", ["name"])

        # Insert/update/delete OVAL rpminfo objects
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
        parsed_evrs = {}
        # Insert new EVRs
        to_insert_evr = set()
        for state in states:
            if state["evr"]:
                evr = parse_evr(state["evr"])
                parsed_evrs[state["evr"]] = evr  # Save, to not need to parse second time below
                if evr not in self.evr_map:
                    to_insert_evr.add(evr)
        insert_table(self.con, "evr", ["epoch", "version", "release"], to_insert_evr)
        if to_insert_evr:  # Refresh cache
            self.evr_map = prepare_table_map(self.con, "evr", ["epoch", "version", "release"])

        # Insert/update/delete OVAL rpminfo states
        oval_rpminfo_state_map = prepare_table_map(self.con, "oval_rpminfo_state", ["stream_id", "oval_id"],
                                                   to_columns=["id", "evr_id", "evr_operation_id", "version"],
                                                   where=f"stream_id = {oval_stream_id}")
        to_insert_oval_rpminfo_state = set()
        to_update_oval_rpminfo_state = set()
        for state in states:
            evr_id = self.evr_map[parsed_evrs[state["evr"]]] if state["evr"] else None
            evr_operation_id = self.oval_operation_evr_map[state["evr_operation"]] if state["evr_operation"] else None
            if (oval_stream_id, state["id"]) not in oval_rpminfo_state_map:
                to_insert_oval_rpminfo_state.add((oval_stream_id, state["id"], evr_id, evr_operation_id, state["version"]))
            elif state["version"] > oval_rpminfo_state_map[(oval_stream_id, state["id"])][3]:  # Version increased -> update
                to_update_oval_rpminfo_state.add((evr_id, evr_operation_id, state["version"], oval_stream_id, state["id"]))
            oval_rpminfo_state_map.pop((oval_stream_id, state["id"]), None)  # Pop out visited items
        
        to_delete_oval_rpminfo_state = set(oval_rpminfo_state_map)  # Delete items in DB which are not in current data

        insert_table(self.con, "oval_rpminfo_state", ["stream_id", "oval_id", "evr_id", "evr_operation_id", "version"], to_insert_oval_rpminfo_state)
        update_table(self.con, "oval_rpminfo_state", ["evr_id", "evr_operation_id", "version"], ["stream_id", "oval_id"], to_update_oval_rpminfo_state)
        delete_table(self.con, "oval_rpminfo_state", ["stream_id", "oval_id"], to_delete_oval_rpminfo_state)

        # Refresh cache for future lookups
        self.oval_rpminfo_state_map = prepare_table_map(self.con, "oval_rpminfo_state", ["stream_id", "oval_id"],
                                                        to_columns=["id", "evr_id", "evr_operation_id", "version"],
                                                        where=f"stream_id = {oval_stream_id}")

        # Insert/delete state architectures
        to_insert_oval_rpminfo_state_arch = set()
        to_delete_oval_rpminfo_state_arch = set()
        for state in states:
            if state["arch_operation"] is not None and state["arch_operation"] not in SUPPORTED_ARCH_OPERATIONS:
                LOGGER.warning("Unsupported arch operation: %s", state["arch_operation"])
                continue
            if state["arch"] is not None:
                state_id = self.oval_rpminfo_state_map[(oval_stream_id, state["id"])][0]
                # Simplified logic, can contain any regex but RH oval files contains only logical OR
                arch_ids = {self.arch_map[arch] for arch in state["arch"].split("|")}
                for arch_id in arch_ids:
                    if arch_id not in self.oval_rpminfo_state_arch_map.get(state_id, []):
                        to_insert_oval_rpminfo_state_arch.add((state_id, arch_id))
                    else:
                        self.oval_rpminfo_state_arch_map[state_id].remove(arch_id)
                
                for arch_id in self.oval_rpminfo_state_arch_map.get(state_id, []):
                    to_delete_oval_rpminfo_state_arch.add((state_id, arch_id))

        insert_table(self.con, "oval_rpminfo_state_arch", ["rpminfo_state_id", "arch_id"], to_insert_oval_rpminfo_state_arch)
        delete_table(self.con, "oval_rpminfo_state_arch", ["rpminfo_state_id", "arch_id"], to_delete_oval_rpminfo_state_arch)

    def _populate_tests(self, oval_stream_id: int, tests: list):
        # Insert/update/delete OVAL rpminfo tests
        oval_rpminfo_test_map = prepare_table_map(self.con, "oval_rpminfo_test", ["stream_id", "oval_id"],
                                                  to_columns=["id", "rpminfo_object_id", "check_id", "check_existence_id", "version"],
                                                  where=f"stream_id = {oval_stream_id}")
        to_insert_oval_rpminfo_test = set()
        to_update_oval_rpminfo_test = set()
        for test in tests:
            rpminfo_object_id = self.oval_rpminfo_object_map[(oval_stream_id, test["object"])][0]
            check_id = self.oval_check_rpminfo_map[test["check"]]
            check_existence_id = self.oval_check_existence_rpminfo_map[test["check_existence"]]
            if (oval_stream_id, test["id"]) not in oval_rpminfo_test_map:
                to_insert_oval_rpminfo_test.add((oval_stream_id, test["id"], rpminfo_object_id, check_id, check_existence_id, test["version"]))
            elif test["version"] > oval_rpminfo_test_map[(oval_stream_id, test["id"])][4]:  # Version increased -> update
                to_update_oval_rpminfo_test.add((rpminfo_object_id, check_id, check_existence_id, test["version"], oval_stream_id, test["id"]))
            oval_rpminfo_test_map.pop((oval_stream_id, test["id"]), None)  # Pop out visited items
        
        to_delete_oval_rpminfo_test = set(oval_rpminfo_test_map)  # Delete items in DB which are not in current data

        insert_table(self.con, "oval_rpminfo_test", ["stream_id", "oval_id", "rpminfo_object_id", "check_id", "check_existence_id", "version"],
                     to_insert_oval_rpminfo_test)
        update_table(self.con, "oval_rpminfo_test", ["rpminfo_object_id", "check_id", "check_existence_id", "version"], ["stream_id", "oval_id"],
                     to_update_oval_rpminfo_test)
        delete_table(self.con, "oval_rpminfo_test", ["stream_id", "oval_id"], to_delete_oval_rpminfo_test)

        # Refresh cache for future lookups
        self.oval_rpminfo_test_map = prepare_table_map(self.con, "oval_rpminfo_test", ["stream_id", "oval_id"],
                                                       to_columns=["id", "rpminfo_object_id", "check_id", "check_existence_id", "version"],
                                                       where=f"stream_id = {oval_stream_id}")

        # Insert/delete test states
        to_insert_oval_rpminfo_test_state = set()
        to_delete_oval_rpminfo_test_state = set()
        for test in tests:
            test_id = self.oval_rpminfo_test_map[(oval_stream_id, test["id"])][0]
            for state in test["states"]:
                state_id = self.oval_rpminfo_state_map[(oval_stream_id, state)][0]
                if state_id not in self.oval_rpminfo_test_state_map.get(test_id, []):
                    to_insert_oval_rpminfo_test_state.add((test_id, state_id))
                else:
                    self.oval_rpminfo_test_state_map[test_id].remove(state_id)
                
            for state_id in self.oval_rpminfo_test_state_map.get(test_id, []):
                to_delete_oval_rpminfo_test_state.add((test_id, state_id))

        insert_table(self.con, "oval_rpminfo_test_state", ["rpminfo_test_id", "rpminfo_state_id"], to_insert_oval_rpminfo_test_state)
        delete_table(self.con, "oval_rpminfo_test_state", ["rpminfo_test_id", "rpminfo_state_id"], to_delete_oval_rpminfo_test_state)

    def _populate_module_tests(self, oval_stream_id: int, module_tests: list):
        # Insert/update/delete OVAL module tests
        oval_module_test_map = prepare_table_map(self.con, "oval_module_test", ["stream_id", "oval_id"],
                                                 to_columns=["id", "module_stream", "version"],
                                                 where=f"stream_id = {oval_stream_id}")
        to_insert_oval_module_test = set()
        to_update_oval_module_test = set()
        for module_test in module_tests:
            if (oval_stream_id, module_test["id"]) not in oval_module_test_map:
                to_insert_oval_module_test.add((oval_stream_id, module_test["id"], module_test["module_stream"], module_test["version"]))
            elif module_test["version"] > oval_module_test_map[(oval_stream_id, module_test["id"])][2]:  # Version increased -> update
                to_update_oval_module_test.add((module_test["module_stream"], module_test["version"], oval_stream_id, module_test["id"]))
            oval_module_test_map.pop((oval_stream_id, module_test["id"]), None)  # Pop out visited items
        
        to_delete_oval_module_test = set(oval_module_test_map)  # Delete items in DB which are not in current data

        insert_table(self.con, "oval_module_test", ["stream_id", "oval_id", "module_stream", "version"], to_insert_oval_module_test)
        update_table(self.con, "oval_module_test", ["module_stream", "version"], ["stream_id", "oval_id"], to_update_oval_module_test)
        delete_table(self.con, "oval_module_test", ["stream_id", "oval_id"], to_delete_oval_module_test)

        # Refresh cache for future lookups
        self.oval_module_test_map = prepare_table_map(self.con, "oval_module_test", ["stream_id", "oval_id"],
                                                      to_columns=["id", "module_stream", "version"],
                                                      where=f"stream_id = {oval_stream_id}")

    def _populate_definitions(self, oval_stream_id: int, definitions: list):
        # Insert new CVEs
        to_insert = {(cve,) for definition in definitions for cve in definition["cves"] if cve not in self.cve_map}
        insert_table(self.con, "cve", ["name"], to_insert)
        if to_insert:  # Refresh cache
            self.cve_map = prepare_table_map(self.con, "cve", ["name"])

    def store(self, oval_stream: OvalStream, force: bool = False):
        oval_stream_id = self._get_oval_stream_id(oval_stream.oval_id, oval_stream.updated, force=force)
        if oval_stream_id:
            self._populate_objects(oval_stream_id, oval_stream.objects)
            self._populate_states(oval_stream_id, oval_stream.states)
            self._populate_tests(oval_stream_id, oval_stream.tests)
            self._populate_module_tests(oval_stream_id, oval_stream.module_tests)
            self._populate_definitions(oval_stream_id, oval_stream.definitions)
        else:
            LOGGER.debug("OVAL stream is unchanged, skipping store")
