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
        self.cpe_map = prepare_table_map(self.con, "cpe", ["name"])
        self.oval_operation_evr_map = prepare_table_map(self.con, "oval_operation_evr", ["name"])
        self.oval_check_rpminfo_map = prepare_table_map(self.con, "oval_check_rpminfo", ["name"])
        self.oval_check_existence_rpminfo_map = prepare_table_map(self.con, "oval_check_existence_rpminfo", ["name"])
        self.oval_definition_type_map = prepare_table_map(self.con, "oval_definition_type", ["name"])
        self.oval_criteria_operator_map = prepare_table_map(self.con, "oval_criteria_operator", ["name"])
        
        # Caches for all streams, used to identify items to delete (items from these dicts are continuosly deleted)
        self.oval_rpminfo_state_arch_map = prepare_table_map(self.con, "oval_rpminfo_state_arch", ["rpminfo_state_id"],
                                                             to_columns=["arch_id"], one_to_many=True)
        self.oval_rpminfo_test_state_map = prepare_table_map(self.con, "oval_rpminfo_test_state", ["rpminfo_test_id"],
                                                             to_columns=["rpminfo_state_id"], one_to_many=True)
        self.oval_definition_test_map = prepare_table_map(self.con, "oval_definition_test", ["definition_id"],
                                                          to_columns=["rpminfo_test_id"], one_to_many=True)
        self.oval_definition_cve_map = prepare_table_map(self.con, "oval_definition_cve", ["definition_id"],
                                                         to_columns=["cve_id"], one_to_many=True)
        self.oval_definition_cpe_map = prepare_table_map(self.con, "oval_definition_cpe", ["definition_id"],
                                                         to_columns=["cpe_id"], one_to_many=True)

        # Caches for single stream
        self.oval_rpminfo_object_map = {}
        self.oval_rpminfo_state_map = {}
        self.oval_rpminfo_test_map = {}
        self.oval_module_test_map = {}
        self.oval_definition_map = {}

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

    def _delete_definition_criteria_tree(self, definition_id: int):
        with SqliteCursor(self.con) as cur:
            try:
                cur.execute("UPDATE oval_definition SET criteria_id = NULL WHERE id = ?", (definition_id,))
                cur.execute("DELETE FROM oval_criteria where definition_id = ?", (definition_id,))
                self.con.commit()
            except sqlite3.DatabaseError as e:
                self.con.rollback()
                LOGGER.error("Error occured during deleting definition criteria tree: \"%s\"", e)

    def _set_definition_criteria_tree(self, definition_id: int, criteria_id: int):
        with SqliteCursor(self.con) as cur:
            try:
                cur.execute("UPDATE oval_definition SET criteria_id = ? WHERE id = ?", (criteria_id, definition_id))
            except sqlite3.DatabaseError as e:
                self.con.rollback()
                LOGGER.error("Error occured during setting definition criteria tree: \"%s\"", e)

    def _populate_definition_criteria(self, oval_stream_id: int, definition_id: int, criteria: dict, dependencies_to_import: list) -> int:
        top_criteria_id = None
        crit = criteria
        criteria_stack = []
        while crit is not None:
            criteria_id = None
            operator_id = self.oval_criteria_operator_map[crit["operator"]]
            with SqliteCursor(self.con) as cur:
                try:
                    criteria_id = cur.execute("INSERT INTO oval_criteria (definition_id, operator_id) VALUES (?, ?)",
                                            (definition_id, operator_id)).lastrowid
                except sqlite3.DatabaseError as e:
                    self.con.rollback()
                    LOGGER.error("Error occured during inserting to oval_criteria: \"%s\"", e)

            if crit.get("parent_criteria_id") is not None:
                dependencies_to_import.append((crit["parent_criteria_id"], criteria_id, None, None))
            else:
                top_criteria_id = criteria_id
            for test in crit["criterions"]:
                test_id = self.oval_rpminfo_test_map.get((oval_stream_id, test))
                module_test_id = self.oval_module_test_map.get((oval_stream_id, test))
                if test_id:  # Unsuported test type may not be imported (rpmverifyfile etc.)
                    dependencies_to_import.append((criteria_id, None, test_id[0], None))
                if module_test_id:
                    dependencies_to_import.append((criteria_id, None, None, module_test_id[0]))

            for child_crit in crit["criteria"]:
                child_crit["parent_criteria_id"] = criteria_id
                criteria_stack.append(child_crit)

            if criteria_stack:
                crit = criteria_stack.pop()
            else:
                crit = None

        return top_criteria_id

    def _populate_definitions(self, oval_stream_id: int, definitions: list):
        # Insert new CVEs
        to_insert = {(cve,) for definition in definitions for cve in definition["cves"] if cve not in self.cve_map}
        insert_table(self.con, "cve", ["name"], to_insert)
        if to_insert:  # Refresh cache
            self.cve_map = prepare_table_map(self.con, "cve", ["name"])

        # Insert/update/delete OVAL definitions
        oval_definition_map = prepare_table_map(self.con, "oval_definition", ["stream_id", "oval_id"],
                                                to_columns=["id", "definition_type_id", "criteria_id", "version"],
                                                where=f"stream_id = {oval_stream_id}")
        to_insert_oval_definition = set()
        to_update_oval_definition = set()
        to_create_criteria_tree = []
        for definition in definitions:
            definition_type_id = self.oval_definition_type_map.get(definition["type"])
            if definition_type_id is None:  # miscellaneous, skip
                continue
            if (oval_stream_id, definition["id"]) not in oval_definition_map:
                to_insert_oval_definition.add((oval_stream_id, definition["id"], definition_type_id, None, definition["version"]))
                to_create_criteria_tree.append((definition["id"], definition["criteria"]))
            elif definition["version"] > oval_definition_map[(oval_stream_id, definition["id"])][3]:  # Version increased -> update
                to_update_oval_definition.add((definition_type_id, None, definition["version"], oval_stream_id, definition["id"]))
                self._delete_definition_criteria_tree(oval_definition_map[(oval_stream_id, definition["id"])][0])  # Delete to re-build the tree
                to_create_criteria_tree.append((definition["id"]))
            oval_definition_map.pop((oval_stream_id, definition["id"]), None)  # Pop out visited items
        
        to_delete_oval_definition = set(oval_definition_map)  # Delete items in DB which are not in current data

        insert_table(self.con, "oval_definition", ["stream_id", "oval_id", "definition_type_id", "criteria_id", "version"],
                     to_insert_oval_definition)
        update_table(self.con, "oval_definition", ["definition_type_id", "criteria_id", "version"], ["stream_id", "oval_id"],
                     to_update_oval_definition)
        delete_table(self.con, "oval_definition", ["stream_id", "oval_id"], to_delete_oval_definition)

        # Refresh cache for future lookups
        self.oval_definition_map = prepare_table_map(self.con, "oval_definition", ["stream_id", "oval_id"],
                                                     to_columns=["id", "definition_type_id", "criteria_id", "version"],
                                                     where=f"stream_id = {oval_stream_id}")

        # Build criteria trees and assign to definitions
        dependencies_to_import = []
        for oval_id, criteria in to_create_criteria_tree:
            definition_id = self.oval_definition_map[(oval_stream_id, oval_id)][0]
            criteria_id = self._populate_definition_criteria(oval_stream_id, definition_id, criteria, dependencies_to_import)
            self._set_definition_criteria_tree(definition_id, criteria_id)
        # Import criteria dependencies
        insert_table(self.con, "oval_criteria_dependency", ["parent_criteria_id", "dep_criteria_id", "dep_test_id", "dep_module_test_id"],
                     dependencies_to_import)

        # Insert/delete definition tests, CVEs, CPEs
        to_insert_oval_definition_test = set()
        to_delete_oval_definition_test = set()
        to_insert_oval_definition_cve = set()
        to_delete_oval_definition_cve = set()
        to_insert_oval_definition_cpe = set()
        to_delete_oval_definition_cpe = set()
        for definition in definitions:
            definition_id = self.oval_definition_map.get((oval_stream_id, definition["id"]))
            if definition_id is None:  # Not inserted previously, probably unsupported type (miscellaneous)
                continue
            definition_id = definition_id[0]
            for test in definition["tests"]:
                test_id = self.oval_rpminfo_test_map.get((oval_stream_id, test))
                if test_id is None:  # Not inserted previously, probably unsupported type
                    continue
                test_id = test_id[0]
                if test_id not in self.oval_definition_test_map.get(definition_id, []):
                    to_insert_oval_definition_test.add((definition_id, test_id))
                else:
                    self.oval_definition_test_map[definition_id].remove(test_id)

            for test_id in self.oval_definition_test_map.get(definition_id, []):
                to_delete_oval_definition_test.add((definition_id, test_id))

            for cve in definition["cves"]:
                cve_id = self.cve_map[cve]
                if cve_id not in self.oval_definition_cve_map.get(definition_id, []):
                    to_insert_oval_definition_cve.add((definition_id, cve_id))
                else:
                    self.oval_definition_cve_map[definition_id].remove(cve_id)

            for cve_id in self.oval_definition_cve_map.get(definition_id, []):
                to_delete_oval_definition_cve.add((definition_id, cve_id))

            for cpe in definition["cpes"]:
                cpe_id = self.cpe_map.get(cpe)
                if cpe_id is None:  # Some CPEs are substrings which are not mapped by Repo-CPE map, unclear how to handle this
                    continue
                if cpe_id not in self.oval_definition_cpe_map.get(definition_id, []):
                    to_insert_oval_definition_cpe.add((definition_id, cpe_id))
                else:
                    self.oval_definition_cpe_map[definition_id].remove(cpe_id)
                
            for cpe_id in self.oval_definition_cpe_map.get(definition_id, []):
                to_delete_oval_definition_cpe.add((definition_id, cpe_id))

        insert_table(self.con, "oval_definition_test", ["definition_id", "rpminfo_test_id"], to_insert_oval_definition_test)
        delete_table(self.con, "oval_definition_test", ["definition_id", "rpminfo_test_id"], to_delete_oval_definition_test)
        insert_table(self.con, "oval_definition_cve", ["definition_id", "cve_id"], to_insert_oval_definition_cve)
        delete_table(self.con, "oval_definition_cve", ["definition_id", "cve_id"], to_delete_oval_definition_cve)
        insert_table(self.con, "oval_definition_cpe", ["definition_id", "cpe_id"], to_insert_oval_definition_cpe)
        delete_table(self.con, "oval_definition_cpe", ["definition_id", "cpe_id"], to_delete_oval_definition_cpe)

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
