import sqlite3

from vmaas_oval.common.logger import get_logger
from vmaas_oval.database.handler import SqliteConnection, SqliteCursor

LOGGER = get_logger(__name__)

TABLES = {
    "package_name":
        """
        CREATE TABLE IF NOT EXISTS package_name (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "evr":
        """
        CREATE TABLE IF NOT EXISTS evr (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            epoch TEXT NOT NULL,
            version TEXT NOT NULL,
            release TEXT NOT NULL,
            UNIQUE (epoch, version, release)
        )
        """,
    "arch":
        """
        CREATE TABLE IF NOT EXISTS arch (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "cve":
        """
        CREATE TABLE IF NOT EXISTS cve (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                name TEXT NOT NULL UNIQUE
        )
        """,
    "cpe":
        """
        CREATE TABLE IF NOT EXISTS cpe (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "content_set":
        """
        CREATE TABLE IF NOT EXISTS content_set (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "repo":
        """
        CREATE TABLE IF NOT EXISTS repo (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL,
            basearch_id INT NULL,
            releasever TEXT NULL,
            UNIQUE (name, basearch_id, releasever),
            CONSTRAINT basearch_id
                FOREIGN KEY (basearch_id)
                REFERENCES arch (id)
        )
        """,
    "cpe_content_set":
        """
        CREATE TABLE IF NOT EXISTS cpe_content_set (
            cpe_id INT NOT NULL,
            content_set_id INT NOT NULL,
            UNIQUE (cpe_id, content_set_id),
            CONSTRAINT cpe_id
                FOREIGN KEY (cpe_id)
                REFERENCES cpe (id),
            CONSTRAINT content_set_id
                FOREIGN KEY (content_set_id)
                REFERENCES content_set (id)
        )
        """,
    "cpe_repo":
        """
        CREATE TABLE IF NOT EXISTS cpe_repo (
            cpe_id INT NOT NULL,
            repo_id INT NOT NULL,
            UNIQUE (cpe_id, repo_id),
            CONSTRAINT cpe_id
                FOREIGN KEY (cpe_id)
                REFERENCES cpe (id),
            CONSTRAINT repo_id
                FOREIGN KEY (repo_id)
                REFERENCES repo (id)
        )
        """,
    "oval_operation_evr":
        """
        CREATE TABLE IF NOT EXISTS oval_operation_evr (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "oval_check_rpminfo":
        """
        CREATE TABLE IF NOT EXISTS oval_check_rpminfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "oval_check_existence_rpminfo":
        """
        CREATE TABLE IF NOT EXISTS oval_check_existence_rpminfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "oval_definition_type":
        """
        CREATE TABLE IF NOT EXISTS oval_definition_type (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "oval_criteria_operator":
        """
        CREATE TABLE IF NOT EXISTS oval_criteria_operator (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name TEXT NOT NULL UNIQUE
        )
        """,
    "oval_stream":
        """
        CREATE TABLE IF NOT EXISTS oval_stream (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            oval_id TEXT UNIQUE NOT NULL,
            updated TIMESTAMP WITH TIME ZONE NOT NULL
        )
        """,
    "oval_rpminfo_object":
        """
        CREATE TABLE IF NOT EXISTS oval_rpminfo_object (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            stream_id INT NOT NULL,
            oval_id TEXT NOT NULL,
            package_name_id INT NOT NULL,
            version INT NOT NULL,
            UNIQUE (stream_id, oval_id)
            CONSTRAINT stream_id
                FOREIGN KEY (stream_id)
                REFERENCES oval_stream (id),
            CONSTRAINT package_name_id
                FOREIGN KEY (package_name_id)
                REFERENCES package_name (id)
        )
        """,
    "oval_rpminfo_state":
        """
        CREATE TABLE IF NOT EXISTS oval_rpminfo_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            stream_id INT NOT NULL,
            oval_id TEXT NOT NULL,
            evr_id INT,
            evr_operation_id INT,
            version INT NOT NULL,
            UNIQUE (stream_id, oval_id)
            CONSTRAINT stream_id
                FOREIGN KEY (stream_id)
                REFERENCES oval_stream (id),
            CONSTRAINT evr_id
                FOREIGN KEY (evr_id)
                REFERENCES evr (id),
            CONSTRAINT evr_operation_id
                FOREIGN KEY (evr_operation_id)
                REFERENCES oval_operation_evr (id)
        )
        """,
    "oval_rpminfo_state_arch":
        """
        CREATE TABLE IF NOT EXISTS oval_rpminfo_state_arch (
            rpminfo_state_id INT NOT NULL,
            arch_id INT NOT NULL,
            UNIQUE (rpminfo_state_id, arch_id),
            CONSTRAINT rpminfo_state_id
                FOREIGN KEY (rpminfo_state_id)
                REFERENCES oval_rpminfo_state (id)
                ON DELETE CASCADE,
            CONSTRAINT arch_id
                FOREIGN KEY (arch_id)
                REFERENCES arch (id)
        )
        """,
    "oval_rpminfo_test":
        """
        CREATE TABLE IF NOT EXISTS oval_rpminfo_test (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            stream_id INT NOT NULL,
            oval_id TEXT NOT NULL,
            rpminfo_object_id INT NOT NULL,
            check_id INT NOT NULL,
            check_existence_id INT NOT NULL,
            version INT NOT NULL,
            UNIQUE (stream_id, oval_id)
            CONSTRAINT stream_id
                FOREIGN KEY (stream_id)
                REFERENCES oval_stream (id),
            CONSTRAINT rpminfo_object_id
                FOREIGN KEY (rpminfo_object_id)
                REFERENCES oval_rpminfo_object (id)
                ON DELETE CASCADE,
            CONSTRAINT check_id
                FOREIGN KEY (check_id)
                REFERENCES oval_check_rpminfo (id),
            CONSTRAINT check_existence_id
                FOREIGN KEY (check_existence_id)
                REFERENCES oval_check_existence_rpminfo (id)
        )
        """,
    "oval_module_test":
        """
        CREATE TABLE IF NOT EXISTS oval_module_test (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            stream_id INT NOT NULL,
            oval_id TEXT NOT NULL,
            module_stream TEXT NOT NULL,
            version INT NOT NULL,
            UNIQUE (stream_id, oval_id)
            CONSTRAINT stream_id
                FOREIGN KEY (stream_id)
                REFERENCES oval_stream (id)
        )
        """,
    "oval_rpminfo_test_state":
        """
        CREATE TABLE IF NOT EXISTS oval_rpminfo_test_state (
            rpminfo_test_id INT NOT NULL,
            rpminfo_state_id INT NOT NULL,
            UNIQUE (rpminfo_test_id, rpminfo_state_id),
            CONSTRAINT rpminfo_test_id
                FOREIGN KEY (rpminfo_test_id)
                REFERENCES oval_rpminfo_test (id)
                ON DELETE CASCADE,
            CONSTRAINT rpminfo_state_id
                FOREIGN KEY (rpminfo_state_id)
                REFERENCES oval_rpminfo_state (id)
                ON DELETE CASCADE
        )
        """,
    "oval_criteria":
        """
        CREATE TABLE IF NOT EXISTS oval_criteria (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            definition_id INT NOT NULL,
            operator_id INT NOT NULL,
            CONSTRAINT definition_id
                FOREIGN KEY (definition_id)
                REFERENCES oval_definition (id)
                ON DELETE CASCADE,
            CONSTRAINT operator_id
                FOREIGN KEY (operator_id)
                REFERENCES oval_criteria_operator (id)
        )
        """,
    "oval_criteria_dependency":
        """
        CREATE TABLE IF NOT EXISTS oval_criteria_dependency (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            parent_criteria_id INT NOT NULL,
            dep_criteria_id INT,
            dep_test_id INT,
            dep_module_test_id INT,
            CONSTRAINT parent_criteria_id
                FOREIGN KEY (parent_criteria_id)
                REFERENCES oval_criteria (id)
                ON DELETE CASCADE,
            CONSTRAINT dep_criteria_id
                FOREIGN KEY (dep_criteria_id)
                REFERENCES oval_criteria (id)
                ON DELETE CASCADE,
            CONSTRAINT dep_test_id
                FOREIGN KEY (dep_test_id)
                REFERENCES oval_rpminfo_test (id)
                ON DELETE CASCADE
            CONSTRAINT dep_module_test_id
                FOREIGN KEY (dep_module_test_id)
                REFERENCES oval_module_test (id)
                ON DELETE CASCADE
        )
        """,
    "oval_definition":
        """
        CREATE TABLE IF NOT EXISTS oval_definition (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            stream_id INT NOT NULL,
            oval_id TEXT NOT NULL,
            definition_type_id INT NOT NULL,
            criteria_id INT,
            version INT NOT NULL,
            UNIQUE (stream_id, oval_id)
            CONSTRAINT stream_id
                FOREIGN KEY (stream_id)
                REFERENCES oval_stream (id),
            CONSTRAINT definition_type_id
                FOREIGN KEY (definition_type_id)
                REFERENCES oval_definition_type (id),
            CONSTRAINT criteria_id
                FOREIGN KEY (criteria_id)
                REFERENCES oval_criteria (id)
        )
        """,
    "oval_definition_test":
        """
        CREATE TABLE IF NOT EXISTS oval_definition_test (
            definition_id INT NOT NULL,
            rpminfo_test_id INT NOT NULL,
            UNIQUE (definition_id, rpminfo_test_id),
            CONSTRAINT definition_id
                FOREIGN KEY (definition_id)
                REFERENCES oval_definition (id)
                ON DELETE CASCADE,
            CONSTRAINT rpminfo_test_id
                FOREIGN KEY (rpminfo_test_id)
                REFERENCES oval_rpminfo_test (id)
                ON DELETE CASCADE
        )
        """,
    "oval_definition_cve":
        """
        CREATE TABLE IF NOT EXISTS oval_definition_cve (
            definition_id INT NOT NULL,
            cve_id INT NOT NULL,
            UNIQUE (definition_id, cve_id),
            CONSTRAINT definition_id
                FOREIGN KEY (definition_id)
                REFERENCES oval_definition (id)
                ON DELETE CASCADE,
            CONSTRAINT cve_id
                FOREIGN KEY (cve_id)
                REFERENCES cve (id)
        )
        """,
    "oval_definition_cpe":
        """
        CREATE TABLE IF NOT EXISTS oval_definition_cpe (
            definition_id INT NOT NULL,
            cpe_id INT NOT NULL,
            UNIQUE (definition_id, cpe_id),
            CONSTRAINT definition_id
                FOREIGN KEY (definition_id)
                REFERENCES oval_definition (id)
                ON DELETE CASCADE,
            CONSTRAINT cpe_id
                FOREIGN KEY (cpe_id)
                REFERENCES cpe (id)
        )
        """
}

DATA = {
    "arch":
        """
        INSERT INTO arch (id, name) VALUES (1, 'noarch'), (2, 'i386'), (3, 'i486'), (4, 'i586'), (5, 'i686'), (6, 'alpha'),
        (7, 'alphaev6'), (8, 'ia64'), (9, 'sparc'), (10, 'sparcv9'), (11, 'sparc64'), (12, 's390'), (13, 'athlon'), (14, 's390x'),
        (15, 'ppc'), (16, 'ppc64'), (17, 'ppc64le'), (18, 'pSeries'), (19, 'iSeries'), (20, 'x86_64'), (21, 'ppc64iseries'),
        (22, 'ppc64pseries'), (23, 'ia32e'), (24, 'amd64'), (25, 'aarch64'), (26, 'armv7hnl'), (27, 'armv7hl'), (28, 'armv7l'),
        (29, 'armv6hl'), (30, 'armv6l'), (31, 'armv5tel'), (32, 'src')
        ON CONFLICT (id) DO NOTHING
        """,
    "oval_operation_evr":
        """
        INSERT INTO oval_operation_evr (id, name) VALUES (1, 'equals'), (2, 'less than')
        ON CONFLICT (id) DO NOTHING
        """,
    "oval_check_rpminfo":
        """
        INSERT INTO oval_check_rpminfo (id, name) VALUES (1, 'at least one')
        ON CONFLICT (id) DO NOTHING
        """,
    "oval_check_existence_rpminfo":
        """
        INSERT INTO oval_check_existence_rpminfo (id, name) VALUES (1, 'at_least_one_exists'), (2, 'none_exist')
        ON CONFLICT (id) DO NOTHING
        """,
    "oval_definition_type":
        """
        INSERT INTO oval_definition_type (id, name) VALUES (1, 'patch'), (2, 'vulnerability')
        ON CONFLICT (id) DO NOTHING
        """,
    "oval_criteria_operator":
        """
        INSERT INTO oval_criteria_operator (id, name) VALUES (1, 'AND'), (2, 'OR')
        ON CONFLICT (id) DO NOTHING
        """,
}


def initialize_schema(db_file_name: str) -> None:
    LOGGER.info("Initializing schema in DB")
    with SqliteConnection(db_file_name) as con:
        with SqliteCursor(con) as cur:
            try:
                for table, sql in TABLES.items():
                    LOGGER.debug("Ensuring table exists: %s", table)
                    cur.execute(sql)
                for table, sql in DATA.items():
                    LOGGER.debug("Ensuring static data in table exist: %s", table)
                    cur.execute(sql)
                con.commit()
                LOGGER.info("DB schema initialization completed")
            except sqlite3.DatabaseError as e:
                con.rollback()
                LOGGER.error("Error occured during initializing DB: \"%s\"", e)
