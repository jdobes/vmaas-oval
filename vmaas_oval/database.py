import sqlite3

from .utils import init_logging, get_logger


class DatabaseHandler:
    TABLES = {
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
        "package_name":
            """
            CREATE TABLE IF NOT EXISTS package_name (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              name TEXT NOT NULL UNIQUE
            )
            """,
        "package":
            """
            CREATE TABLE IF NOT EXISTS package (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              name_id INT NOT NULL,
              evr_id INT NOT NULL,
              arch_id INT NOT NULL,
              summary TEXT NULL,
              description TEXT NULL,
              UNIQUE (name_id, evr_id, arch_id),
              CONSTRAINT name_id
                FOREIGN KEY (name_id)
                REFERENCES package_name (id),
              CONSTRAINT evr_id
                FOREIGN KEY (evr_id)
                REFERENCES evr (id),
              CONSTRAINT arch_id
                FOREIGN KEY (arch_id)
                REFERENCES arch (id)
            )
            """,
        "cve":
            """
            CREATE TABLE IF NOT EXISTS cve (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                name TEXT NOT NULL UNIQUE
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
        "oval_file":
            """
            CREATE TABLE IF NOT EXISTS oval_file (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              oval_id TEXT UNIQUE NOT NULL,
              updated TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
        "oval_rpminfo_object":
            """
            CREATE TABLE IF NOT EXISTS oval_rpminfo_object (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              oval_id TEXT UNIQUE NOT NULL,
              package_name_id INT NOT NULL,
              version INT NOT NULL,
              CONSTRAINT package_name_id
                FOREIGN KEY (package_name_id)
                REFERENCES package_name (id)
            )
            """,
        "oval_rpminfo_state":
            """
            CREATE TABLE IF NOT EXISTS oval_rpminfo_state (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              oval_id TEXT UNIQUE NOT NULL,
              evr_id INT,
              evr_operation_id INT,
              version INT NOT NULL,
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
                REFERENCES oval_rpminfo_state (id),
              CONSTRAINT arch_id
                FOREIGN KEY (arch_id)
                REFERENCES arch (id)
            )
            """,
        "oval_rpminfo_test":
            """
            CREATE TABLE IF NOT EXISTS oval_rpminfo_test (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              oval_id TEXT UNIQUE NOT NULL,
              rpminfo_object_id INT NOT NULL,
              check_id INT NOT NULL,
              check_existence_id INT NOT NULL,
              version INT NOT NULL,
              CONSTRAINT rpminfo_object_id
                FOREIGN KEY (rpminfo_object_id)
                REFERENCES oval_rpminfo_object (id),
              CONSTRAINT check_id
                FOREIGN KEY (check_id)
                REFERENCES oval_check_rpminfo (id),
              CONSTRAINT check_existence_id
                FOREIGN KEY (check_existence_id)
                REFERENCES oval_check_existence_rpminfo (id)
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
                REFERENCES oval_rpminfo_test (id),
              CONSTRAINT rpminfo_state_id
                FOREIGN KEY (rpminfo_state_id)
                REFERENCES oval_rpminfo_state (id)
            )
            """,
        "oval_criteria":
            """
            CREATE TABLE IF NOT EXISTS oval_criteria (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              operator_id INT NOT NULL,
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
              CONSTRAINT parent_criteria_id
                FOREIGN KEY (parent_criteria_id)
                REFERENCES oval_criteria (id),
              CONSTRAINT dep_criteria_id
                FOREIGN KEY (dep_criteria_id)
                REFERENCES oval_criteria (id),
              CONSTRAINT dep_test_id
                FOREIGN KEY (dep_test_id)
                REFERENCES oval_rpminfo_test (id)
            )
            """,
        "oval_definition":
            """
            CREATE TABLE IF NOT EXISTS oval_definition (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              oval_id TEXT UNIQUE NOT NULL,
              definition_type_id INT NOT NULL,
              criteria_id INT,
              version INT NOT NULL,
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
                REFERENCES oval_definition (id),
              CONSTRAINT rpminfo_test_id
                FOREIGN KEY (rpminfo_test_id)
                REFERENCES oval_rpminfo_test (id)
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
                REFERENCES oval_definition (id),
              CONSTRAINT cve_id
                FOREIGN KEY (cve_id)
                REFERENCES cve (id)
            )
            """
    }

    DATA = {
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

    def __init__(self, db_file_name: str = "data.db"):
        self.logger = get_logger(self.__class__.__name__)
        self.db_file_name = db_file_name

    def initialize_db(self):
        con = sqlite3.connect(self.db_file_name)
        try:
            with con:
                con.execute("PRAGMA foreign_keys = ON")
                for table, sql in self.TABLES.items():
                    self.logger.info("Ensuring table exists: %s", table)
                    con.execute(sql)
                for table, sql in self.DATA.items():
                    self.logger.info("Ensuring static data in table exist: %s", table)
                    con.execute(sql)
        except sqlite3.DatabaseError as e:
            self.logger.error("Error occured during initializing DB: \"%s\"", e)
        con.close()
    
    def fetch_data(self, table_name: str, columns: list) -> list:
        data = []
        con = sqlite3.connect(self.db_file_name)
        try:
            with con:
                con.execute("PRAGMA foreign_keys = ON")
                data = list(con.execute(f"SELECT {', '.join(columns)} FROM {table_name}"))
        except sqlite3.DatabaseError as e:
            self.logger.error("Error occured during fetching data from DB: \"%s\"", e)
        con.close()
        return data


if __name__ == "__main__":
    init_logging()
    db_handler = DatabaseHandler()
    db_handler.initialize_db()
    data = db_handler.fetch_data("oval_criteria_operator", ["id", "name"])
    print(data)
