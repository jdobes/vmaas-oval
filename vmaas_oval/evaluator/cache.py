from vmaas_oval.database.handler import SqliteConnection
from vmaas_oval.common.logger import get_logger

LOGGER = get_logger(__name__)


class Cache:
    def __init__(self, con: SqliteConnection):
        self.con = con

        self.id_to_evr = {}
        self.evr_to_id = {}
        self.id_to_arch = {}
        self.arch_to_id = {}
        self.id_to_package_name = {}
        self.package_name_to_id = {}
        self.id_to_package = {}
        self.package_to_id = {}
        self.id_to_cve = {}
        self.cve_to_id = {}
        self.id_to_oval_operation_evr = {}
        self.oval_operation_evr_to_id = {}
        self.id_to_oval_check_rpminfo = {}
        self.oval_check_rpminfo_to_id = {}
        self.id_to_oval_check_existence_rpminfo = {}
        self.oval_check_existence_rpminfo_to_id = {}
        self.id_to_oval_definition_type = {}
        self.oval_definition_type_to_id = {}
        self.id_to_oval_criteria_operator = {}
        self.oval_criteria_operator_to_id = {}
        self.id_to_oval_file = {}
        #self.oval_file_to_id = {}
        self.id_to_oval_rpminfo_object = {}
        self.oval_rpminfo_object_to_id = {}
        self.id_to_oval_rpminfo_state = {}
        self.oval_rpminfo_state_to_id = {}
        #self.id_to_oval_rpminfo_state_arch = {}
        #self.oval_rpminfo_state_arch_to_id = {}
        self.id_to_oval_rpminfo_test = {}
        self.oval_rpminfo_test_to_id = {}
        #self.id_to_oval_rpminfo_test_state = {}
        #self.oval_rpminfo_test_state_to_id = {}
        self.id_to_oval_criteria = {}
        #self.oval_criteria_to_id = {}
        self.id_to_oval_criteria_dependency = {}
        #self.oval_criteria_dependency_to_id = {}
        self.id_to_oval_definition = {}
        self.oval_definition_to_id = {}
        #self.id_to_oval_definition_test = {}
        #self.oval_definition_test_to_id = {}
        #self.id_to_oval_definition_cve = {}
        #self.oval_definition_cve_to_id = {}

        self._load_cache()

    def _load_evr(self) -> None:
        columns = ["id", "epoch", "version", "release"]

    def _load_cache(self) -> None:
        self._load_evr()
