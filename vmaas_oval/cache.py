from .database import DatabaseHandler
from .utils import init_logging, get_logger


class Cache:
    def __init__(self, db_handler: DatabaseHandler):
        self.logger = get_logger(self.__class__.__name__)
        self.db_handler = db_handler

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

    def _load_evr(self):
        columns = ["id", "epoch", "version", "release"]
        for evr_id, epoch, version, release in self.db_handler.fetch_data("evr", columns):
            self.id_to_evr[evr_id] = (epoch, version, release)
            self.evr_to_id[(epoch, version, release)] = evr_id

    def _load_cache(self):
        self._load_evr()


if __name__ == "__main__":
    init_logging()
    db_handler = DatabaseHandler()
    cache = Cache(db_handler)
    print(cache.id_to_evr)
    print(cache.evr_to_id)
