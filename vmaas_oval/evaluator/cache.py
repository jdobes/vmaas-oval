import array

from vmaas_oval.database.handler import SqliteConnection
from vmaas_oval.common.logger import get_logger

LOGGER = get_logger(__name__)


class Cache:
    def __init__(self, con: SqliteConnection):
        self.con = con

        self.arch2id = {}
        self.id2arch = {}
        self.packagename2id = {}
        self.id2evr = {}
        self.repo2id = {}
        self.label2content_set_id = {}
        self.repo_id2cpe_ids = {}
        self.content_set_id2cpe_ids = {}
        self.cpe_id2ovaldefinition_ids = {}
        self.packagename_id2definition_ids = {}
        self.ovaldefinition_detail = {}
        self.ovaldefinition_id2cves = {}
        self.ovalcriteria_id2type = {}
        self.ovalcriteria_id2depcriteria_ids = {}
        self.ovalcriteria_id2deptest_ids = {}
        self.ovalcriteria_id2depmoduletest_ids = {}
        self.ovaltest_detail = {}
        self.ovaltest_id2states = {}
        self.ovalmoduletest_detail = {}
        self.ovalstate_id2arches = {}

        self._load_cache()

    def _load_cache(self) -> None:
        LOGGER.info("Loading sqlite cache dump...")
        for (id, name) in self.con.execute("select id, name from arch"):
            self.id2arch[id] = name
            self.arch2id[name] = id
        for (id, name) in self.con.execute("select id, name from package_name"):
            self.packagename2id[name] = id
        for (id, epoch, version, release) in self.con.execute("select id, epoch, version, release from evr"):
            self.id2evr[id] = (epoch, version, release)
        for (id, name, basearch_id, releasever) in self.con.execute("select id, name, basearch_id, releasever from repo"):
            self.repo2id[(name, basearch_id, releasever)] = id
        for (id, name) in self.con.execute("select id, name from content_set"):
            self.label2content_set_id[name] = id
        for (cpe_id, repo_id) in self.con.execute("select cpe_id, repo_id from cpe_repo"):
            self.repo_id2cpe_ids.setdefault(repo_id, array.array('q')).append(cpe_id)
        for (cpe_id, cs_id) in self.con.execute("select cpe_id, content_set_id from cpe_content_set"):
            self.content_set_id2cpe_ids.setdefault(cs_id, array.array('q')).append(cpe_id)
        for (cpe_id, definition_id) in self.con.execute("select cpe_id, definition_id from oval_definition_cpe"):
            self.cpe_id2ovaldefinition_ids.setdefault(cpe_id, array.array('q')).append(definition_id)
        for (package_name_id, definition_id) in self.con.execute(
                """select distinct o.package_name_id, d.id
                    from oval_definition d join
                    oval_definition_test dt on d.id = dt.definition_id join
                    oval_rpminfo_test t on dt.rpminfo_test_id = t.id join
                    oval_rpminfo_object o on t.rpminfo_object_id = o.id
                """):
            self.packagename_id2definition_ids.setdefault(package_name_id, array.array('q')).append(definition_id)
        for (id, definition_type_id, criteria_id) in self.con.execute("select id, definition_type_id, criteria_id from oval_definition"):
            self.ovaldefinition_detail[id] = (definition_type_id, criteria_id)
        for (definition_id, cve) in self.con.execute("select dc.definition_id, cve.name from oval_definition_cve dc join cve on dc.cve_id = cve.id"):
            self.ovaldefinition_id2cves.setdefault(definition_id, []).append(cve)
        for (id, operator_id) in self.con.execute("select id, operator_id from oval_criteria"):
            self.ovalcriteria_id2type[id] = operator_id
        for (parent_criteria_id, dep_criteria_id, dep_test_id, dep_module_test_id) in self.con.execute(
                "select parent_criteria_id, dep_criteria_id, dep_test_id, dep_module_test_id from oval_criteria_dependency"):
            if dep_test_id is None and dep_module_test_id is None:
                self.ovalcriteria_id2depcriteria_ids.setdefault(parent_criteria_id, array.array('q')).append(dep_criteria_id)
            elif dep_criteria_id is None and dep_module_test_id is None:
                self.ovalcriteria_id2deptest_ids.setdefault(parent_criteria_id, array.array('q')).append(dep_test_id)
            else:
                self.ovalcriteria_id2depmoduletest_ids.setdefault(parent_criteria_id, array.array('q')).append(dep_module_test_id)
        for id, package_name_id, check_existence_id in self.con.execute(
                """select t.id, o.package_name_id, t.check_existence_id
                    from oval_rpminfo_test t join
                    oval_rpminfo_object o on t.rpminfo_object_id = o.id
                """):
            self.ovaltest_detail[id] = (package_name_id, check_existence_id)
        for test_id, state_id, evr_id, evr_operation_id in self.con.execute(
                """select ts.rpminfo_test_id, s.id, s.evr_id, s.evr_operation_id
                    from oval_rpminfo_test_state ts join
                    oval_rpminfo_state s on ts.rpminfo_state_id = s.id
                    where s.evr_id is not null
                    and s.evr_operation_id is not null
                """):
            self.ovaltest_id2states.setdefault(test_id, []).append((state_id, evr_id, evr_operation_id))
        for id, module_stream in self.con.execute("select id, module_stream from oval_module_test"):
            self.ovalmoduletest_detail[id] = module_stream
        for rpminfo_state_id, arch_id in self.con.execute("select rpminfo_state_id, arch_id from oval_rpminfo_state_arch"):
            self.ovalstate_id2arches.setdefault(rpminfo_state_id, set()).add(arch_id)
        LOGGER.info("Loaded cache.")
