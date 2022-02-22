from vmaas_oval.common.logger import get_logger
from vmaas_oval.common.rpm import parse_rpm_name, rpmver2array
from vmaas_oval.evaluator.cache import Cache

LOGGER = get_logger(__name__)

OVAL_OPERATION_EVR_EQUALS = 1
OVAL_OPERATION_EVR_LESS_THAN = 2

OVAL_CHECK_EXISTENCE_AT_LEAST_ONE = 1
OVAL_CHECK_EXISTENCE_NONE = 2

OVAL_DEFINITION_TYPE_PATCH = 1
OVAL_DEFINITION_TYPE_VULNERABILITY = 2

OVAL_CRITERIA_OPERATOR_AND = 1
OVAL_CRITERIA_OPERATOR_OR = 2


class VulnerabilitiesEvaluator:
    def __init__(self, cache: Cache):
        self.cache = cache

    def _process_input_packages(self, packages_to_process: list) -> dict:
        filtered_packages_to_process = {}
        if packages_to_process is not None:
            for pkg in packages_to_process:
                name, epoch, ver, rel, arch = parse_rpm_name(pkg)
                if name in self.cache.packagename2id:
                    filtered_packages_to_process[pkg] = (name, epoch, ver, rel, arch)
        return filtered_packages_to_process

    def _evaluate_state(self, state: tuple, epoch: int, ver: str, rel: str, arch: str):
        oval_state_id, evr_id, oval_operation_evr = state
        matched = False

        candidate_epoch, candidate_ver, candidate_rel = self.cache.id2evr[evr_id]
        if oval_operation_evr == OVAL_OPERATION_EVR_EQUALS:
            matched = epoch == candidate_epoch and ver == candidate_ver and rel == candidate_rel
        elif oval_operation_evr == OVAL_OPERATION_EVR_LESS_THAN:
            epoch = rpmver2array(epoch)
            candidate_epoch = rpmver2array(candidate_epoch)
            ver = rpmver2array(ver)
            candidate_ver = rpmver2array(candidate_ver)
            rel = rpmver2array(rel)
            candidate_rel = rpmver2array(candidate_rel)

            matched = ((epoch < candidate_epoch) or
                       (epoch == candidate_epoch and ver < candidate_ver) or
                       (epoch == candidate_epoch and ver == candidate_ver and rel < candidate_rel))
        else:
            raise ValueError("Unsupported oval_operation_evr: %s" % oval_operation_evr)

        candidate_arches = self.cache.ovalstate_id2arches.get(oval_state_id, [])
        if candidate_arches:
            matched = matched and self.cache.arch2id[arch] in candidate_arches

        LOGGER.debug("Evaluated state id=%s, candidate_evr_id=%s, operation=%s, matched=%s",
                     oval_state_id, evr_id, oval_operation_evr, matched)
        return matched

    def _evaluate_module_test(self, module_test_id: int, modules_list: set):
        return self.cache.ovalmoduletest_detail[module_test_id] in modules_list

    def _evaluate_test(self, test_id: int, nevra: tuple):
        package_name_id, epoch, ver, rel, arch = nevra
        candidate_package_name_id, check_existence = self.cache.ovaltest_detail[test_id]

        matched = False
        package_name_matched = package_name_id == candidate_package_name_id
        if check_existence == OVAL_CHECK_EXISTENCE_AT_LEAST_ONE:
            states = self.cache.ovaltest_id2states.get(test_id, [])
            if package_name_matched and states:
                for state in states:
                    if self._evaluate_state(state, epoch, ver, rel, arch):
                        matched = True
                        break  # at least one
            else:
                matched = package_name_matched
        elif check_existence == OVAL_CHECK_EXISTENCE_NONE:
            matched = not package_name_matched
        else:
            raise ValueError("Unsupported check_existence: %s" % check_existence)

        LOGGER.debug("Evaluated test id=%s, package=%s, candidate_package=%s, check_existence=%s, matched=%s",
                     test_id, package_name_id, candidate_package_name_id, check_existence, matched)
        return matched

    def _evaluate_criteria(self, criteria_id: int, nevra: tuple, modules_list: set):
        module_test_deps = self.cache.ovalcriteria_id2depmoduletest_ids.get(criteria_id, [])
        test_deps = self.cache.ovalcriteria_id2deptest_ids.get(criteria_id, [])
        criteria_deps = self.cache.ovalcriteria_id2depcriteria_ids.get(criteria_id, [])

        criteria_type = self.cache.ovalcriteria_id2type[criteria_id]
        if criteria_type == OVAL_CRITERIA_OPERATOR_AND:
            required_matches = len(module_test_deps) + len(test_deps) + len(criteria_deps)
            must_match = True
        elif criteria_type == OVAL_CRITERIA_OPERATOR_OR:
            required_matches = min(1, (len(module_test_deps) + len(test_deps) + len(criteria_deps)))
            must_match = False
        else:
            raise ValueError("Unsupported operator: %s" % criteria_type)

        matches = 0

        for module_test_id in module_test_deps:
            if matches >= required_matches:
                break
            if self._evaluate_module_test(module_test_id, modules_list):
                matches += 1
            elif must_match:  # AND
                break

        for test_id in test_deps:
            if matches >= required_matches:
                break
            if self._evaluate_test(test_id, nevra):
                matches += 1
            elif must_match:  # AND
                break

        for dep_criteria_id in criteria_deps:
            if matches >= required_matches:
                break
            if self._evaluate_criteria(dep_criteria_id, nevra, modules_list):
                matches += 1
            elif must_match:  # AND
                break

        LOGGER.debug("Evaluated criteria id=%s, type=%s, matched=%s", criteria_id, criteria_type,
                     matches >= required_matches)
        return matches >= required_matches

    def _repos_to_definitions(self, content_set_list: list, basearch: str, releasever: str):
        # TODO: some CPEs are not matching because they are substrings/subtrees
        repo_ids = set()
        content_set_ids = set()
        # Try to identify repos (CS+basearch+releasever) or at least CS
        for label in content_set_list:
            if basearch or releasever:
                basearch_id = self.cache.arch2id.get(basearch)
                repo_id = self.cache.repo2id.get((label, basearch_id, releasever))
                if repo_id:
                    repo_ids.add(repo_id)
            if label in self.cache.label2content_set_id:
                content_set_ids.add(self.cache.label2content_set_id[label])

        cpe_ids = set()
        if repo_ids:  # Check CPE-Repo mapping first
            for repo_id in repo_ids:
                if repo_id in self.cache.repo_id2cpe_ids:
                    cpe_ids.update(self.cache.repo_id2cpe_ids[repo_id])

        if not cpe_ids:  # No CPE-Repo mapping? Use CPE-CS mapping
            for content_set_id in content_set_ids:
                if content_set_id in self.cache.content_set_id2cpe_ids:
                    cpe_ids.update(self.cache.content_set_id2cpe_ids[content_set_id])

        candidate_definitions = set()
        for cpe_id in cpe_ids:
            if cpe_id in self.cache.cpe_id2ovaldefinition_ids:
                candidate_definitions.update(self.cache.cpe_id2ovaldefinition_ids[cpe_id])
        return candidate_definitions

    def process_list(self, data: dict):
        cves_final = set()
        unpatched_cves_final = set()

        packages_to_process = self._process_input_packages(data.get('package_list'))
        modules_list = {f"{x['module_name']}:{x['module_stream']}" for x in data.get('modules_list', [])}

        # Get CPEs for affected repos/content sets
        candidate_definitions = self._repos_to_definitions(data.get('repository_list', []),
                                                           data.get('basearch'),
                                                           data.get('releasever'))

        for package, parsed_package in packages_to_process.items():
            name, epoch, ver, rel, arch = parsed_package
            package_name_id = self.cache.packagename2id[name]
            definition_ids = candidate_definitions.intersection(
                self.cache.packagename_id2definition_ids.get(package_name_id, []))
            LOGGER.debug("OVAL definitions found for package_name=%s, count=%s", name, len(definition_ids))
            for definition_id in definition_ids:
                definition_type, criteria_id = self.cache.ovaldefinition_detail[definition_id]
                cves = self.cache.ovaldefinition_id2cves.get(definition_id, [])
                # Skip if all CVEs from definition were already found somewhere
                if not [cve for cve in cves
                        if cve not in cves_final and
                        cve not in unpatched_cves_final]:
                    continue

                if self._evaluate_criteria(criteria_id, (package_name_id, epoch, ver, rel, arch), modules_list):
                    # Vulnerable
                    LOGGER.debug("Definition id=%s, type=%s matched! Adding CVEs.", definition_id, definition_type)
                    if definition_type == OVAL_DEFINITION_TYPE_PATCH:
                        cves_final.update(cves)
                    elif definition_type == OVAL_DEFINITION_TYPE_VULNERABILITY:
                        for cve in cves:
                            # Skip fixable CVEs (should never happen, just in case)
                            if cve in cves_final:
                                continue
                            unpatched_cves_final.add(cve)
                    else:
                        raise ValueError("Unsupported definition type: %s" % definition_type)

        return {"cve_list": list(cves_final), "unpatched_cve_list": list(unpatched_cves_final)}
