import json


class RepoCpeMap:
    def __init__(self, file_name: str, arch_map: dict):
        with open(file_name, 'r', encoding='utf8') as repo_cpe_file:
            data = json.load(repo_cpe_file)

        self.cpes = set()
        self.content_sets = set()
        self.repos = set()
        self.content_set_to_cpes = {}
        self.repo_to_cpes = {}

        for repo_label in data["data"]:
            repo_label_parts = repo_label.split("__")
            content_set_label = repo_label_parts[0]
            basearch = None
            releasever = None
            if len(repo_label_parts) > 1:
                for part in repo_label_parts[1:]:
                    part = part.replace("_DOT_", ".")
                    if part in arch_map:
                        basearch = part
                    else:
                        releasever = part
            cpes = data["data"][repo_label]["cpes"]

            self.cpes.update(cpes)
            if basearch or releasever:
                self.repos.add((content_set_label, basearch, releasever))
                self.repo_to_cpes[(content_set_label, basearch, releasever)] = cpes
            else:
                self.content_sets.add(content_set_label)
                self.content_set_to_cpes[content_set_label] = cpes
