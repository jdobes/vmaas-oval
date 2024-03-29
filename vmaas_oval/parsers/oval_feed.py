import os
import json

from vmaas_oval.common.constants import OVAL_FEED_BASE_URL
from vmaas_oval.common.dateutils import parse_datetime_iso


class OvalFeed:
    def __init__(self, file_name: str):
        with open(file_name, 'r', encoding='utf8') as feed_file:
            data = json.load(feed_file)

        self.streams_count = len(data["feed"]["entry"])
        self.streams_url = {}
        self.streams_local_path = {}
        self.streams_updated = {}

        metadata_dir = os.path.dirname(file_name)
        for entry in data["feed"]["entry"]:
            self.streams_url[entry["id"]] = entry["content"]["src"]
            self.streams_local_path[entry["id"]] = os.path.join(metadata_dir, entry["content"]["src"].replace(OVAL_FEED_BASE_URL, ""))
            self.streams_updated[entry["id"]] = parse_datetime_iso(entry["updated"])
