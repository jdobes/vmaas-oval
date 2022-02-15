from datetime import datetime


def parse_datetime_iso(datetime_str: str) -> datetime:
    return datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S%z")


def parse_datetime_sqlite(datetime_str: str) -> datetime:
    return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S%z")
