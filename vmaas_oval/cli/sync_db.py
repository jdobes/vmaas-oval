import argparse

from vmaas_oval.sync import sync_data
from vmaas_oval.utils import init_logging


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Populate data into DB schema.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--file", help="sqlite DB file path", default="data.sqlite")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    sync_data(args.file)
