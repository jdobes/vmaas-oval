import argparse
from json import JSONDecodeError

from aiohttp import web

from vmaas_oval.common.logger import get_logger, init_logging
from vmaas_oval.database.handler import SqliteConnection
from vmaas_oval.evaluator.cache import Cache
from vmaas_oval.evaluator.vulnerabilities import VulnerabilitiesEvaluator

LOGGER = get_logger(__name__)


class VulnerabilitiesHandler:
    evaluator = None

    @classmethod
    async def post_handler(cls, request):
        try:
            data = await request.json()
        except JSONDecodeError:
            return web.json_response({"error": "Request is not a JSON."}, status=400)
        result = cls.evaluator.process_list(data)
        return web.json_response(result)

app = web.Application()
app.add_routes([web.post('/vulnerabilities', VulnerabilitiesHandler.post_handler)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run evaluator.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--database", default="database.sqlite", help="sqlite DB file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    init_logging(verbose=args.verbose)
    LOGGER.info("Sqlite DB file: %s", args.database)
    with SqliteConnection(args.database) as con:
        VulnerabilitiesHandler.evaluator = VulnerabilitiesEvaluator(Cache(con))
        web.run_app(app, port=8000)
