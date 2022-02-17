import re
from typing import Optional

EVR_RE = re.compile(
    r'((?P<e2>[0-9]+):)?(?P<ver>[^-:]+)-(?P<rel>[^-:]+)')
NEVRA_RE = re.compile(
    r'((?P<e1>[0-9]+):)?(?P<pn>[^:]+)(?(e1)-|-((?P<e2>[0-9]+):)?)(?P<ver>[^-:]+)-(?P<rel>[^-:]+)\.(?P<arch>[a-z0-9_]+)')


def parse_evr(evr: str) -> Optional[tuple]:
    match = EVR_RE.match(evr)
    if not match:
        return None

    epoch = match.group('e2')
    if not epoch:
        epoch = "0"
    version = match.group('ver')
    release = match.group('rel')
    return epoch, version, release


def parse_rpm_name(rpm_name: str) -> Optional[tuple]:
    if rpm_name[-4:] == '.rpm':
        rpm_name = rpm_name[:-4]

    match = NEVRA_RE.match(rpm_name)
    if not match:
        return None

    name = match.group('pn')
    epoch = match.group('e1')
    if not epoch:
        epoch = match.group('e2')
    if not epoch:
        epoch = "0"
    version = match.group('ver')
    release = match.group('rel')
    arch = match.group('arch')
    return name, epoch, version, release, arch
