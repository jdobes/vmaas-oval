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


def rpmver2array(rpm_version: str) -> list:
    """
    Convert RPM version string to comparable array
    of (num, word) tuples.
    Example: '1a' -> [(1,''),(0,'a'),(-2,'')]
    """

    parsed_arr = re.findall(r"(~*)(([A-Za-z]+)|(\d+))(\^*)",
                            rpm_version)  # parse all letters and digits with or without ~ or ^ to
    arr = []
    for til, _, word, num_str, cir in parsed_arr:
        if til != '':
            num = -2              # set num lower if it's after "~" than default (-1)
        elif num_str != '':
            num = int(num_str)    # use parsed number if found
        else:
            num = 0               # for letter-only member set num to zero

        arr.append((num, word))
        if cir != '':
            arr.append((-1, ''))  # if circumflex found, append one member between zero and default (-2)
    arr.append((-2, ''))          # fill array to "n_len"
    return arr
