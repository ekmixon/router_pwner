import importlib
import os
import re
import sys

import requests

from glob import glob
from pprint import pprint
from random import shuffle

CURRENT_SUB = __name__.split(".")[0]

# Import all files in the scanners directory
for f in glob(os.path.join(os.getcwd(), CURRENT_SUB, "*")):
    __all__ = []

    f_bname = os.path.basename(f)

    if not f_bname.startswith("_") and f_bname.endswith(".py"):
        mod_name = f_bname.strip(".py")
        importlib.import_module(".".join([CURRENT_SUB, mod_name]))
        __all__.append(mod_name)


class RouterBase(object):

    def __init__(self):
        self.name = None
        self.page = None
        self.url = None
        self.results = {}
        self.regex_found = None
        self.brute_force_combos = []

    def _finalize_results(self):
        return

    def _print_results(self):
        pprint(self.results)

    def start(self):
        return

    def rex_to_func(self):
        """
        :return: Converts self.regex_found into a format that can be mapped to a Python function
        """

        rex = re.sub("-", "", self.regex_found)
        if len(rex) == 1:
            return rex.upper()[0].upper()
        else:
            return rex.upper()[0].upper() + rex.lower()[1:].strip()

    def load_creds(self, user_list, pw_list):
        """
        :param user_list: list of user names
        :param pw_list: list of passwords
        :return: Returns a list of tuples accounting for all possible user/pass combos randomized
        """

        self.brute_force_combos = [(x, y) for x in user_list for y in pw_list]
        shuffle(self.brute_force_combos)


def get_id(url):
    """
    :param url: full URL to GET.  i.e. http://www.google.com
    :return: Class of the appropriate module based on the regex that was found.  i.e. scanners.dlink
    """

    try:
        r = requests.get(url)
    except requests.exceptions.ConnectionError:
        print "Error: Failed to connect to " + url
        return False

    if r.status_code != 200:
        print "Error: " + url + " returned status code " + str(r.status_code)
        return False

    for mod in __all__:
        app = sys.modules[".".join([CURRENT_SUB, mod])]
        fn = getattr(app, "regex_list")

        for rex in fn:
            if re.search(rex, r.text):
                res = re.findall(rex, r.text)[0]
                spec_fn = getattr(app, "Base")
                return spec_fn(url, res, r.text)

    print "Unable to detect device for " + url
    return None
