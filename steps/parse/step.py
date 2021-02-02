#!/usr/local/bin/python

from relay_sdk import Interface, Dynamic as D

import json
import logging

logging.getLogger().setLevel(logging.INFO)

relay = Interface()

project = relay.get(D.event)

formatted_json = json.dumps(project, indent=4, sort_keys=True)

logging.info("project info from snyk \n{}".format(formatted_json))