#!/usr/local/bin/python

from relay_sdk import Interface, Dynamic as D
import json
import logging

logging.getLogger().setLevel(logging.INFO)

relay = Interface()

project = relay.get(D.project)
worst = relay.get(D.worst)

secret = relay.get(D.secret)

formatted_json = json.dumps(project, indent=4, sort_keys=True)

logging.info("project info from snyk \n{}".format(formatted_json))

logging.info("example secret {}".format(secret))
if worst != 0:
    worst = json.dumps(worst, indent=4, sort_keys=True)

logging.info("the worst {}".format(worst))

relay.outputs.set("outputkey","This will be the value of outputkey")