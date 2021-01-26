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
    keys = ['id','issueType','pkgName','priorityScore']
    res = dict((k, worst[k]) for k in keys if k in worst)
    keys2 = ['severity','url','exploitMaturity','publicationTime','CVSSv3','cvssScore','identifiers']
    summary = dict((k, worst['issueData'][k]) for k in keys if k in worst['issueData'])
    summary.update(res)

    logging.info("the worst summary {}".format(json.dumps(summary, indent=4, sort_keys=True)))

relay.outputs.set("outputkey","This will be the value of outputkey")