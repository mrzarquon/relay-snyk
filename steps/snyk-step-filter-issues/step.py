#!/usr/local/bin/python

from relay_sdk import Interface, Dynamic as D

import json
import logging

def extract(d: list, keep: list) -> list:
    return ((k, d[k]) for k in keep if k in d)

logging.getLogger().setLevel(logging.INFO)

relay = Interface()

event = relay.get(D.event)

projects = relay.get(D.projects)
projects = projects.split(',')

if event['project']['id'] not in projects:
    exit(1)

severities = relay.get(D.severities)
severities = severities.split(',')

issues = extract(event['newIssues'],severities)

logging.info("filtered snyk issues:\n{}".format(issues))

relay.outputs.set('issues',issues)