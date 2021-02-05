#!/usr/local/bin/python

from relay_sdk import Interface, Dynamic as D

import json
import logging

def extract(d: list, keep: list) -> list:
    issues = []
    
    for issue in d:
        if issue['issueData']['severity'] in keep:
            issues.append(issue)
    
    return issues

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

logging.info("filtered snyk issues:\n{}".format(json.dumps(issues,indent=4)))

relay.outputs.set('issues',issues)