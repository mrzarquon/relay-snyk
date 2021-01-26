#!/usr/local/bin/python

# simple webhook responder that just puts the entire
# content of the webhook into a parameter for use by a 
# workflow.

from relay_sdk import Interface, WebhookServer
from quart import Quart, request, jsonify, make_response

import logging
import json
import hashlib
import hmac

logging.getLogger().setLevel(logging.INFO)

relay = Interface()
app = Quart('snyk-issues-filter')

def verify_signature(payload, secret, signature):
    signature=signature.split('=')[1]
    
    payload = payload.encode()
    secret = secret.encode()
    
    digest = hmac.new(key=secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

    return signature == digest

def v0_parse(payload) -> dict:

    payload['project_id'] = payload['project']['id']
    payload['project_name'] = payload['project']['name']
    payload['org_id'] = payload['org']['id']
    payload['org_name'] = payload['org']['name']
    payload['newIssues_count'] = len(payload['newIssues'])

    if payload['newIssues_count'] > 0:
        payload['newIssues_worst'] = most_severe(payload['newIssues'])


    return payload

def most_severe(issues: list) -> dict:
    worst = sorted(issues, key=lambda d: d['priorityScore'])[0]
    return worst


@app.route('/', methods=['POST'])
async def handler():

    logging.info("starting 2")
    payload = await request.get_json()
    if payload is None:
        return {'message': 'not a valid webhook'}, 400, {}

    signature = request.headers.get('X-Hub-Signature')
    
    secret = relay.get('snykToken')

    if verify_signature(payload, secret, signature ) == False:
        return {'message': 'not secure webhook'}, 400, {}
    else:
        logging.info("Valid checksum of: %s", signature)

    eventtype = request.headers.get('X-Snyk-Event')
    eventtype , eventvers = eventtype.split('/')

    if eventvers == 'v0':
        payload = v0_parse(payload)
    else:
        return {'message': 'unsupported payload version'}, 400, {}

    relay.events.emit(payload)

    return {'message': 'success'}, 200, {}

if __name__ == '__main__':
    logging.info("starting")
    WebhookServer(app).serve_forever()
