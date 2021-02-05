#!/usr/local/bin/python

# simple webhook responder that just puts the entire
# content of the webhook into a parameter for use by a 
# workflow.

from relay_sdk import Interface, WebhookServer, Dynamic as D
from quart import Quart, request, jsonify, make_response

import logging
import json
import hashlib
import hmac

logging.getLogger().setLevel(logging.INFO)

relay = Interface()
app = Quart('snyk-trigger-issues')

def verify(payload, secret, signature):
    signature=signature.split('=')[1]

    payload = json.dumps(payload)
    
    payload = payload.encode()
    secret = secret.encode()
    
    digest = hmac.new(key=secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

    return signature == digest

@app.route('/', methods=['POST'])
async def handler():

    payload = await request.get_json()
    if payload is None:
        return {'message': 'not a valid webhook'}, 400, {}


    signature = request.headers.get('X-Hub-Signature')
    
    secret = relay.get(D.webhooktoken)

    if verify(payload, secret, signature ) == False:
        logging.info("Invalid checksum of: %s", signature)
        return {'message': 'invalid'}, 400, {}
    else:
        logging.info("Valid checksum of: %s", signature)

    if len(payload['newIssues']) > 0:
        relay.events.emit({'event': payload})

    return {'message': 'success'}, 200, {}

if __name__ == '__main__':
    WebhookServer(app).serve_forever()
