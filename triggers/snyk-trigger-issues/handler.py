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

foo = {}

def verify_signature(payload, secret, signature):
    signature=signature.split('=')[1]
    
    payload = payload.encode()
    secret = secret.encode()
    
    digest = hmac.new(key=secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

    return signature == digest

@app.route('/', methods=['POST'])
async def handler():

    payload = await request.get_json()
    if payload is None:
        return {'message': 'not a valid webhook'}, 400, {}

    #signature = request.headers.get('X-Hub-Signature')
    
    secret = relay.get(D.webhooktoken)

    logging.info("got the secret: \n%s", secret)

    payload['secret'] = secret

    relay.events.emit({'webhook_contents': payload})

    return {'message': 'success'}, 200, {}

if __name__ == '__main__':
    WebhookServer(app).serve_forever()
