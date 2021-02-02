import json
import requests
import hashlib
import hmac
import sys


# debugging command, ie webhook on demand with the proper checksum function included
# python submit_hook.py no_new_vulns.json https://webhookurl/

JSON = sys.argv[1]
URL = sys.argv[2]

USERAGENT = 'Snyk-Webhooks'

SIGNATURE = 'averylongsecrettouseforthis'

def generate_signature(data: str, secret: str) -> str:
     
     #received_sign = req.headers.get('X-Hub-Signature').split('sha1=')[-1].strip()
     
     #secret = 'my_secret_string'.encode()

     secret_byte = secret.encode()
     data_b = data.encode()

     hmac_gen = hmac.new(key=secret_byte, msg=data_b, digestmod=hashlib.sha256)

     return hmac_gen.hexdigest()

vulns = open(JSON)

data = json.load(vulns)
data = json.dumps(data)

sig = generate_signature(data,SIGNATURE)

headers = {
    'X-Hub-Signature'   : 'sha256=%s' % sig,
    'X-Snyk-Timestamp'  : '2021-01-26T14:28:56.430Z',
    'X-Snyk-Event'      : 'project_snapshot/v0',
    'content-type'      : 'application/json',
    'user-agent'        : USERAGENT
    }



print(headers)

# https://23cqmp3u4d5t90mucdar1e9buk.relay-webhook.net


#r = requests.post('https://webhook.site/0820e568-99df-454f-8607-4ed89ad59b18', headers=headers, data=data)

#print(r.text)

r2 = requests.post(URL, headers=headers, data=data)

print(r2.text)
