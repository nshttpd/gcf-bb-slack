#
# simple GCF to handle a BB Webhook to Slack Webhook. i.e. a Thunk layer.
#

from flask import abort
import hashlib
import hmac
import base64
import os
from urllib import request, parse


#
# Validate the request based on a shared secret signature based on the body
#
# https://confluence.atlassian.com/bitbucketserver/managing-webhooks-in-bitbucket-server-938025878.html#ManagingwebhooksinBitbucketServer-Securingyourwebhook
#
def validate_request(body, signature):
    sekret = os.environ.get('BITBUCKET_SECRET', None)
    if sekret is not None:
        calc_sig = base64.b64encode(hmac.new(sekret, body, digestmod=hashlib.sha256).digest())
        if calc_sig == signature:
            return True
    return False


def send_slack_msg(msg):
    webhook = os.environ.get('SLACK_WEBHOOK', None)
    if webhook is not None:
        headers = {'Content-type': 'application/json'}
        data = {'text': msg}
        payload = parse.urlencode(data).encode()
        req = request.Request(webhook, data=payload, headers=headers)
        resp = request.urlopen(req)
    return


def get_event_string(event):
    events = {
        'pullrequest:created': 'PR Created',
        'pullrequest:updated': 'PR Updated',
        'pullrequest:approved': 'PR Approved',
        'pullrequest:unapproved': 'PR Unapproved',
        'pullrequest:fulfilled': 'PR Merged',
        'pullrequest:rejected': 'PR Rejected',
        'pullrequest:comment_created': 'PR Comment Added',
        'pullrequest:comment_updated': 'PR Comment Updated',
        'pullrequest:comment_deleted': 'PR Comment Deleted'
    }

    return events.get(event, 'Unknown')


def slack_template(event, d):
    templates = {
        'pullrequest:created': lambda d : '%s (%d) : %s by %s in %s branch %s' % (d['event_str'], d['pr_id'], d['pr_desc'], d['nick'], d['repo_name'], d['pr_branch'])
    }

    x = templates.get(event, None)
    if x is not None:
        return x(d)

    return None


def bb_webhook(request):
    if validate_request(request.data, request.headers['X-Hub-Signature']):
        if request.method == 'POST':
            if request.headers['content-type'] == 'application/json':
                slack_data = {'event_str': get_event_string(request.headers['X-Event-Key'])}
                req_json = request.get_json()
                if 'actor' in req_json:
                    slack_data['nick'] = req_json['actor']['nickname']
                if 'pullrequest' in req_json:
                    slack_data['pr_id'] = req_json['pullrequest']['id']
                    slack_data['pr_desc'] = req_json['pullrequest']['description']
                    slack_data['pr_branch'] = req_json['pullrequest']['source']['branch']
                if 'repository' in req_json:
                    slack_data['repo_name'] = req_json['repository']['name']
                if 'comment' in req_json:
                    slack_data['comment_text'] = req_json['comment']['content']['raw']
                if 'approval' in req_json:
                    slack_data['approver'] = req_json['approval']['user']['nickname']

                slack_msg = slack_template(request.headers['X-Event-Key'], slack_data)

                if slack_msg is not None:
                    send_slack_msg(slack_msg)
                    return 'OK'

    return abort(404)
