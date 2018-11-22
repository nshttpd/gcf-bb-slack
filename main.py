#
# simple GCF to handle a BB Webhook to Slack Webhook. i.e. a Thunk layer.
#

from flask import abort
import hashlib
import hmac
import os
import json
import logging
from urllib import request, parse


#
# Validate the request based on a shared secret signature based on the body
#
# https://confluence.atlassian.com/bitbucketserver/managing-webhooks-in-bitbucket-server-938025878.html#ManagingwebhooksinBitbucketServer-Securingyourwebhook
#
def validate_request(body, signature):
    sekret = os.environ.get('BITBUCKET_SECRET', None)
    if sekret is not None:
        s = bytes(sekret, 'utf-8')
        h = hmac.new(s, body, digestmod=hashlib.sha256).hexdigest()
        calc_sig = "sha256=%s" % h
        if calc_sig == signature:
            return True
    logging.info('got invalid signature')
    return False


def send_slack_msg(msg):
    webhook = os.environ.get('SLACK_WEBHOOK', None)
    if webhook is not None:
        headers = {'Content-type': 'application/json'}
        data = {'text': msg, 'icon_emoji': ':bitbucket:'}
        payload = bytes(json.dumps(data), 'utf-8')
        req = request.Request(webhook, data=payload, headers=headers)
        resp = request.urlopen(req)
    return


def get_event_string(event):
    events = {
        'pr:opened': 'PR Created',
        'pullrequest:updated': 'PR Updated',
        'pr:reviewer:approved': 'PR Approved',
        'pullrequest:unapproved': 'PR Unapproved',
        'pullrequest:fulfilled': 'PR Merged',
        'pullrequest:rejected': 'PR Rejected',
        'pr:comment:added': 'PR Comment Added',
        'pullrequest:comment_updated': 'PR Comment Updated',
        'pullrequest:comment_deleted': 'PR Comment Deleted'
    }

    return events.get(event, 'Unknown')


def slack_template(event, d):
    templates = {
        'pr:opened': lambda d : '%s (%d) : %s by %s in %s branch %s' % (d['event_str'], d['pr_id'], d['pr_desc'], d['nick'], d['repo_name'], d['pr_branch']),
        'pr:reviewer:approved': lambda d : '%s (%d) : %s (%s | %s) by %s' % (d['event_str'], d['pr_id'], d['pr_desc'], d['pr_branch'], d['repo_nane'], d['approver']),
        'pr:comment:added': lambda d: '%s (%d) : %s - %s' % (d['event_str'], d['pr_id'], d['nick'], d['comment_text'])
    }

    x = templates.get(event, None)
    if x is not None:
        return x(d)

    return None


def bb_webhook(req):
    event_key = req.headers['x-event-key']

    # ping to validate webhook.
    if event_key == 'diagnostics:ping':
        return 'PONG'

    raw_req = req.get_data()

    if validate_request(raw_req, req.headers['X-Hub-Signature']):
        if req.method == 'POST':
            if req.headers['content-type'] == 'application/json':
                req_json = json.loads(raw_req)
                slack_data = {'event_str': get_event_string(event_key)}
                if 'actor' in req_json:
                    slack_data['nick'] = req_json['actor']['name']
                if 'pullRequest' in req_json:
                    slack_data['pr_id'] = req_json['pullRequest']['id']
                    slack_data['pr_desc'] = req_json['pullRequest']['title']
                    slack_data['pr_branch'] = req_json['pullRequest']['fromRef']['displayId']
                if 'repository' in req_json:
                    slack_data['repo_name'] = req_json['repository']['name']
                if 'comment' in req_json:
                    slack_data['comment_text'] = req_json['comment']['text']
                if 'approval' in req_json:
                    slack_data['approver'] = req_json['approval']['user']['nickname']

                slack_msg = slack_template(event_key, slack_data)

                if slack_msg is not None:
                    send_slack_msg(slack_msg)
                    return 'OK'

    return abort(404)
