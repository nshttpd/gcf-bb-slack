#
# simple GCF to handle a BB Webhook to Slack Webhook. i.e. a Thunk layer.
#

from flask import abort
import hashlib
import hmac
import os
import json
import logging
from urllib import request


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
        data = {'attachments': [msg], 'icon_emoji': ':bitbucket:'}
        payload = bytes(json.dumps(data), 'utf-8')
        req = request.Request(webhook, data=payload, headers=headers)
        resp = request.urlopen(req)
    return


def get_attachment_base(event):
    events = {
        'pr:opened': {'pretext': 'Pull Request Created', 'color': 'good'},
        'pr:modified': {'pretext': 'Pull Request Modified', 'color': 'warning'},
        'pr:reviewer:approved': {'pretext': 'Pull Request Approved', 'color': 'good'},
        'pr:reviewer:unapproved': {'pretext': 'Pull Request Unapproved', 'color': 'danger'},
        'pr:reviewer:needs_work': {'pretext': 'Pull Request Needs Work', 'color': 'warning'},
        'pr:merged': {'pretext': 'Pull Request Merged', 'color': '#000000'},
        'pr:declined': {'pretext': 'Pull Request Declined', 'color': 'danger'},
        'pr:comment:added': {'pretext': 'Pull Request Comment Added', 'color': 'good'},
        'pr:comment:edited': {'pretext': 'Pull Request Comment Edited', 'color': 'warning'},
        'pr:comment:deleted': {'pretext': 'Pull Request Comment Deleted', 'color': 'danger'}
    }

    return events.get(event, None)


def slack_template(event_key, d, attachment):
    bb_host = os.environ.get('BITBUCKET_HOST', None)

    link = 'https://%s/projects/%s/repos/%s/pull-requests/%s/' % (bb_host,
                                                                  d['pullRequest']['fromRef']['repository']['project']['key'],
                                                                  d['pullRequest']['fromRef']['repository']['slug'],
                                                                  d['pullRequest']['id'])
    if event_key.startswith('pr:comment'):
        attachment['text'] = '<%s|#%s> : %s' % (link, d['pullRequest']['id'], d['comment']['text'])
    else:
        attachment['text'] = '<%s|#%s> : %s' % (link, d['pullRequest']['id'], d['pullRequest']['title'])

    attachment['fields'] = [
        {
            'title': 'Author',
            'value': d['actor']['displayName'],
            'short': True
        },
        {
            'title': 'Repo : Branch',
            'value': '%s : %s' % (d['pullRequest']['fromRef']['repository']['slug'], d['pullRequest']['fromRef']['displayId']),
            'short': True
        }
    ]

    return attachment


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
                attachment = get_attachment_base(event_key)
                if attachment is not None:
                    attachment = slack_template(event_key, req_json, attachment)
                    send_slack_msg(attachment)
                    return 'OK'

    return abort(404)
