##### Cloud Functions Bitbucket->Slack handler

A simple basic GCF that handles a Webhook POST from a Bitbucket Server and formats the message into a Slack
payload.

Deploy with : 

```
gcloud beta functions deploy bb_webhook --set-env-vars BITBUCKET_SECRET=ThESeKret,SLACK_WEBHOOK=https://hooks.slack.com/services/MY/MAGIC/WEBHOOK,BITBUCKET_HOST=bitbucket.domain.co
```