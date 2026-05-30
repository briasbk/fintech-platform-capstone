import boto3, json, os, logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
s3  = boto3.client('s3')
sns = boto3.client('sns')

def handler(event, context):
    action = event.get('action', 'validate')
    logger.info(f"Action: {action} | Event: {json.dumps(event, default=str)[:500]}")

    if action == 'validate':
        return validate(event)
    elif action == 'isolate':
        return isolate(event)
    elif action == 'notify':
        return notify(event)
    elif action == 'notify_failure':
        return notify_failure(event)

def validate(event):
    finding = event.get('event', {}).get('detail', {})
    instance_id = (finding.get('resource', {})
                          .get('instanceDetails', {})
                          .get('instanceId'))
    return {
        **event,
        'finding_id':   finding.get('id', 'SAMPLE'),
        'finding_type': finding.get('type', 'UnauthorizedAccess:EC2/SSHBruteForce'),
        'severity':     finding.get('severity', 8),
        'instance_id':  instance_id,
        'timestamp':    datetime.now(timezone.utc).isoformat()
    }

def isolate(event):
    instance_id = event.get('instance_id')
    if not instance_id:
        logger.warning("No instance ID — skipping isolation")
        event['isolation'] = 'skipped'
        return event

    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[os.environ['QUARANTINE_SG']]
    )
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'Status',     'Value': 'QUARANTINED'},
        {'Key': 'IncidentId', 'Value': event.get('finding_id', 'unknown')},
        {'Key': 'IsolatedAt', 'Value': event.get('timestamp', '')},
    ])

    # Log to S3
    key = f"findings/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{event.get('finding_id','unknown')}.json"
    s3.put_object(
        Bucket=os.environ['FINDINGS_BUCKET'],
        Key=key,
        Body=json.dumps(event, indent=2, default=str),
        ContentType='application/json'
    )
    event['isolation'] = 'done'
    event['s3_key']    = key
    return event

def notify(event):
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject=f"[ALERT] GuardDuty: {event.get('finding_type')} | Severity {event.get('severity')}",
        Message=f"""
Security Incident Detected
==========================
Finding ID:   {event.get('finding_id')}
Type:         {event.get('finding_type')}
Severity:     {event.get('severity')}
Instance:     {event.get('instance_id', 'N/A')}
Isolation:    {event.get('isolation', 'N/A')}
S3 Log:       s3://{os.environ['FINDINGS_BUCKET']}/{event.get('s3_key', 'N/A')}
Timestamp:    {event.get('timestamp')}

Automated actions completed. Review GuardDuty console for full details.
"""
    )
    return {'status': 'complete'}

def notify_failure(event):
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject="[ALERT] Incident response FAILED — manual action needed",
        Message=f"Automation failed for finding: {event.get('finding_id')}. Error: {event.get('error')}"
    )
    return {'status': 'failed'}
