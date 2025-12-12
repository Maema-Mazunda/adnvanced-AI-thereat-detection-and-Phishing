import json, os, time, re
import boto3
from botocore.exceptions import ClientError

ddb = boto3.resource('dynamodb')
sns = boto3.client('sns')
s3 = boto3.client('s3')

TABLE_NAME = os.environ.get('DDB_TABLE')
ALERT_TOPIC = os.environ.get('ALERT_TOPIC_ARN')
S3_BUCKET = os.environ.get('S3_BUCKET')

table = ddb.Table(TABLE_NAME)

def lambda_handler(event, context):
    # EventBridge test will often deliver our test object at top-level; GuardDuty real events hold 'detail'.
    detail = event.get('detail') if event.get('detail') else event
    finding_id = detail.get('id') or detail.get('findingId') or str(time.time())
    if is_duplicate(finding_id):
        return {"status": "skipped", "reason": "duplicate", "id": finding_id}

    enriched = enrich(detail)
    persist(enriched)
    publish(enriched)
    return {"status": "processed", "id": finding_id}

def is_duplicate(fid):
    try:
        table.put_item(Item={'finding_id': fid, 'ts': int(time.time())}, ConditionExpression='attribute_not_exists(finding_id)')
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return True
        raise

def enrich(detail):
    enriched = {}
    enriched['id'] = detail.get('id')
    enriched['title'] = detail.get('title', 'No title')
    enriched['severity'] = detail.get('severity', 0)
    enriched['description'] = detail.get('description', '')
    enriched['urls'] = extract_urls(enriched['description'])
    # Simple score: severity * (1 + n_urls)
    enriched['score'] = enriched['severity'] * (1 + len(enriched['urls']))
    enriched['raw'] = detail
    return enriched

def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s,"]+', text)

def persist(enriched):
    # store to s3
    if S3_BUCKET:
        key = f"guardduty/{enriched.get('id', str(time.time()))}.json"
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=json.dumps(enriched).encode('utf-8'))
    return

def publish(enriched):
    subject = f"[ALERT] {enriched.get('title')} sev:{enriched.get('severity')}"
    message = json.dumps(enriched, default=str)
    try:
        sns.publish(TopicArn=ALERT_TOPIC, Subject=subject, Message=message)
    except Exception as e:
        print("SNS publish failed:", str(e))
