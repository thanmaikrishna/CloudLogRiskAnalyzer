from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from auth_utils import (
    load_users,
    authenticate_user,
    register_user,
    token_required,
    forgot_password as forgot_password_func,
    send_reset_email,
    save_users,
)
from aws_log_handler import fetch_aws_logs_securely
from risk_classifier import classify_logs, classify_log_entry
import json
import os
from config import SECRET_KEY
import boto3
from botocore.exceptions import ClientError
import gzip
import io

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = SECRET_KEY

# Store AWS sessions per user email (string)
aws_sessions = {}

# Utility to prepare custom rules (adds match field if missing and ensures eventName)
def prepare_custom_rules(raw_rules):
    prepared = []
    seen = set()
    for rule in raw_rules:
        # Normalize: always have eventName
        if "eventName" not in rule and "name" in rule:
            rule["eventName"] = rule["name"]
        # Remove legacy 'name' to avoid confusion
        if "name" in rule:
            rule.pop("name")
        event_name = rule.get("eventName", "").strip()
        if not event_name or event_name in seen:
            continue
        seen.add(event_name)
        if "match" not in rule:
            match = {"eventName": event_name}
            prepared.append({
                "eventName": event_name,
                "match": match,
                "risk": rule.get("risk", "Low"),
                "reason": rule.get("reason", "No reason provided")
            })
        else:
            prepared.append(rule)
    return prepared

# Register user
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password required'}), 400
    success, message = register_user(email, password)
    return jsonify({'message': message}), 200 if success else 400

# Login and get JWT
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password required'}), 400
    user = authenticate_user(email, password)
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    token_str = token if isinstance(token, str) else token.decode()
    return jsonify({'token': token_str})

# Forgot password (send reset link)
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email') if data else None
    if not email:
        return jsonify({'message': 'Email required'}), 400

    users = load_users()
    if email not in users:
        return jsonify({'message': 'If the email exists, a reset link has been sent'}), 200

    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    token_str = token if isinstance(token, str) else token.decode()
    reset_link = f"http://yourfrontend/reset-password?token={token_str}"

    try:
        send_reset_email(email, reset_link)
    except Exception as e:
        print("Error sending email:", e)

    return jsonify({'message': 'If the email exists, a reset link has been sent'}), 200

# Change password (authenticated user)
@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(current_user_email):
    data = request.get_json()
    old_password = data.get('oldPassword') if data else None
    new_password = data.get('newPassword') if data else None

    if not old_password or not new_password:
        return jsonify({'message': 'Old and new passwords required'}), 400

    user = authenticate_user(current_user_email, old_password)
    if not user:
        return jsonify({'message': 'Old password incorrect'}), 401

    success, message = register_user(current_user_email, new_password, update=True)
    return jsonify({'message': message}), 200 if success else 400

# Get current user info (email)
@app.route('/api/user', methods=['GET'])
@token_required
def user_info(current_user_email):
    return jsonify({'email': current_user_email})

# Set AWS session info for current user
@app.route('/api/aws/session', methods=['POST'])
@token_required
def set_aws_session(current_user_email):
    data = request.get_json()
    required_fields = ['awsAccessKey', 'awsSecretKey', 'awsRegion', 's3Bucket', 's3Path']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing AWS session info'}), 400
    aws_sessions[current_user_email] = {
        'awsAccessKey': data['awsAccessKey'],
        'awsSecretKey': data['awsSecretKey'],
        'awsRegion': data['awsRegion'],
        's3Bucket': data['s3Bucket'],
        's3Path': data['s3Path'],
        'timestamp': datetime.datetime.utcnow()
    }
    return jsonify({'message': 'AWS session saved'}), 200

# Clear AWS session info
@app.route('/api/aws/session', methods=['DELETE'])
@token_required
def delete_aws_session(current_user_email):
    aws_sessions.pop(current_user_email, None)
    return jsonify({'message': 'AWS session cleared'}), 200

# Fetch AWS logs and classify them
@app.route('/api/fetch-analyze', methods=['POST'])
@token_required
def fetch_and_analyze(current_user_email):
    data = request.get_json()
    aws_access_key = data.get('awsAccessKey')
    aws_secret_key = data.get('awsSecretKey')
    aws_region = data.get('awsRegion')
    s3_bucket = data.get('s3Bucket')
    s3_path = data.get('s3Path')

    if not all([aws_access_key, aws_secret_key, aws_region, s3_bucket, s3_path]):
        return jsonify({'message': 'Missing AWS credentials or path'}), 400

    logs, err = fetch_aws_logs_securely(aws_access_key, aws_secret_key, aws_region, s3_bucket, s3_path)
    if err:
        return jsonify({'message': err}), 500

    try:
        with open('rules/predefined_rules.json') as f:
            predefined = json.load(f)
        with open('rules/custom_rules.json') as f:
            custom = prepare_custom_rules(json.load(f))
    except Exception as e:
        return jsonify({'message': f'Error loading rules: {str(e)}'}), 500

    classified = classify_logs(logs, predefined, custom)

    predefined_count = 0
    custom_count = 0
    both_count = 0
    none_count = 0

    for item in classified:
        reasons = item.get('reasons', [])
        has_pre = any("Predefined rule matched" in r for r in reasons)
        has_cust = any("Custom rule matched" in r for r in reasons)

        if has_pre and has_cust:
            both_count += 1
        elif has_pre:
            predefined_count += 1
        elif has_cust:
            custom_count += 1
        else:
            none_count += 1

    comparison_stats = {
        'predefinedOnly': predefined_count,
        'customOnly': custom_count,
        'both': both_count,
        'none': none_count,
        'total': len(classified)
    }

    unique_event_names = sorted({log.get('eventName', '') for log in logs if 'eventName' in log})
    aws_sessions[current_user_email]['eventNames'] = unique_event_names

    return jsonify({
        'results': classified,
        'comparisonStats': comparison_stats,
        'validEventNames': unique_event_names
    })

@app.route('/api/risk-stats', methods=['POST'])
@token_required
def risk_stats(current_user_email):
    data = request.get_json()
    aws_access_key = data.get('awsAccessKey')
    aws_secret_key = data.get('awsSecretKey')
    aws_region = data.get('awsRegion')
    s3_bucket = data.get('s3Bucket')
    s3_path = data.get('s3Path')

    if not all([aws_access_key, aws_secret_key, aws_region, s3_bucket, s3_path]):
        return jsonify({'message': 'Missing AWS credentials or path'}), 400

    logs, err = fetch_aws_logs_securely(aws_access_key, aws_secret_key, aws_region, s3_bucket, s3_path)
    if err:
        return jsonify({'message': err}), 500

    with open('rules/predefined_rules.json') as f:
        predefined = json.load(f)
    with open('rules/custom_rules.json') as f:
        custom = prepare_custom_rules(json.load(f))

    classified = classify_logs(logs, predefined, custom)

    ruleBasedCounts = {'Low': 0, 'Medium': 0, 'High': 0}
    customBasedCounts = {'Low': 0, 'Medium': 0, 'High': 0}
    for item in classified:
        reasons = item.get('reasons', [])
        risk = item.get('risk', 'Low')
        if any("Custom rule matched" in r for r in reasons):
            customBasedCounts[risk] += 1
        if any("Predefined rule matched" in r for r in reasons):
            ruleBasedCounts[risk] += 1

    return jsonify({
        'ruleBasedCounts': ruleBasedCounts,
        'customBasedCounts': customBasedCounts
    })

# Get all rules (predefined + custom)
@app.route('/api/rules', methods=['GET'])
@token_required
def get_rules(current_user_email):
    try:
        with open('rules/predefined_rules.json') as f:
            predefined = json.load(f)
        with open('rules/custom_rules.json') as f:
            custom = json.load(f)
        return jsonify({'predefinedRules': predefined, 'customRules': custom})
    except Exception as e:
        return jsonify({'message': f'Error loading rules: {str(e)}'}), 500

@app.route('/api/rules/custom', methods=['POST', 'PUT'])
@token_required
def update_custom_rules(current_user_email):
    data = request.get_json()
    new_rules = data.get('customRules')

    if not isinstance(new_rules, list):
        return jsonify({'message': 'Invalid rules format'}), 400

    # Validate and deduplicate eventName
    seen = set()
    deduped_rules = []
    for rule in new_rules:
        event_name = rule.get('eventName')
        if not event_name or not isinstance(event_name, str) or event_name.strip() == '':
            return jsonify({'message': 'Invalid or missing eventName in custom rule'}), 400
        event_name = event_name.strip()
        if event_name not in seen:
            deduped_rules.append(rule)
            seen.add(event_name)

    try:
        path = 'rules/custom_rules.json'
        # Overwrite with deduped, normalized rules
        prepared = prepare_custom_rules(deduped_rules)
        with open(path, 'w') as f:
            json.dump(prepared, f, indent=2)
        return jsonify({'message': f'{len(prepared)} rule(s) saved', 'totalRules': len(prepared)})
    except Exception as e:
        return jsonify({'message': f'Error updating rules: {str(e)}'}), 500

@app.route('/api/rules/custom/<string:event_name>', methods=['DELETE'])
@token_required
def delete_custom_rule(current_user_email, event_name):
    try:
        path = 'rules/custom_rules.json'
        with open(path, 'r') as f:
            rules = json.load(f)
        filtered = [r for r in rules if r.get('eventName') != event_name]
        if len(filtered) == len(rules):
            return jsonify({'message': 'Rule not found'}), 404
        with open(path, 'w') as f:
            json.dump(filtered, f, indent=2)
        return jsonify({'message': 'Rule deleted'})
    except Exception as e:
        return jsonify({'message': f'Error deleting rule: {str(e)}'}), 500

@app.route('/api/connect-aws', methods=['POST'])
def connect_aws():
    data = request.json
    access_key = data.get('accessKey')
    secret_key = data.get('secretKey')
    region = data.get('region')
    log_path = data.get('logPath')

    if not all([access_key, secret_key, region, log_path]):
        return jsonify({'message': 'Missing AWS credentials, region or log path'}), 400
    if not log_path.startswith('s3://'):
        return jsonify({'message': 'Log path must start with s3://'}), 400
    try:
        s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        bucket, prefix = log_path[5:].split('/', 1)
        response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        if 'Contents' not in response:
            return jsonify({'message': 'No logs found'}), 404
        logs = []
        for obj in response['Contents']:
            key = obj['Key']
            file_obj = s3.get_object(Bucket=bucket, Key=key)
            raw_data = file_obj['Body'].read()
            content = gzip.decompress(raw_data).decode() if key.endswith('.gz') else raw_data.decode()
            for line in content.splitlines():
                try:
                    data = json.loads(line)
                    for record in data.get('Records', []):
                        risk, reason = classify_log_entry(record)
                        logs.append({'eventName': record.get('eventName', 'N/A'), 'risk': risk, 'reason': reason})
                except:
                    continue
        return jsonify({'message': 'AWS verified', 'logs': logs})
    except ClientError as e:
        return jsonify({'message': f'AWS error: {e.response["Error"]["Message"]}'}), 400
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/logs/eventnames', methods=['GET'])
@token_required
def get_event_names(current_user_email):
    session = aws_sessions.get(current_user_email)
    if not session or 'eventNames' not in session:
        return jsonify({'message': 'No valid event names cached. Please fetch logs first.'}), 400
    return jsonify({'eventNames': session['eventNames']}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)