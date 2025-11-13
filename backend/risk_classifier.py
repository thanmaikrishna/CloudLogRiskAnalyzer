def classify_logs(logs, predefined_rules, custom_rules):
    results = []

    all_event_names = {log.get('eventName') for log in logs if 'eventName' in log}

    processed_custom_rules = []
    for rule in custom_rules:
        if 'match' in rule:
            processed_custom_rules.append({
                'name': rule.get('name', 'Unnamed Custom Rule'),
                'match': rule['match'],
                'risk': rule.get('risk', 'Low'),
                'reason': rule.get('reason', 'No reason provided'),
                'source': 'custom'
            })
        elif 'eventName' in rule:
            event_name = rule['eventName']
            if event_name not in all_event_names:
                print(f"Warning: Custom rule eventName '{event_name}' not found in logs.")
            processed_custom_rules.append({
                'name': rule.get('eventName', 'Unnamed Custom Rule'),
                'match': {'eventName': event_name},
                'risk': rule.get('risk', 'Low'),
                'reason': rule.get('reason', 'No reason provided'),
                'source': 'custom'
            })

    for log in logs:
        risk_level = 'Low'
        reasons = []

        for rule in predefined_rules:
            if rule_match(log, rule):
                rule_name = rule.get('name', 'Unnamed Predefined Rule')
                risk_level = max_risk(risk_level, rule['risk'])
                reasons.append("Predefined rule matched")
                # Optionally: reasons.append(f"Predefined rule matched: {rule_name}")

        for rule in processed_custom_rules:
            if rule_match(log, rule):
                rule_name = rule.get('name', 'Unnamed Custom Rule')
                rule_reason = rule.get('reason', 'No reason provided')
                risk_level = max_risk(risk_level, rule['risk'])
                reasons.append("Custom rule matched")
                # Optionally: reasons.append(f"Custom rule matched: {rule_name} — {rule_reason}")

        # Return as a flat dict (not under 'log': log)
        result = dict(log)
        result['risk'] = risk_level
        result['reasons'] = reasons
        result['reason'] = "; ".join(reasons)
        results.append(result)

    return results

def get_nested_value(d, key_path):
    """Retrieve nested value from dict d using dot-separated key_path."""
    keys = key_path.split('.')
    current = d
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def rule_match(log, rule):
    """
    Match a rule against a log.
    Supports nested keys in rule['match'] with dot notation.
    Case-insensitive, stripped string comparison.
    """
    for key, value in rule.get('match', {}).items():
        log_val = get_nested_value(log, key)
        if log_val is None:
            return False
        if str(log_val).strip().lower() != str(value).strip().lower():
            return False
    return True


def max_risk(current, new):
    levels = ['Low', 'Medium', 'High']
    return new if levels.index(new) > levels.index(current) else current


def classify_log_entry(entry):
    """
    A quick single-log risk categorization method.
    This function is optional if you're using classify_logs in bulk.
    """
    event_name = entry.get("eventName", "")
    user_type = entry.get("userIdentity", {}).get("type", "")

    if event_name in ["DeleteTrail", "StopLogging"]:
        return "High", "Critical AWS service manipulation"
    elif user_type == "AssumedRole":
        return "Medium", "Role-based access"
    else:
        return "Low", "Common API usage"
