import json
import os
import requests

def check_vulnerabilities(report_file):
    with open(report_file, 'r') as file:
        data = json.load(file)
        
        for item in data['data']:
            for result in item.get('results', []):
                for vulnerability in result.get('vulnerabilities', []):
                    if vulnerability.get('severity') == 'medium':
                        # Gather necessary details
                        return True, {
                            "component": result.get("component", "Unknown Component"),
                            "severity": vulnerability.get("severity", "Unknown Severity"),
                            "summary": vulnerability.get("identifiers", {}).get("summary", "No Summary Provided"),
                        }
    return False, None

def send_slack_message(slack_webhook, details):
    slack_message = {
        "text": f":rotating_light: Medium severity vulnerability found in {details['component']}.\nSummary: {details['summary']}"
    }
    response = requests.post(slack_webhook, json=slack_message)
    return response.status_code

if __name__ == "__main__":
    report_file = 'retirejs-report.json'
    slack_webhook = os.environ['SLACK_WEBHOOK']
    
    is_vulnerable, details = check_vulnerabilities(report_file)
    if is_vulnerable:
        send_slack_message(slack_webhook, details)
    else:
        print('No medium severity vulnerabilities found.')
