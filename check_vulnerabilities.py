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
                        return True, vulnerability
    return False, None

def send_slack_message( slack_webhook, details):
    slack_webhook_url = slack_webhook
    slack_message = {
        "text": f"Medium severity vulnerability found in {details['package_name']} package. Please check the report for more details."
    }
    response = requests.post(slack_webhook_url, json=slack_message)
    return response.status_code

# get the slack_webhook from github secrets

if __name__ == "__main__":
    report_file = 'retirejs-report.json'
    slack_webhook = os.environ['SLACK_WEBHOOK']
    is_vulnerable, details = check_vulnerabilities(report_file)
    if is_vulnerable:
        send_slack_message(slack_webhook, details)
    else:
        print('No medium severity vulnerabilities found.')
        
