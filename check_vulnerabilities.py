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
    author = os.getenv('Author', 'Unknown Author')
    repository = os.getenv('Repository', 'Unknown Repository')
    branch = os.getenv('Branch', 'Unknown Branch')
    author_email = os.getenv('AuthorEmail', 'Unknown Email')
    
    slack_message = {
        "text": (
            f":rotating_light: *Medium severity vulnerability found in {details['component']}*.\n"
            f"*Summary:* {details['summary']}\n"
            f"*CVE:* {', '.join(details['CVE'])}\n"
            f"*Bug:* {details['bug']}\n"
            f"*Info:* {', '.join(details['info'])}\n"
            f"*Author:* {author}\n"
            f"*Author Email:* {author_email}\n"
            f"*Repository:* {repository}\n"
            f"*Branch:* {branch}"
        )
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
