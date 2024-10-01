import json
import os
import requests


def check_vulnerabilities(report_file):
    with open(report_file, 'r') as file:
        data = json.load(file)
        vulnerabilities_found = []
        for item in data['data']:
            for result in item.get('results', []):
                if result.get('vulnerabilities', []):
                    for vuln in result['vulnerabilities']:
                        if vuln['severity'] == 'high' or vuln['severity'] == 'medium':
                            vulnerabilities_found.append({
                                'component': result.get('component', ''),
                                'version': result.get('version', ''),
                                'severity': vuln.get('severity', ''),
                                'detailed_summary': vuln.get('detailed_summary', ''),
                                'CVE': vuln.get('identifiers', {}).get('CVE', []),
                                'bug': vuln.get('info', {}).get('bug', ''),
                                'cwe': vuln.get('info', {}).get('cwe', []),
                                'info': vuln.get('info', {}).get('info', [])
                            })
                            # just one vulnerability in every result
                            break
        if vulnerabilities_found:
            return True, vulnerabilities_found
    return False, None


 
def send_slack_message(slack_webhook, vulnerabilities, author, repository, branch, commit):
    slack_webhook_url = slack_webhook
    commit_url = f"https://github.com/SMaltin93/Retire-Owasp-ZAP-GitHub-Action/commit/{commit}"
    slack_message = {"text": f":rotating_light: *Severity Vulnerabilities Found* :rotating_light:\n"
                            f"*Author:* {author}\n"
                            f"*Repository:* {repository}\n"
                            f"*Branch:* {branch}\n"
                            f"*Commit:* {commit}\n"
                            f"*Click here to view the commit:* {commit_url}\n"
                            f"*Vulnerabilities Found:*"}
    
    for vuln in vulnerabilities:
        slack_message["text"] += (
            f"\n*Component:* {vuln['component']} (Version: {vuln['version']})"
            f"\n*Severity:* {vuln['severity']}"
            f"\n*Summary:* {vuln['detailed_summary']}"
            f"\n*CVE:* {', '.join(vuln['CVE'])}"
            f"\n*Bug:* {vuln['bug']}"
            f"\n*CWE:* {', '.join(vuln['cwe'])}"
            f"\n*More Info:* {', '.join(vuln['info'])}\n"
        )
    response = requests.post(slack_webhook_url, json=slack_message)
    return response.status_code



if __name__ == "__main__":
    report_file = 'retirejs-report.json'
    slack_webhook = os.environ['SLACK_WEBHOOK']
    author = os.environ.get('Author')
    repository = os.environ.get('Repository')
    branch = os.environ.get('Branch')
    commit = os.environ.get('Commit')
    
    
    is_vulnerable, vulnerabilities = check_vulnerabilities(report_file)
    if is_vulnerable:
        send_slack_message(slack_webhook, vulnerabilities, author, repository, branch, commit)
        # dont allow the pipeline to continue if vulnerabilities are found..... 
        print('Vulnerabilities found. Exiting...')
        exit(1)
    else:
        print('No severity vulnerabilities found.')
        # allow the pipeline to continue
        exit(0)
