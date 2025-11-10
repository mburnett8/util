import os

import requests
from dotenv import load_dotenv

load_dotenv()

# Constants
ORG = "Intelladon-LLC"  # This is also the owner
TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_API_ORIGIN = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def get_user():
    response = requests.get(f"{GITHUB_API_ORIGIN}/user", headers=HEADERS)
    return response.json()


def get_user_repos():
    response = requests.get(f"{GITHUB_API_ORIGIN}/user/repos", headers=HEADERS)
    return response.json()


def get_org_repos():
    response = requests.get(
        f"{GITHUB_API_ORIGIN}/orgs/{ORG}/repos?per_page=10", headers=HEADERS
    )
    return response.json()


def get_org_repo(repo):
    response = requests.get(f"{GITHUB_API_ORIGIN}/repos/{ORG}/{repo}", headers=HEADERS)
    return response.json()


# TODO: Not working
def get_org_dependabot_alerts():
    response = requests.get(
        f"{GITHUB_API_ORIGIN}/orgs/{ORG}/dependabot/alerts", headers=HEADERS
    )
    return response.json()


def get_repo_dependabot_alerts(repo):
    response = requests.get(
        f"{GITHUB_API_ORIGIN}/repos/{ORG}/{repo}/dependabot/alerts?severity=critical,high",
        headers=HEADERS,
    )
    return response.json()


def get_repo_codescanning_alerts(repo):
    response = requests.get(
        f"{GITHUB_API_ORIGIN}/repos/{ORG}/{repo}/code-scanning/alerts?severity=critical,high",
        headers=HEADERS,
    )
    return response.json()
