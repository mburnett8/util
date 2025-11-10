from gh_api import (
    get_org_dependabot_alerts,
    get_org_repo,
    get_org_repos,
    get_repo_codescanning_alerts,
    get_repo_dependabot_alerts,
    get_user,
    get_user_repos,
)

x = get_user_repos()
# print(x)

x = get_user()
# print(x)

x = get_org_repos()
# print(x)

x = get_org_repo("jnj_crw_app")
# print(x)

x = get_org_dependabot_alerts()
print(x)

x = get_repo_dependabot_alerts("jnj_crw_app")
# output_json("jnj-db-alerts", x)

x = get_repo_codescanning_alerts("jnj_crw_app")
# output_json("jnj-cs-alerts", x)
