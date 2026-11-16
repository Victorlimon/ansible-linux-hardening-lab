# Least-privilege Wazuh API user for `ansible-job` orders

Goal: a Wazuh API identity that can only send `PUT /active-response` to the
**ansible-control agent** (no `security:*`, no other agents, no configuration,
no agent management).

**Scope of `active-response:command`.** The permission is not tied to the
`ansible-job` command. On `agent:id:<controller>` it lets the user run **any**
active-response script that exists in that agent's `active-response/bin`
directory. Treat the ansible-control agent as fully reachable by this user:
remove or disable every active-response script and `<command>` entry that is
not needed there (keep only `ansible-job`), and review the directory after each
agent upgrade. The gateway validates every order it receives, but it cannot
restrict what other scripts on the same agent do.

Everything below targets the Wazuh 4.12 server API. Items marked **(verify)**
were written from the documented RBAC model and must be confirmed on the
institution's manager (`GET /security/actions` lists every valid action and its
resources) before production use.

## Model

| Object | Value |
| --- | --- |
| Policy `ansible_job_order_ctrl` | `effect: allow`, `actions: ["active-response:command"]`, `resources: ["agent:id:<CONTROL_AGENT_ID>"]` |
| Role `ansible_operator` | holds only that policy |
| User `ansible_operator` | holds only that role; `run_as` stays disabled |

`<CONTROL_AGENT_ID>` is the id of the ansible-control agent (for example
`001`). Do not use `agent:id:*`: that would let the user run active response
on every agent. Do not assign built-in roles (`administrator`, `agents_all`,
`users_admin`, ...) to this user. Wazuh RBAC is allow-list based in its default
white mode; anything not granted is denied **(verify with `GET /security/config`
that `rbac_mode` is `white`)**.

## Creation (run as a Wazuh administrator)

Set `TOKEN` from an administrator session. Do not put passwords on a command
line: the new user's password is read from a file created with `umask 077`.

```bash
API=https://wazuh-manager.example.org:55000
AUTH="Authorization: Bearer $TOKEN"
JSON="Content-Type: application/json"

# 1. Policy (the response contains the policy id)
curl --cacert ca.pem -sS -X POST "$API/security/policies" -H "$AUTH" -H "$JSON" -d '{
  "name": "ansible_job_order_ctrl",
  "policy": {
    "actions": ["active-response:command"],
    "resources": ["agent:id:001"],
    "effect": "allow"
  }
}'

# 2. Role
curl --cacert ca.pem -sS -X POST "$API/security/roles" -H "$AUTH" -H "$JSON" \
  -d '{"name": "ansible_operator"}'

# 3. Attach the policy to the role
curl --cacert ca.pem -sS -X POST "$API/security/roles/$ROLE_ID/policies?policy_ids=$POLICY_ID" -H "$AUTH"

# 4. User (credentials from a private file, never from argv)
curl --cacert ca.pem -sS -X POST "$API/security/users" -H "$AUTH" -H "$JSON" -d @user.json

# 5. Attach the role to the user
curl --cacert ca.pem -sS -X POST "$API/security/users/$USER_ID/roles?role_ids=$ROLE_ID" -H "$AUTH"
```

`user.json` is `{"username": "ansible_operator", "password": "<strong password>"}`
(Wazuh requires 8-64 characters mixing cases, digits and symbols). Delete the
file after use and store the password in the institution's secret manager.
Each person should have a personal user with the same role rather than a shared
account, so that Wazuh's API log attributes every order.

Endpoints used, per the Wazuh 4.12 API reference **(verify)**:
`POST /security/policies`, `POST /security/roles`,
`POST /security/roles/{role_id}/policies`, `POST /security/users`,
`POST /security/users/{user_id}/roles`, `POST /security/user/authenticate`,
`GET /security/users/me/policies`.

## Validation

1. Authenticate as `ansible_operator` and run `GET /security/users/me/policies`:
   the only entry must be the policy above.
2. `PUT /active-response?agents_list=001` with a CHECK order must reach the
   gateway (HTTP 200 only acknowledges receipt).
3. The same request for any other agent id must return an authorization error
   (HTTP 403).
4. `GET /security/users`, `GET /agents` and `PUT /agents/restart` must be
   denied (HTTP 403). If `GET /agents` is needed to look up the agent id,
   add a second policy with `agent:read` limited to the same `agent:id:<id>`
   **(verify the exact action name with `GET /security/actions`)**.

## Lab validation (Wazuh 4.12.0, single-node Docker)

Created with the steps above (policy, role and user ids were `100`) and tested
as `ansible_operator`:

| Request | Result |
| --- | --- |
| `GET /security/config` (as admin) | `rbac_mode: white` |
| `GET /security/users/me/policies` | only `active-response:command` → `agent:id:001: allow` |
| `PUT /active-response?agents_list=001` (`!ansible-job`) | HTTP 200, order reached the gateway (`rejected` event for the deliberately inactive release) |
| `PUT /active-response?agents_list=002` | HTTP 403 Permission Denied |
| `PUT /active-response` without `agents_list` | HTTP 200 but filtered to agent `001` only (`total_affected_items: 1`) |
| `GET /security/users`, `GET /agents` | HTTP 200 with **0 items** (list endpoints filter instead of returning 403; no data exposed) |
| `PUT /agents/restart`, `GET /manager/configuration`, `POST /security/users` | HTTP 403 Permission Denied |
| `!firewall-drop` on `001` after pruning the agent's `active-response/bin` | HTTP 200 (API cannot restrict the script) but no effect: the script is absent, no firewall rule created |

The endpoints and the `active-response:command` / `agent:id:<id>` resource
format marked **(verify)** above are therefore confirmed on 4.12.0. The agent
default `<active-response><disabled>no</disabled>` was also confirmed.

### Pruning active-response scripts on the controller agent

Keep only `ansible-job`, `restart.sh` and `restart-wazuh` in
`/var/ossec/active-response/bin` of the ansible-control agent; move the rest
to a root-only directory (do not delete them, so the change is reversible):

```bash
sudo install -d -o root -g root -m 0700 /var/ossec/active-response/disabled
cd /var/ossec/active-response/bin
for f in default-firewall-drop disable-account firewalld-drop firewall-drop host-deny \
         ip-customblock ipfw kaspersky kaspersky.py npf pf route-null wazuh-slack; do
  [ -e "$f" ] && sudo mv "$f" ../disabled/
done
```

Agent package upgrades restore these files: repeat this step after every agent
upgrade and check `ls /var/ossec/active-response/bin`.

## What this user still cannot see

Reading the outcome of an order (alerts, terminal events) goes through the
Wazuh indexer/dashboard, whose permissions are separate (OpenSearch roles on
`wazuh-alerts-*`). Grant a read-only dashboard role for that to the same people;
do not widen the API role.

## Operational notes

- The API token lifetime defaults to 900 s; do not extend it for convenience.
- `APPLY` is never authorised by this user alone: it also needs the one-shot
  approval issued on the controller with `ansible-job --managed-v2-approve` and
  the root-local safety file.
- Review `GET /security/users/me/policies` after every Wazuh upgrade.
- Manager-side active response commands run on the agent only if the agent
  accepts them: confirm `<active-response><disabled>` is not `yes` in the
  ansible-control agent's `ossec.conf` **(verify against the 4.12 agent defaults)**.
