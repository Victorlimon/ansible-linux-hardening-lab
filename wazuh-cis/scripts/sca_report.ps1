# Query Wazuh SCA summaries (and optionally failed check lists) for the lab
# agents. Run from the Windows host against the manager API exposed on 127.0.0.1.
param(
    [string]$Api = "https://127.0.0.1:57000",
    [string]$User = "wazuh-wui",
    [string]$Pass = "MyS3cr37P450r.*-",
    [string[]]$Agents = @("004", "005"),
    [switch]$Detail
)

$tok = & curl.exe -sk -u "${User}:${Pass}" -X POST "$Api/security/user/authenticate?raw=true"
if (-not $tok -or $tok.Length -lt 40) { Write-Error "authentication failed"; exit 1 }

foreach ($a in $Agents) {
    $sca = & curl.exe -sk -H "Authorization: Bearer $tok" "$Api/sca/$a" | ConvertFrom-Json
    foreach ($p in $sca.data.affected_items) {
        "{0} agent {1}: score={2}% pass={3} fail={4} invalid={5} total={6} (scan {7})" -f `
            $p.policy_id, $a, $p.score, $p.pass, $p.fail, $p.invalid, $p.total_checks, $p.end_scan
    }
    if ($Detail) {
        $checks = & curl.exe -sk -H "Authorization: Bearer $tok" `
            "$Api/sca/$a/checks/cis_debian12?result=failed&limit=500"
        if ($a -eq "004") {
            $checks = & curl.exe -sk -H "Authorization: Bearer $tok" `
                "$Api/sca/$a/checks/cis_ubuntu24-04?result=failed&limit=500"
        }
        $items = ($checks | ConvertFrom-Json).data.affected_items
        $items | ForEach-Object { "  FAIL {0} {1}" -f $_.id, $_.title }
        "  (failed count: {0})" -f $items.Count
    }
}
