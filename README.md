# ADCS ESC Manual Verification Runbook

## How to run this

You don't need to understand the commands or change anything in them. They find the Certificate Authorities, templates, permissions and domain controllers on their own, only read settings, and save everything to an evidence folder. Nothing on the server or in the domain is changed.

**Which parts to run, and where**

- **Part A (Steps 1–7):** on every Certificate Authority server, logged on as a local administrator. Nothing connects to other servers. If the CA is also a domain controller, Part A checks its DC settings too (step 6.3).
- **Part B (B.1–B.3):** on every other domain controller, as listed in the yellow `NEXT` line at the end of Part A, logged on as an administrator of that DC. A CA that is also a DC doesn't need Part B.
- **Part C (C.1–C.4):** only on servers the reviewer names that host web enrollment but are not CAs.
- **Part D (D.1–D.3):** run once by the reviewer, on any Windows machine, after every zip from Parts A, B and C has come back. It combines all runs into one report.

Parts B and C are self-contained: they don't use any boxes from Part A.

Each run creates its own evidence folder. Send all of them back.

**Before you start**

- Log on to the Certificate Authority (CA) server you were asked to run this on, with the account you were given.
- Open **Windows PowerShell** (version 5.1) or PowerShell 7: right-click it and choose **Run as administrator**.
- Keep this one window open until Step 7 is finished. If it closes by accident, start again from Step 1.

**For each grey box**

1. Click the copy button on the box (or select all of the text in it) and copy it.
2. Right-click inside the PowerShell window to paste, then press **Enter**.
3. Wait until the green line starting with the step number (for example `[2.1] DONE`) appears, then move to the next box.

**What the colours mean**

- **Green** `DONE`: the step worked. Carry on.
- **Yellow** `SKIPPED` or `WARNING`: expected in some environments. Carry on.
- **Red** `STOP`: stop, and send a screenshot of the window to the person who gave you this runbook.
- **Red error text without the word STOP**: take a screenshot, then carry on. The transcript records it.

You don't need to judge whether anything is good or bad. A reviewer reads the results afterwards, using the last section of this document.

## Step 1: Setup

**1.1 Start recording**

```powershell
$part = 'A'   # Which part this run is: A = CA server, B = domain controller, C = other web enrollment server
# Create the evidence folder and start recording everything
$ev = "C:\ESC_Evidence\$($env:COMPUTERNAME)_Part$($part)_$(Get-Date -Format yyyyMMdd_HHmm)"
New-Item $ev -ItemType Directory -Force | Out-Null
Start-Transcript "$ev\transcript.txt"
$MaximumErrorCount = 10000
$Error.Clear()
$fqdn = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem).Domain)".ToLower()
# Results list, and helpers that add FINDING / MANUAL CHECK / CLEAR rows to it
$F = New-Object System.Collections.ArrayList
$row = {
    param($status, $check, $target, $detail, $manual)
    [void]$F.Add([pscustomobject]@{
        Status      = $status
        Check       = $check
        Target      = $target
        Detail      = $detail
        ManualCheck = $manual
        Host        = $env:COMPUTERNAME
        Part        = $part
    })
}
$add = { param($check, $target, $detail, $manual) & $row 'FINDING' $check $target $detail $manual }
$man = { param($check, $target, $detail, $manual) & $row 'MANUAL CHECK' $check $target $detail $manual }
# At the end of each step: flag any errors, and mark checks with no rows as CLEAR
$close = {
    param($step, [string[]]$checks, $e0)
    $err = $Error.Count -gt $e0
    if ($err) {
        & $man "Step $step" '' "Errors occurred while step $step ran, so its results may be incomplete." "Find the red text for step $step in transcript.txt, resolve the cause (usually permissions or connectivity) and re-run step $step."
    }
    foreach ($c in $checks) {
        $hasRows = @($F | Where-Object { $_.Check -eq $c }).Count -gt 0
        if (-not $hasRows -and $err) {
            & $man $c '' "Nothing was found, but step $step had errors, so this can't be confirmed as clear." "Re-run step $step after resolving the errors."
        }
        if (-not $hasRows -and -not $err) {
            & $row 'CLEAR' $c '' "Checked in step $step; nothing found." ''
        }
    }
}
# Summary text for the DONE lines
$cnt = {
    param([string[]]$checks)
    $parts = foreach ($c in $checks) {
        $f = @($F | Where-Object Check -eq $c)
        "${c}: $(@($f | Where-Object Status -eq 'FINDING').Count) finding, $(@($f | Where-Object Status -eq 'MANUAL CHECK').Count) manual"
    }
    $parts -join ' | '
}
# Reads the owner and permissions of an AD object (works in Windows PowerShell 5.1 and PowerShell 7)
$getSd = {
    param($dn)
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($dn -replace '/', '\/')")
    $de.ObjectSecurity
}
# Build numbers of the security updates that matter (Microsoft's Windows Server release information)
$thr = @{
    '14393' = @{ May2022 = 5125; Nov2024 = 7515; Feb2025 = 7785; Sep2025 = 8422; Jul2026 = 9339 }    # Server 2016
    '17763' = @{ May2022 = 2928; Nov2024 = 6532; Feb2025 = 6893; Sep2025 = 7792; Jul2026 = 9020 }    # Server 2019
    '20348' = @{ May2022 = 707;  Nov2024 = 2849; Feb2025 = 3207; Sep2025 = 4171; Jul2026 = 5386 }    # Server 2022
    '26100' = @{ May2022 = 0;    Nov2024 = 2314; Feb2025 = 3194; Sep2025 = 6584; Jul2026 = 33158 }   # Server 2025
}
# Hotpatch builds for the same months; builds between the two numbers can't be judged exactly
$thrHp = @{
    '20348' = @{ Nov2024 = 2819; Feb2025 = 3148; Sep2025 = 4106 }
    '26100' = @{ Nov2024 = 2240; Feb2025 = 3107; Sep2025 = 6508 }
}
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osb = "$($cv.CurrentBuild)"
$ubr = [int]$cv.UBR
# Answers YES, NO or UNKNOWN to "does this server have update $k?"
$patched = {
    param($k)
    if (-not $thr.ContainsKey($osb)) { return 'UNKNOWN' }
    if ($ubr -ge $thr[$osb][$k]) { return 'YES' }
    if ($thrHp.ContainsKey($osb) -and $thrHp[$osb].ContainsKey($k) -and $ubr -ge $thrHp[$osb][$k]) { return 'UNKNOWN' }
    return 'NO'
}
# Record who, where and when
whoami /user /groups
hostname
Get-Date -Format o
(Get-CimInstance Win32_OperatingSystem).Caption
"Part $part | OS build: $osb.$ubr | PowerShell $($PSVersionTable.PSVersion)" | Tee-Object "$ev\00_os_build.txt"
# Check this window is elevated, and PowerShell is version 5.1 or later
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$psOk    = $PSVersionTable.PSVersion -ge [version]'5.1'
if (-not $isAdmin) {
    Write-Host "[1.1] STOP: this window is not running as administrator." -ForegroundColor Red
}
if (-not $psOk) {
    Write-Host "[1.1] STOP: PowerShell $($PSVersionTable.PSVersion) is too old. Use Windows PowerShell 5.1 or PowerShell 7." -ForegroundColor Red
}
if ($isAdmin -and $psOk) {
    Write-Host "[1.1] DONE - evidence folder: $ev" -ForegroundColor Green
}
```

You should see: `Transcript started`, your account details, and a green `[1.1] DONE` line.

**1.2 Load the tools**

```powershell
$adOk = [bool](Get-Module -ListAvailable ActiveDirectory)
if ($adOk) {
    Import-Module ActiveDirectory
    Write-Host "[1.2] DONE - ActiveDirectory module loaded" -ForegroundColor Green
} else {
    Write-Host "[1.2] STOP: the ActiveDirectory PowerShell module is not installed on this server." -ForegroundColor Red
}
```

You should see: a green `[1.2] DONE` line.

**1.3 Read the domain and forest**

```powershell
$Error.Clear(); $e0 = 0
$dom    = Get-ADDomain
$forest = Get-ADForest
if (-not $forest) {
    Write-Host "[1.3] STOP: could not read the domain. Check this server can reach a domain controller." -ForegroundColor Red
}
$cfg = (Get-ADRootDSE).configurationNamingContext
$pks = "CN=Public Key Services,CN=Services,$cfg"
# SID of every domain in the forest
$domSid = @{}
foreach ($d in $forest.Domains) {
    try {
        $domSid[$d] = (Get-ADDomain -Identity $d -Server $d).DomainSID.Value
    } catch {
        & $man 'Setup' $d 'Could not reach this domain. Its admin groups are not in the expected-admin list, and its domain controllers and accounts are not checked.' "Run Part A from a server in $d, or confirm with the client that this domain is out of scope."
        $Error.RemoveAt(0)
    }
}
$rootSid = $domSid[$forest.RootDomain]
if (-not $rootSid) {
    & $man 'Setup' $forest.RootDomain 'Could not read the forest root domain, so Enterprise Admins, Schema Admins and Enterprise Key Admins are not in the expected-admin list.' 'Treat any finding that names only those groups as expected.'
}
# Broad groups: Everyone, Authenticated Users, Anonymous, Users, Guests, Domain Users, Domain Guests, Domain Computers
$lowSid = @('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545', 'S-1-5-32-546')
$lowSid += @($domSid.Values | ForEach-Object { "$_-513"; "$_-514"; "$_-515" })
# Built-in admin and system principals
$t0Sid = @('S-1-5-18', 'S-1-5-10', 'S-1-5-9', 'S-1-3-0', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551')
if ($rootSid) {
    $t0Sid += @("$rootSid-518", "$rootSid-519", "$rootSid-527")
}
$t0Sid += @($domSid.Values | ForEach-Object { "$_-500"; "$_-512"; "$_-516"; "$_-517"; "$_-526" })
# Add every user, group and computer nested inside the admin groups
$privUserDN = @()
foreach ($d in @($domSid.Keys)) {
    $gs = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', "$($domSid[$d])-512")
    if ($d -eq $forest.RootDomain) {
        $gs += @("$rootSid-518", "$rootSid-519")
    }
    foreach ($gsid in $gs) {
        try {
            $g = Get-ADGroup -Identity $gsid -Server $d -ErrorAction Stop
            $m = @(Get-ADObject -Server $d -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName))" -Properties objectSid -ErrorAction Stop)
            $t0Sid      += @($m | Where-Object objectSid | ForEach-Object { $_.objectSid.Value })
            $privUserDN += @($m | Where-Object { $_.ObjectClass -eq 'user' } | ForEach-Object DistinguishedName)
        } catch {
            & $man 'Setup' "$d ($gsid)" "Could not expand the members of this admin group: $($_.Exception.Message)" 'Members of this group may be reported as non-admin; check any finding that names them.'
            $Error.RemoveAt(0)
        }
    }
}
if ($domSid.Count -gt 1) {
    & $man 'Setup' $forest.Name "This forest has $($domSid.Count) domains. Nested admin-group membership is resolved within each domain, so a principal that is an admin only through another domain's group may be reported as non-admin." 'For any finding naming a principal from another domain, check whether it belongs to an admin group in that domain.'
}
$maq = (Get-ADObject $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
# Certificate purposes that allow logon, and the Enroll / AutoEnroll / All-extended-rights permissions
$authEKU     = '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'
$zeroGuid    = '00000000-0000-0000-0000-000000000000'
$enrollGuids = '0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2', $zeroGuid
# Turns a SID into a readable name
$nm = {
    param($s)
    try {
        ([System.Security.Principal.SecurityIdentifier]$s).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $Error.RemoveAt(0)
        $s
    }
}
"Domain: $($dom.DNSRoot) | Forest: $($forest.Name) | Domains reachable: $($domSid.Count) of $(@($forest.Domains).Count) | MachineAccountQuota: $maq | Admin principals recognised: $(@($t0Sid | Sort-Object -Unique).Count)" | Tee-Object "$ev\00_environment.txt"
& $close '1.3' @() $e0
Write-Host "[1.3] DONE" -ForegroundColor Green
```

You should see: one line naming the domain and forest, then a green `[1.3] DONE` line.

## Step 2: Find the CAs, templates and permissions

**2.1 Find every Certificate Authority**

```powershell
$Error.Clear(); $e0 = 0
# Every Certificate Authority in the forest
$cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,$pks" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates, 'msPKI-Enrollment-Servers')
$cas | Select-Object Name, dNSHostName,
    @{ n = 'Templates'; e = { $_.certificateTemplates -join ', ' } },
    @{ n = 'CESUrls';   e = { ([regex]::Matches(($_.'msPKI-Enrollment-Servers' -join ' '), 'https?://\S+') | ForEach-Object Value) -join ' ' } } |
    Tee-Object "$ev\01_CAs.txt" | Format-List
# Which CA is this server, and which CAs need their own run
$thisCA = @($cas | Where-Object { ($_.dNSHostName -split '\.')[0] -eq $env:COMPUTERNAME })
$others = @($cas | Where-Object { ($_.dNSHostName -split '\.')[0] -ne $env:COMPUTERNAME })
$others | Select-Object Name, dNSHostName | Out-File "$ev\ALSO_RUN_ON_THESE_SERVERS.txt"
# CA computer accounts count as expected admins
foreach ($c in $cas) {
    $hn, $hd = $c.dNSHostName -split '\.', 2
    try {
        $t0Sid += (Get-ADComputer -Identity $hn -Server $hd).SID.Value
    } catch {
        & $man 'Setup' $c.dNSHostName "Could not look up this CA's computer account, so rights it holds on its own AD objects may appear as ESC5 findings." 'Treat ESC5 rows naming this CA computer account as expected.'
        $Error.RemoveAt(0)
    }
}
foreach ($o in $others) {
    & $man 'CA server checks' $o.dNSHostName 'Steps 4.1, 4.2 and 5.2 read settings on the CA server itself, so ESC3 agent restrictions, ESC6, ESC7, ESC11, ESC12, ESC15, ESC16, the CA patch level and local ESC8 settings for this CA were not checked.' "Run Part A on $($o.dNSHostName)."
}
& $close '2.1' @() $e0
if ($cas.Count -eq 0) {
    Write-Host "[2.1] STOP: no Certificate Authority was found in this forest." -ForegroundColor Red
}
if ($cas.Count -gt 0 -and $thisCA.Count -eq 0) {
    Write-Host "[2.1] WARNING: this server is not a Certificate Authority. Steps 4.1, 4.2 and 5.2 will be skipped." -ForegroundColor Yellow
    Write-Host "[2.1] DONE - CAs found: $($cas.Count)" -ForegroundColor Green
}
if ($thisCA.Count -gt 0) {
    Write-Host "[2.1] DONE - CAs found: $($cas.Count). This server is the CA '$($thisCA[0].Name)'." -ForegroundColor Green
}
```

You should see: a short list of CAs with their templates, then a green `[2.1] DONE` line.

**2.2 Read every certificate template**

```powershell
$Error.Clear(); $e0 = 0
$pub    = @($cas.certificateTemplates | Sort-Object -Unique)
$allTpl = @(Get-ADObject -SearchBase "CN=Certificate Templates,$pks" -SearchScope OneLevel -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties *)
$allTpl | Select-Object Name, displayName,
    @{ n = 'Published';      e = { $_.Name -in $pub } },
    'msPKI-Template-Schema-Version', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature',
    @{ n = 'EKU';            e = { $_.pKIExtendedKeyUsage -join ';' } },
    @{ n = 'AppPolicy';      e = { $_.'msPKI-Certificate-Application-Policy' -join ';' } },
    @{ n = 'IssuancePolicy'; e = { $_.'msPKI-Certificate-Policy' -join ';' } },
    @{ n = 'RAPolicy';       e = { $_.'msPKI-RA-Application-Policies' -join ';' } } |
    Export-Csv "$ev\02_all_templates.csv" -NoTypeInformation
# Only templates published on a CA can be used
$tpl = @($allTpl | Where-Object Name -in $pub)
foreach ($n in @($pub | Where-Object { $_ -notin $allTpl.Name })) {
    & $man 'Templates' $n 'A CA publishes this template name, but no template with that name was found in AD.' 'Check in certtmpl.msc whether the template still exists, and in certsrv.msc whether the CA should still publish it.'
}
& $close '2.2' @() $e0
Write-Host "[2.2] DONE - templates in AD: $($allTpl.Count); published on a CA: $($tpl.Count)" -ForegroundColor Green
```

You should see: a green `[2.2] DONE` line with two numbers. Any numbers are fine; the reviewer interprets them.

**2.3 Read template permissions and owners**

This can take a minute in large environments.

```powershell
$Error.Clear(); $e0 = 0
$acl    = New-Object System.Collections.ArrayList
$owners = New-Object System.Collections.ArrayList
# Read the owner and every permission entry of each published template
foreach ($t in $tpl) {
    try {
        $sd = & $getSd $t.DistinguishedName
        $o  = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        [void]$owners.Add([pscustomobject]@{
            Template = $t.Name
            Owner    = (& $nm $o)
            OwnerSid = $o
            Expected = ($o -in $t0Sid)
        })
        foreach ($r in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $s = $r.IdentityReference.Value
            [void]$acl.Add([pscustomobject]@{
                Template   = $t.Name
                Type       = "$($r.AccessControlType)"
                Name       = (& $nm $s)
                Sid        = $s
                Rights     = "$($r.ActiveDirectoryRights)"
                ObjectType = "$($r.ObjectType)"
                Broad      = ($s -in $lowSid)
                Expected   = ($s -in $t0Sid)
            })
        }
    } catch {
        & $man 'Template permissions' $t.Name "Could not read this template's permissions: $($_.Exception.Message)" 'Open certtmpl.msc, open this template and screenshot its Security tab.'
        $Error.RemoveAt(0)
    }
}
$acl    | Export-Csv "$ev\03_template_permissions.csv" -NoTypeInformation
$owners | Export-Csv "$ev\04_template_owners.csv" -NoTypeInformation
$allow = @($acl | Where-Object Type -eq 'Allow')
# Deny entries are not evaluated automatically
foreach ($n in @($acl | Where-Object Type -eq 'Deny' | ForEach-Object Template | Sort-Object -Unique)) {
    & $man 'Template permissions' $n 'This template has Deny permission entries. The automatic checks only use Allow entries, so a finding for this template may be blocked by a Deny.' 'Open certtmpl.msc, open this template, and confirm on the Security tab whether the Deny entries stop the principals named in any finding for it.'
}
# Non-admin principals that can enroll (Enroll, AutoEnroll, All extended rights or Full Control)
$enr = @($allow | Where-Object {
    -not $_.Expected -and (
        $_.Rights -match 'GenericAll' -or
        ($_.Rights -match 'ExtendedRight' -and $_.ObjectType -in $enrollGuids)
    )
})
$enr | Export-Csv "$ev\05_template_enroll_non_admin.csv" -NoTypeInformation
$enrT = @($enr.Template | Sort-Object -Unique)
$who  = { param($n) (@($enr | Where-Object Template -eq $n).Name | Sort-Object -Unique) -join '; ' }
& $close '2.3' @() $e0
Write-Host "[2.3] DONE - permission entries: $($acl.Count); templates non-admins can enroll in: $($enrT.Count)" -ForegroundColor Green
```

You should see: a green `[2.3] DONE` line. The second number is normally at least 1, because ordinary users can enroll in the built-in User template.

## Step 3: Template checks

**3.1 Check templates for ESC1, ESC2, ESC3 and ESC4**

```powershell
$Error.Clear(); $e0 = 0
# Does the template need manager approval or an authorised signature?
$gate = { param($x) [bool]($x.'msPKI-Enrollment-Flag' -band 2) -or [bool]($x.'msPKI-RA-Signature' -gt 0) }
# Can the certificate be used to log on (or has no EKU, which allows anything)?
$auth = { param($x) [bool](-not $x.pKIExtendedKeyUsage) -or [bool]($x.pKIExtendedKeyUsage | Where-Object { $_ -in $authEKU }) }
$conf = 'Confirm in tpl_<template>_settings.txt and tpl_<template>_permissions.txt. The principals named are not members of any admin group: confirm whether each is an approved PKI administrator.'
$appr = 'Requests need manager approval or an authorised signature. Confirm who can approve (ManageCertificates in CA_permissions.csv) and that requests are really reviewed, not auto-approved.'
# EKU list and Application Policies disagree: EKU-based checks may be wrong
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and $_.'msPKI-Certificate-Application-Policy' })) {
    $eku = (@($t.pKIExtendedKeyUsage) | Sort-Object) -join ';'
    $app = (@($t.'msPKI-Certificate-Application-Policy') | Sort-Object) -join ';'
    if ($eku -ne $app) {
        & $man 'EKU' $t.Name 'The template EKU list and its Application Policies differ, so the EKU-based checks (ESC1, ESC2, ESC3, ESC9, ESC17) may be wrong for it.' 'Open the template in certtmpl.msc, check Extensions > Application Policies, and re-assess ESC1, ESC2, ESC3, ESC9 and ESC17 by hand.'
    }
}
# ESC1: requester supplies the subject on a logon-capable certificate
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and ($_.'msPKI-Certificate-Name-Flag' -band 1) -and (& $auth $_) })) {
    if (& $gate $t) {
        & $man 'ESC1' $t.Name "Would be ESC1, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        & $add 'ESC1' $t.Name "Requester supplies the subject and the certificate allows logon. Can enroll: $(& $who $t.Name)" $conf
    }
}
# ESC2: Any Purpose EKU or no EKU at all
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and ((-not $_.pKIExtendedKeyUsage -and -not $_.'msPKI-Certificate-Application-Policy') -or $_.pKIExtendedKeyUsage -contains '2.5.29.37.0') })) {
    if (& $gate $t) {
        & $man 'ESC2' $t.Name "Would be ESC2, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        & $add 'ESC2' $t.Name "Any Purpose EKU or no EKU. Can enroll: $(& $who $t.Name)" $conf
    }
}
# ESC3: enrollment agent template, plus a template that accepts on-behalf-of requests
$esc3a = @($tpl | Where-Object { $_.Name -in $enrT -and $_.pKIExtendedKeyUsage -contains '1.3.6.1.4.1.311.20.2.1' })
$esc3t = @($tpl | Where-Object {
    (& $auth $_) -and (
        $_.'msPKI-Template-Schema-Version' -eq 1 -or
        ($_.'msPKI-RA-Signature' -eq 1 -and "$($_.'msPKI-RA-Application-Policies')" -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1')
    )
})
foreach ($t in $esc3a) {
    if (& $gate $t) {
        & $man 'ESC3' $t.Name "Would be ESC3, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        if ($esc3t.Count) {
            & $add 'ESC3' $t.Name "Enrollment agent template. Can enroll: $(& $who $t.Name). On-behalf-of targets: $($esc3t.Name -join ', ')" "$conf Agent restrictions on the CA are checked in step 4.1."
        } else {
            & $man 'ESC3' $t.Name "Enrollment agent template, but no published template accepts on-behalf-of requests. Can enroll: $(& $who $t.Name)" 'Confirm no CA publishes a schema v1 logon template or one requiring a single Certificate Request Agent signature.'
        }
    }
}
# ESC4: non-admins with broad write rights on a template
foreach ($a in @($allow | Where-Object { -not $_.Expected -and ($_.Rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' -or ($_.Rights -match 'WriteProperty' -and $_.ObjectType -eq $zeroGuid)) })) {
    & $add 'ESC4' $a.Template "$($a.Name) has $($a.Rights)" 'Confirm in 03_template_permissions.csv. The principal is not a member of any admin group: confirm whether it is an approved PKI administrator.'
}
# ESC4: non-admins who can write one specific attribute
foreach ($a in @($allow | Where-Object { -not $_.Expected -and $_.Rights -match 'WriteProperty' -and $_.ObjectType -ne $zeroGuid -and $_.ObjectType -notin $enrollGuids -and $_.Rights -notmatch 'GenericAll|GenericWrite|WriteDacl|WriteOwner' })) {
    & $man 'ESC4' $a.Template "$($a.Name) can write one specific attribute (GUID $($a.ObjectType))." 'Identify the attribute or property set with that GUID and decide whether writing it changes how certificates are issued.'
}
# ESC4: templates owned by a non-admin
foreach ($ow in @($owners | Where-Object { -not $_.Expected })) {
    & $add 'ESC4' $ow.Template "Template owned by $($ow.Owner)" 'An owner can change the template permissions. The owner is not a member of any admin group: confirm whether it is an approved PKI administrator.'
}
& $close '3.1' @('ESC1', 'ESC2', 'ESC3', 'ESC4') $e0
Write-Host "[3.1] DONE - $(& $cnt 'ESC1','ESC2','ESC3','ESC4')" -ForegroundColor Green
```

You should see: a green `[3.1] DONE` line with counts. Any counts are fine, including zero.

**3.2 Check templates for ESC9, ESC13 and ESC15**

```powershell
$Error.Clear(); $e0 = 0
# ESC9: logon-capable template that leaves out the SID security extension
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and ($_.'msPKI-Enrollment-Flag' -band 0x80000) -and (& $auth $_) })) {
    if (& $gate $t) {
        & $man 'ESC9' $t.Name "Would be ESC9, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        & $add 'ESC9' $t.Name "No-security-extension flag set on a logon-capable template. Can enroll: $(& $who $t.Name)" "Exploitable only while any DC accepts weak mappings: rate using the Part B results. $conf"
    }
}
# ESC13: issuance policy that grants membership of an AD group
$oids = @(Get-ADObject -SearchBase "CN=OID,$pks" -LDAPFilter '(msDS-OIDToGroupLink=*)' -Properties displayName, 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink')
$oids | Select-Object displayName, 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink' | Format-List | Out-File "$ev\06_issuance_policy_group_links.txt"
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and ($_.'msPKI-Certificate-Policy' | Where-Object { $_ -in $oids.'msPKI-Cert-Template-OID' }) })) {
    $lg = @($oids | Where-Object { $_.'msPKI-Cert-Template-OID' -in $t.'msPKI-Certificate-Policy' } | ForEach-Object { $_.'msDS-OIDToGroupLink' })
    $lgAdmin = @()
    foreach ($gd in $lg) {
        try {
            if ((Get-ADGroup -Identity $gd -Server "$($forest.Name):3268" -ErrorAction Stop).SID.Value -in $t0Sid) { $lgAdmin += $gd }
        } catch {
            & $man 'ESC13' $t.Name "Could not look up the linked group $gd, so it is unknown whether it is an admin group." 'Check this group in Active Directory Users and Computers and whether it belongs to an admin group.'
            $Error.RemoveAt(0)
        }
    }
    if (& $gate $t) {
        & $man 'ESC13' $t.Name "Would be ESC13, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        if ($lgAdmin.Count) {
            & $add 'ESC13' $t.Name "Issuance policy grants membership of admin group(s): $($lgAdmin -join '; '). Can enroll: $(& $who $t.Name)" 'Confirm in 06_issuance_policy_group_links.txt.'
        } else {
            & $add 'ESC13' $t.Name "Issuance policy grants membership of group(s) $($lg -join '; '), which are not admin groups. Can enroll: $(& $who $t.Name)" 'Check what rights the linked group holds (permissions on AD objects, GPO rights, local admin rights) to rate the impact.'
        }
    }
}
# ESC15: schema v1 template where the requester supplies the subject (CA patch level is checked in 4.1)
$esc15c = @()
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and $_.'msPKI-Template-Schema-Version' -eq 1 -and ($_.'msPKI-Certificate-Name-Flag' -band 1) })) {
    if (& $gate $t) {
        & $man 'ESC15' $t.Name "Would be ESC15, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        $esc15c += $t
    }
}
# ESC17: requester supplies the subject on a Server Authentication certificate
foreach ($t in @($tpl | Where-Object { $_.Name -in $enrT -and ($_.'msPKI-Certificate-Name-Flag' -band 1) -and $_.pKIExtendedKeyUsage -contains '1.3.6.1.5.5.7.3.1' })) {
    if (& $gate $t) {
        & $man 'ESC17' $t.Name "Would be ESC17, but requests need approval. Can enroll: $(& $who $t.Name)" $appr
    } else {
        & $add 'ESC17' $t.Name "Requester supplies the subject on a Server Authentication certificate, so it can be used to impersonate web or TLS servers (for example WSUS). Can enroll: $(& $who $t.Name)" $conf
    }
}
& $close '3.2' @('ESC9', 'ESC13', 'ESC17') $e0
Write-Host "[3.2] DONE - $(& $cnt 'ESC9','ESC13','ESC17') | ESC15 candidates (patch checked in 4.1): $($esc15c.Count)" -ForegroundColor Green
```

You should see: a green `[3.2] DONE` line with counts.

**3.3 Save detailed evidence for each flagged template**

```powershell
$Error.Clear(); $e0 = 0
# Save certutil's readable view of every template that appears in a result
$flagged = @(@($F | Where-Object { $_.Target -in $tpl.Name } | ForEach-Object Target) + @($esc15c | ForEach-Object Name) | Sort-Object -Unique)
foreach ($n in $flagged) {
    $o1 = certutil -v -dstemplate $n
    $o1 | Out-File "$ev\tpl_$($n)_settings.txt"
    $o2 = certutil -v -template $n
    $o2 | Out-File "$ev\tpl_$($n)_permissions.txt"
    if (($o1 -match 'FAILED') -or ($o2 -match 'FAILED')) {
        & $man 'Evidence' $n 'certutil could not save full details for this template.' 'Open the template in certtmpl.msc and screenshot its General, Subject Name, Extensions, Issuance Requirements and Security tabs.'
    }
}
& $close '3.3' @() $e0
Write-Host "[3.3] DONE - detailed evidence saved for $($flagged.Count) template(s)" -ForegroundColor Green
```

You should see: a green `[3.3] DONE` line. If the number is 0, that is fine.

## Step 4: CA server checks

Steps 4.1 and 4.2 only run on a CA server; on any other server they print a yellow `SKIPPED` line, which is fine.

**4.1 Read the CA's settings (ESC3, ESC6, ESC11, ESC16)**

```powershell
$Error.Clear(); $e0 = 0
if ($thisCA.Count -eq 0) {
    Write-Host "[4.1] SKIPPED - this server is not a CA" -ForegroundColor Yellow
    foreach ($t in $esc15c) {
        & $man 'ESC15' $t.Name 'Schema v1 template where the requester supplies the subject; the patch level of the CAs that publish it was not checked from this server.' 'Run Part A on each CA that publishes this template (see 01_CAs.txt).'
    }
} else {
    # Where this CA keeps its settings
    $caName  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction Ignore).Active
    $caKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    $caReg   = Get-ItemProperty $caKey -ErrorAction Ignore
    $polName = (Get-ItemProperty "$caKey\PolicyModules" -ErrorAction Ignore).Active
    $polReg  = $null
    if ($polName) {
        $polReg = Get-ItemProperty "$caKey\PolicyModules\$polName" -ErrorAction Ignore
    }
    # Human-readable evidence
    certutil -getreg policy\EditFlags            | Out-File "$ev\CA_EditFlags.txt"
    certutil -getreg CA\InterfaceFlags           | Out-File "$ev\CA_InterfaceFlags.txt"
    certutil -getreg policy\DisableExtensionList | Out-File "$ev\CA_DisableExtensionList.txt"
    certutil -getreg CA\EnrollmentAgentRights    | Out-File "$ev\CA_EnrollmentAgentRights.txt"
    certutil -getreg CA\AuditFilter              | Out-File "$ev\CA_AuditFilter.txt"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Out-File "$ev\CA_recent_updates.txt"
    $caRead = [bool]($caName -and $caReg)
    if (-not $caRead) {
        foreach ($c in 'ESC6', 'ESC11', 'ESC12', 'ESC16') {
            & $man $c $env:COMPUTERNAME 'Could not read the CA configuration from the registry.' 'Confirm the CA role is installed on this server and re-run step 4.1, or review the CA_*.txt files by hand.'
        }
    } else {
        # ESC6 and ESC16: policy module settings
        $defaultPolicy = $polName -eq 'CertificateAuthority_MicrosoftDefault.Policy'
        if (-not $defaultPolicy) {
            foreach ($c in 'ESC6', 'ESC16') {
                & $man $c $caName "This CA uses the policy module '$polName', not the Windows default, so this can't be judged from its settings." 'Ask the CA owner whether this policy module accepts requester-supplied SANs and whether it includes the SID security extension.'
            }
        } else {
            if ($null -eq $polReg.EditFlags) {
                & $man 'ESC6' $caName 'EditFlags could not be read.' 'Check CA_EditFlags.txt for EDITF_ATTRIBUTESUBJECTALTNAME2.'
            }
            if ($polReg.EditFlags -band 0x40000) {
                & $add 'ESC6' $caName 'EDITF_ATTRIBUTESUBJECTALTNAME2 is set.' 'Confirm in CA_EditFlags.txt. Exploitable mainly while any DC accepts weak mappings: rate using the Part B results.'
            }
            if (@($polReg.DisableExtensionList) -contains '1.3.6.1.4.1.311.25.2') {
                & $add 'ESC16' $caName 'The SID security extension (1.3.6.1.4.1.311.25.2) is disabled for every certificate.' 'Confirm in CA_DisableExtensionList.txt. Rate using the Part B results.'
            }
        }
        # ESC11: encrypted RPC requests (flag 0x200)
        if ($null -eq $caReg.InterfaceFlags) {
            & $man 'ESC11' $caName 'InterfaceFlags could not be read.' 'Check CA_InterfaceFlags.txt for IF_ENFORCEENCRYPTICERTREQUEST.'
        } else {
            if (-not ($caReg.InterfaceFlags -band 0x200)) {
                & $add 'ESC11' $caName 'IF_ENFORCEENCRYPTICERTREQUEST is not set, so certificate requests over RPC can be relayed.' 'Confirm in CA_InterfaceFlags.txt.'
            }
        }
        # ESC3: enrollment agent restrictions on this CA
        if ($esc3a.Count -and -not $caReg.EnrollmentAgentRights) {
            & $add 'ESC3' $caName 'No enrollment agent restrictions are configured on this CA.' 'Confirm in certsrv.msc > CA Properties > Enrollment Agents (should say Restrict enrollment agents).'
        }
        if ($esc3a.Count -and $caReg.EnrollmentAgentRights) {
            & $man 'ESC3' $caName "Enrollment agent restrictions are configured, but their content can't be judged automatically." 'Open certsrv.msc > CA Properties > Enrollment Agents, confirm only intended agents, templates and target groups are allowed, and screenshot it.'
        }
        # ESC15: is this CA patched (November 12, 2024)?
        $myT = @($thisCA[0].certificateTemplates)
        $p15 = & $patched 'Nov2024'
        foreach ($t in $esc15c) {
            if ($t.Name -notin $myT) {
                & $man 'ESC15' $t.Name 'Schema v1 template where the requester supplies the subject, published on another CA.' 'Checked by Part A on the CA that publishes it (see 01_CAs.txt).'
            } else {
                if ($p15 -eq 'NO') {
                    & $add 'ESC15' $t.Name "Schema v1 template where the requester supplies the subject, and this CA (OS build $osb.$ubr) does not have the November 12, 2024 update. Can enroll: $(& $who $t.Name)" 'Confirm in tpl_<template>_settings.txt and 00_os_build.txt.'
                }
                if ($p15 -eq 'UNKNOWN') {
                    & $man 'ESC15' $t.Name "Schema v1 template where the requester supplies the subject; could not confirm whether build $osb.$ubr includes the November 12, 2024 update (hotpatch build or unsupported Windows version)." "Check build $osb.$ubr against Microsoft's update history for this Windows Server version."
                }
            }
        }
        # Certighost and Certifried: is this CA patched?
        $cves = @(
            @{ Id = 'CVE-2026-54121'; K = 'Jul2026'; Name = 'Certighost'; Date = 'July 14, 2026' },
            @{ Id = 'CVE-2022-26923'; K = 'May2022'; Name = 'Certifried'; Date = 'May 10, 2022' }
        )
        foreach ($cve in $cves) {
            $p = & $patched $cve.K
            if ($p -eq 'NO') {
                & $add $cve.Id $caName "$($cve.Name): this CA (OS build $osb.$ubr) does not have the $($cve.Date) security update." "Confirm in 00_os_build.txt. MachineAccountQuota is $maq (any value above 0 lets ordinary users create computer accounts for this attack)."
            }
            if ($p -eq 'UNKNOWN') {
                & $man $cve.Id $caName "Could not confirm whether build $osb.$ubr includes the $($cve.Date) update ($($cve.Name)): hotpatch build or unsupported Windows version." "Check build $osb.$ubr against Microsoft's update history for this Windows Server version."
            }
        }
        # ESC12 and CA key protection: where is the CA private key held?
        $prov = (Get-ItemProperty "$caKey\CSP" -ErrorAction Ignore).Provider
        "CA key provider: $prov" | Out-File "$ev\CA_key_provider.txt"
        $kind = 'other'
        if (-not $prov) { $kind = 'unknown' }
        if ($prov -match 'YubiHSM') { $kind = 'yubihsm' }
        if ($prov -match '^Microsoft (Software Key Storage Provider|.*Cryptographic Provider)') { $kind = 'software' }
        if ($kind -eq 'unknown') {
            & $man 'ESC12' $caName 'Could not read which provider holds the CA private key.' 'Open certsrv.msc > CA Properties > General > View Certificate, or ask the CA owner, and record whether the key is in software or a hardware security module.'
        }
        if ($kind -eq 'yubihsm') {
            $yk = Get-ItemProperty 'HKLM:\SOFTWARE\Yubico\YubiHSM' -ErrorAction Ignore
            if ($yk.AuthKeysetPassword) {
                & $add 'ESC12' $caName "The CA key is on a YubiHSM and its authentication password is stored in the registry (HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword, key ID $($yk.AuthKeysetID)). Anyone with administrator access to this server can use the CA key." 'Confirm the value exists (do not record it). Key ID 1 with the default password is the worst case.'
            } else {
                & $man 'ESC12' $caName "The CA key is on a YubiHSM ('$prov'), but no stored authentication password was found in the usual registry location." 'Ask the CA owner how the YubiHSM authentication key is supplied, and check ProgramData\YubiHSM\yubihsm-connector.yaml.'
            }
        }
        if ($kind -eq 'software') {
            & $add 'CA-KEY' $caName "The CA private key is held in software ('$prov'), so any administrator of this server, or anyone with a backup of it, can export the key and forge any certificate (golden certificate)." 'Confirm in CA_key_provider.txt. Rate based on who administers and backs up this server (CA_local_administrators.txt).'
        }
        if ($kind -eq 'other') {
            & $man 'CA-KEY' $caName "The CA private key uses the provider '$prov', which is not a known software provider." 'Confirm with the CA owner that this is a hardware security module and who can use the key.'
        }
        # CA auditing (127 = all events)
        if ($caReg.AuditFilter -ne 127) {
            & $add 'CA-AUDIT' $caName "CA auditing is not fully enabled (AuditFilter=$($caReg.AuditFilter); 127 means all events)." 'Without CA auditing, certificate abuse (including Certighost) leaves no trace on the CA. Confirm in CA_AuditFilter.txt.'
        }
        & $close '4.1' @('ESC6', 'ESC11', 'ESC12', 'ESC15', 'ESC16', 'CVE-2026-54121', 'CVE-2022-26923', 'CA-AUDIT') $e0
    }
    Write-Host "[4.1] DONE - $(& $cnt 'ESC6','ESC11','ESC12','ESC15','ESC16','CVE-2026-54121','CVE-2022-26923')" -ForegroundColor Green
}
```

You should see: a green `[4.1] DONE` line (or yellow `SKIPPED`).

**4.2 Read who can manage the CA (ESC7)**

```powershell
$Error.Clear(); $e0 = 0
if ($thisCA.Count -eq 0 -or -not $caReg) {
    Write-Host "[4.2] SKIPPED - this server is not a CA, or step 4.1 could not read it" -ForegroundColor Yellow
} else {
    certutil -getreg CA\Security      | Out-File "$ev\CA_Security.txt"
    certutil -getreg CA\OfficerRights | Out-File "$ev\CA_OfficerRights.txt"
    # Decode the CA's own permission list
    $sd = $null
    try {
        $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$caReg.Security, 0)
    } catch {
        & $man 'ESC7' $caName "Could not decode the CA permissions: $($_.Exception.Message)" 'Open certsrv.msc > the CA > Properties > Security, screenshot it, and check that only admins have Manage CA or Issue and Manage Certificates.'
        $Error.RemoveAt(0)
    }
    if ($sd) {
        $caAcl = @(foreach ($ace in $sd.DiscretionaryAcl) {
            $s = $ace.SecurityIdentifier.Value
            [pscustomobject]@{
                Name               = (& $nm $s)
                Sid                = $s
                Type               = "$($ace.AceType)"
                Mask               = ('0x{0:X}' -f $ace.AccessMask)
                ManageCA           = [bool]($ace.AccessMask -band 1)
                ManageCertificates = [bool]($ace.AccessMask -band 2)
                Expected           = ($s -in $t0Sid)
            }
        })
        $caAcl | Export-Csv "$ev\CA_permissions.csv" -NoTypeInformation
        # ESC7: non-admins who can manage the CA or approve certificates
        foreach ($a in @($caAcl | Where-Object { $_.Type -eq 'AccessAllowed' -and ($_.ManageCA -or $_.ManageCertificates) -and -not $_.Expected })) {
            & $add 'ESC7' $caName "$($a.Name): ManageCA=$($a.ManageCA), ManageCertificates=$($a.ManageCertificates)" 'Confirm in CA_Security.txt. The principal is not a member of any admin group: confirm whether it is an approved PKI administrator.'
        }
        if (@($caAcl | Where-Object { $_.Type -ne 'AccessAllowed' }).Count) {
            & $man 'ESC7' $caName 'The CA permissions contain Deny or other non-Allow entries, which the automatic check does not evaluate.' 'Review CA_Security.txt and confirm those entries do not change the ESC7 result.'
        }
        & $close '4.2' @('ESC7') $e0
    }
    Write-Host "[4.2] DONE - $(& $cnt 'ESC7')" -ForegroundColor Green
}
```

You should see: a green `[4.2] DONE` line (or yellow `SKIPPED`).

**4.3 Read permissions on PKI objects in AD (ESC5)**

This runs on any server.

```powershell
$Error.Clear(); $e0 = 0
# PKI containers in AD, the CA objects, and the CA computer accounts
$pkiObj = @(
    "CN=Public Key Services,CN=Services,$cfg"
    "CN=Certificate Templates,$pks"
    "CN=Enrollment Services,$pks"
    "CN=NTAuthCertificates,$pks"
    "CN=Certification Authorities,$pks"
    "CN=AIA,$pks"
    "CN=OID,$pks"
)
$pkiObj += @($cas.DistinguishedName)
foreach ($c in $cas) {
    $hn, $hd = $c.dNSHostName -split '\.', 2
    try {
        $pkiObj += (Get-ADComputer -Identity $hn -Server $hd).DistinguishedName
    } catch {
        & $man 'ESC5' "$hn.$hd" 'Could not find this CA computer account, so its permissions were not checked.' 'Check the Security tab of this computer object in Active Directory Users and Computers.'
        $Error.RemoveAt(0)
    }
}
# Read the owner and write permissions of each object
$pkiAcl = New-Object System.Collections.ArrayList
foreach ($d in $pkiObj) {
    try {
        $sd = & $getSd $d
        $o  = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($o -notin $t0Sid) {
            & $add 'ESC5' $d "Owned by $(& $nm $o)" 'An owner can change permissions on this object. The owner is not a member of any admin group: confirm whether it is an approved PKI administrator.'
        }
        foreach ($r in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $rt = "$($r.ActiveDirectoryRights)"
            if ($rt -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild') {
                $s = $r.IdentityReference.Value
                [void]$pkiAcl.Add([pscustomobject]@{
                    Object     = $d
                    Type       = "$($r.AccessControlType)"
                    Name       = (& $nm $s)
                    Sid        = $s
                    Rights     = $rt
                    ObjectType = "$($r.ObjectType)"
                    Expected   = ($s -in $t0Sid)
                })
            }
        }
    } catch {
        & $man 'ESC5' $d "Could not read permissions: $($_.Exception.Message)" 'Open this object in ADSI Edit (Configuration partition) and screenshot Security > Advanced.'
        $Error.RemoveAt(0)
    }
}
$pkiAcl | Export-Csv "$ev\07_pki_object_write_permissions.csv" -NoTypeInformation
# ESC5: non-admins with write rights
foreach ($p in @($pkiAcl | Where-Object { $_.Type -eq 'Allow' -and -not $_.Expected })) {
    if ($p.Rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' -or $p.ObjectType -eq $zeroGuid) {
        & $add 'ESC5' $p.Object "$($p.Name) has $($p.Rights)" 'Confirm in 07_pki_object_write_permissions.csv. The principal is not a member of any admin group: confirm whether it is an approved PKI administrator.'
    } else {
        & $man 'ESC5' $p.Object "$($p.Name) has $($p.Rights) limited to one attribute or object type (GUID $($p.ObjectType))." 'Identify what the GUID refers to and decide whether it allows changing PKI configuration.'
    }
}
foreach ($ob in @($pkiAcl | Where-Object Type -eq 'Deny' | ForEach-Object Object | Sort-Object -Unique)) {
    & $man 'ESC5' $ob 'This object has Deny entries, which the automatic check does not evaluate.' 'Confirm in 07_pki_object_write_permissions.csv whether the Deny entries cancel any ESC5 finding for this object.'
}
# Local administrators of the CA server control the CA
if ($thisCA.Count) {
    net localgroup administrators | Out-File "$ev\CA_local_administrators.txt"
    try {
        $la = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
        foreach ($mbr in $la) {
            $msid = "$($mbr.SID)"
            if ($msid -notin $t0Sid -and $msid -notmatch '-500$') {
                & $man 'ESC5' "$env:COMPUTERNAME local Administrators" "$($mbr.Name) is a local administrator on the CA server." 'Anyone in this group controls the CA. Confirm this account or group is limited to Tier 0 administrators.'
            }
        }
    } catch {
        & $man 'ESC5' "$env:COMPUTERNAME local Administrators" 'Could not list local administrators automatically.' 'Review CA_local_administrators.txt: every member should be a Tier 0 administrator.'
        $Error.RemoveAt(0)
    }
}
& $close '4.3' @('ESC5') $e0
Write-Host "[4.3] DONE - $(& $cnt 'ESC5')" -ForegroundColor Green
```

You should see: a green `[4.3] DONE` line.

## Step 5: Web enrollment checks (ESC8)

**5.1 Test this server's web enrollment addresses**

This only tests this server's own addresses, by sending a header request; it doesn't log in or request anything. Addresses that don't exist show `No response`.

```powershell
$Error.Clear(); $e5 = 0
# This server's own name, the CA hosts, and any CES addresses published in AD
$fqdn    = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem).Domain)".ToLower()
$caHosts = @($cas | ForEach-Object { ($_.dNSHostName -split '\.')[0] })
$ces     = @($cas | ForEach-Object { [regex]::Matches(($_.'msPKI-Enrollment-Servers' -join ' '), 'https?://\S+') | ForEach-Object Value } | Sort-Object -Unique)
# CES addresses on servers that are not CAs need Part C
foreach ($u in $ces) {
    $h = (([uri]$u).Host -split '\.')[0]
    if ($h -ne $env:COMPUTERNAME -and $h -notin $caHosts) {
        & $man 'ESC8' $u 'This CES address is on a server that is not a CA, so Part A does not test it.' "Run Part C of this runbook on $(([uri]$u).Host)."
    }
}
# Addresses on this server to test, over HTTP and HTTPS
$urls = @("http://$fqdn/certsrv/", "https://$fqdn/certsrv/")
foreach ($u in $ces) {
    if ((([uri]$u).Host -split '\.')[0] -eq $env:COMPUTERNAME) {
        $urls += $u
        $urls += ($u -replace '^https://', 'http://')
    }
}
# Send a header request to each address (no login, no certificate request)
$web = @(foreach ($u in ($urls | Sort-Object -Unique)) {
    $q = [System.Net.HttpWebRequest]::Create($u)
    $q.Method            = 'HEAD'
    $q.AllowAutoRedirect = $false
    $q.Timeout           = 15000
    $r = $null; $msg = ''; $ns = ''
    try {
        $r = $q.GetResponse()
    } catch {
        $we = $_.Exception
        if ($we.InnerException) { $we = $we.InnerException }
        $r   = $we.Response
        $msg = $we.Message
        $ns  = "$($we.Status)"
        $Error.RemoveAt(0)
    }
    if ($r) {
        [pscustomobject]@{ Url = $u; Status = [int]$r.StatusCode; Authentication = $r.Headers['WWW-Authenticate']; RedirectsTo = $r.Headers['Location']; NetStatus = $ns; Note = $msg }
        $r.Close()
    } else {
        [pscustomobject]@{ Url = $u; Status = 'No response'; Authentication = ''; RedirectsTo = ''; NetStatus = $ns; Note = $msg }
    }
})
$web | Export-Csv "$ev\08_web_enrollment_probe.csv" -NoTypeInformation
$web | Format-Table Url, Status, NetStatus, Authentication -AutoSize
# Judge each answer (each address matches exactly one rule)
$webRole = [bool](@(Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc -ErrorAction Ignore) | Where-Object Installed)
foreach ($w in $web) {
    $isHttp   = $w.Url -like 'http://*'
    $answered = $w.Status -in 200, 401
    $redirect = $w.Status -in 301, 302, 303, 307, 308
    $nothing  = $w.Status -eq 404 -or ($w.Status -eq 'No response' -and $w.NetStatus -eq 'ConnectFailure')
    # Plain HTTP answers: relayable
    if ($answered -and $isHttp) {
        & $add 'ESC8' $w.Url "Web enrollment answers over plain HTTP (status $($w.Status)). Authentication offered: $($w.Authentication)" 'Confirm by browsing to the address from a domain workstation.'
    }
    # HTTPS answers but no web enrollment role here (HTTPS with the role is checked in 5.2)
    if ($answered -and -not $isHttp -and -not $webRole) {
        & $man 'ESC8' $w.Url "This HTTPS address answers (status $($w.Status)), but no web enrollment role is installed on this server." 'Browse to the address and identify what is hosted there.'
    }
    # Redirects somewhere that is not HTTPS
    if ($redirect -and "$($w.RedirectsTo)" -notlike 'https://*') {
        & $man 'ESC8' $w.Url "Redirects to '$($w.RedirectsTo)', which is not an HTTPS address." 'Browse to the address and confirm whether web enrollment can be used without HTTPS.'
    }
    # Anything else unexpected (timeouts, certificate errors, other status codes)
    if (-not $answered -and -not $redirect -and -not $nothing) {
        & $man 'ESC8' $w.Url "Could not tell whether web enrollment is exposed here (status: $($w.Status); $($w.NetStatus) $($w.Note))." "Browse to $($w.Url) from a domain workstation and record what happens."
    }
}
if ($cas) {
    & $man 'ESC8' 'Servers other than CAs' "Web enrollment can be installed on servers that are not CAs, and that can't be discovered from AD." 'Ask the client whether CA Web Enrollment or Certificate Enrollment Web Service is installed on any server other than the CAs. If so, run Part C on each.'
}
& $close '5.1' @() $e5
Write-Host "[5.1] DONE - addresses tested: $($web.Count)" -ForegroundColor Green
```

You should see: a small table of addresses, then a green `[5.1] DONE` line.

**5.2 Read this server's web enrollment settings**

This prints a yellow `SKIPPED` line if web enrollment isn't installed on this server, which is fine.

```powershell
$feat = @(Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc, ADCS-Enroll-Web-Pol -ErrorAction Ignore)
$feat | Select-Object Name, InstallState | Out-File "$ev\09_local_web_features.txt"
$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
$roleInstalled = [bool]($feat | Where-Object Installed)
if (-not $roleInstalled) {
    Write-Host "[5.2] SKIPPED - no web enrollment role on this server" -ForegroundColor Yellow
} else {
    & $appcmd list site | Out-File "$ev\09_iis_sites.txt"
    # Web enrollment (CertSrv) and any CES applications on this server
    $locs = @()
    if (($feat | Where-Object Name -eq 'ADCS-Web-Enrollment').Installed) {
        $locs += 'Default Web Site/CertSrv'
    }
    $locs += @(& $appcmd list app | ForEach-Object { if ($_ -match '^APP "([^"]+)"') { $Matches[1] } } | Where-Object { $_ -match '_CES_' })
    if (-not $locs.Count) {
        & $man 'ESC8' $env:COMPUTERNAME 'Web enrollment is installed, but no CertSrv or CES application was found.' 'In IIS Manager, find where CertSrv or CES is hosted and check SSL Settings (Require SSL) and Authentication > Windows Authentication > Advanced Settings (Extended Protection: Required).'
    }
    # Read the SSL, Windows Authentication and Extended Protection settings with appcmd
    $iis = @(foreach ($l in $locs) {
        $tag   = $l.Split('/')[-1]
        $waRaw = & $appcmd list config $l -section:system.webServer/security/authentication/windowsAuthentication /config:*
        $acRaw = & $appcmd list config $l -section:system.webServer/security/access /config:*
        $waRaw | Out-File "$ev\09_iis_windowsauth_$tag.txt"
        $acRaw | Out-File "$ev\09_iis_access_$tag.txt"
        try {
            $wa = ([xml]($waRaw -join "`n")).SelectSingleNode('//windowsAuthentication')
            $ac = ([xml]($acRaw -join "`n")).SelectSingleNode('//access')
            if (-not $wa -or -not $ac) { throw "appcmd did not return the expected settings for $l." }
            $epNode = $wa.SelectSingleNode('extendedProtection')
            $epa = ''
            if ($epNode) { $epa = $epNode.GetAttribute('tokenChecking') }
            [pscustomobject]@{
                Location    = $l
                SslFlags    = $ac.GetAttribute('sslFlags')
                WindowsAuth = $wa.GetAttribute('enabled')
                EPA         = $epa
                Providers   = (@($wa.SelectNodes('providers/add') | ForEach-Object { $_.GetAttribute('value') }) -join ', ')
            }
        } catch {
            & $man 'ESC8' $l "Could not read IIS settings: $($_.Exception.Message)" "Check 09_iis_windowsauth_$tag.txt and 09_iis_access_$tag.txt, or check SSL Settings and Extended Protection for this application in IIS Manager."
            $Error.RemoveAt(0)
        }
    })
    $iis | Export-Csv "$ev\09_iis_settings.csv" -NoTypeInformation
    $iis | Format-Table -AutoSize
    foreach ($i in $iis) {
        # Extended Protection must be Require
        if ($i.EPA -in 'None', 'Allow') {
            & $add 'ESC8' $i.Location "Extended Protection is '$($i.EPA)' (should be Require). Providers: $($i.Providers)" "Confirm in 09_iis_windowsauth_$($i.Location.Split('/')[-1]).txt or IIS Manager."
        }
        if ($i.EPA -notin 'None', 'Allow', 'Require') {
            & $man 'ESC8' $i.Location "Extended Protection value could not be read ('$($i.EPA)')." 'Check Authentication > Windows Authentication > Advanced Settings in IIS Manager.'
        }
        # SSL must be required
        $sslOn  = @("$($i.SslFlags)" -split ',' | ForEach-Object { $_.Trim() }) -contains 'Ssl'
        $sslOff = "$($i.SslFlags)" -in '', 'None'
        if (-not $sslOn -and $sslOff) {
            & $add 'ESC8' $i.Location "SSL is not required (sslFlags='$($i.SslFlags)')." 'Confirm in IIS Manager > SSL Settings.'
        }
        if (-not $sslOn -and -not $sslOff) {
            & $man 'ESC8' $i.Location "SSL setting not recognised ('$($i.SslFlags)')." 'Check SSL Settings for this application in IIS Manager.'
        }
        if ("$($i.WindowsAuth)" -ne 'true') {
            & $man 'ESC8' $i.Location "Windows Authentication enabled = '$($i.WindowsAuth)'." 'Check which authentication methods this application uses in IIS Manager.'
        }
    }
}
# Finish step 5 (5.1 and 5.2 together): flag any errors, and mark ESC8 as CLEAR if nothing was found
& $close '5' @('ESC8') $e5
Write-Host "[5.2] DONE - $(& $cnt 'ESC8')" -ForegroundColor Green
```

You should see: a green `[5.2] DONE` line. If web enrollment isn't installed on this server, a yellow `SKIPPED` line appears first, which is fine.

## Step 6: Domain controller and account checks

**6.1 List the domain controllers to check in Part B (ESC10)**

Certificate logon settings on domain controllers can only be read on each DC, so this step lists them for Part B.

```powershell
$Error.Clear(); $e0 = 0
# Every domain controller in the forest. Their settings are read in Part B (or in step 6.3 for this server, if it is a DC)
$dcs = @()
foreach ($d in @($domSid.Keys)) {
    try {
        $dcs += @(Get-ADDomainController -Filter * -Server $d -ErrorAction Stop | Select-Object HostName, Domain, OperatingSystem, OperatingSystemVersion)
    } catch {
        & $man 'ESC10' $d "Could not list the domain controllers in this domain: $($_.Exception.Message)" "Get the list of DCs in $d from the client and run Part B on each."
        $Error.RemoveAt(0)
    }
}
$dcs | Export-Csv "$ev\10_domain_controllers_to_check.csv" -NoTypeInformation
$dcs | Format-Table -AutoSize
# Every other DC needs a Part B run
$dcNext = @($dcs | Where-Object { ($_.HostName -split '\.')[0] -ne $env:COMPUTERNAME })
foreach ($dc in $dcNext) {
    & $man 'ESC10' $dc.HostName "Certificate logon settings can only be read on the DC itself ($($dc.OperatingSystem) $($dc.OperatingSystemVersion))." "Run Part B on $($dc.HostName). Until every DC has been checked, ESC6, ESC9, ESC16 and weak ESC14 mappings can't be rated."
}
& $close '6.1' @() $e0
Write-Host "[6.1] DONE - domain controllers found: $($dcs.Count); to check in Part B: $($dcNext.Count)" -ForegroundColor Green
```

You should see: a table of domain controllers, then a green `[6.1] DONE` line. This list is saved in `10_domain_controllers_to_check.csv` for Part B.

**6.2 Check certificate mappings on accounts, and who can change them on admin accounts (ESC14)**

```powershell
$Error.Clear(); $e0 = 0
# Every explicit certificate mapping in the forest
$alt = New-Object System.Collections.ArrayList
foreach ($dn in @($domSid.Keys)) {
    try {
        $objs = @(Get-ADObject -Server $dn -LDAPFilter '(altSecurityIdentities=*)' -Properties altSecurityIdentities, adminCount -ErrorAction Stop)
        foreach ($ob in $objs) {
            foreach ($m in $ob.altSecurityIdentities) {
                [void]$alt.Add([pscustomobject]@{ Domain = $dn; Name = $ob.Name; ObjectClass = $ob.ObjectClass; AdminCount = $ob.adminCount; Mapping = $m })
            }
        }
    } catch {
        & $man 'ESC14' $dn "Could not search this domain: $($_.Exception.Message)" "From a server in $dn, list accounts with altSecurityIdentities set and check their mapping formats."
        $Error.RemoveAt(0)
    }
}
$alt | Export-Csv "$ev\11_explicit_certificate_mappings.csv" -NoTypeInformation
# Weak formats: <I>..<S>, <S>, <RFC822>.  Strong formats: <I>..<SR>, <SKI>, <SHA1-PUKEY>.
foreach ($a in $alt) {
    $t      = "$($a.Domain)\$($a.Name)"
    $weak   = $a.Mapping -match '^X509:<S>|^X509:<RFC822>|^X509:<I>.*<S>'
    $strong = $a.Mapping -match '^X509:<I>.*<SR>|^X509:<SKI>|^X509:<SHA1-PUKEY>'
    if ($weak) {
        & $add 'ESC14' $t "Weak explicit certificate mapping ($($a.Mapping)). Privileged account (adminCount=1): $($a.AdminCount -eq 1)." 'DCs in Full Enforcement reject weak mappings: rate using the Part B results.'
    }
    if (-not $weak -and -not $strong) {
        & $man 'ESC14' $t "Unrecognised mapping format: $($a.Mapping)" 'Compare this value with the six formats in Microsoft KB5014754 and decide whether it is strong or weak.'
    }
}
# Who can change altSecurityIdentities on admin accounts
$asa  = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(lDAPDisplayName=altSecurityIdentities)' -Properties schemaIDGUID, attributeSecurityGUID
$asaG = @([guid]::new([byte[]]$asa.schemaIDGUID).ToString())
if ($asa.attributeSecurityGUID) {
    $asaG += [guid]::new([byte[]]$asa.attributeSecurityGUID).ToString()
}
$awp = New-Object System.Collections.ArrayList
foreach ($u in @($privUserDN | Sort-Object -Unique)) {
    try {
        $sd = & $getSd $u
        foreach ($r in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $s  = $r.IdentityReference.Value
            $rt = "$($r.ActiveDirectoryRights)"
            $ot = "$($r.ObjectType)"
            $canWrite = $rt -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' -or ($rt -match 'WriteProperty' -and ($ot -eq $zeroGuid -or $ot -in $asaG))
            if ("$($r.AccessControlType)" -eq 'Allow' -and $s -notin $t0Sid -and $canWrite) {
                [void]$awp.Add([pscustomobject]@{ Account = $u; Name = (& $nm $s); Sid = $s; Rights = $rt; ObjectType = $ot })
                & $add 'ESC14' $u "$(& $nm $s) can change altSecurityIdentities on this admin account ($rt)." 'Confirm in 12_admin_account_write_permissions.csv. Whoever can write this attribute can map their own certificate to the admin account.'
            }
        }
    } catch {
        & $man 'ESC14' $u "Could not read this admin account's permissions: $($_.Exception.Message)" 'Check the Security > Advanced tab of this account in Active Directory Users and Computers for write access to altSecurityIdentities.'
        $Error.RemoveAt(0)
    }
}
$awp | Export-Csv "$ev\12_admin_account_write_permissions.csv" -NoTypeInformation
& $close '6.2' @('ESC14') $e0
Write-Host "[6.2] DONE - mappings found: $($alt.Count); admin accounts checked: $(@($privUserDN | Sort-Object -Unique).Count). $(& $cnt 'ESC14')" -ForegroundColor Green
```

You should see: a green `[6.2] DONE` line. It can take a minute in large environments.

**6.3 If this CA is also a domain controller, check its certificate logon settings (ESC10)**

This is the same check as Part B. On a CA that isn't a DC it prints a yellow `SKIPPED` line, which is fine. A CA that is also a DC doesn't need a separate Part B run.

```powershell
$Error.Clear(); $e0 = 0
$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
if (-not $isDC) {
    Write-Host "[6.3] SKIPPED - this CA is not a domain controller" -ForegroundColor Yellow
} else {
    # The two settings that control certificate logon
    $kdc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -ErrorAction Ignore
    $sch = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -ErrorAction Ignore
    $sb  = "$($kdc.StrongCertificateBindingEnforcement)"
    $sm  = "$($sch.CertificateMappingMethods)"
    # Evidence
    reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc | Out-File "$ev\DC_Kdc_registry.txt"
    reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel | Out-File "$ev\DC_Schannel_registry.txt"
    # Which of the relevant updates does this server have?
    $may = & $patched 'May2022'
    $feb = & $patched 'Feb2025'
    $sep = & $patched 'Sep2025'
    # Does this DC enforce strong certificate mapping? The first matching rule wins.
    $state = ''
    if (-not $state -and $sep -eq 'YES')                     { $state = 'FULL (September 2025 update installed)' }
    if (-not $state -and $may -eq 'YES' -and $sb -eq '2')    { $state = 'FULL (registry set to 2)' }
    if (-not $state -and ($sep -eq 'UNKNOWN' -or $may -eq 'UNKNOWN')) { $state = 'UNKNOWN' }
    if (-not $state -and $may -eq 'NO')                      { $state = 'WEAK' }
    if (-not $state -and $sb -eq '' -and $feb -eq 'YES')     { $state = 'FULL (February 2025 default)' }
    if (-not $state -and $sb -eq '' -and $feb -eq 'UNKNOWN') { $state = 'UNKNOWN' }
    if (-not $state)                                         { $state = 'WEAK' }
    "OS build $osb.$ubr | StrongCertificateBindingEnforcement='$sb' | CertificateMappingMethods='$sm' | Result: $state" | Tee-Object "$ev\DC_certificate_mapping.txt"
    if ($state -eq 'WEAK') {
        & $add 'ESC10-KDC' $env:COMPUTERNAME "This DC accepts weak certificate mappings (OS build $osb.$ubr, StrongCertificateBindingEnforcement='$sb')." 'Confirm in DC_certificate_mapping.txt and DC_Kdc_registry.txt. While any DC accepts weak mappings, ESC6, ESC9, ESC16 and weak ESC14 mappings are exploitable.'
    }
    if ($state -eq 'UNKNOWN') {
        & $man 'ESC10-KDC' $env:COMPUTERNAME "Could not confirm whether OS build $osb.$ubr includes the required updates (hotpatch build or unsupported Windows version)." "Check build $osb.$ubr against Microsoft's update history for this Windows Server version. Full Enforcement is guaranteed from the September 9, 2025 update, or from February 11, 2025 if StrongCertificateBindingEnforcement is not set."
    }
    # ESC10 case 2: Schannel UPN mapping (bit 0x4)
    if ($sm -ne '' -and ([int]$sm -band 4)) {
        & $add 'ESC10-Schannel' $env:COMPUTERNAME ('CertificateMappingMethods=0x{0:X} includes UPN mapping (0x4).' -f [int]$sm) 'Confirm in DC_Schannel_registry.txt. This applies at any patch level.'
    }
    & $close '6.3' @('ESC10-KDC', 'ESC10-Schannel') $e0
    Write-Host "[6.3] DONE - $state. $(& $cnt 'ESC10-KDC','ESC10-Schannel')" -ForegroundColor Green
}
```

You should see: a green `[6.3] DONE` line with a result, or a yellow `SKIPPED` line.

## Step 7: Finish and hand over

**7.1 Save the summary and close the evidence**

```powershell
$info = [ordered]@{   # Record what this run covered, for the consolidation in Part D
    Part       = $part
    Host       = $env:COMPUTERNAME
    Fqdn       = $fqdn
    RunAt      = (Get-Date -Format o)
    OSBuild    = "$osb.$ubr"
    PowerShell = "$($PSVersionTable.PSVersion)"
    CAs        = @($cas    | Where-Object { $_ } | ForEach-Object { "$($_.dNSHostName)".ToLower() })
    ThisCA     = @($thisCA | Where-Object { $_ } | ForEach-Object { "$($_.dNSHostName)".ToLower() })
    DCs        = @($dcs    | Where-Object { $_ } | ForEach-Object { "$($_.HostName)".ToLower() })
    CESHosts   = @($ces    | Where-Object { $_ } | ForEach-Object { ([uri]$_).Host.ToLower() } | Sort-Object -Unique)
    DCState    = "$state"
}
$info | ConvertTo-Json -Depth 3 | Out-File "$ev\00_run_info.json" -Encoding utf8
# Save and show the results
$F | Sort-Object Status, Check | Export-Csv "$ev\FINDINGS.csv" -NoTypeInformation
$F | Group-Object Status | Select-Object @{ n = 'Status'; e = { $_.Name } }, Count | Format-Table -AutoSize
$F | Where-Object Status -ne 'CLEAR' | Sort-Object Status, Check | Format-Table Status, Check, Target, Detail -AutoSize -Wrap
Get-ChildItem $ev | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "[7.1] DONE - findings: $(@($F | Where-Object Status -eq 'FINDING').Count); manual checks: $(@($F | Where-Object Status -eq 'MANUAL CHECK').Count); clear: $(@($F | Where-Object Status -eq 'CLEAR').Count)" -ForegroundColor Green
# Stop recording, then zip and fingerprint the evidence
Stop-Transcript
Compress-Archive "$ev\*" "$ev.zip" -Force
Get-FileHash "$ev.zip" -Algorithm SHA256 | Select-Object Hash, Path | Tee-Object -FilePath "$ev.sha256.txt"
# What to run next: Part B on every other DC, and Part A on every other CA
if ($dcNext.Count) {
    Write-Host "NEXT: run Part B on these domain controllers: $($dcNext.HostName -join ', ')" -ForegroundColor Yellow
}
if ($others.Count) {
    Write-Host "NEXT: run Part A on these CA servers too: $($others.dNSHostName -join ', ')" -ForegroundColor Yellow
}
Write-Host "FINISHED. Send these two files to the person who gave you this runbook: $ev.zip and $ev.sha256.txt" -ForegroundColor Green
```

You should see: a count of FINDING, MANUAL CHECK and CLEAR results, a list of the findings and manual checks, a list of files, `Transcript stopped`, a long hash value, and a green `FINISHED` line naming two files. You don't need to act on the findings or manual checks; the reviewer does.

**7.2 Hand over**

1. Send the `.zip` file and the `.sha256.txt` file named in the `FINISHED` line to the person who gave you this runbook.
2. Send any screenshots you took of red text.
3. If a yellow `NEXT` line named CA servers, run Part A on each of them.
4. If a yellow `NEXT` line named domain controllers, run Part B on each of them.
5. You can close the PowerShell window.

## Part B: Run on each domain controller

Run this on every domain controller named in the `NEXT` line at the end of Part A (also listed in `10_domain_controllers_to_check.csv`), logged on with an account that is an administrator of that DC.

1. Open Windows PowerShell 5.1 or PowerShell 7 as administrator, as described in "Before you start".
2. Run boxes **B.1**, **B.2** and **B.3** below, in order. Part B doesn't use any boxes from Part A.
3. Hand over the `.zip` and `.sha256.txt` files named in the `FINISHED` line, as in 7.2.

**B.1 Start recording**

```powershell
$part = 'B'   # Which part this run is: A = CA server, B = domain controller, C = other web enrollment server
# Create the evidence folder and start recording everything
$ev = "C:\ESC_Evidence\$($env:COMPUTERNAME)_Part$($part)_$(Get-Date -Format yyyyMMdd_HHmm)"
New-Item $ev -ItemType Directory -Force | Out-Null
Start-Transcript "$ev\transcript.txt"
$MaximumErrorCount = 10000
$Error.Clear()
$fqdn = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem).Domain)".ToLower()
# Results list, and helpers that add FINDING / MANUAL CHECK / CLEAR rows to it
$F = New-Object System.Collections.ArrayList
$row = {
    param($status, $check, $target, $detail, $manual)
    [void]$F.Add([pscustomobject]@{
        Status      = $status
        Check       = $check
        Target      = $target
        Detail      = $detail
        ManualCheck = $manual
        Host        = $env:COMPUTERNAME
        Part        = $part
    })
}
$add = { param($check, $target, $detail, $manual) & $row 'FINDING' $check $target $detail $manual }
$man = { param($check, $target, $detail, $manual) & $row 'MANUAL CHECK' $check $target $detail $manual }
# At the end of each step: flag any errors, and mark checks with no rows as CLEAR
$close = {
    param($step, [string[]]$checks, $e0)
    $err = $Error.Count -gt $e0
    if ($err) {
        & $man "Step $step" '' "Errors occurred while step $step ran, so its results may be incomplete." "Find the red text for step $step in transcript.txt, resolve the cause (usually permissions or connectivity) and re-run step $step."
    }
    foreach ($c in $checks) {
        $hasRows = @($F | Where-Object { $_.Check -eq $c }).Count -gt 0
        if (-not $hasRows -and $err) {
            & $man $c '' "Nothing was found, but step $step had errors, so this can't be confirmed as clear." "Re-run step $step after resolving the errors."
        }
        if (-not $hasRows -and -not $err) {
            & $row 'CLEAR' $c '' "Checked in step $step; nothing found." ''
        }
    }
}
# Summary text for the DONE lines
$cnt = {
    param([string[]]$checks)
    $parts = foreach ($c in $checks) {
        $f = @($F | Where-Object Check -eq $c)
        "${c}: $(@($f | Where-Object Status -eq 'FINDING').Count) finding, $(@($f | Where-Object Status -eq 'MANUAL CHECK').Count) manual"
    }
    $parts -join ' | '
}
# Build numbers of the security updates that matter (Microsoft's Windows Server release information)
$thr = @{
    '14393' = @{ May2022 = 5125; Nov2024 = 7515; Feb2025 = 7785; Sep2025 = 8422; Jul2026 = 9339 }    # Server 2016
    '17763' = @{ May2022 = 2928; Nov2024 = 6532; Feb2025 = 6893; Sep2025 = 7792; Jul2026 = 9020 }    # Server 2019
    '20348' = @{ May2022 = 707;  Nov2024 = 2849; Feb2025 = 3207; Sep2025 = 4171; Jul2026 = 5386 }    # Server 2022
    '26100' = @{ May2022 = 0;    Nov2024 = 2314; Feb2025 = 3194; Sep2025 = 6584; Jul2026 = 33158 }   # Server 2025
}
# Hotpatch builds for the same months; builds between the two numbers can't be judged exactly
$thrHp = @{
    '20348' = @{ Nov2024 = 2819; Feb2025 = 3148; Sep2025 = 4106 }
    '26100' = @{ Nov2024 = 2240; Feb2025 = 3107; Sep2025 = 6508 }
}
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osb = "$($cv.CurrentBuild)"
$ubr = [int]$cv.UBR
# Answers YES, NO or UNKNOWN to "does this server have update $k?"
$patched = {
    param($k)
    if (-not $thr.ContainsKey($osb)) { return 'UNKNOWN' }
    if ($ubr -ge $thr[$osb][$k]) { return 'YES' }
    if ($thrHp.ContainsKey($osb) -and $thrHp[$osb].ContainsKey($k) -and $ubr -ge $thrHp[$osb][$k]) { return 'UNKNOWN' }
    return 'NO'
}
# Record who, where and when
whoami /user /groups
hostname
Get-Date -Format o
(Get-CimInstance Win32_OperatingSystem).Caption
"Part $part | OS build: $osb.$ubr | PowerShell $($PSVersionTable.PSVersion)" | Tee-Object "$ev\00_os_build.txt"
# Check this window is elevated, and PowerShell is version 5.1 or later
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$psOk    = $PSVersionTable.PSVersion -ge [version]'5.1'
if (-not $isAdmin) {
    Write-Host "[B.1] STOP: this window is not running as administrator." -ForegroundColor Red
}
if (-not $psOk) {
    Write-Host "[B.1] STOP: PowerShell $($PSVersionTable.PSVersion) is too old. Use Windows PowerShell 5.1 or PowerShell 7." -ForegroundColor Red
}
if ($isAdmin -and $psOk) {
    Write-Host "[B.1] DONE - evidence folder: $ev" -ForegroundColor Green
}
```

You should see: `Transcript started`, your account details, and a green `[B.1] DONE` line.

**B.2 Read this DC's certificate logon settings (ESC10)**

```powershell
$Error.Clear(); $e0 = 0
$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
if (-not $isDC) {
    Write-Host "[B.2] STOP: this server is not a domain controller." -ForegroundColor Red
} else {
    # The two settings that control certificate logon
    $kdc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -ErrorAction Ignore
    $sch = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -ErrorAction Ignore
    $sb  = "$($kdc.StrongCertificateBindingEnforcement)"
    $sm  = "$($sch.CertificateMappingMethods)"
    # Evidence
    reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc | Out-File "$ev\DC_Kdc_registry.txt"
    reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel | Out-File "$ev\DC_Schannel_registry.txt"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Out-File "$ev\DC_recent_updates.txt"
    # Which of the relevant updates does this DC have?
    $may = & $patched 'May2022'
    $feb = & $patched 'Feb2025'
    $sep = & $patched 'Sep2025'
    # Does this DC enforce strong certificate mapping? The first matching rule wins.
    $state = ''
    if (-not $state -and $sep -eq 'YES')                     { $state = 'FULL (September 2025 update installed)' }
    if (-not $state -and $may -eq 'YES' -and $sb -eq '2')    { $state = 'FULL (registry set to 2)' }
    if (-not $state -and ($sep -eq 'UNKNOWN' -or $may -eq 'UNKNOWN')) { $state = 'UNKNOWN' }
    if (-not $state -and $may -eq 'NO')                      { $state = 'WEAK' }
    if (-not $state -and $sb -eq '' -and $feb -eq 'YES')     { $state = 'FULL (February 2025 default)' }
    if (-not $state -and $sb -eq '' -and $feb -eq 'UNKNOWN') { $state = 'UNKNOWN' }
    if (-not $state)                                         { $state = 'WEAK' }
    "OS build $osb.$ubr | StrongCertificateBindingEnforcement='$sb' | CertificateMappingMethods='$sm' | Result: $state" | Tee-Object "$ev\DC_certificate_mapping.txt"
    if ($state -eq 'WEAK') {
        & $add 'ESC10-KDC' $env:COMPUTERNAME "This DC accepts weak certificate mappings (OS build $osb.$ubr, StrongCertificateBindingEnforcement='$sb')." 'Confirm in DC_certificate_mapping.txt and DC_Kdc_registry.txt. While any DC accepts weak mappings, ESC6, ESC9, ESC16 and weak ESC14 mappings are exploitable.'
    }
    if ($state -eq 'UNKNOWN') {
        & $man 'ESC10-KDC' $env:COMPUTERNAME "Could not confirm whether OS build $osb.$ubr includes the required updates (hotpatch build or unsupported Windows version)." "Check build $osb.$ubr against Microsoft's update history for this Windows Server version. Full Enforcement is guaranteed from the September 9, 2025 update, or from February 11, 2025 if StrongCertificateBindingEnforcement is not set."
    }
    # ESC10 case 2: Schannel UPN mapping (bit 0x4)
    if ($sm -ne '' -and ([int]$sm -band 4)) {
        & $add 'ESC10-Schannel' $env:COMPUTERNAME ('CertificateMappingMethods=0x{0:X} includes UPN mapping (0x4).' -f [int]$sm) 'Confirm in DC_Schannel_registry.txt. This applies at any patch level.'
    }
    & $close 'B.2' @('ESC10-KDC', 'ESC10-Schannel') $e0
    Write-Host "[B.2] DONE - $state. $(& $cnt 'ESC10-KDC','ESC10-Schannel')" -ForegroundColor Green
}
```

You should see: one line with the OS build, the two settings and a result, then a green `[B.2] DONE` line.

**B.3 Save the results and close the evidence**

```powershell
$info = [ordered]@{   # Record what this run covered, for the consolidation in Part D
    Part       = $part
    Host       = $env:COMPUTERNAME
    Fqdn       = $fqdn
    RunAt      = (Get-Date -Format o)
    OSBuild    = "$osb.$ubr"
    PowerShell = "$($PSVersionTable.PSVersion)"
    CAs        = @()
    ThisCA     = @()
    DCs        = @()
    CESHosts   = @()
    DCState    = "$state"
}
$info | ConvertTo-Json -Depth 3 | Out-File "$ev\00_run_info.json" -Encoding utf8
# Save and show the results
$F | Sort-Object Status, Check | Export-Csv "$ev\FINDINGS.csv" -NoTypeInformation
$F | Group-Object Status | Select-Object @{ n = 'Status'; e = { $_.Name } }, Count | Format-Table -AutoSize
$F | Where-Object Status -ne 'CLEAR' | Sort-Object Status, Check | Format-Table Status, Check, Target, Detail -AutoSize -Wrap
Get-ChildItem $ev | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "[B.3] DONE - findings: $(@($F | Where-Object Status -eq 'FINDING').Count); manual checks: $(@($F | Where-Object Status -eq 'MANUAL CHECK').Count); clear: $(@($F | Where-Object Status -eq 'CLEAR').Count)" -ForegroundColor Green
# Stop recording, then zip and fingerprint the evidence
Stop-Transcript
Compress-Archive "$ev\*" "$ev.zip" -Force
Get-FileHash "$ev.zip" -Algorithm SHA256 | Select-Object Hash, Path | Tee-Object -FilePath "$ev.sha256.txt"
Write-Host "FINISHED. Send these two files to the person who gave you this runbook: $ev.zip and $ev.sha256.txt" -ForegroundColor Green
```

You should see: a count of results, a list of files, `Transcript stopped`, a long hash value, and a green `FINISHED` line naming two files.

## Part C: Run on other web enrollment servers

Only run this on servers the reviewer names: servers that host CA Web Enrollment or the Certificate Enrollment Web Service but are not CAs.

1. Open Windows PowerShell 5.1 or PowerShell 7 as administrator, as described in "Before you start".
2. Run boxes **C.1** to **C.4** below, in order. Part C doesn't use any boxes from Part A, and doesn't need the ActiveDirectory module.
3. Hand over the `.zip` and `.sha256.txt` files named in the `FINISHED` line, as in 7.2.

**C.1 Start recording**

```powershell
$part = 'C'   # Which part this run is: A = CA server, B = domain controller, C = other web enrollment server
# Create the evidence folder and start recording everything
$ev = "C:\ESC_Evidence\$($env:COMPUTERNAME)_Part$($part)_$(Get-Date -Format yyyyMMdd_HHmm)"
New-Item $ev -ItemType Directory -Force | Out-Null
Start-Transcript "$ev\transcript.txt"
$MaximumErrorCount = 10000
$Error.Clear()
$fqdn = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem).Domain)".ToLower()
# Results list, and helpers that add FINDING / MANUAL CHECK / CLEAR rows to it
$F = New-Object System.Collections.ArrayList
$row = {
    param($status, $check, $target, $detail, $manual)
    [void]$F.Add([pscustomobject]@{
        Status      = $status
        Check       = $check
        Target      = $target
        Detail      = $detail
        ManualCheck = $manual
        Host        = $env:COMPUTERNAME
        Part        = $part
    })
}
$add = { param($check, $target, $detail, $manual) & $row 'FINDING' $check $target $detail $manual }
$man = { param($check, $target, $detail, $manual) & $row 'MANUAL CHECK' $check $target $detail $manual }
# At the end of each step: flag any errors, and mark checks with no rows as CLEAR
$close = {
    param($step, [string[]]$checks, $e0)
    $err = $Error.Count -gt $e0
    if ($err) {
        & $man "Step $step" '' "Errors occurred while step $step ran, so its results may be incomplete." "Find the red text for step $step in transcript.txt, resolve the cause (usually permissions or connectivity) and re-run step $step."
    }
    foreach ($c in $checks) {
        $hasRows = @($F | Where-Object { $_.Check -eq $c }).Count -gt 0
        if (-not $hasRows -and $err) {
            & $man $c '' "Nothing was found, but step $step had errors, so this can't be confirmed as clear." "Re-run step $step after resolving the errors."
        }
        if (-not $hasRows -and -not $err) {
            & $row 'CLEAR' $c '' "Checked in step $step; nothing found." ''
        }
    }
}
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osb = "$($cv.CurrentBuild)"
$ubr = [int]$cv.UBR
# Record who, where and when
whoami /user /groups
hostname
Get-Date -Format o
(Get-CimInstance Win32_OperatingSystem).Caption
"Part $part | OS build: $osb.$ubr | PowerShell $($PSVersionTable.PSVersion)" | Tee-Object "$ev\00_os_build.txt"
# Check this window is elevated, and PowerShell is version 5.1 or later
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$psOk    = $PSVersionTable.PSVersion -ge [version]'5.1'
if (-not $isAdmin) {
    Write-Host "[C.1] STOP: this window is not running as administrator." -ForegroundColor Red
}
if (-not $psOk) {
    Write-Host "[C.1] STOP: PowerShell $($PSVersionTable.PSVersion) is too old. Use Windows PowerShell 5.1 or PowerShell 7." -ForegroundColor Red
}
if ($isAdmin -and $psOk) {
    Write-Host "[C.1] DONE - evidence folder: $ev" -ForegroundColor Green
}
```

You should see: `Transcript started`, your account details, and a green `[C.1] DONE` line.

**C.2 Test this server's web enrollment addresses (ESC8)**

This only sends a header request to this server's own addresses; it doesn't log in or request anything.

```powershell
$Error.Clear(); $e5 = 0
$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
# CES applications hosted on this server, read from IIS
$cesPaths = @()
if (Test-Path $appcmd) {
    $cesPaths = @(& $appcmd list app | ForEach-Object { if ($_ -match '^APP "[^/"]+(/[^"]*)"') { $Matches[1] } } | Where-Object { $_ -match '_CES_' })
}
# Addresses on this server to test, over HTTP and HTTPS
$urls = @("http://$fqdn/certsrv/", "https://$fqdn/certsrv/")
foreach ($p in $cesPaths) {
    $urls += "http://$fqdn$p/service.svc"
    $urls += "https://$fqdn$p/service.svc"
}
# Send a header request to each address (no login, no certificate request)
$web = @(foreach ($u in ($urls | Sort-Object -Unique)) {
    $q = [System.Net.HttpWebRequest]::Create($u)
    $q.Method            = 'HEAD'
    $q.AllowAutoRedirect = $false
    $q.Timeout           = 15000
    $r = $null; $msg = ''; $ns = ''
    try {
        $r = $q.GetResponse()
    } catch {
        $we = $_.Exception
        if ($we.InnerException) { $we = $we.InnerException }
        $r   = $we.Response
        $msg = $we.Message
        $ns  = "$($we.Status)"
        $Error.RemoveAt(0)
    }
    if ($r) {
        [pscustomobject]@{ Url = $u; Status = [int]$r.StatusCode; Authentication = $r.Headers['WWW-Authenticate']; RedirectsTo = $r.Headers['Location']; NetStatus = $ns; Note = $msg }
        $r.Close()
    } else {
        [pscustomobject]@{ Url = $u; Status = 'No response'; Authentication = ''; RedirectsTo = ''; NetStatus = $ns; Note = $msg }
    }
})
$web | Export-Csv "$ev\08_web_enrollment_probe.csv" -NoTypeInformation
$web | Format-Table Url, Status, NetStatus, Authentication -AutoSize
# Judge each answer (each address matches exactly one rule)
$webRole = [bool](@(Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc -ErrorAction Ignore) | Where-Object Installed)
foreach ($w in $web) {
    $isHttp   = $w.Url -like 'http://*'
    $answered = $w.Status -in 200, 401
    $redirect = $w.Status -in 301, 302, 303, 307, 308
    $nothing  = $w.Status -eq 404 -or ($w.Status -eq 'No response' -and $w.NetStatus -eq 'ConnectFailure')
    # Plain HTTP answers: relayable
    if ($answered -and $isHttp) {
        & $add 'ESC8' $w.Url "Web enrollment answers over plain HTTP (status $($w.Status)). Authentication offered: $($w.Authentication)" 'Confirm by browsing to the address from a domain workstation.'
    }
    # HTTPS answers but no web enrollment role here (HTTPS with the role is checked in C.3)
    if ($answered -and -not $isHttp -and -not $webRole) {
        & $man 'ESC8' $w.Url "This HTTPS address answers (status $($w.Status)), but no web enrollment role is installed on this server." 'Browse to the address and identify what is hosted there.'
    }
    # Redirects somewhere that is not HTTPS
    if ($redirect -and "$($w.RedirectsTo)" -notlike 'https://*') {
        & $man 'ESC8' $w.Url "Redirects to '$($w.RedirectsTo)', which is not an HTTPS address." 'Browse to the address and confirm whether web enrollment can be used without HTTPS.'
    }
    # Anything else unexpected (timeouts, certificate errors, other status codes)
    if (-not $answered -and -not $redirect -and -not $nothing) {
        & $man 'ESC8' $w.Url "Could not tell whether web enrollment is exposed here (status: $($w.Status); $($w.NetStatus) $($w.Note))." "Browse to $($w.Url) from a domain workstation and record what happens."
    }
}
& $close 'C.2' @() $e5
Write-Host "[C.2] DONE - addresses tested: $($web.Count)" -ForegroundColor Green
```

You should see: a small table of addresses, then a green `[C.2] DONE` line.

**C.3 Read this server's web enrollment settings (ESC8)**

```powershell
$feat = @(Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc, ADCS-Enroll-Web-Pol -ErrorAction Ignore)
$feat | Select-Object Name, InstallState | Out-File "$ev\09_local_web_features.txt"
$roleInstalled = [bool]($feat | Where-Object Installed)
if (-not $roleInstalled) {
    & $man 'ESC8' $env:COMPUTERNAME 'Part C was run on this server, but no web enrollment role is installed here.' 'Confirm with the client which server hosts web enrollment or CES, and run Part C there.'
    Write-Host "[C.3] No web enrollment role on this server (recorded for the reviewer)" -ForegroundColor Yellow
} else {
    & $appcmd list site | Out-File "$ev\09_iis_sites.txt"
    # Web enrollment (CertSrv) and any CES applications on this server
    $locs = @()
    if (($feat | Where-Object Name -eq 'ADCS-Web-Enrollment').Installed) {
        $locs += 'Default Web Site/CertSrv'
    }
    $locs += @(& $appcmd list app | ForEach-Object { if ($_ -match '^APP "([^"]+)"') { $Matches[1] } } | Where-Object { $_ -match '_CES_' })
    if (-not $locs.Count) {
        & $man 'ESC8' $env:COMPUTERNAME 'Web enrollment is installed, but no CertSrv or CES application was found.' 'In IIS Manager, find where CertSrv or CES is hosted and check SSL Settings (Require SSL) and Authentication > Windows Authentication > Advanced Settings (Extended Protection: Required).'
    }
    # Read the SSL, Windows Authentication and Extended Protection settings with appcmd
    $iis = @(foreach ($l in $locs) {
        $tag   = $l.Split('/')[-1]
        $waRaw = & $appcmd list config $l -section:system.webServer/security/authentication/windowsAuthentication /config:*
        $acRaw = & $appcmd list config $l -section:system.webServer/security/access /config:*
        $waRaw | Out-File "$ev\09_iis_windowsauth_$tag.txt"
        $acRaw | Out-File "$ev\09_iis_access_$tag.txt"
        try {
            $wa = ([xml]($waRaw -join "`n")).SelectSingleNode('//windowsAuthentication')
            $ac = ([xml]($acRaw -join "`n")).SelectSingleNode('//access')
            if (-not $wa -or -not $ac) { throw "appcmd did not return the expected settings for $l." }
            $epNode = $wa.SelectSingleNode('extendedProtection')
            $epa = ''
            if ($epNode) { $epa = $epNode.GetAttribute('tokenChecking') }
            [pscustomobject]@{
                Location    = $l
                SslFlags    = $ac.GetAttribute('sslFlags')
                WindowsAuth = $wa.GetAttribute('enabled')
                EPA         = $epa
                Providers   = (@($wa.SelectNodes('providers/add') | ForEach-Object { $_.GetAttribute('value') }) -join ', ')
            }
        } catch {
            & $man 'ESC8' $l "Could not read IIS settings: $($_.Exception.Message)" "Check 09_iis_windowsauth_$tag.txt and 09_iis_access_$tag.txt, or check SSL Settings and Extended Protection for this application in IIS Manager."
            $Error.RemoveAt(0)
        }
    })
    $iis | Export-Csv "$ev\09_iis_settings.csv" -NoTypeInformation
    $iis | Format-Table -AutoSize
    foreach ($i in $iis) {
        # Extended Protection must be Require
        if ($i.EPA -in 'None', 'Allow') {
            & $add 'ESC8' $i.Location "Extended Protection is '$($i.EPA)' (should be Require). Providers: $($i.Providers)" "Confirm in 09_iis_windowsauth_$($i.Location.Split('/')[-1]).txt or IIS Manager."
        }
        if ($i.EPA -notin 'None', 'Allow', 'Require') {
            & $man 'ESC8' $i.Location "Extended Protection value could not be read ('$($i.EPA)')." 'Check Authentication > Windows Authentication > Advanced Settings in IIS Manager.'
        }
        # SSL must be required
        $sslOn  = @("$($i.SslFlags)" -split ',' | ForEach-Object { $_.Trim() }) -contains 'Ssl'
        $sslOff = "$($i.SslFlags)" -in '', 'None'
        if (-not $sslOn -and $sslOff) {
            & $add 'ESC8' $i.Location "SSL is not required (sslFlags='$($i.SslFlags)')." 'Confirm in IIS Manager > SSL Settings.'
        }
        if (-not $sslOn -and -not $sslOff) {
            & $man 'ESC8' $i.Location "SSL setting not recognised ('$($i.SslFlags)')." 'Check SSL Settings for this application in IIS Manager.'
        }
        if ("$($i.WindowsAuth)" -ne 'true') {
            & $man 'ESC8' $i.Location "Windows Authentication enabled = '$($i.WindowsAuth)'." 'Check which authentication methods this application uses in IIS Manager.'
        }
    }
}
# Finish C.2 and C.3 together: flag any errors, and mark ESC8 as CLEAR if nothing was found
& $close 'C.3' @('ESC8') $e5
Write-Host "[C.3] DONE - ESC8 findings: $(@($F | Where-Object { $_.Check -eq 'ESC8' -and $_.Status -eq 'FINDING' }).Count); manual: $(@($F | Where-Object { $_.Check -eq 'ESC8' -and $_.Status -eq 'MANUAL CHECK' }).Count)" -ForegroundColor Green
```

You should see: a green `[C.3] DONE` line.

**C.4 Save the results and close the evidence**

```powershell
$info = [ordered]@{   # Record what this run covered, for the consolidation in Part D
    Part       = $part
    Host       = $env:COMPUTERNAME
    Fqdn       = $fqdn
    RunAt      = (Get-Date -Format o)
    OSBuild    = "$osb.$ubr"
    PowerShell = "$($PSVersionTable.PSVersion)"
    CAs        = @()
    ThisCA     = @()
    DCs        = @()
    CESHosts   = @()
    DCState    = ''
}
$info | ConvertTo-Json -Depth 3 | Out-File "$ev\00_run_info.json" -Encoding utf8
# Save and show the results
$F | Sort-Object Status, Check | Export-Csv "$ev\FINDINGS.csv" -NoTypeInformation
$F | Group-Object Status | Select-Object @{ n = 'Status'; e = { $_.Name } }, Count | Format-Table -AutoSize
$F | Where-Object Status -ne 'CLEAR' | Sort-Object Status, Check | Format-Table Status, Check, Target, Detail -AutoSize -Wrap
Get-ChildItem $ev | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "[C.4] DONE - findings: $(@($F | Where-Object Status -eq 'FINDING').Count); manual checks: $(@($F | Where-Object Status -eq 'MANUAL CHECK').Count); clear: $(@($F | Where-Object Status -eq 'CLEAR').Count)" -ForegroundColor Green
# Stop recording, then zip and fingerprint the evidence
Stop-Transcript
Compress-Archive "$ev\*" "$ev.zip" -Force
Get-FileHash "$ev.zip" -Algorithm SHA256 | Select-Object Hash, Path | Tee-Object -FilePath "$ev.sha256.txt"
Write-Host "FINISHED. Send these two files to the person who gave you this runbook: $ev.zip and $ev.sha256.txt" -ForegroundColor Green
```

You should see: a count of results, a list of files, `Transcript stopped`, a long hash value, and a green `FINISHED` line naming two files.

## Part D: Consolidate all runs (reviewer)

Run this once, after every zip from Parts A, B and C has come back. It can run on any Windows machine with Windows PowerShell 5.1 or PowerShell 7; it doesn't need the ActiveDirectory module, administrator rights or access to the client's network.

It checks each zip against its hash, unpacks it, and combines the results. Forest-wide results that appear in every CA's run are merged into one row. Manual checks that another run answered are marked RESOLVED. Findings that depend on DC enforcement are rated using the Part B results. Every server that should have been checked but wasn't is listed.

1. Create the folder `C:\ESC_Returned`. Copy into it **every** returned `.zip` file and its matching `.sha256.txt` file: the Part A files from every CA, the Part B files from every DC, and any Part C files. Don't unzip them, and don't put them in subfolders.
2. Open PowerShell and run boxes **D.1**, **D.2** and **D.3** below, in order.
3. `REPORT.html` opens when D.3 finishes. Everything is also saved in the `CONSOLIDATED_...` folder and zip inside `C:\ESC_Returned`. If the report lists servers that still need a run, add their zips to the folder and run Part D again.

**D.1 Check and unpack every returned zip**

```powershell
$in  = 'C:\ESC_Returned'   # The folder that holds every returned .zip and .sha256.txt file (Parts A, B and C)
$out = Join-Path $in "CONSOLIDATED_$(Get-Date -Format yyyyMMdd_HHmm)"
New-Item $out -ItemType Directory -Force | Out-Null
Start-Transcript "$out\consolidation_transcript.txt"
$Error.Clear()
# Short server name, used to match runs to servers
$short = { param($n) ("$n" -split '\.')[0].ToLower() }
$zips  = @(Get-ChildItem $in -Filter '*.zip' -File | Where-Object { $_.Name -notlike 'CONSOLIDATED_*' })
if (-not $zips.Count) {
    Write-Host "[D.1] STOP: no .zip files were found in $in." -ForegroundColor Red
}
# Check each zip against its hash file, then unpack it
$runs = @(foreach ($z in $zips) {
    $hashFile = $z.FullName -replace '\.zip$', '.sha256.txt'
    $expected = ''
    if (Test-Path $hashFile) {
        $expected = [regex]::Match((Get-Content $hashFile -Raw), '[0-9A-Fa-f]{64}').Value
    }
    $actual = (Get-FileHash $z.FullName -Algorithm SHA256).Hash
    $note = 'OK'
    if (-not $expected) { $note = 'No matching .sha256.txt file was returned.' }
    if ($expected -and $expected -ne $actual) { $note = 'The zip does not match its hash, so it may have been changed after the run.' }
    $dest = Join-Path $out $z.BaseName
    Expand-Archive $z.FullName -DestinationPath $dest -Force
    $info = $null
    if (Test-Path "$dest\00_run_info.json") {
        $info = Get-Content "$dest\00_run_info.json" -Raw | ConvertFrom-Json
    }
    [pscustomobject]@{
        Zip      = $z.Name
        Part     = "$($info.Part)"
        Host     = "$($info.Host)".ToLower()
        Fqdn     = "$($info.Fqdn)".ToLower()
        HashOk   = ($note -eq 'OK')
        HashNote = $note
        Folder   = $dest
        Info     = $info
    }
})
$runs | Select-Object Zip, Part, Host, Fqdn, HashOk, HashNote | Export-Csv "$out\RUNS.csv" -NoTypeInformation
$runs | Format-Table Zip, Part, Host, HashOk -AutoSize
Write-Host "[D.1] DONE - runs found: $($runs.Count); hash problems: $(@($runs | Where-Object { -not $_.HashOk }).Count)" -ForegroundColor Green
```

You should see: a table with one row per zip, then a green `[D.1] DONE` line.

**D.2 Combine the results and resolve cross-run items**

```powershell
$all = New-Object System.Collections.ArrayList   # Every row from every run, tagged with the zip it came from
foreach ($r in $runs) {
    $csv = Join-Path $r.Folder 'FINDINGS.csv'
    if (Test-Path $csv) {
        foreach ($line in (Import-Csv $csv)) {
            $line | Add-Member -NotePropertyName Source -NotePropertyValue $r.Zip
            [void]$all.Add($line)
        }
    }
}
# Combine identical rows: forest-wide checks give the same answer on every CA, so they are merged;
# checks about one specific server are kept separate for each server
$perHost = 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC12', 'ESC15', 'ESC16', 'CVE-2026-54121', 'CVE-2022-26923', 'CA-KEY', 'CA-AUDIT', 'ESC10-KDC', 'ESC10-Schannel', 'Evidence'
$groups = $all | Group-Object {
    $h = ''
    if (($_.Check -in $perHost -or $_.Check -like 'Step *' -or $_.Part -ne 'A') -and $_.Target -ne 'Servers other than CAs') { $h = $_.Host }
    "$($_.Status)|$($_.Check)|$($_.Target)|$($_.Detail)|$h"
}
$merged = New-Object System.Collections.ArrayList
foreach ($g in $groups) {
    $first = $g.Group[0]
    [void]$merged.Add([pscustomobject]@{
        Status      = $first.Status
        Check       = $first.Check
        Target      = $first.Target
        Detail      = $first.Detail
        ManualCheck = $first.ManualCheck
        Rating      = ''
        Hosts       = (@($g.Group | ForEach-Object Host | Sort-Object -Unique) -join ', ')
        Sources     = (@($g.Group | ForEach-Object Source | Sort-Object -Unique) -join ', ')
    })
}
# What should have been checked, and what was
$partA   = @($runs | Where-Object Part -eq 'A')
$partB   = @($runs | Where-Object Part -eq 'B')
$partC   = @($runs | Where-Object Part -eq 'C')
$ranA    = @($partA | ForEach-Object { & $short $_.Host })
$ranB    = @(@($partB) + @($partA | Where-Object { "$($_.Info.DCState)" }) | ForEach-Object { & $short $_.Host })   # Part B runs, plus CAs that are DCs (step 6.3)
$ranC    = @($partC | ForEach-Object { & $short $_.Host })
$expCAs  = @($partA | ForEach-Object { $_.Info.CAs } | Where-Object { $_ } | Sort-Object -Unique)
$expDCs  = @($partA | ForEach-Object { $_.Info.DCs } | Where-Object { $_ } | Sort-Object -Unique)
$caShort = @($expCAs | ForEach-Object { & $short $_ })
$expCES  = @($partA | ForEach-Object { $_.Info.CESHosts } | Where-Object { $_ } | Sort-Object -Unique | Where-Object { (& $short $_) -notin $caShort })
$dcState = @{}
foreach ($b in @(@($partB) + @($partA | Where-Object { "$($_.Info.DCState)" }))) {
    $dcState[(& $short $b.Host)] = "$($b.Info.DCState)"
}
$coverage = New-Object System.Collections.ArrayList
foreach ($h in $expCAs) {
    [void]$coverage.Add([pscustomobject]@{ Server = $h; Role = 'Certificate Authority (Part A)'; Checked = ((& $short $h) -in $ranA); Result = '' })
}
foreach ($h in $expDCs) {
    $s = & $short $h
    [void]$coverage.Add([pscustomobject]@{ Server = $h; Role = 'Domain controller (Part B)'; Checked = ($s -in $ranB); Result = "$($dcState[$s])" })
}
foreach ($h in $expCES) {
    [void]$coverage.Add([pscustomobject]@{ Server = $h; Role = 'CES server (Part C)'; Checked = ((& $short $h) -in $ranC); Result = '' })
}
$cesShort = @($expCES | ForEach-Object { & $short $_ })
foreach ($c in $partC) {
    if ((& $short $c.Host) -notin $cesShort) {
        [void]$coverage.Add([pscustomobject]@{ Server = $c.Fqdn; Role = 'Other web enrollment server (Part C)'; Checked = $true; Result = '' })
    }
}
# Mark manual checks that another run has answered as RESOLVED
$allCAsRan = -not @($expCAs | Where-Object { (& $short $_) -notin $ranA }).Count
foreach ($m in $merged) {
    if ($m.Check -eq 'CA server checks' -and (& $short $m.Target) -in $ranA) {
        $m.Status = 'RESOLVED'
        $m.Rating = "Covered by the Part A run on $($m.Target)."
    }
    if ($m.Check -eq 'ESC10' -and $m.Status -eq 'MANUAL CHECK' -and (& $short $m.Target) -in $ranB) {
        $m.Status = 'RESOLVED'
        $m.Rating = "Covered by the Part B run on $($m.Target)."
    }
    if ($m.Check -eq 'ESC15' -and $m.Status -eq 'MANUAL CHECK' -and $m.Detail -like '*published on another CA*' -and $allCAsRan) {
        $m.Status = 'RESOLVED'
        $m.Rating = 'Every CA has a Part A run, so the CA that publishes this template reports it.'
    }
    if ($m.Check -eq 'ESC8' -and $m.Status -eq 'MANUAL CHECK' -and $m.Detail -like 'This CES address is on a server that is not a CA*') {
        $ch = & $short ([uri]$m.Target).Host
        if ($ch -in $ranC) {
            $m.Status = 'RESOLVED'
            $m.Rating = "Covered by the Part C run on $ch."
        }
    }
}
# Rate findings that only work while a DC accepts weak certificate mappings
$dcMissing = @($expDCs | Where-Object { (& $short $_) -notin $ranB })
$dcWeak    = @($dcState.Keys | Where-Object { $dcState[$_] -eq 'WEAK' })
$dcUnknown = @($dcState.Keys | Where-Object { $dcState[$_] -notlike 'FULL*' -and $dcState[$_] -ne 'WEAK' })
foreach ($m in $merged) {
    $dependent = $m.Status -eq 'FINDING' -and ($m.Check -in 'ESC6', 'ESC9', 'ESC16' -or ($m.Check -eq 'ESC14' -and $m.Detail -like 'Weak explicit*'))
    $allFull   = $expDCs.Count -gt 0 -and -not $dcWeak.Count -and -not $dcMissing.Count -and -not $dcUnknown.Count
    if ($dependent -and $dcWeak.Count) {
        $m.Rating = "Exploitable: these DCs accept weak certificate mappings: $($dcWeak -join ', ')."
    }
    if ($dependent -and -not $dcWeak.Count -and -not $allFull) {
        $m.Rating = "Unconfirmed: no confirmed Part B result for $(@($dcMissing + $dcUnknown) -join ', ')."
    }
    if ($dependent -and $allFull) {
        $m.Status = 'MITIGATED'
        $m.Rating = 'Every DC enforces strong certificate mapping (Part B), so this is not exploitable today. Fix it anyway in case enforcement changes.'
    }
}
# Problems with the runs themselves, and servers that still need a run
$newRow = {
    param($status, $check, $target, $detail, $manual)
    [void]$merged.Add([pscustomobject]@{ Status = $status; Check = $check; Target = $target; Detail = $detail; ManualCheck = $manual; Rating = ''; Hosts = ''; Sources = '' })
}
foreach ($r in $runs) {
    if (-not $r.HashOk) {
        & $newRow 'MANUAL CHECK' 'Consolidation' $r.Zip $r.HashNote 'Ask for the zip and its .sha256.txt file to be sent again, and confirm nobody changed them.'
    }
    if (-not $r.Part) {
        & $newRow 'MANUAL CHECK' 'Consolidation' $r.Zip "This zip has no 00_run_info.json, so it can't be matched to a server (it may come from an older version of the runbook)." 'Re-run the relevant part with the current runbook.'
    }
    if (-not (Test-Path (Join-Path $r.Folder 'FINDINGS.csv'))) {
        & $newRow 'MANUAL CHECK' 'Consolidation' $r.Zip 'This zip has no FINDINGS.csv, so the run probably did not finish.' 'Check transcript.txt in this zip, then re-run that part.'
    }
}
foreach ($c in @($coverage | Where-Object { -not $_.Checked })) {
    & $newRow 'MANUAL CHECK' 'Coverage' $c.Server "$($c.Role) has not been run on this server." "Run $($c.Role -replace '^.*\((Part [ABC])\)$', '$1') on $($c.Server) and add its zip to $in, then re-run Part D."
}
if (-not $partA.Count) {
    & $newRow 'MANUAL CHECK' 'Coverage' '' 'No Part A run was found, so the CAs, templates and DC list are unknown.' 'Run Part A on every CA, add the zips, then re-run Part D.'
}
if ($Error.Count) {
    & $newRow 'MANUAL CHECK' 'Consolidation' '' 'Errors occurred while combining the results, so some rows may be missing.' 'Check consolidation_transcript.txt for red text, fix the cause and re-run Part D.'
}
Write-Host "[D.2] DONE - combined rows: $($merged.Count); servers still to check: $(@($coverage | Where-Object { -not $_.Checked }).Count)" -ForegroundColor Green
```

You should see: a green `[D.2] DONE` line.

**D.3 Write the report and package the results**

```powershell
$order = @{ 'FINDING' = 1; 'MANUAL CHECK' = 2; 'MITIGATED' = 3; 'RESOLVED' = 4; 'CLEAR' = 5 }   # Sort: findings first, then manual checks, mitigated, resolved and clear
$final = @($merged | Sort-Object @{ e = { $order["$($_.Status)"] } }, Check, Target)
$final    | Export-Csv "$out\CONSOLIDATED_FINDINGS.csv" -NoTypeInformation
$coverage | Export-Csv "$out\COVERAGE.csv" -NoTypeInformation
# Build a readable HTML report, one section per status
$section = {
    param($title, $rows, [string[]]$cols)
    $rows = @($rows)
    $html = "<h2>$title ($($rows.Count))</h2>"
    if ($rows.Count) {
        $html += ($rows | Select-Object $cols | ConvertTo-Html -Fragment | Out-String)
    } else {
        $html += '<p>None.</p>'
    }
    $html
}
$summary = $final | Group-Object Status | Select-Object @{ n = 'Status'; e = { $_.Name } }, Count
$body = @(
    '<h1>AD CS ESC assessment: consolidated results</h1>'
    "<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $($runs.Count) run(s).</p>"
    ($summary | ConvertTo-Html -Fragment | Out-String)
    (& $section 'Coverage' $coverage @('Server', 'Role', 'Checked', 'Result'))
    (& $section 'Findings' ($final | Where-Object Status -eq 'FINDING') @('Check', 'Target', 'Detail', 'Rating', 'ManualCheck', 'Hosts'))
    (& $section 'Manual checks' ($final | Where-Object Status -eq 'MANUAL CHECK') @('Check', 'Target', 'Detail', 'ManualCheck', 'Hosts'))
    (& $section 'Mitigated' ($final | Where-Object Status -eq 'MITIGATED') @('Check', 'Target', 'Detail', 'Rating', 'Hosts'))
    (& $section 'Resolved by other runs' ($final | Where-Object Status -eq 'RESOLVED') @('Check', 'Target', 'Rating'))
    (& $section 'Clear' ($final | Where-Object Status -eq 'CLEAR') @('Check', 'Detail', 'Hosts'))
    (& $section 'Runs' $runs @('Zip', 'Part', 'Host', 'HashOk', 'HashNote'))
)
$style = '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;margin-bottom:24px;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top;font-size:13px}th{background:#eee}</style>'
ConvertTo-Html -Title 'AD CS ESC assessment' -Head $style -Body ($body -join "`n") | Out-File "$out\REPORT.html" -Encoding utf8
$summary | Format-Table -AutoSize
Write-Host "[D.3] DONE - report: $out\REPORT.html" -ForegroundColor Green
# Stop recording, then zip and fingerprint the consolidated results
Stop-Transcript
Compress-Archive "$out\*" "$out.zip" -Force
Get-FileHash "$out.zip" -Algorithm SHA256 | Select-Object Hash, Path | Tee-Object -FilePath "$out.sha256.txt"
Invoke-Item "$out\REPORT.html"
```

You should see: a summary table, a green `[D.3] DONE` line, a hash value, and the report opening in a browser.

`CONSOLIDATED_FINDINGS.csv` holds every combined row; `COVERAGE.csv` lists each CA, DC and web enrollment server with whether it was checked; `RUNS.csv` lists each zip and whether its hash matched.

## For the reviewer: reading the results

Every check ends in one of three states in `FINDINGS.csv`, so nothing passes or fails silently:

- **FINDING**: the vulnerable configuration was read directly and confirmed. The `ManualCheck` column says what to confirm before reporting it.
- **MANUAL CHECK**: the runbook couldn't confirm the result either way. The `ManualCheck` column says exactly what to look at by hand.
- **CLEAR**: the check ran without errors and found nothing. A check is only marked CLEAR if its step had no errors; otherwise it becomes a MANUAL CHECK.
- **MITIGATED** (Part D only): a finding that only works while a DC accepts weak certificate mappings (ESC6, ESC9, ESC16, weak ESC14 mappings), where every DC was checked in Part B and enforces strong mapping.
- **RESOLVED** (Part D only): a manual check from one run that another run answered, for example "run Part B on this DC" once that DC's Part B zip is present.

After Part D, use `CONSOLIDATED_FINDINGS.csv` and `REPORT.html` rather than the individual `FINDINGS.csv` files. The `Rating` column explains how DC results affected each dependent finding.

| Check | FINDING means | Raised as MANUAL CHECK when | Depends on Part B? |
| --- | --- | --- | --- |
| ESC1 | Non-admins can enroll, supply the subject, and get a logon-capable certificate | The template needs manager approval or an authorised signature | No |
| ESC2 | Non-admins can enroll in an Any Purpose or no-EKU template | As ESC1 | No |
| ESC3 | Non-admins can get an enrollment agent certificate and a target template exists; or (Target = CA) the CA has no agent restrictions | Approval needed; no target template found; agent restrictions exist and their content needs reviewing | No |
| ESC4 | A non-admin principal has broad write rights on, or owns, a template | The principal can only write one specific attribute | No |
| ESC5 | A non-admin principal has broad write rights on, or owns, a PKI object or CA computer object | Rights limited to one attribute or object type; Deny entries; a local administrator on the CA who isn't in an admin group; an object couldn't be read | No |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` is set | Non-default policy module, or EditFlags unreadable | Yes |
| ESC7 | A non-admin principal holds ManageCA or ManageCertificates | CA permissions couldn't be decoded, or contain Deny entries | No |
| ESC8 | This server's web enrollment answers over plain HTTP, or lacks Extended Protection or required SSL | Non-HTTPS redirect, timeout, certificate error or unexpected response; IIS settings unreadable; a CES address or possible web enrollment server elsewhere (run Part C) | No |
| ESC9 | A logon-capable template omits the SID security extension | Approval needed | Yes |
| ESC10 (Part A) | n/a | Always raised once per DC: the DC must be checked with Part B | Is the instruction to run it |
| ESC10-KDC (Part B) | The DC accepts weak certificate mappings | The DC's build is in a hotpatch range or an unsupported Windows version, so its update level can't be matched exactly | Is Part B |
| ESC10-Schannel (Part B) | The DC allows UPN certificate mapping in Schannel (any patch level) | n/a | Is Part B |
| ESC11 | CA RPC requests aren't required to be encrypted | InterfaceFlags unreadable | No |
| ESC12 | The CA key is on a YubiHSM whose authentication password is stored in the registry | YubiHSM in use but no stored password found; key provider unreadable | No |
| ESC13 | A template's issuance policy grants membership of a group (Detail says whether it is an admin group) | Approval needed | No |
| ESC14 | An account has a weak explicit mapping, or a non-admin can change `altSecurityIdentities` on an admin account | Unrecognised mapping format; a domain or account couldn't be read | Weak mappings: yes. Write access: no |
| ESC15 | Schema v1 template where the requester supplies the subject, published on this CA, and this CA lacks the November 12, 2024 update | Approval needed; build in a hotpatch range or unsupported; template published only on another CA | No |
| ESC16 | The CA omits the SID security extension from every certificate | Non-default policy module | Yes |
| ESC17 | Non-admins can supply the subject on a Server Authentication certificate (TLS/WSUS impersonation) | Approval needed | No |
| CVE-2026-54121 | This CA lacks the July 14, 2026 update (Certighost: any domain user can obtain a DC certificate) | Build in a hotpatch range or unsupported | No |
| CVE-2022-26923 | This CA lacks the May 10, 2022 update (Certifried) | As above | No |
| CA-KEY | The CA private key is stored in software and can be exported by server admins or from backups | A provider that isn't a known software provider: confirm it is a real HSM | No |
| CA-AUDIT | CA auditing is not fully enabled (AuditFilter isn't 127) | n/a | No |
| EKU | n/a | A template's EKU list and Application Policies differ, so its ESC1/2/3/9/17 results need checking by hand | n/a |
| Setup, Templates, Template permissions, CA server checks, Evidence | n/a | A domain, admin group, CA computer account, template or permission set couldn't be read; another CA must be run separately | n/a |
| Step x.y | n/a | Unexpected errors occurred during that step; its results may be incomplete | n/a |

**How the automatic judgments work**

- **Admin principals** are resolved automatically: SYSTEM, SELF, Enterprise Domain Controllers, Creator Owner, the built-in Administrators, Account/Server/Print/Backup Operators, Domain Admins, Enterprise Admins, Schema Admins, Key Admins, Enterprise Key Admins, Cert Publishers, Domain Controllers, the built-in Administrator account, the CA computer accounts, and every user, group and computer nested inside the admin groups (resolved by SID, so it works on non-English domains). Anything else is "non-admin"; a finding naming a delegated PKI admin group is a real finding for the client to accept or remediate.
- **Patch levels** are matched against the exact OS build numbers Microsoft publishes for Windows Server 2016, 2019, 2022 and 2025: November 12, 2024 (ESC15), May 10, 2022 (Certifried), February 11 and September 9, 2025 (DC enforcement) and July 14, 2026 (Certighost). A build in the gap between a hotpatch and the standard update, or an unsupported Windows version (2012 R2 or older), is raised as a MANUAL CHECK rather than guessed.
- **DC enforcement** (Part B) is Full if the September 9, 2025 update is installed; or if the May 2022 update is installed and `StrongCertificateBindingEnforcement` is 2; or if it's not set and the February 11, 2025 update is installed. Otherwise the DC accepts weak mappings. Until every DC listed in `10_domain_controllers_to_check.csv` has a Part B result, ESC6, ESC9, ESC16 and weak ESC14 mappings can't be rated. If any DC accepts weak mappings, rate them as exploitable.
- **Permission checks** use Allow entries; where Deny entries exist, a MANUAL CHECK is raised for that template, object or CA.
- **CA settings** (ESC6, ESC11, ESC16) are read from the CA's registry as numeric flags; the `certutil` files are the human-readable evidence. Registry changes only take effect after the CA service restarts, so if a setting looks recently changed, confirm the service has been restarted since.
- Strong mapping on DCs does not mitigate ESC1–5, ESC7, ESC8, ESC11, ESC12, ESC13, ESC15, ESC17 or the CVEs; don't downgrade those based on Part B.

**What always needs a person to decide**

A few questions can't be answered from configuration alone. They always appear as MANUAL CHECK rows that say exactly what to confirm:

- Whether manager approval on a template is really performed by a person, rather than auto-approved.
- Whether a non-admin group holding PKI rights is an approved delegation (for example a "PKI Admins" group).
- What rights a non-admin group linked by an ESC13 issuance policy holds elsewhere in the environment.
- Whether a non-software CA key provider is a genuine HSM, and who can use it.
- Whether web enrollment is installed on servers that are not CAs (not discoverable from AD); the client must confirm, and Part C covers any they name.
- In multi-domain forests, whether a principal is an admin through another domain's group.

The build thresholds were taken from Microsoft's Windows Server release information as of October 2026. Later updates are cumulative, so newer builds automatically pass. Cross-reference ESC1–4, ESC7 and ESC8 with the ADSecurityAudit HTML report; where they differ, the evidence files here are the tie-breaker.
