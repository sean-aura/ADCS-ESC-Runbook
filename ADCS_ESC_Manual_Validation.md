# AD CS ESC Manual Validation and Remediation Guide

Use this guide to confirm by hand any FINDING or MANUAL CHECK raised by the ADCS ESC runbook, and to fix what you confirm. Each ESC has the same three parts:

- **What the risk is**
- **How to detect and confirm**: which servers to check, the commands to run, and what to look for in each output
- **How to remediate**

The detection steps only read configuration. They never request, issue or change a certificate or setting. The remediation steps **do** change configuration. Agree them through change control, test them in a lab first, and back up the CA (`certutil -backup`) before changing CA settings.

---

## Before you start

- Run commands in **Windows PowerShell 5.1** as administrator, on a domain-joined machine with the RSAT ActiveDirectory module, unless a step names a specific server.
- Load the module once per window: `Import-Module ActiveDirectory`
- Commands starting `certutil -getreg CA\` or `certutil -getreg policy\` read the CA's own settings, so run them **on the CA server**.
- Replace each placeholder in square brackets (including the brackets) with the real value. Keep any quotes around it.
- Save each command's output (copy it or take a screenshot) as evidence.

### Placeholders

| Placeholder | What it is | Example |
| --- | --- | --- |
| `[template]` | Template **short name** (no spaces), as in `FINDINGS.csv` or `certutil -catemplates` | `ContosoUser` |
| `[ca-server]` | CA server's full DNS name | `ca01.contoso.local` |
| `[web-server]` | Server hosting CA Web Enrollment or CES (often the CA) | `ca01.contoso.local` |
| `[ces-app]` | CES application name in IIS | `Contoso-Issuing-CA_CES_Kerberos` |
| `[dc]` | Domain controller's full DNS name | `dc01.contoso.local` |
| `[username]` | An account's sAMAccountName | `jsmith` |
| `[group]` | A group's sAMAccountName | `PKI-Issuers` |
| `[oid]` | An issuance policy OID | `1.3.6.1.4.1.311.21.8.1234567.7654321.1` |
| `[guid]` | A permission's ObjectType GUID | `bf967a7f-0de6-11d0-a285-00aa003049e2` |

### Build numbers that include each security update

Get a server's build with `cmd /c ver` (for example `Microsoft Windows [Version 10.0.20348.5386]`). The last number is the revision. If it is equal to or higher than the number in the table, the update is installed.

| Windows Server | Build | May 10, 2022 (Certifried) | Nov 12, 2024 (ESC15) | Feb 11, 2025 (DC default enforcement) | Sep 9, 2025 (DC full enforcement) | Jul 14, 2026 (Certighost) |
| --- | --- | --- | --- | --- | --- | --- |
| 2016 | 14393 | 5125 | 7515 | 7785 | 8422 | 9339 |
| 2019 | 17763 | 2928 | 6532 | 6893 | 7792 | 9020 |
| 2022 | 20348 | 707 | 2849 | 3207 | 4171 | 5386 |
| 2025 | 26100 | (included) | 2314 | 3194 | 6584 | 33158 |

Hotpatched Server 2022 and 2025 machines use lower revisions for some months: 2022 uses 2819, 3148 and 4106, and 2025 uses 2240, 3107 and 6508, for November 2024, February 2025 and September 2025 respectively. If a revision falls between the hotpatch and standard numbers, check Microsoft's update history for that build. Server 2012 R2 and older aren't covered.

### Listing commands

When a step has to be run on every template, CA, DC or account of a kind, use these to get the full list first. Each section's **Servers** line says which ones apply. Run them on any domain-joined machine unless stated.

**L1. Every CA** (gives `[ca-server]`):

```
Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName | Select-Object @{ n = 'CAName'; e = { $_.Name } }, dNSHostName | Format-Table -AutoSize
```

Example output: `Contoso-Issuing-CA  ca01.contoso.local`. Use the `dNSHostName` value as `[ca-server]`.

**L2. Every published template, and which CA publishes it** (gives `[template]`):

```
Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates | ForEach-Object { $ca = $_.dNSHostName; $_.certificateTemplates | ForEach-Object { [pscustomobject]@{ Template = $_; CA = $ca } } } | Sort-Object Template | Format-Table -AutoSize
```

Only published templates can be used, so these are the templates to check.

**L3. Key settings of every published template, in one table:**

```
$pub = (Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates).certificateTemplates | Sort-Object -Unique; Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties * | Where-Object { $_.Name -in $pub } | Select-Object Name, @{ n = 'Version'; e = { $_.'msPKI-Template-Schema-Version' } }, @{ n = 'SuppliesSubject'; e = { [bool]($_.'msPKI-Certificate-Name-Flag' -band 1) } }, @{ n = 'NeedsApproval'; e = { [bool]($_.'msPKI-Enrollment-Flag' -band 2) } }, @{ n = 'NoSecurityExt'; e = { [bool]($_.'msPKI-Enrollment-Flag' -band 0x80000) } }, @{ n = 'Signatures'; e = { $_.'msPKI-RA-Signature' } }, @{ n = 'EKU'; e = { $_.pKIExtendedKeyUsage -join '; ' } } | Sort-Object Name | Format-Table -AutoSize -Wrap
```

Look for:
- `SuppliesSubject = True` with a logon EKU (ESC1) or Server Authentication EKU (ESC17).
- Any Purpose or an empty EKU (ESC2).
- `NoSecurityExt = True` (ESC9).
- `Version = 1` with `SuppliesSubject = True` (ESC15).

Rows with `NeedsApproval = True` or `Signatures` above 0 aren't exploitable by ordinary users. The EKU column shows OIDs; the ESC sections say which ones matter.

**L4. Who can enroll in every published template:**

```
$pub = (Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates).certificateTemplates | Sort-Object -Unique; $pub | ForEach-Object { $t = $_; (Get-Acl "AD:CN=$t,CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.ActiveDirectoryRights -match 'GenericAll' -or $_.ObjectType -in '0e10c968-78fb-11d2-90d4-00c04f79dc55','a05b8cc2-17bc-4802-a710-e7c15ab866a2','00000000-0000-0000-0000-000000000000') } | Select-Object @{ n = 'Template'; e = { $t } }, IdentityReference, ActiveDirectoryRights } | Format-Table -AutoSize
```

Look for: broad groups (Domain Users, Domain Computers, Authenticated Users, Everyone) or other non-admin groups against templates flagged in L3.

**L5. Full decoded settings of every published template, saved to one file:**

```
$pub = (Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates).certificateTemplates | Sort-Object -Unique; $pub | ForEach-Object { "===== $_ ====="; certutil -v -dstemplate $_ } | Out-File "$env:USERPROFILE\Desktop\all_published_templates.txt"
```

Search the file (Ctrl+F) for `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, `CT_FLAG_NO_SECURITY_EXTENSION` and `msPKI-Template-Schema-Version = 1`. The `=====` line above each match names the template.

**L6. Every template in AD, published or not:**

```
$pub = (Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates).certificateTemplates | Sort-Object -Unique; Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName, msPKI-Template-Schema-Version | Select-Object Name, displayName, @{ n = 'Version'; e = { $_.'msPKI-Template-Schema-Version' } }, @{ n = 'Published'; e = { $_.Name -in $pub } } | Sort-Object Name | Format-Table -AutoSize
```

Use this for ESC4: write access to an unpublished template matters too, because a CA admin could publish it later.

**L7. Every domain controller in the forest** (gives `[dc]`):

```
(Get-ADForest).Domains | ForEach-Object { Get-ADDomainController -Filter * -Server $_ } | Select-Object HostName, Domain, OperatingSystem, IsGlobalCatalog | Sort-Object HostName | Format-Table -AutoSize
```

**L8. Web enrollment (CES) addresses published in AD** (gives `[web-server]`):

```
Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, msPKI-Enrollment-Servers | ForEach-Object { $ca = $_.dNSHostName; [regex]::Matches(($_.'msPKI-Enrollment-Servers' -join ' '), 'https?://\S+') | ForEach-Object { [pscustomobject]@{ CA = $ca; CESUrl = $_.Value } } } | Format-Table -AutoSize
```

The host in each URL is a `[web-server]`. CA Web Enrollment (`/certsrv`) isn't recorded in AD, so also test `http://[ca-server]/certsrv/` for every CA from L1. Ask the client whether web enrollment runs on any other server.

**L9. IIS applications on a web server** (gives `[ces-app]`; run on the **web server**):

```
& "$env:windir\system32\inetsrv\appcmd.exe" list app
```

Look for: `APP "Default Web Site/CertSrv"` (web enrollment) and applications ending in `_CES_Kerberos`, `_CES_UsernamePassword` or `_CES_Certificate` (CES). Use the part after `Default Web Site/` as `[ces-app]`.

**L10. Privileged accounts** (gives `[username]` for ESC14):

```
Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount | Select-Object SamAccountName, Enabled | Sort-Object SamAccountName | Format-Table -AutoSize
```

`adminCount=1` marks accounts that are, or once were, in a protected admin group. Run ESC14 step 2 for each one, and repeat with `-Server [domain]` for every other domain in the forest.

### Shared commands

These commands are referenced by name in the sections below.

**Template settings (decoded).** Run on any domain-joined machine.

```
certutil -v -dstemplate [template]
```

Example: `certutil -v -dstemplate ContosoUser`

In the output, the fields that matter are:

- `msPKI-Certificate-Name-Flag`: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` means the requester supplies the subject.
- `pKIExtendedKeyUsage`: what the certificate can be used for.
- `msPKI-Enrollment-Flag`: `CT_FLAG_PEND_ALL_REQUESTS` means manager approval is required; `CT_FLAG_NO_SECURITY_EXTENSION` means the template omits the SID extension.
- `msPKI-RA-Signature`: above 0 means authorised signatures are required.
- `msPKI-Template-Schema-Version`: the template version.

**Template is published.** Run on **each CA**.

```
certutil -catemplates
```

Look for: a line starting with the template's short name. If no CA lists it, nobody can enroll in it. To see every CA's published templates at once, use **L2**.

**Who can enroll in a template.** Run on any domain-joined machine.

```
(Get-Acl "AD:CN=[template],CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.ActiveDirectoryRights -match 'GenericAll' -or $_.ObjectType -in '0e10c968-78fb-11d2-90d4-00c04f79dc55','a05b8cc2-17bc-4802-a710-e7c15ab866a2','00000000-0000-0000-0000-000000000000') } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType -AutoSize
```

Look for: broad groups (Domain Users, Domain Computers, Authenticated Users, Everyone) or any non-admin group. To check every published template at once, use **L4**. In the `ObjectType` column, `0e10c968-...` is Enroll, `a05b8cc2-...` is AutoEnroll, and all zeros with ExtendedRight means every extended right.

**Who can enroll on the CA.** Run on the **CA**.

```
certutil -getreg CA\Security
```

Look for: `Allow Enroll` for the same group. Authenticated Users has it by default.

**Change who can enroll in a template.** Open `certtmpl.msc`, open the template, and go to the **Security** tab. Remove Enroll and Autoenroll from broad groups, and grant them only to a group that genuinely needs the template.

**Unpublish a template from a CA.** Run on the **CA**.

```
certutil -SetCATemplates -[template]
```

Example: `certutil -SetCATemplates -ContosoUser`

---

## ESC1: Requester supplies the subject on a logon certificate

### What the risk is

An ordinary user requests a certificate in another account's name (for example a Domain Admin) and uses it to log on as that account. With domain admin rights this way, an attacker controls the whole domain.

### How to detect and confirm

**Servers:** any domain-joined machine for the template, and each CA for publication. Use **L2** for the list of published templates, **L3** to spot candidates in one table, **L4** to see who can enroll, and **L1** for the CAs.

1. Run the template settings command: `certutil -v -dstemplate [template]`. Look for all of:
   - `msPKI-Certificate-Name-Flag` contains `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.
   - `pKIExtendedKeyUsage` contains Client Authentication (`1.3.6.1.5.5.7.3.2`), Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`), PKINIT Client (`1.3.6.1.5.2.3.4`) or Any Purpose (`2.5.29.37.0`), or is empty.
   - No `CT_FLAG_PEND_ALL_REQUESTS`, and `msPKI-RA-Signature = 0`.
2. Run `certutil -catemplates` on each CA. Look for: the template listed.
3. Run the "Who can enroll in a template" command. Look for: non-admin groups with Enroll.
4. Optional GUI check: in `certtmpl.msc`, open the template and look at the **Subject Name** tab (*Supply in the request*), **Extensions > Application Policies**, **Issuance Requirements** and **Security**.

**Confirmed when:** all of the above are true.

**Not vulnerable if:** the subject is built from Active Directory, the template is unpublished, only admins can enroll, or approval or signatures are required.

### How to remediate

1. If the template isn't needed, unpublish it from every CA (`certutil -SetCATemplates -[template]`).
2. Otherwise, choose one of these:
   - In `certtmpl.msc`, go to the template's **Subject Name** tab and select **Build from this Active Directory information**.
   - If requesters must supply the subject (for example for web server certificates), remove the logon EKUs under **Extensions > Application Policies**, and turn on **Issuance Requirements > CA certificate manager approval**.
3. Restrict Enroll on the template's **Security** tab to the group that needs it.
4. Revoke any certificates already issued from this template to unexpected subjects. Review them in `certsrv.msc` under **Issued Certificates**, filtered by template.

---

## ESC2: Any Purpose EKU or no EKU

### What the risk is

The certificate can be used for anything, including logging on as the requester or other abuse paths. A template with no EKU at all can even produce certificates that act as a subordinate CA.

### How to detect and confirm

**Servers:** any domain-joined machine, and each CA for publication. Use **L2** and **L3** to find candidates across every published template, **L4** for enrollment rights, and **L1** for the CAs.

1. `certutil -v -dstemplate [template]`. Look for:
   - `pKIExtendedKeyUsage` contains `2.5.29.37.0`, or both `pKIExtendedKeyUsage` and `msPKI-Certificate-Application-Policy` are empty.
   - No approval flag, and `msPKI-RA-Signature = 0`.
2. `certutil -catemplates` on each CA. Look for: the template listed.
3. Run the "Who can enroll in a template" command. Look for: non-admin groups with Enroll.

**Confirmed when:** all are true. Treat a template with no EKU as critical.

### How to remediate

1. Unpublish the template if it isn't needed.
2. Otherwise, under **Extensions > Application Policies**, replace Any Purpose or the empty list with only the EKUs the certificate actually needs.
3. Restrict Enroll to the group that needs it, or require manager approval.

---

## ESC3: Enrollment agent abuse

### What the risk is

An ordinary user gets an enrollment agent certificate, then uses it to request certificates on behalf of any other user, including admins.

### How to detect and confirm

**Servers:** any domain-joined machine for the templates, and each CA for agent restrictions. Use **L3** to find agent and target templates (agent EKU `1.3.6.1.4.1.311.20.2.1`; targets with `Version = 1` or `Signatures = 1`), **L4** for enrollment rights, and **L1** for the CAs.

1. Check the agent template: `certutil -v -dstemplate [template]`. Look for:
   - `pKIExtendedKeyUsage` contains `1.3.6.1.4.1.311.20.2.1` (Certificate Request Agent).
   - No `CT_FLAG_PEND_ALL_REQUESTS`.
   - Non-admins can enroll (the "Who can enroll in a template" command).
2. Check each possible target template: `certutil -v -dstemplate [template]`. Look for:
   - The EKU allows logon.
   - Either `msPKI-Template-Schema-Version = 1`, or `msPKI-RA-Signature = 1` with `msPKI-RA-Application-Policies` containing `1.3.6.1.4.1.311.20.2.1`.
3. On each **CA**, run `certutil -getreg CA\EnrollmentAgentRights`. Look for: "not found" or empty, which means there are no restrictions.
4. GUI: in `certsrv.msc`, right-click the CA and choose **Properties > Enrollment Agents**. *Do not restrict enrollment agents* confirms the risk. Otherwise, screenshot which agents, templates and target groups are allowed.

**Confirmed when:** all three conditions hold, or the restrictions still let a broad group act for privileged accounts.

### How to remediate

1. Restrict Enroll on the agent template to the small group that issues smart cards, and require manager approval.
2. On each CA, select **Restrict enrollment agents** on the **Enrollment Agents** tab. Allow only the named agents, only the templates they need, and only non-privileged target groups.
3. Replace schema version 1 logon templates with a duplicated (version 2 or later) template that doesn't accept agent signatures, and unpublish the version 1 template.

---

## ESC4: Write access to a template

### What the risk is

Someone who can modify a template can make it vulnerable to ESC1, use it, then change it back.

### How to detect and confirm

**Servers:** any domain-joined machine. Run step 1 for every template from **L6**, not only published ones.

1. List the write rights:

   ```
   (Get-Acl "AD:CN=[template],CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty' } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType -AutoSize
   ```

   Look for: non-admin principals. `WriteProperty` with an all-zero `ObjectType` covers every attribute, which is a finding. A specific GUID covers one attribute only, so identify it with step 3.

2. Check the owner:

   ```
   (Get-Acl "AD:CN=[template],CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)").Owner
   ```

   Look for: any owner other than Domain Admins, Enterprise Admins or another Tier 0 account.

3. Identify a specific GUID from step 1:

   ```
   Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(schemaIDGUID=$((([guid]'[guid]').ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''))" -Properties lDAPDisplayName | Select-Object lDAPDisplayName
   ```

   If it returns nothing, the GUID is a property set or extended right. Look it up with:

   ```
   Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(rightsGuid=[guid])' -Properties displayName | Select-Object displayName
   ```

**Confirmed when:** a non-admin principal has broad write rights or owns the template, and isn't an approved PKI administrator.

### How to remediate

1. In `certtmpl.msc`, open the template and go to **Security**. Remove Full Control and Write from every non-admin principal. Read and Enroll can stay where they're needed.
2. Under **Advanced > Owner**, set the owner to Enterprise Admins.
3. Review every other template the same principal can modify, because the same rights are often granted widely.

---

## ESC5: Write access to PKI objects in AD, or to the CA server

### What the risk is

Control of the PKI containers in AD, the CA's AD objects, or the CA server itself means control of certificate issuance, and so of the domain.

### How to detect and confirm

**Servers:** any domain-joined machine for AD objects, and each CA for local administrators. Use **L1** for the list of CAs. Run step 2 and step 3 for each one.

1. List write rights on the PKI containers:

   ```
   'CN=Public Key Services','CN=Certificate Templates,CN=Public Key Services','CN=Enrollment Services,CN=Public Key Services','CN=NTAuthCertificates,CN=Public Key Services','CN=Certification Authorities,CN=Public Key Services','CN=AIA,CN=Public Key Services','CN=OID,CN=Public Key Services' | ForEach-Object { $dn = "$_,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"; (Get-Acl "AD:$dn").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild' } | Select-Object @{ n = 'Object'; e = { $dn.Split(',')[0] } }, IdentityReference, ActiveDirectoryRights, ObjectType } | Format-Table -AutoSize
   ```

   Look for: any principal other than SYSTEM, Administrators, Domain Admins, Enterprise Admins, Cert Publishers (expected on some objects) or other Tier 0 accounts.

2. List write rights on the CA computer account:

   ```
   (Get-Acl "AD:$((Get-ADComputer ([string]'[ca-server]').Split('.')[0]).DistinguishedName)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' } | Format-Table IdentityReference, ActiveDirectoryRights -AutoSize
   ```

   Look for: non-admin principals.

3. On the **CA**, run `net localgroup administrators`. Look for: any member who isn't a Tier 0 administrator.

**Confirmed when:** a non-admin principal has broad write rights, or a non-Tier 0 account is a local administrator on the CA.

### How to remediate

1. Remove non-Tier 0 principals' write rights on the PKI containers. Use ADSI Edit, connected to the Configuration partition: open the object, then **Properties > Security > Advanced**.
2. Remove the same principals' rights on the CA computer object, in Active Directory Users and Computers with Advanced Features on.
3. Remove non-Tier 0 members from the CA's local Administrators group. Manage the CA as a Tier 0 asset, with the same controls as a domain controller.

---

## ESC6: CA accepts a requester-supplied SAN on any template

### What the risk is

Any user can add another account's name (a SAN) to any certificate request, turning every client authentication template into ESC1.

### How to detect and confirm

**Servers:** each CA, plus the DCs (see ESC10) to rate it. Use **L1** for the list of CAs, and **L7** for the DCs.

1. On the **CA**, run `certutil -getreg policy\EditFlags`. Look for: `EDITF_ATTRIBUTESUBJECTALTNAME2` in the list of set flags.
2. On the **CA**, check which policy module is active:

   ```
   (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active)\PolicyModules").Active
   ```

   Look for: `CertificateAuthority_MicrosoftDefault.Policy`. A third-party module means step 1 may not apply, so ask the CA owner how it handles SANs.

3. Check DC enforcement (ESC10). On DCs in Full Enforcement, this is largely blocked.

**Confirmed when:** the flag is set. It is exploitable today if any DC accepts weak mappings.

### How to remediate

1. On the **CA**, clear the flag:

   ```
   certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
   ```

2. Restart the CA service: `Restart-Service certsvc`
3. Re-run detection step 1 to confirm the flag is gone.
4. Make sure every DC is in Full Enforcement (ESC10).

---

## ESC7: Non-admins can manage the CA

### What the risk is

ManageCA lets someone change CA settings (for example enable ESC6) or appoint certificate managers. ManageCertificates lets someone approve pending requests, bypassing manager approval.

### How to detect and confirm

**Servers:** each CA. Use **L1** for the list of CAs.

1. On the **CA**, run `certutil -getreg CA\Security`. Look for: `Allow CA Administrator` (ManageCA) or `Allow Certificate Manager` (ManageCertificates) granted to anyone other than Administrators, Domain Admins or Enterprise Admins.
2. On the **CA**, run `certutil -getreg CA\OfficerRights`. Look for: "not found", which means certificate managers can approve requests for any template and any requester.
3. GUI: in `certsrv.msc`, right-click the CA and choose **Properties > Security**. Screenshot it.

**Confirmed when:** a non-admin principal holds either right and isn't an approved PKI administrator.

### How to remediate

1. In `certsrv.msc`, open **Properties > Security**. Remove Manage CA and Issue and Manage Certificates from every non-Tier 0 principal.
2. If certificate managers are needed, open **Properties > Certificate Managers**, select **Restrict certificate managers**, and limit each manager to specific templates and requester groups.
3. Optionally enable role separation (`certutil -setreg CA\RoleSeparationEnabled 1`, then restart certsvc). That stops one person holding both roles, but first confirm the CA administrators aren't relying on holding both.

---

## ESC8: NTLM relay to web enrollment

### What the risk is

An attacker forces a machine (for example a DC) to authenticate to them, relays that NTLM authentication to web enrollment, and gets a certificate for the machine. With a DC certificate, they control the domain.

### How to detect and confirm

**Servers:** every server hosting CA Web Enrollment (`/certsrv`) or CES. This is often the CA itself. Use **L1** (test `/certsrv` on every CA), **L8** (CES servers) and **L9** (application names on each web server).

1. Test the HTTP address, from any domain machine:

   ```
   curl.exe -s -I http://[web-server]/certsrv/
   ```

   Example: `curl.exe -s -I http://ca01.contoso.local/certsrv/`

   Look for: `HTTP/1.1 401` with `WWW-Authenticate: NTLM` or `Negotiate`, which is relayable. A redirect to `https://`, a 403, a 404 or no connection means HTTP isn't usable.

   Server 2016 has no `curl.exe`, so use this instead:

   ```
   $q = [System.Net.HttpWebRequest]::Create('http://[web-server]/certsrv/'); $q.Method = 'HEAD'; $q.AllowAutoRedirect = $false; try { $r = $q.GetResponse() } catch { $r = $_.Exception.InnerException.Response }; "$([int]$r.StatusCode) $($r.Headers['WWW-Authenticate'])"
   ```

2. On the **web server**, check Extended Protection:

   ```
   & "$env:windir\system32\inetsrv\appcmd.exe" list config "Default Web Site/CertSrv" -section:system.webServer/security/authentication/windowsAuthentication /config:*
   ```

   Look for: `extendedProtection tokenChecking="Require"`. `None` or `Allow` is a finding. For CES, replace `CertSrv` with `[ces-app]`.

3. On the **web server**, check SSL is required:

   ```
   & "$env:windir\system32\inetsrv\appcmd.exe" list config "Default Web Site/CertSrv" -section:system.webServer/security/access /config:*
   ```

   Look for: `sslFlags` containing `Ssl`. `None` means plain HTTP is allowed.

**Confirmed when:** step 1 shows a 401 over HTTP, or step 2 shows anything other than `Require`.

### How to remediate

1. If web enrollment isn't used, remove it on the **web server**:

   ```
   Uninstall-WindowsFeature ADCS-Web-Enrollment
   ```

   Use `ADCS-Enroll-Web-Svc` instead for CES.

2. Otherwise, on the **web server**, require Extended Protection (Microsoft KB5005413):

   ```
   & "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /commit:apphost
   ```

3. Require SSL:

   ```
   & "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" -section:system.webServer/security/access /sslFlags:"Ssl" /commit:apphost
   ```

4. Make sure the site has an HTTPS binding with a valid certificate, then run `iisreset`.
5. Repeat steps 2 to 4 for each CES application (`[ces-app]`).
6. Re-run the detection steps to confirm the changes.

---

## ESC9: Template omits the SID security extension

### What the risk is

Certificates from the template don't carry the requester's SID. On DCs that accept weak mappings, an attacker who can change another account's UPN can use this to impersonate a different account.

### How to detect and confirm

**Servers:** any domain-joined machine, plus the DCs (ESC10). Use **L3** to find templates with `NoSecurityExt = True`, and **L7** for the DCs.

1. `certutil -v -dstemplate [template]`. Look for:
   - `msPKI-Enrollment-Flag` contains `CT_FLAG_NO_SECURITY_EXTENSION`.
   - The EKU allows logon.
   - No approval is required, and non-admins can enroll.
2. Check DC enforcement (ESC10).

**Confirmed when:** the flag is set and any DC accepts weak mappings. If every DC is in Full Enforcement, record it as mitigated, and still fix it.

### How to remediate

1. Clear the flag on the template:

   ```
   $dn = "CN=[template],CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"; Set-ADObject $dn -Replace @{ 'msPKI-Enrollment-Flag' = ((Get-ADObject $dn -Properties 'msPKI-Enrollment-Flag').'msPKI-Enrollment-Flag' -band -bnot 0x80000) }
   ```

2. Re-run detection step 1 to confirm the flag is gone.
3. Make sure every DC is in Full Enforcement (ESC10).

---

## ESC10: Domain controllers accept weak certificate mappings

### What the risk is

DCs match certificates to accounts by name rather than by SID. That makes ESC6, ESC9, ESC16 and weak ESC14 mappings exploitable. Separately, Schannel UPN mapping enables impersonation over LDAPS.

### How to detect and confirm

**Servers:** **every domain controller** (`[dc]`). Use **L7** for the list of DCs, and run every step on each one.

1. Check the KDC setting:

   ```
   reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement
   ```

   Look for: `0x2`, which is Full Enforcement. `0x1` or `0x0` means weak mappings are accepted. "Unable to find" means the default for the installed updates applies (step 3).

2. Check the Schannel setting:

   ```
   reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v CertificateMappingMethods
   ```

   Look for: any value with the `0x4` bit set (for example `0x1f`). That allows UPN mapping, which is ESC10 case 2, at any patch level. "Unable to find" means the default `0x18`, which is fine. To test a value, run `0x1f -band 4`: it returns `4` when the bit is set.

3. Check the build with `cmd /c ver` against the table:
   - At or above **September 9, 2025**: Full Enforcement, regardless of the registry.
   - At or above **February 11, 2025** with no registry value: Full Enforcement.
   - Below those, with `0x1`, `0x0` or no value: weak mappings are accepted.

4. Look for weak-mapping events:

   ```
   Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id = 39, 40, 41 } -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message
   ```

   Look for: any events. They show certificates in use without a strong mapping, which will fail under Full Enforcement. No output means none were logged.

**Confirmed when:** step 1 or 3 shows weak mappings accepted, or step 2 shows the `0x4` bit.

### How to remediate

1. Install the latest cumulative update on every DC. From the September 9, 2025 update onwards, Full Enforcement is always on.
2. Before that, on DCs that can't be updated yet, set Full Enforcement once step 4 shows no events:

   ```
   reg add HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
   ```

3. Remove the UPN bit from Schannel by setting the default value:

   ```
   reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v CertificateMappingMethods /t REG_DWORD /d 0x18 /f
   ```

   Then restart the DC in a maintenance window.

4. For accounts named in the step 4 events, reissue their certificates from an updated CA (which adds the SID extension), or give them a strong explicit mapping (ESC14).

---

## ESC11: CA accepts unencrypted RPC requests

### What the risk is

NTLM authentication can be relayed to the CA's RPC interface to request certificates as the relayed machine or user.

### How to detect and confirm

**Servers:** each CA. Use **L1** for the list of CAs.

1. On the **CA**, run `certutil -getreg CA\InterfaceFlags`. Look for: `IF_ENFORCEENCRYPTICERTREQUEST` in the set flags. If it's missing, the CA is vulnerable.

**Confirmed when:** the flag is absent.

### How to remediate

1. On the **CA**, set the flag:

   ```
   certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
   ```

2. Restart the CA service: `Restart-Service certsvc`
3. Re-run the detection step. Old clients (Windows XP and older) can't enroll once this flag is set.

---

## ESC12: CA key on a YubiHSM with a stored password

### What the risk is

Anyone with administrator or shell access on the CA can use the CA's private key through the YubiHSM, because the HSM authentication password is stored in the registry. With the CA key, they can forge any certificate.

### How to detect and confirm

**Servers:** each CA. Use **L1** for the list of CAs.

1. On the **CA**, run `certutil -getreg CA\CSP\Provider`. Look for: `YubiHSM Key Storage Provider`.
2. On the **CA**, check for a stored password without displaying it:

   ```
   (Get-ItemProperty HKLM:\SOFTWARE\Yubico\YubiHSM -ErrorAction Ignore).PSObject.Properties.Name -contains 'AuthKeysetPassword'
   ```

   Look for: `True`, which means a password is stored. Don't use `reg query` for this check, because it prints the password.

**Confirmed when:** the provider is YubiHSM and step 2 returns `True`.

### How to remediate

1. Replace the default authentication key (ID 1) and its password with a dedicated key that only has the capabilities the CA needs.
2. Limit local administrators on the CA to Tier 0 accounts, because anyone who can read the registry can use the key.
3. Protect backups of the CA server and its registry the same way as the CA itself.

---

## ESC13: Issuance policy linked to a group

### What the risk is

Anyone who enrolls in the template is treated as a member of the linked group when they log on with the certificate.

### How to detect and confirm

**Servers:** any domain-joined machine. Use **L4** to see who can enroll in templates that carry a linked policy.

1. List the issuance policies linked to groups:

   ```
   Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(msDS-OIDToGroupLink=*)' -Properties displayName, msPKI-Cert-Template-OID, msDS-OIDToGroupLink | Format-List displayName, msPKI-Cert-Template-OID, msDS-OIDToGroupLink
   ```

   Look for: each `[oid]` and the group it links to.

2. `certutil -v -dstemplate [template]`. Look for:
   - `msPKI-Certificate-Policy` contains the `[oid]`.
   - Non-admins can enroll, and no approval is required.

3. Check what the linked group can do:

   ```
   Get-ADGroup [group] -Properties memberOf, adminCount, description | Format-List Name, GroupScope, adminCount, memberOf, description
   ```

   Look for: `adminCount = 1` or membership of an admin group. Also check whether the group has rights on servers, GPOs or other AD objects.

**Confirmed when:** non-admins can enroll and the linked group grants meaningful rights.

### How to remediate

1. If the link isn't needed, remove it. In ADSI Edit (Configuration partition), open the OID object under `CN=OID,CN=Public Key Services,CN=Services` and clear `msDS-OIDToGroupLink`.
2. Otherwise, restrict Enroll on the template to the people who should have the group's rights, and require manager approval.
3. Remove unnecessary rights from the linked group.

---

## ESC14: Weak explicit certificate mappings, or write access to them

### What the risk is

A weak explicit mapping on an account lets anyone holding a matching certificate log on as that account. Write access to the mapping attribute (`altSecurityIdentities`) lets an attacker map their own certificate to an admin account.

### How to detect and confirm

**Servers:** any domain-joined machine, plus the DCs (ESC10) for weak mappings. Use **L10** for the privileged accounts to check in step 2, and **L7** for the DCs.

1. List explicit mappings:

   ```
   Get-ADObject -LDAPFilter '(altSecurityIdentities=*)' -Properties altSecurityIdentities, adminCount | Format-List Name, adminCount, altSecurityIdentities
   ```

   Look for:
   - Weak formats: `X509:<I>...<S>...` (issuer and subject), `X509:<S>...` (subject only) and `X509:<RFC822>...` (email).
   - Strong formats, which are fine: `X509:<I>...<SR>...`, `X509:<SKI>...` and `X509:<SHA1-PUKEY>...`.
   - `adminCount = 1`, which marks a privileged account.

2. Check who can change the mapping on a privileged account:

   ```
   (Get-Acl "AD:$((Get-ADUser [username]).DistinguishedName)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty' } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType -AutoSize
   ```

   Example: replace `[username]` with `administrator`.

   Look for: non-admin principals with `GenericAll`, `GenericWrite`, `WriteDacl` or `WriteOwner`, or `WriteProperty` with an all-zero `ObjectType` or the altSecurityIdentities GUID from step 3.

3. Get the altSecurityIdentities GUID:

   ```
   [guid]::new([byte[]](Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(lDAPDisplayName=altSecurityIdentities)' -Properties schemaIDGUID).schemaIDGUID)
   ```

**Confirmed when:**
- a weak mapping exists and any DC accepts weak mappings (ESC10), or
- a non-admin can write the attribute on a privileged account, at any patch level.

### How to remediate

1. Replace each weak mapping with a strong one: `X509:<I>...<SR>...` (issuer and serial number) or `X509:<SHA1-PUKEY>...`. Remove mappings that are no longer needed. Edit them in Active Directory Users and Computers (Advanced Features) under **Name Mappings**, or on the Attribute Editor tab.
2. Remove non-admin write rights on privileged accounts. For protected accounts (`adminCount = 1`), fix the permissions on `CN=AdminSDHolder,CN=System` in each domain, because AD copies them onto those accounts every hour.
3. Make sure every DC is in Full Enforcement (ESC10).

---

## ESC15 (CVE-2024-49019): Schema v1 template with a requester-supplied subject

### What the risk is

On an unpatched CA, a requester can add any Application Policy to a certificate from a version 1 template. That turns it into a logon certificate or an enrollment agent certificate.

### How to detect and confirm

**Servers:** any domain-joined machine for the template, and **each CA that publishes it** for the patch level. Use **L3** to find templates with `Version = 1` and `SuppliesSubject = True`, **L2** for the CAs that publish them, and **L1** for the CA list.

1. `certutil -v -dstemplate [template]`. Look for:
   - `msPKI-Template-Schema-Version = 1`.
   - `msPKI-Certificate-Name-Flag` contains `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.
   - No approval is required, and non-admins can enroll.
2. Find which CAs publish it (`certutil -catemplates` on each). On each of those, run `cmd /c ver` and compare with the **November 12, 2024** column.

**Confirmed when:** all template conditions are true and any publishing CA is below that build.

### How to remediate

1. Install the November 12, 2024 update (or any later cumulative update) on every CA.
2. If the template is still needed, duplicate it in `certtmpl.msc` to create a version 2 or later template. On the new template, either select **Build from this Active Directory information** or require manager approval, then publish it and unpublish the old one.
3. Restrict Enroll on any remaining version 1 templates that let requesters supply the subject (the built-in WebServer template is the usual one).

---

## ESC16: CA omits the SID security extension from every certificate

### What the risk is

Like ESC9, but for every template the CA issues.

### How to detect and confirm

**Servers:** each CA, plus the DCs (ESC10). Use **L1** for the list of CAs, and **L7** for the DCs.

1. On the **CA**, run `certutil -getreg policy\DisableExtensionList`. Look for: `1.3.6.1.4.1.311.25.2`. "not found" or an empty list is clear.
2. Check DC enforcement (ESC10).

**Confirmed when:** the OID is listed. It is exploitable today if any DC accepts weak mappings.

### How to remediate

1. On the **CA**, remove the OID from the list:

   ```
   certutil -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2
   ```

2. Restart the CA service: `Restart-Service certsvc`
3. Re-run detection step 1. Find out why the extension was disabled (usually an old application) and fix that application instead.

---

## ESC17: Requester supplies the subject on a Server Authentication certificate

### What the risk is

An ordinary user gets a trusted TLS certificate for any server name. That allows impersonation of internal web servers or WSUS, which can lead to code running on clients.

### How to detect and confirm

**Servers:** any domain-joined machine, and each CA for publication. Use **L3** to find templates with `SuppliesSubject = True` and Server Authentication (`1.3.6.1.5.5.7.3.1`), **L4** for enrollment rights, and **L1** for the CAs.

1. `certutil -v -dstemplate [template]`. Look for:
   - `msPKI-Certificate-Name-Flag` contains `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.
   - `pKIExtendedKeyUsage` contains Server Authentication (`1.3.6.1.5.5.7.3.1`).
   - No approval is required.
2. `certutil -catemplates` on each CA, and the "Who can enroll in a template" command. Look for: the template published, and non-admin groups with Enroll.

**Confirmed when:** all are true.

### How to remediate

1. Restrict Enroll to the server administrators who request web certificates.
2. Require manager approval on the template, or switch to **Build from this Active Directory information** for machine certificates.
3. Review issued certificates from this template in `certsrv.msc` for unexpected server names, and revoke any you don't recognise.

---

## Related CA risks

### CVE-2026-54121 (Certighost): unpatched CA

#### What the risk is

Any domain user can obtain a certificate for a domain controller using default templates, and so take over the domain.

#### How to detect and confirm

**Servers:** each CA, plus any domain-joined machine for the quota. Use **L1** for the list of CAs.

1. On the **CA**, run `cmd /c ver` and compare with the **July 14, 2026** column.
2. Check how many computer accounts ordinary users can create:

   ```
   (Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
   ```

   Look for: any value above 0 (the default is 10), which lets users create computer accounts.

**Confirmed when:** the CA is below that build.

#### How to remediate

1. Install the July 14, 2026 update (or later) on every CA.
2. Set MachineAccountQuota to 0, and grant computer-join rights only to a delegated group:

   ```
   Set-ADDomain -Identity [domain] -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
   ```

   Example: `Set-ADDomain -Identity contoso.local -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }`

3. Enable CA auditing (see CA auditing) so any past or future abuse is visible.

### CVE-2022-26923 (Certifried): unpatched CA

#### What the risk is

A user creates a computer account, sets its DNS name to a DC's, and gets a certificate for that DC.

#### How to detect and confirm

**Servers:** each CA, plus any domain-joined machine for the quota. Use **L1** for the list of CAs.

1. On the **CA**, run `cmd /c ver` and compare with the **May 10, 2022** column.
2. Check MachineAccountQuota with the command from the Certighost section.

**Confirmed when:** the CA is below that build. A MachineAccountQuota above 0 makes it easier to exploit.

#### How to remediate

1. Install the latest cumulative update on every CA and DC.
2. Set MachineAccountQuota to 0, as in the Certighost section.

### CA key protection (golden certificate)

#### What the risk is

If the CA's private key is held in software, any administrator of the CA server, or anyone with a backup of it, can export the key and forge any certificate. The forged certificates stay valid until the CA itself is replaced.

#### How to detect and confirm

**Servers:** each CA. Use **L1** for the list of CAs.

1. On the **CA**, run `certutil -getreg CA\CSP\Provider`. Look for:
   - `Microsoft Software Key Storage Provider`, or a provider ending in `Cryptographic Provider`, means the key is in software.
   - A vendor HSM provider means a hardware module holds it. Confirm with the CA owner.
2. On the **CA**, check who administers the server and its backups: `net localgroup administrators` and `net localgroup "Backup Operators"`.

**Confirmed when:** the key is in software. Rate the risk by how many people administer or back up the CA.

#### How to remediate

1. Plan to move the CA key to a hardware security module. This is usually done by building a new CA on an HSM, because an existing software key can't be made non-exportable after the fact.
2. Until then, limit administrators and Backup Operators on the CA to Tier 0 accounts, and protect CA and system-state backups as Tier 0 data.

### CA auditing

#### What the risk is

Without CA auditing, certificate abuse leaves no trace on the CA, so incidents can't be investigated.

#### How to detect and confirm

**Servers:** each CA. Use **L1** for the list of CAs.

1. On the **CA**, run `certutil -getreg CA\AuditFilter`. Look for: `127` (`0x7f`), which means all CA events are audited.
2. On the **CA**, run `auditpol /get /subcategory:"Certification Services"`. Look for: `Success and Failure`. Without this, no CA events are written even when AuditFilter is 127.

**Confirmed when:** AuditFilter isn't 127, or the audit policy isn't Success and Failure.

#### How to remediate

1. On the **CA**, enable all CA audit events: `certutil -setreg CA\AuditFilter 127`
2. On the **CA**, turn on the Windows audit policy, or set it through Group Policy:

   ```
   auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
   ```

3. Restart the CA service: `Restart-Service certsvc`
4. Forward the CA's Security log (event IDs 4886, 4887 and 4888 cover requests, issued certificates and denied requests) to your SIEM.
