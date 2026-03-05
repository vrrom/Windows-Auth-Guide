import { useState, useMemo } from "react";

const scenarios = [
  // ───── NORMAL AUTH ─────
  { id:"interactive", title:"Interactive Logon", desc:"Physical console logon with domain credentials", icon:"🖥️", cat:"normal",
    devices:["Workstation","Domain Controller"],
    steps:[
      {n:1,d:0,label:"User enters username & password at login screen",events:[],why:"No event logged yet. Winlogon.exe handles credential input locally before any network authentication begins.",arrow:null},
      {n:2,d:0,label:"Workstation sends AS-REQ to DC with encrypted timestamp",events:[],why:"AS-REQ is a network packet — only visible via packet capture (Wireshark/Zeek kerberos.log). The DC logs the response in step 3.",arrow:{to:1,proto:"kerberos"}},
      {n:3,d:1,label:"DC validates credentials, issues TGT",events:[
        {id:4768,t:"Kerberos TGT requested",f:[{k:"TargetUserName",v:"jsmith"},{k:"ServiceName",v:"krbtgt"},{k:"TicketEncryptionType",v:"0x12 (AES-256)"},{k:"PreAuthType",v:"15 (preauth enabled)"},{k:"IpAddress",v:"::ffff:10.1.2.50"},{k:"Status",v:"0x0"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:4,d:0,label:"Workstation requests service ticket for local machine",events:[],why:"TGS-REQ is a network packet. No Windows event on the workstation. The DC logs the response as 4769 in step 5.",arrow:{to:1,proto:"kerberos"}},
      {n:5,d:1,label:"DC issues service ticket (TGS)",events:[
        {id:4769,t:"Service ticket issued",f:[{k:"TargetUserName",v:"jsmith@CORP.LOCAL"},{k:"ServiceName",v:"WS-JSMITH01$"},{k:"TicketEncryptionType",v:"0x12"},{k:"IpAddress",v:"::ffff:10.1.2.50"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:6,d:0,label:"Session created — user is logged on",events:[
        {id:4624,t:"Successful logon — Type 2",logon:2,f:[{k:"TargetUserName",v:"jsmith"},{k:"TargetDomainName",v:"CORP"},{k:"LogonType",v:"2"},{k:"WorkstationName",v:"WS-JSMITH01"},{k:"IpAddress",v:"127.0.0.1"},{k:"AuthenticationPackageName",v:"Negotiate"},{k:"KeyLength",v:"0"},{k:"ElevatedToken",v:"Yes/No"}]},
        {id:4672,t:"Special privileges assigned",f:[{k:"SubjectUserName",v:"jsmith"},{k:"PrivilegeList",v:"SeDebugPrivilege, SeBackupPrivilege..."}]}
      ],arrow:null},
    ],
    notes:"Standard Kerberos flow: AS-REQ→AS-REP (TGT), then TGS-REQ→TGS-REP (service ticket). KeyLength=0 is normal for Kerberos. LogonGuid in 4624 correlates with DC's 4769. If NTLM fallback occurs, you see 4776 instead of 4768/4769.",
    mitre:"T1078 — Valid Accounts",
  },
  { id:"rdp", title:"RDP Remote Logon", desc:"Remote Desktop to a server with NLA", icon:"🌐", cat:"normal",
    devices:["Source Workstation","Target Server","Domain Controller"],
    steps:[
      {n:1,d:0,label:"User launches mstsc.exe and enters server name + credentials",events:[
        {id:4648,t:"Explicit credentials used",f:[{k:"SubjectUserName",v:"jsmith"},{k:"TargetUserName",v:"admin-jsmith"},{k:"TargetServerName",v:"SRV-APP01"},{k:"ProcessName",v:"C:\\Windows\\System32\\mstsc.exe"}]}
      ],arrow:{to:2,proto:"kerberos"}},
      {n:2,d:2,label:"NLA validates credentials before session — DC issues TGT + service ticket for TERMSRV SPN",events:[
        {id:4768,t:"TGT requested",f:[{k:"TargetUserName",v:"admin-jsmith"},{k:"IpAddress",v:"::ffff:10.1.2.50"}]},
        {id:4769,t:"Service ticket for TERMSRV/SRV-APP01",f:[{k:"ServiceName",v:"TERMSRV/SRV-APP01"},{k:"TicketEncryptionType",v:"0x12"}]}
      ],arrow:{to:1,proto:"rdp"}},
      {n:3,d:1,label:"RDP session established on target server",events:[
        {id:4624,t:"Successful logon — Type 10 (RemoteInteractive)",logon:10,f:[{k:"TargetUserName",v:"admin-jsmith"},{k:"IpAddress",v:"10.1.2.50 (source IP)"},{k:"LogonProcessName",v:"User32"},{k:"RestrictedAdminMode",v:"Yes/No"}]},
        {id:21,t:"RDP Session Logon (TerminalServices log)",f:[{k:"User",v:"CORP\\admin-jsmith"},{k:"Source Network Address",v:"10.1.2.50"}]}
      ],arrow:null},
    ],
    notes:"NLA validates BEFORE the session starts — more secure. IpAddress in 4624 reveals the source. Event 25 (reconnection) can indicate lateral movement. RestrictedAdminMode=Yes limits credential exposure on target.",
    mitre:"T1021.001 — Remote Desktop Protocol",
  },
  { id:"smb", title:"Network / SMB Share", desc:"Accessing a file share or mapped drive", icon:"📁", cat:"normal",
    devices:["Source Workstation","File Server","Domain Controller"],
    steps:[
      {n:1,d:0,label:"User opens \\\\FS01\\Documents or maps a drive",events:[],why:"Explorer.exe initiates the connection. No security event yet — the Kerberos ticket request to DC is logged in step 2. Sysmon Event 3 (network connect) could capture this.",arrow:{to:2,proto:"kerberos"}},
      {n:2,d:2,label:"DC issues service ticket for CIFS SPN (if not cached)",events:[
        {id:4769,t:"Service ticket for CIFS/FS01",f:[{k:"ServiceName",v:"CIFS/FS01.corp.local"},{k:"TargetUserName",v:"jsmith@CORP.LOCAL"},{k:"TicketEncryptionType",v:"0x12"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:3,d:0,label:"Workstation connects to file server with service ticket",events:[],why:"Workstation presents the Kerberos ticket over SMB. No event on the workstation itself — the file server logs the inbound connection in step 4.",arrow:{to:1,proto:"smb"}},
      {n:4,d:1,label:"File server validates ticket, grants access",events:[
        {id:4624,t:"Successful logon — Type 3 (Network)",logon:3,f:[{k:"TargetUserName",v:"jsmith"},{k:"IpAddress",v:"10.1.2.50"},{k:"AuthenticationPackageName",v:"Kerberos"},{k:"KeyLength",v:"0"}]},
        {id:5140,t:"Share object accessed",f:[{k:"ShareName",v:"\\\\FS01\\Documents"},{k:"ShareLocalPath",v:"C:\\Shared\\Documents"},{k:"AccessMask",v:"0x1 (ReadData)"}]},
        {id:5145,t:"File-level audit",f:[{k:"RelativeTargetName",v:"Financials\\Q3-Report.xlsx"},{k:"AccessMask",v:"0x12019F"},{k:"AccessList",v:"%%4416 ReadData, %%4417 WriteData"}]}
      ],arrow:null},
    ],
    notes:"Type 3 logons are extremely common. Credentials are NOT cached on the target — safe from credential theft. KeyLength=0 is normal for Kerberos. No TGT request if one is already cached from a prior logon. 5145 gives file-level audit trail.",
    mitre:"T1078 — Valid Accounts",
  },
  { id:"ntlm", title:"NTLM Fallback", desc:"When Kerberos fails and authentication falls back to NTLM — and why it matters", icon:"🔐", cat:"normal",
    devices:["Source Workstation","Target Server","Domain Controller"],
    steps:[
      {n:1,d:0,label:"User accesses a server by IP address (e.g. \\\\10.1.3.20\\Share) — Kerberos requires a hostname, so NTLM is used instead",events:[],why:"Kerberos needs a Service Principal Name (SPN) which is hostname-based. When you use an IP address, the client cannot construct an SPN, so it falls back to NTLM automatically. This is the #1 reason NTLM appears in modern environments. Other triggers: cross-forest trust, legacy app, DC unreachable.",arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"Target server receives NTLM Type 1 (Negotiate) → sends Type 2 (Challenge) → receives Type 3 (Response)",events:[
        {id:4624,t:"Successful logon — Type 3 (Network) with NTLM",logon:3,f:[{k:"TargetUserName",v:"jsmith"},{k:"TargetDomainName",v:"CORP"},{k:"LogonType",v:"3"},{k:"WorkstationName",v:"WS-JSMITH01 (source hostname)"},{k:"IpAddress",v:"10.1.2.50 (source IP)"},{k:"LogonProcessName",v:"NtLmSsp"},{k:"AuthenticationPackageName",v:"NTLM"},{k:"LmPackageName",v:"NTLM V2 (should always be V2, never V1)"},{k:"KeyLength",v:"128 ← CRITICAL: normal NTLM = 128. PtH = 0"},{k:"ImpersonationLevel",v:"Impersonation"}]}
      ],arrow:{to:2,proto:"ntlm"}},
      {n:3,d:2,label:"DC validates the NTLM response (pass-through authentication via Netlogon secure channel)",events:[
        {id:4776,t:"NTLM credential validation",f:[{k:"TargetUserName",v:"jsmith"},{k:"Workstation",v:"WS-JSMITH01"},{k:"Status",v:"0x0 (Success)"},{k:"PackageName",v:"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"},{k:"🔍 Key Baseline",v:"Normal 4776: TargetUserName matches an expected user, Workstation matches their known machine"}]}
      ],arrow:{to:1,proto:"ntlm"}},
      {n:4,d:1,label:"Access granted — user can access the share or service",events:[
        {id:5140,t:"Network share accessed (if file share)",f:[{k:"SubjectUserName",v:"jsmith"},{k:"ShareName",v:"\\\\SRV-FS01\\Share"},{k:"IpAddress",v:"10.1.2.50"}]}
      ],arrow:null},
    ],
    notes:"Understanding normal NTLM is CRITICAL for detecting PtH and relay attacks. The key forensic differences: Normal NTLM has KeyLength=128 (session key present) — PtH typically has KeyLength=0. Normal NTLM has LmPackageName=NTLM V2 — never V1 in modern environments (V1 = misconfiguration or attack). Normal 4776: TargetUserName + Workstation are consistent and expected. In PtH: Workstation may not match the account's normal machine. NTLM triggers: IP-based access, cross-forest, legacy apps, WPAD, fallback when DC unreachable. ALWAYS investigate why NTLM is being used — every NTLM auth is a potential attack surface.",
    mitre:"T1078 — Valid Accounts",
  },
  { id:"ntlmlocal", title:"NTLM Local Account Auth", desc:"Authenticating with a local (non-domain) account over the network", icon:"🏠", cat:"normal",
    devices:["Source Machine","Target Server"],
    steps:[
      {n:1,d:0,label:"User or script connects to a server using a local account (e.g. .\\Administrator or TARGETHOST\\admin)",events:[
        {id:4648,t:"Explicit credentials used (if different from logged-on user)",f:[{k:"SubjectUserName",v:"current-user"},{k:"TargetUserName",v:"Administrator"},{k:"TargetServerName",v:"SRV-DB01"},{k:"ProcessName",v:"net.exe or powershell.exe"}]}
      ],arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"Target validates credentials against its LOCAL SAM database — no DC involved",events:[
        {id:4624,t:"Successful logon — Type 3 with local account",logon:3,f:[{k:"TargetUserName",v:"Administrator"},{k:"TargetDomainName",v:"SRV-DB01 (machine name, NOT domain)"},{k:"LogonProcessName",v:"NtLmSsp"},{k:"AuthenticationPackageName",v:"NTLM"},{k:"KeyLength",v:"128"},{k:"IpAddress",v:"10.1.2.99"},{k:"🔍 Key Indicator",v:"TargetDomainName = machine name (not domain) = local account auth"}]},
        {id:4776,t:"Local NTLM validation (on TARGET, not DC)",f:[{k:"TargetUserName",v:"Administrator"},{k:"Workstation",v:"WS-SOURCE"},{k:"🔍 Key Difference",v:"This 4776 is logged on the TARGET server, NOT the DC — because it's a local account"}]}
      ],arrow:null},
      {n:3,d:1,label:"No DC involvement at all — DC has zero events for this authentication",events:[],why:"Local accounts are validated against the target's local SAM database. The DC is never contacted. This is important because: (1) DC-only monitoring misses local account abuse entirely. (2) Attackers who dump local admin hashes (via LSASS, SAM) can use PtH with local accounts across multiple machines if the same local admin password is reused (common with no LAPS).",arrow:null},
    ],
    notes:"Local account auth bypasses the DC entirely — if you only monitor DC logs, you're blind to this. TargetDomainName = machine name (not domain name) is the indicator of local account use. Common in: RDP with local admin, PsExec with local creds, LAPS-managed accounts. With no LAPS: same local admin password across machines = lateral movement goldmine. UAC RemoteAccountTokenFilterPolicy may restrict remote local admin access (enabled by default post-Vista except for built-in RID 500 Administrator). 4776 appears on the TARGET server, not the DC.",
    mitre:"T1078.003 — Local Accounts",
  },
  // ───── ATTACKS ─────
  { id:"kerberoast", title:"Kerberoasting", desc:"Requesting RC4 service tickets to crack passwords offline", icon:"🔓", cat:"attack",
    devices:["Attacker Workstation","Domain Controller"],
    normal:{
      label:"Legitimate TGS Request",
      steps:[
        {n:1,d:0,label:"User accesses a service (e.g. SQL server) during normal work"},
        {n:2,d:1,label:"DC issues ONE service ticket with AES-256 encryption (0x12)"},
        {n:3,d:0,label:"User presents ticket to service — access granted"},
      ],
      key:"Single ticket, AES encryption, machine SPN (ending in $), during work hours"
    },
    steps:[
      {n:1,d:0,label:"Attacker runs Rubeus/Impacket to enumerate all user SPNs via LDAP",events:[
        {id:4104,t:"PowerShell Script Block (if PS-based)",f:[{k:"ScriptBlockText",v:"Contains 'Invoke-Kerberoast' or 'Get-DomainSPNTicket'"}]}
      ],arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"DC receives burst of TGS requests for USER account SPNs — all with RC4 encryption",events:[
        {id:4769,t:"Service ticket #1 — RC4 encrypted",f:[{k:"TargetUserName",v:"compromised-user@CORP.LOCAL"},{k:"ServiceName",v:"MSSQLSvc/sql01 (USER SPN, no $)"},{k:"TicketEncryptionType",v:"0x17 (RC4) ← KEY INDICATOR"},{k:"IpAddress",v:"::ffff:10.1.2.99"}]},
        {id:4769,t:"Service ticket #2, #3, #4... in rapid succession",f:[{k:"ServiceName",v:"HTTP/web01 → SAPSvc/sap01 → ..."},{k:"TicketEncryptionType",v:"0x17 (all RC4)"},{k:"🔍 Detection",v:">5 distinct user SPNs from 1 account in 5 min + RC4"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:3,d:0,label:"Attacker takes tickets offline — cracks with Hashcat/John. NO further network activity",events:[],why:"CRITICAL BLIND SPOT: Offline cracking generates ZERO network or Windows events. This is why detection MUST happen at step 2 — once tickets leave the network, you've lost visibility.",arrow:null},
      {n:4,d:0,label:"If cracked: attacker now has service account plaintext password",events:[],why:"No event for a cracked password. Next visible activity: attacker authenticates AS the service account (4624 Type 3/10 from unexpected source IP).",arrow:null},
    ],
    notes:"Detection: 4769 WHERE ServiceName is a user SPN (no $) AND EncryptionType=0x17 (RC4). Volume: >5 unique SPNs from one user in minutes. The offline cracking phase is INVISIBLE — detection must happen at step 2. Tools: Rubeus, Impacket GetUserSPNs, PowerSploit.",
    mitre:"T1558.003 — Kerberoasting",
  },
  { id:"asrep", title:"AS-REP Roasting", desc:"Attacking accounts with pre-authentication disabled", icon:"🔓", cat:"attack",
    devices:["Attacker Machine","Domain Controller"],
    normal:{
      label:"Legitimate TGT Request",
      steps:[
        {n:1,d:0,label:"User logs in, workstation sends AS-REQ with encrypted timestamp (preauth)"},
        {n:2,d:1,label:"DC verifies timestamp, issues TGT — PreAuthType=15"},
        {n:3,d:0,label:"User proceeds to request service tickets and log on"},
      ],
      key:"PreAuthType=15 (enabled), AES encryption, followed by TGS + logon events"
    },
    steps:[
      {n:1,d:0,label:"Attacker enumerates accounts with 'Do not require Kerberos pre-authentication' flag",events:[],why:"LDAP queries for userAccountControl with DONT_REQ_PREAUTH flag. Detectable via LDAP monitoring (Event 1644 with expensive search logging enabled) or EDR watching for GetNPUsers.py/Rubeus.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"DC returns TGT WITHOUT verifying identity — encrypted with user's password hash",events:[
        {id:4768,t:"TGT issued WITHOUT pre-authentication",f:[{k:"TargetUserName",v:"svc-legacy"},{k:"ServiceName",v:"krbtgt"},{k:"TicketEncryptionType",v:"0x17 (RC4) ← crackable"},{k:"PreAuthType",v:"0 ← SMOKING GUN"},{k:"IpAddress",v:"::ffff:10.1.2.99"},{k:"Status",v:"0x0"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:3,d:0,label:"Workflow STOPS — no TGS (4769) or logon (4624) follows. Attacker cracks hash offline",events:[],why:"CRITICAL: The workflow stops here. Normal auth continues with TGS+logon. The ABSENCE of 4769/4624 after a 4768 with PreAuthType=0 is itself an indicator — the attacker only wanted the hash, not access.",arrow:null},
    ],
    notes:"Detection: 4768 WHERE PreAuthType=0 AND EncryptionType=0x17. The workflow STOPS after TGT — absence of subsequent 4769/4624 is suspicious. Multiple PreAuthType=0 from same IP in seconds = enumeration. Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}.",
    mitre:"T1558.004 — AS-REP Roasting",
  },
  { id:"golden", title:"Golden Ticket", desc:"Forged TGT using stolen KRBTGT hash — domain-wide access", icon:"🎫", cat:"attack",
    devices:["Attacker Machine","Domain Controller","Target Server"],
    normal:{
      label:"Legitimate Kerberos Flow",
      steps:[
        {n:1,d:0,label:"User authenticates → DC logs 4768 (TGT issued)"},
        {n:2,d:1,label:"User requests service → DC logs 4769 (TGS issued)"},
        {n:3,d:2,label:"Server logs 4624 with correct NetBIOS domain name"},
      ],
      key:"4768 always precedes 4769. Domain field = short NetBIOS name (e.g. 'CORP')"
    },
    steps:[
      {n:1,d:0,label:"Attacker already has KRBTGT hash (from DCSync). Forges TGT with Mimikatz — skips DC entirely",events:[],why:"TGT is forged locally in memory. No network traffic, no DC involvement, no Windows event. The forged TGT is cryptographically valid because it uses the real KRBTGT hash.",arrow:null},
      {n:2,d:0,label:"Attacker presents forged TGT directly to DC for service ticket",events:[],why:"The TGS-REQ is a network packet. The DC will process it and log the response (4769) in step 3. The critical point: there was NEVER a 4768 (TGT issuance) for this user.",arrow:{to:1,proto:"kerberos"}},
      {n:3,d:1,label:"DC accepts forged TGT (valid KRBTGT signature) — issues TGS. BUT no 4768 was ever logged",events:[
        {id:4769,t:"TGS issued — but NO preceding 4768 exists",f:[{k:"TargetUserName",v:"fakeadmin@CORP.LOCAL"},{k:"ServiceName",v:"cifs/SRV-DB01"},{k:"TicketEncryptionType",v:"0x17 (if old KRBTGT hash)"},{k:"🔍 Detection",v:"4769 WITHOUT any 4768 from this IP = Golden Ticket"}]}
      ],arrow:{to:2,proto:"kerberos"}},
      {n:4,d:2,label:"Target server accepts ticket — domain field may show anomaly",events:[
        {id:4624,t:"Logon — domain field anomaly",logon:3,f:[{k:"TargetUserName",v:"fakeadmin"},{k:"TargetDomainName",v:"CORP.LOCAL (FQDN — should be CORP)"},{k:"🔍 Detection",v:"FQDN instead of NetBIOS = forged ticket"}]},
        {id:4672,t:"Admin privileges for non-admin user",f:[{k:"SubjectUserName",v:"fakeadmin"},{k:"🔍 Detection",v:"4672 for unknown/non-admin user = forged PAC"}]}
      ],arrow:null},
    ],
    notes:"Key detections: (1) 4769 without preceding 4768 — ticket appeared from nowhere. (2) Domain=FQDN instead of NetBIOS in 4624/4672. (3) TGT lifetime >10hrs (default). (4) 4672 for non-privileged users. Remediation: reset KRBTGT password TWICE (wait for replication between resets).",
    mitre:"T1558.001 — Golden Ticket",
  },
  { id:"silver", title:"Silver Ticket", desc:"Forged TGS — DC is blind, only target sees it", icon:"🎟️", cat:"attack",
    devices:["Attacker Machine","Target Server","Domain Controller"],
    normal:{
      label:"Legitimate Service Access",
      steps:[
        {n:1,d:0,label:"User requests TGS from DC → DC logs 4769"},
        {n:2,d:1,label:"Server logs 4624 — both events exist and correlate"},
      ],
      key:"DC has 4769 record for every 4624 on the server. Events correlate."
    },
    steps:[
      {n:1,d:0,label:"Attacker has service account NTLM hash. Forges TGS for that specific service — never contacts DC",events:[],why:"TGS is forged entirely offline using the service account hash. No network traffic to the DC at all. This is what makes Silver Tickets so stealthy — the DC never participates.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"Target server accepts forged ticket — logs a logon",events:[
        {id:4624,t:"Logon succeeds — but DC has NO record",logon:3,f:[{k:"TargetUserName",v:"fakeuser"},{k:"TargetDomainName",v:"blank or FQDN (anomaly)"},{k:"AuthenticationPackageName",v:"Kerberos"},{k:"🔍 Detection",v:"4624 on server with NO matching 4769 on DC"}]}
      ],arrow:null},
      {n:3,d:2,label:"DC is COMPLETELY BLIND — zero events logged for this access",events:[
        {id:"NONE",t:"No events — DC never participated in this authentication",f:[{k:"🔍 Key Insight",v:"Detection requires CROSS-DEVICE correlation"},{k:"Method",v:"Compare target 4624 Kerberos logons vs DC 4769 — any gaps = Silver Ticket"}]}
      ],arrow:null},
    ],
    notes:"Silver Ticket bypasses the DC entirely. Detection relies on NEGATIVE correlation: 4624 (Kerberos) on target WITHOUT matching 4769 on DC. Domain field anomalies (blank or FQDN) may also appear. Scope is limited to one service (unlike Golden Ticket). Requires service account hash.",
    mitre:"T1558.002 — Silver Ticket",
  },
  { id:"pth", title:"Pass-the-Hash / Ticket", desc:"Using stolen NTLM hash or Kerberos ticket to authenticate", icon:"🚨", cat:"attack",
    devices:["Attacker Machine","Target Server","Domain Controller"],
    normal:{
      label:"Legitimate NTLM Authentication",
      steps:[
        {n:1,d:0,label:"User authenticates with password → NTLM challenge/response"},
        {n:2,d:2,label:"DC validates → 4776 with matching workstation + KeyLength=128"},
        {n:3,d:1,label:"Server logs 4624 Type 3 with KeyLength=128"},
      ],
      key:"KeyLength=128 (NTLM session key present), workstation matches expected user, 4768 precedes any Kerberos"
    },
    steps:[
      {n:1,d:0,label:"Attacker uses Mimikatz sekurlsa::pth with stolen NTLM hash — no password needed",events:[
        {id:4624,t:"NewCredentials logon (local)",logon:9,f:[{k:"TargetUserName",v:"stolen-admin"},{k:"LogonProcessName",v:"seclogo"},{k:"KeyLength",v:"0"}]}
      ],arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"Target accepts NTLM auth — account doesn't match source user",events:[
        {id:4624,t:"Network logon — KeyLength=0 is the smoking gun",logon:3,f:[{k:"TargetUserName",v:"stolen-admin"},{k:"IpAddress",v:"10.1.2.99 (attacker)"},{k:"LogonProcessName",v:"NtLmSsp"},{k:"AuthenticationPackageName",v:"NTLM"},{k:"KeyLength",v:"0 ← CRITICAL (normal=128)"},{k:"WorkstationName",v:"ATKR-PC"}]}
      ],arrow:{to:2,proto:"ntlm"}},
      {n:3,d:2,label:"DC validates NTLM — but no Kerberos TGT was ever requested",events:[
        {id:4776,t:"NTLM validation — no preceding 4768",f:[{k:"TargetUserName",v:"stolen-admin"},{k:"Workstation",v:"ATKR-PC"},{k:"Status",v:"0x0"},{k:"🔍 Detection",v:"4776 WITHOUT 4768 from this host = PtH"}]}
      ],arrow:null},
    ],
    notes:"PtH: KeyLength=0 with NTLM is the smoking gun (normal NTLM=128). PtT: 4769 without preceding 4768. User/workstation mismatches between source and expected user. Mimikatz tools often leave NtLmSsp as LogonProcess.",
    mitre:"T1550.002 — Pass the Hash",
  },
  { id:"psexec", title:"PsExec Lateral Movement", desc:"Remote command execution via SMB + service creation", icon:"⚠️", cat:"attack",
    devices:["Source Machine","Target Server","Domain Controller"],
    normal:{
      label:"Legitimate Admin Remote Management",
      steps:[
        {n:1,d:0,label:"Admin uses approved RMM tool with proper account"},
        {n:2,d:1,label:"Server logs 4624 Type 3 from known admin workstation"},
        {n:3,d:1,label:"No ADMIN$ access, no service creation"},
      ],
      key:"Known admin workstation, approved tools, no ADMIN$ share access, no new service installation"
    },
    steps:[
      {n:1,d:0,label:"Attacker runs PsExec with stolen admin credentials",events:[
        {id:4648,t:"Explicit credentials for remote connection",f:[{k:"SubjectUserName",v:"compromised-user"},{k:"TargetUserName",v:"admin-account"},{k:"TargetServerName",v:"SRV-DB01"},{k:"ProcessName",v:"C:\\Tools\\PsExec.exe"}]}
      ],arrow:{to:1,proto:"smb"}},
      {n:2,d:1,label:"PsExec connects to ADMIN$ share via SMB",events:[
        {id:4624,t:"Network logon",logon:3,f:[{k:"TargetUserName",v:"admin-account"},{k:"IpAddress",v:"10.1.2.99"},{k:"AuthenticationPackageName",v:"NTLM"}]},
        {id:5140,t:"ADMIN$ share accessed",f:[{k:"ShareName",v:"\\\\*\\ADMIN$"},{k:"ShareLocalPath",v:"C:\\Windows"},{k:"🔍 Detection",v:"ADMIN$ access from non-DC = suspicious"}]}
      ],arrow:null},
      {n:3,d:1,label:"PsExec uploads and installs PSEXESVC service on target",events:[
        {id:7045,t:"PSEXESVC service installed (System log)",f:[{k:"ServiceName",v:"PSEXESVC"},{k:"ImagePath",v:"%SystemRoot%\\PSEXESVC.exe"},{k:"StartType",v:"demand start"},{k:"🔍 Detection",v:"PSEXESVC service name is a dead giveaway"}]},
        {id:4672,t:"Admin privileges assigned",f:[{k:"SubjectUserName",v:"admin-account"}]}
      ],arrow:null},
    ],
    notes:"Kill chain: SMB connect → ADMIN$ access → service install → command exec. Event 7045 (PSEXESVC) is the signature. ADMIN$ access (5140) from non-DC sources is always suspicious. Combine with 4648 ProcessName to identify the tool used. Renamed PsExec will have different service names.",
    mitre:"T1021.002 + T1569.002 — SMB Admin Shares + Service Execution",
  },
  { id:"dcsync", title:"DCSync", desc:"Simulating DC replication to extract all password hashes", icon:"🏛️", cat:"attack",
    devices:["Attacker Machine","Domain Controller"],
    normal:{
      label:"Legitimate DC Replication",
      steps:[
        {n:1,d:0,label:"DC02$ (machine account) requests replication from DC01"},
        {n:2,d:1,label:"DC01 logs 4662 with SubjectUserName = DC02$ (machine account ending in $)"},
      ],
      key:"Replication ONLY from DC machine accounts (ending in $). Never from user accounts."
    },
    steps:[
      {n:1,d:0,label:"Attacker runs mimikatz lsadump::dcsync with compromised admin account",events:[],why:"Mimikatz execution may be caught by EDR/Sysmon (Event 1 — process creation) but generates no Windows Security event itself. The DC logs the replication request in step 2.",arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"DC processes replication request — but from a USER account, not a DC",events:[
        {id:4624,t:"Network logon from attacker",logon:3,f:[{k:"TargetUserName",v:"compromised-admin"},{k:"IpAddress",v:"10.1.2.99"}]},
        {id:4662,t:"Directory service access — replication GUIDs used",f:[{k:"SubjectUserName",v:"compromised-admin (NOT DC$!)"},{k:"ObjectType",v:"domainDNS"},{k:"AccessMask",v:"0x100 (Control Access)"},{k:"Properties",v:"{1131f6aa-...} DS-Replication-Get-Changes"},{k:"Properties",v:"{1131f6ad-...} DS-Replication-Get-Changes-All"},{k:"🔍 Detection",v:"User account (no $) + replication GUIDs = DCSync ATTACK"}]}
      ],arrow:{to:0,proto:"ntlm"}},
      {n:3,d:0,label:"Attacker receives all domain password hashes — game over",events:[],why:"Hash extraction completes over the DRS protocol. No distinct event for 'hashes received' — detection must happen at step 2 (4662). Once hashes are exfiltrated, assume full domain compromise.",arrow:null},
    ],
    notes:"DEFINITIVE detection: 4662 with replication GUIDs (1131f6aa-*, 1131f6ad-*) WHERE SubjectUserName does NOT end in $. Legitimate replication ONLY comes from DC machine accounts. If a user account triggers this = confirmed attack. Often precedes Golden Ticket creation.",
    mitre:"T1003.006 — DCSync",
  },
  { id:"adcs", title:"ADCS ESC1 / ESC8", desc:"Abusing certificate services for privilege escalation", icon:"📜", cat:"attack",
    devices:["Attacker Machine","Certificate Authority","Domain Controller"],
    normal:{
      label:"Legitimate Certificate Request",
      steps:[
        {n:1,d:0,label:"User requests certificate for themselves"},
        {n:2,d:1,label:"CA logs 4886/4887 — Requester = Certificate Subject (same person)"},
        {n:3,d:0,label:"User uses certificate for intended purpose (VPN, email signing)"},
      ],
      key:"Requester MATCHES the certificate subject (SAN). No impersonation."
    },
    steps:[
      {n:1,d:0,label:"Attacker finds vulnerable template (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT). Requests cert with SAN=administrator",events:[],why:"Template enumeration via LDAP (Certify/Certipy). Detectable via Sysmon or EDR. The certificate request itself is logged on the CA in step 2.",arrow:{to:1,proto:"smb"}},
      {n:2,d:1,label:"CA processes request — Requester ≠ SAN is the key indicator",events:[
        {id:4886,t:"Certificate request received",f:[{k:"Requester",v:"CORP\\lowpriv-user"},{k:"Attributes",v:"CertificateTemplate:VulnTemplate"},{k:"Attributes",v:"SAN:upn=administrator@corp.local"},{k:"🔍 Detection",v:"Requester (lowpriv) ≠ SAN (administrator) = ESC1"}]},
        {id:4887,t:"Certificate approved and issued",f:[{k:"Requester",v:"CORP\\lowpriv-user"},{k:"Attributes",v:"SAN:upn=administrator@corp.local"}]}
      ],arrow:{to:0,proto:"smb"}},
      {n:3,d:0,label:"Attacker uses certificate to request TGT as administrator (PKINIT)",events:[],why:"The certificate is presented to the DC via PKINIT. No event on the attacker machine — the DC logs the certificate-based TGT in step 4 (4768 with PreAuthType=16).",arrow:{to:2,proto:"kerberos"}},
      {n:4,d:2,label:"DC issues TGT for administrator based on certificate",events:[
        {id:4768,t:"TGT via certificate auth",f:[{k:"TargetUserName",v:"administrator"},{k:"PreAuthType",v:"16 (certificate/PKINIT)"},{k:"CertIssuerName",v:"CORP-CA"},{k:"🔍 Detection",v:"Certificate-based TGT for unexpected account"}]}
      ],arrow:null},
    ],
    notes:"ESC1: Vulnerable template allows enrollee to set SAN. Detection = 4886/4887 WHERE Requester ≠ SAN UPN. ESC8: NTLM relay to HTTP enrollment. CA auditing is DISABLED by default — enable via certsrv → Properties → Auditing. Event 4900 = template permissions changed.",
    mitre:"T1649 — Steal or Forge Authentication Certificates",
  },
  { id:"ntlmrelay", title:"NTLM Relay", desc:"Relaying captured NTLM auth to a different target", icon:"🔀", cat:"attack",
    devices:["Victim Machine","Attacker (Relay)","Target Server","Domain Controller"],
    normal:{
      label:"Legitimate NTLM Authentication",
      steps:[
        {n:1,d:0,label:"Client authenticates directly to intended server"},
        {n:2,d:2,label:"Server sees client's real IP as source"},
        {n:3,d:3,label:"DC validates — Workstation field matches client"},
      ],
      key:"Source IP in 4624 matches the machine that initiated auth. No middleman."
    },
    steps:[
      {n:1,d:1,label:"Attacker poisons LLMNR/NBT-NS or uses PetitPotam/PrinterBug to coerce victim auth",events:[],why:"Poisoning tools (Responder, PetitPotam) don't generate Security events on the attacker. Detectable via network monitoring for LLMNR/NBT-NS traffic, or Sysmon Event 3 for unusual connections to port 445.",arrow:null},
      {n:2,d:0,label:"Victim sends NTLM auth to attacker (thinking it's a legitimate resource)",events:[],why:"The victim machine initiates a normal NTLM handshake — it doesn't know the target is an attacker. May generate a 4648 if explicit creds used, but typically invisible in Security logs.",arrow:{to:1,proto:"ntlm"}},
      {n:3,d:1,label:"Attacker relays victim's credentials to target server (SMB, LDAP, or ADCS HTTP)",events:[],why:"The relay itself generates no event on the attacker. The TARGET server sees the auth (step 4) but the source IP is the attacker, not the victim — this mismatch is the key detection.",arrow:{to:2,proto:"ntlm"}},
      {n:4,d:2,label:"Target sees auth from ATTACKER'S IP but VICTIM'S credentials",events:[
        {id:4624,t:"Logon — source IP is ATTACKER, not victim",logon:3,f:[{k:"TargetUserName",v:"VICTIM-PC$ or victim-user"},{k:"IpAddress",v:"10.1.2.99 (ATTACKER IP — not victim!)"},{k:"WorkstationName",v:"ATKR-PC"},{k:"AuthenticationPackageName",v:"NTLM"},{k:"🔍 Detection",v:"Machine account logon from wrong IP = relay"}]}
      ],arrow:{to:3,proto:"ntlm"}},
      {n:5,d:3,label:"DC validates NTLM — workstation field may show relay indicators",events:[
        {id:4776,t:"NTLM validation",f:[{k:"TargetUserName",v:"VICTIM-PC$"},{k:"Workstation",v:"ATKR-PC (mismatch!)"},{k:"🔍 Detection",v:"TargetUserName vs Workstation mismatch = relay"}]}
      ],arrow:null},
    ],
    notes:"Key detection: 4624 where IpAddress doesn't match the expected source for that account. Machine account ($) logons from unexpected IPs. 4776 where TargetUserName and Workstation don't match. Often combined with ADCS ESC8 (relay to HTTP enrollment). Mitigation: EPA, SMB signing, disable NTLM.",
    mitre:"T1557.001 — LLMNR/NBT-NS Poisoning + T1187 — Forced Authentication",
  },
  { id:"delegation", title:"Unconstrained Delegation", desc:"Stealing TGTs from users who connect to a trusted-for-delegation server", icon:"🔗", cat:"attack",
    devices:["Victim User","Delegation Server","Attacker on Server","Domain Controller"],
    normal:{
      label:"Legitimate Delegation",
      steps:[
        {n:1,d:0,label:"User connects to app server trusted for delegation"},
        {n:2,d:1,label:"Server uses user's delegated ticket to access backend DB on behalf of user"},
        {n:3,d:3,label:"DC issues service ticket for backend — this is the intended use"},
      ],
      key:"Server accesses only the intended backend service. TGT is used and discarded."
    },
    steps:[
      {n:1,d:0,label:"Victim (Domain Admin) connects to server that has unconstrained delegation enabled",events:[],why:"This is a normal user action (e.g. browsing a file share). No suspicious event — the danger is that the delegation server is configured to STORE the user's TGT in LSASS.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"Server receives AND STORES victim's TGT in LSASS memory (this is the vulnerability)",events:[
        {id:4624,t:"Logon — TGT stored in memory",logon:3,f:[{k:"TargetUserName",v:"domain-admin"},{k:"IpAddress",v:"10.1.2.10 (victim)"},{k:"AuthenticationPackageName",v:"Kerberos"}]},
        {id:4672,t:"Admin privileges assigned — high-value target",f:[{k:"SubjectUserName",v:"domain-admin"},{k:"PrivilegeList",v:"SeDebugPrivilege..."}]}
      ],arrow:null},
      {n:3,d:2,label:"Attacker (who compromised the server) extracts victim's TGT from LSASS with Rubeus/Mimikatz",events:[],why:"LSASS memory access may be detected by EDR or Sysmon (Event 10 — process access to lsass.exe). No Security event log entry for reading tickets from memory. This is a local operation on the compromised server.",arrow:{to:3,proto:"kerberos"}},
      {n:4,d:3,label:"Attacker uses stolen TGT to request service tickets for ANY resource as Domain Admin",events:[
        {id:4769,t:"TGS requests from delegation server — for unexpected services",f:[{k:"TargetUserName",v:"domain-admin@CORP.LOCAL"},{k:"ServiceName",v:"cifs/DC01, ldap/DC01 (accessing DC!)"},{k:"IpAddress",v:"::ffff:10.1.3.50 (delegation server IP)"},{k:"🔍 Detection",v:"Delegation server requesting tickets for DC services = abuse"}]}
      ],arrow:null},
    ],
    notes:"Detection: Service ticket requests (4769) originating FROM a delegation server FOR services it shouldn't access (especially DC services). 4672 for high-privilege accounts on delegation servers is a risk indicator. Mitigation: use constrained delegation, Protected Users group, disable unconstrained delegation. Audit: Get-ADComputer -Filter {TrustedForDelegation -eq $True}.",
    mitre:"T1558 — Steal or Forge Kerberos Tickets",
  },
  { id:"shadow", title:"Shadow Credentials", desc:"Writing to msDS-KeyCredentialLink for certificate-based auth", icon:"👤", cat:"attack",
    devices:["Attacker Machine","Domain Controller"],
    normal:{
      label:"Legitimate Key Credential",
      steps:[
        {n:1,d:1,label:"Windows Hello for Business or device enrollment writes to msDS-KeyCredentialLink"},
        {n:2,d:1,label:"5136 logged — but from an expected enrollment service account"},
      ],
      key:"Changes to msDS-KeyCredentialLink only from authorized enrollment processes"
    },
    steps:[
      {n:1,d:0,label:"Attacker with GenericWrite over target account uses Whisker/pyWhisker to add a shadow credential",events:[],why:"The LDAP modification is logged on the DC (step 2) as Event 5136. The attacker's tool execution may be caught by EDR/Sysmon but not the Security log.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"msDS-KeyCredentialLink attribute modified on target account",events:[
        {id:5136,t:"Directory Service object modified",f:[{k:"SubjectUserName",v:"compromised-user (not enrollment svc!)"},{k:"ObjectDN",v:"CN=admin-target,OU=Users,DC=corp,DC=local"},{k:"AttributeLDAPDisplayName",v:"msDS-KeyCredentialLink"},{k:"OperationType",v:"Value Added"},{k:"🔍 Detection",v:"Non-enrollment account modifying KeyCredentialLink = Shadow Creds"}]}
      ],arrow:null},
      {n:3,d:0,label:"Attacker uses the shadow key to request a certificate, then authenticates as target via PKINIT",events:[],why:"Certificate request may generate 4886/4887 on a CA. The PKINIT authentication is logged on the DC in step 4 (4768 with PreAuthType=16). The certificate-based auth bypasses password requirements.",arrow:{to:1,proto:"kerberos"}},
      {n:4,d:1,label:"DC issues TGT for target account based on the shadow credential",events:[
        {id:4768,t:"TGT via certificate/key credential",f:[{k:"TargetUserName",v:"admin-target"},{k:"PreAuthType",v:"16 (certificate)"},{k:"IpAddress",v:"::ffff:10.1.2.99 (attacker)"},{k:"🔍 Detection",v:"Certificate-based auth from unexpected IP for this account"}]}
      ],arrow:null},
    ],
    notes:"Detection: Event 5136 WHERE AttributeLDAPDisplayName=msDS-KeyCredentialLink AND SubjectUserName is not an authorized enrollment service. Requires 'Audit Directory Service Changes' enabled. Often chained with ADCS. Similar to ESC10 exploitation path. Tools: Whisker, pyWhisker, Certipy.",
    mitre:"T1556.007 — Modify Authentication Process",
  },
  { id:"skeleton", title:"Skeleton Key", desc:"Patching DC's LSASS to accept a master password for any account", icon:"💀", cat:"attack",
    devices:["Attacker Machine","Domain Controller"],
    normal:{
      label:"Normal DC Operation",
      steps:[
        {n:1,d:1,label:"LSASS authenticates users with their real passwords only"},
        {n:2,d:1,label:"No unusual service installations or privilege use"},
      ],
      key:"LSASS is unmodified. No new services. No unusual SeTcbPrivilege usage."
    },
    steps:[
      {n:1,d:0,label:"Attacker with Domain Admin runs Mimikatz misc::skeleton on DC",events:[],why:"Mimikatz execution on DC should be caught by EDR/Sysmon (Event 1). The LSASS patch itself generates events in step 2 (7045, 4673, 4611). Remote execution may show 4624 Type 3 + 4672 on the DC.",arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"LSASS is patched in memory — now accepts master password ('mimikatz') for ANY account",events:[
        {id:7045,t:"Service installation (if deployed as service)",f:[{k:"ServiceName",v:"suspicious service name"},{k:"ImagePath",v:"path to mimikatz or loader"},{k:"AccountName",v:"LocalSystem"},{k:"🔍 Detection",v:"New service on DC = always investigate"}]},
        {id:4673,t:"Privileged service called",f:[{k:"SubjectUserName",v:"compromised-admin"},{k:"Service",v:"LsaRegisterLogonProcess()"},{k:"🔍 Detection",v:"LsaRegisterLogonProcess on DC = LSASS tampering"}]},
        {id:4611,t:"Trusted logon process registered with LSA",f:[{k:"SubjectUserName",v:"SYSTEM"},{k:"LogonProcessName",v:"suspicious process name"},{k:"🔍 Detection",v:"New trusted logon process on DC is extremely rare"}]}
      ],arrow:null},
      {n:3,d:0,label:"Attacker can now log in as ANY user with the skeleton key password",events:[],why:"Authentication using the skeleton key looks COMPLETELY NORMAL in the logs — standard 4624 events with valid user credentials. This is why detection must focus on the LSASS patch (step 2), not the logons. The skeleton key does not survive a DC reboot.",arrow:{to:1,proto:"kerberos"}},
      {n:4,d:1,label:"Authentication succeeds — but with the real user's normal events, making it very hard to detect",events:[
        {id:4624,t:"Normal-looking logon (skeleton key is invisible in auth logs)",logon:3,f:[{k:"TargetUserName",v:"any-user"},{k:"🔍 Detection",v:"Auth logs look NORMAL — detection must focus on the LSASS patch, not the logons"}]}
      ],arrow:null},
    ],
    notes:"Skeleton Key patches LSASS in memory — does NOT survive reboot. Detection focuses on the INSTALLATION, not the logons (which look normal). Key events: 7045 (new service on DC), 4673 (LsaRegisterLogonProcess), 4611 (new trusted logon process). System event log may show LSASS crash/restart. Monitor DC process creation (Sysmon Event 1) for mimikatz signatures.",
    mitre:"T1556.001 — Modify Authentication Process: Domain Controller",
  },
  { id:"rbcd", title:"RBCD Abuse", desc:"Resource-Based Constrained Delegation — S4U2Self+S4U2Proxy to impersonate any user", icon:"🔗", cat:"attack",
    devices:["Attacker Machine","Domain Controller","Target Server"],
    normal:{ label:"Legitimate Delegation", steps:[
      {n:1,d:0,label:"Service A accesses Service B on behalf of user — configured by admins"},
      {n:2,d:1,label:"DC logs standard 4769 with TransitedServices for S4U2Proxy"},
    ], key:"Delegation configured by admins on known service accounts. S4U requests from expected servers only." },
    steps:[
      {n:1,d:0,label:"Attacker creates fake computer account (MachineAccountQuota) or compromises existing one",events:[
        {id:4741,t:"Computer account created",f:[{k:"TargetUserName",v:"FAKEPC$ (attacker-created)"},{k:"SubjectUserName",v:"lowpriv-user"},{k:"🔍 Detection",v:"Non-admin creating computer accounts = suspicious"}]}
      ],arrow:{to:1,proto:"kerberos"}},
      {n:2,d:0,label:"Attacker modifies target's msDS-AllowedToActOnBehalfOfOtherIdentity to trust FAKEPC$",events:[],why:"The LDAP modification is logged on the DC in step 3. The attacker only needs GenericWrite over the target computer object.",arrow:{to:1,proto:"kerberos"}},
      {n:3,d:1,label:"DC logs directory modification — delegation attribute changed",events:[
        {id:5136,t:"Directory service object modified",f:[{k:"SubjectUserName",v:"lowpriv-user"},{k:"ObjectDN",v:"CN=SRV-DB01,OU=Servers,DC=corp,DC=local"},{k:"AttributeLDAPDisplayName",v:"msDS-AllowedToActOnBehalfOfOtherIdentity"},{k:"OperationType",v:"Value Added"},{k:"🔍 Detection",v:"Non-admin modifying delegation attribute = RBCD setup"}]}
      ],arrow:null},
      {n:4,d:0,label:"Attacker runs Rubeus S4U — requests ticket as FAKEPC$ to itself (S4U2Self), then to target (S4U2Proxy)",events:[],why:"S4U requests are Kerberos protocol extensions. Rubeus handles both in sequence. The DC logs these as paired 4769 events in step 5.",arrow:{to:1,proto:"kerberos"}},
      {n:5,d:1,label:"DC processes S4U2Self then S4U2Proxy — two 4769 events in rapid succession",events:[
        {id:4769,t:"S4U2Self — ServiceName = AccountName (same account)",f:[{k:"TargetUserName",v:"FAKEPC$@CORP.LOCAL"},{k:"ServiceName",v:"FAKEPC$ (SAME as account — S4U2Self indicator)"},{k:"TicketOptions",v:"0x40800018"},{k:"🔍 Detection",v:"ServiceName = AccountName in same 4769 = S4U2Self"}]},
        {id:4769,t:"S4U2Proxy — TransitedServices is NOT empty",f:[{k:"TargetUserName",v:"FAKEPC$@CORP.LOCAL"},{k:"ServiceName",v:"cifs/SRV-DB01.corp.local (target)"},{k:"TransitedServices",v:"administrator@CORP.LOCAL (NOT empty — S4U2Proxy)"},{k:"🔍 Detection",v:"Non-empty TransitedServices = S4U2Proxy delegation"}]}
      ],arrow:{to:2,proto:"kerberos"}},
      {n:6,d:2,label:"Attacker accesses target server as Administrator",events:[
        {id:4624,t:"Logon as impersonated user",logon:3,f:[{k:"TargetUserName",v:"administrator"},{k:"IpAddress",v:"10.1.2.99 (attacker)"},{k:"AuthenticationPackageName",v:"Kerberos"}]}
      ],arrow:null},
    ],
    notes:"Detection chain: 4741 (new computer account by non-admin) → 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity modified) → 4769 pair (S4U2Self: ServiceName=AccountName, then S4U2Proxy: TransitedServices not empty). MachineAccountQuota default is 10 — set to 0 to block. Tools: Rubeus, Impacket.",
    mitre:"T1134.001 — Access Token Manipulation + T1558 — Kerberos Tickets",
  },
  { id:"opth", title:"Overpass-the-Hash", desc:"Using NTLM hash to obtain a Kerberos TGT — bridges PtH into Kerberos", icon:"🔄", cat:"attack",
    devices:["Attacker Machine","Domain Controller","Target Server"],
    normal:{ label:"Legitimate Kerberos Auth", steps:[
      {n:1,d:0,label:"User authenticates with password → AES-encrypted AS-REQ"},
      {n:2,d:1,label:"DC issues TGT with AES encryption (0x12), PreAuthType=15"},
    ], key:"TGT uses AES-256 (0x12). PreAuthType=15 (encrypted timestamp with user's key). No RC4 in modern environments." },
    steps:[
      {n:1,d:0,label:"Attacker has NTLM hash (from LSASS dump). Uses Rubeus asktgt to request TGT using the hash",events:[],why:"Rubeus/Mimikatz sends an AS-REQ encrypted with the NTLM hash (RC4). No Windows Security event on attacker — the DC logs the request in step 2.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"DC issues TGT — but with RC4 encryption instead of AES (because hash was NTLM)",events:[
        {id:4768,t:"TGT requested — RC4 encryption is the key indicator",f:[{k:"TargetUserName",v:"stolen-admin"},{k:"ServiceName",v:"krbtgt"},{k:"TicketEncryptionType",v:"0x17 (RC4-HMAC) ← should be 0x12 (AES)"},{k:"PreAuthType",v:"15 (encrypted timestamp — looks normal)"},{k:"IpAddress",v:"::ffff:10.1.2.99 (attacker)"},{k:"🔍 Detection",v:"RC4 (0x17) TGT for account that normally uses AES = Overpass-the-Hash"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:3,d:0,label:"Attacker now has a valid Kerberos TGT — all subsequent activity is pure Kerberos, blending in",events:[],why:"From this point, the attacker uses standard Kerberos. Service tickets, logons — everything looks normal. Detection MUST happen at step 2. This is why Overpass-the-Hash is more stealthy than PtH.",arrow:{to:2,proto:"kerberos"}},
      {n:4,d:2,label:"Target server sees normal Kerberos auth — indistinguishable from legitimate",events:[
        {id:4624,t:"Normal-looking Kerberos logon",logon:3,f:[{k:"TargetUserName",v:"stolen-admin"},{k:"AuthenticationPackageName",v:"Kerberos (not NTLM!)"},{k:"KeyLength",v:"0"},{k:"🔍 Detection",v:"This logon looks completely normal — detection must focus on the 4768 RC4 TGT"}]}
      ],arrow:null},
    ],
    notes:"Key insight: Unlike PtH (which stays NTLM), Overpass-the-Hash converts the NTLM hash into a Kerberos TGT, making all subsequent activity look like normal Kerberos. Detection: 4768 WHERE TicketEncryptionType=0x17 (RC4) for accounts that normally use AES. In a hardened environment with RC4 disabled, this attack fails entirely. Tools: Rubeus asktgt, Mimikatz sekurlsa::pth.",
    mitre:"T1550.002 — Pass the Hash (Kerberos variant)",
  },
  { id:"wmi", title:"WMI / WinRM Lateral", desc:"Living-off-the-land remote execution — no dropped binaries", icon:"💨", cat:"attack",
    devices:["Source Machine","Target Server","Domain Controller"],
    normal:{ label:"Legitimate Remote Admin", steps:[
      {n:1,d:0,label:"IT admin runs WMIC or Enter-PSSession from approved jumpbox"},
      {n:2,d:1,label:"Target logs 4624 Type 3 + wmiprvse.exe spawns expected admin commands"},
    ], key:"From known admin jumpbox, approved account, during work hours. Commands match admin tasks." },
    steps:[
      {n:1,d:0,label:"Attacker runs wmic /node:TARGET process call create 'cmd.exe /c malicious.exe'",events:[
        {id:4648,t:"Explicit credentials used",f:[{k:"SubjectUserName",v:"compromised-user"},{k:"TargetUserName",v:"admin-account"},{k:"TargetServerName",v:"SRV-DB01"},{k:"ProcessName",v:"C:\\Windows\\System32\\wbem\\WMIC.exe"}]},
        {id:4688,t:"Process creation — wmic.exe on source",f:[{k:"NewProcessName",v:"C:\\Windows\\System32\\wbem\\WMIC.exe"},{k:"CommandLine",v:"wmic /node:SRV-DB01 process call create..."},{k:"ParentProcessName",v:"cmd.exe"},{k:"🔍 Detection",v:"/node: parameter in wmic = remote execution"}]}
      ],arrow:{to:1,proto:"smb"}},
      {n:2,d:1,label:"Target creates wmiprvse.exe which spawns child process — this is the execution",events:[
        {id:4624,t:"Network logon from source",logon:3,f:[{k:"TargetUserName",v:"admin-account"},{k:"IpAddress",v:"10.1.2.99 (source)"},{k:"AuthenticationPackageName",v:"Kerberos or NTLM"}]},
        {id:4672,t:"Admin privileges assigned",f:[{k:"SubjectUserName",v:"admin-account"}]},
        {id:4688,t:"wmiprvse.exe spawns child process",f:[{k:"NewProcessName",v:"cmd.exe (or powershell.exe)"},{k:"ParentProcessName",v:"C:\\Windows\\System32\\wbem\\wmiprvse.exe"},{k:"CommandLine",v:"cmd.exe /c malicious.exe"},{k:"🔍 Detection",v:"Unexpected child process of wmiprvse.exe = WMI lateral movement"}]}
      ],arrow:null},
      {n:3,d:2,label:"DC validates authentication — standard Kerberos/NTLM",events:[
        {id:4769,t:"Service ticket for target (if Kerberos)",f:[{k:"ServiceName",v:"HOST/SRV-DB01 or RPCSS/SRV-DB01"},{k:"TargetUserName",v:"admin-account@CORP.LOCAL"}]}
      ],arrow:null},
    ],
    notes:"WMI: Key = unexpected child processes of wmiprvse.exe (cmd.exe, powershell.exe, unknown binaries). No service installation (unlike PsExec). WinRM: Look for wsmprovhost.exe as parent + connections on port 5985/5986. 4624 Type 3 + 4688 wmiprvse.exe/wsmprovhost.exe from unexpected sources = lateral movement. WMI-Activity/Operational log Events 5857/5861 provide additional visibility.",
    mitre:"T1047 — WMI + T1021.006 — WinRM",
  },
  { id:"dcshadow", title:"DCShadow", desc:"Registering a rogue DC to push malicious AD changes via replication", icon:"👻", cat:"attack",
    devices:["Attacker Machine (Rogue DC)","Legitimate Domain Controller"],
    normal:{ label:"Legitimate DC Replication", steps:[
      {n:1,d:1,label:"Only real DCs (in DC OU) have GC/ and DRS SPNs"},
      {n:2,d:1,label:"Replication only between known DC machine accounts"},
    ], key:"GC/ and DRS SPNs only on actual Domain Controllers. No short-lived server objects." },
    steps:[
      {n:1,d:0,label:"Attacker runs Mimikatz lsadump::dcshadow — registers workstation as a DC by adding GC/ and DRS SPNs",events:[],why:"Mimikatz modifies the attacker's computer account SPN. This is logged on the DC as Event 4742 in step 2. The DRS GUID E3514235-4B06-11D1-AB04-00C04FC2DCD2 is key to watch for.",arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"DC logs SPN change — GC/ and DRS SPNs added to NON-DC computer",events:[
        {id:4742,t:"Computer account changed — SPN modification",f:[{k:"TargetUserName",v:"ATKR-PC$ (not a DC!)"},{k:"ServicePrincipalNames",v:"GC/ATKR-PC.corp.local AND E3514235-4B06-11D1-AB04-00C04FC2DCD2/..."},{k:"SubjectUserName",v:"compromised-admin"},{k:"🔍 Detection",v:"GC/ or DRS GUID SPN on non-DC computer = DCShadow"}]}
      ],arrow:null},
      {n:3,d:0,label:"Attacker creates rogue nTDSDSA object (DC registration) in Sites container",events:[],why:"Creates server + NTDS Settings in CN=Configuration. Logged as Event 5137 on the DC. The rogue DC is short-lived — created and deleted within seconds.",arrow:{to:1,proto:"ntlm"}},
      {n:4,d:1,label:"Rogue DC object created and quickly deleted (within 30 seconds)",events:[
        {id:5137,t:"Directory service object created (rogue DC)",f:[{k:"ObjectDN",v:"CN=NTDS Settings,CN=ATKR-PC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,..."},{k:"ObjectClass",v:"nTDSDSA"},{k:"SubjectUserName",v:"compromised-admin"}]},
        {id:5141,t:"Directory service object deleted (cleanup)",f:[{k:"ObjectDN",v:"Same NTDS Settings object"},{k:"🔍 Detection",v:"5137 + 5141 for nTDSDSA within 30 seconds = DCShadow"}]}
      ],arrow:null},
      {n:5,d:0,label:"Attacker pushes malicious AD changes via replication — real DCs accept them as legitimate",events:[],why:"Replication changes are accepted because the rogue DC is (briefly) trusted. Changes bypass normal SIEM logging because they come through replication, not LDAP. Event 4929 may appear on DCs.",arrow:{to:1,proto:"ntlm"}},
      {n:6,d:1,label:"Malicious changes are now in AD — SPNs cleaned up to cover tracks",events:[
        {id:4929,t:"AD replica source naming context removed",f:[{k:"SourceAddress",v:"attacker machine GUID"},{k:"🔍 Detection",v:"4929 from non-DC source = replication from rogue DC"}]},
        {id:4742,t:"SPNs removed (cleanup)",f:[{k:"TargetUserName",v:"ATKR-PC$"},{k:"ServicePrincipalNames",v:"GC/ and DRS SPNs removed"}]}
      ],arrow:null},
    ],
    notes:"DCShadow bypasses traditional SIEM logging because changes come through replication. Detection: (1) 4742 with GC/ or DRS GUID SPN on non-DC computer. (2) 5137+5141 (nTDSDSA create+delete) within 30 seconds. (3) 4929 from non-DC source. Requires Domain Admin. Does NOT survive if the fake DC registration is blocked. Monitor all SPN changes on computer accounts.",
    mitre:"T1207 — Rogue Domain Controller",
  },
  { id:"diamond", title:"Diamond / Sapphire Ticket", desc:"Next-gen ticket forging — modifies LEGITIMATE TGTs, harder to detect than Golden", icon:"💎", cat:"attack",
    devices:["Attacker Machine","Domain Controller","Target Server"],
    normal:{ label:"Legitimate Kerberos", steps:[
      {n:1,d:1,label:"DC issues TGT with correct PAC (groups, privileges match AD)"},
      {n:2,d:1,label:"4768 exists, PAC matches real group memberships"},
    ], key:"PAC reflects actual AD group memberships. 4768 exists for every TGT. AES encryption." },
    steps:[
      {n:1,d:0,label:"Attacker requests a legitimate TGT as a low-priv user (or uses tgtdeleg trick)",events:[],why:"This generates a real 4768 on the DC — unlike Golden Ticket. That's what makes Diamond Tickets harder to detect: there IS a legitimate TGT request.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"DC issues legitimate TGT — normal 4768 logged",events:[
        {id:4768,t:"Legitimate TGT issued (this event EXISTS — unlike Golden Ticket)",f:[{k:"TargetUserName",v:"lowpriv-user"},{k:"TicketEncryptionType",v:"0x12 (AES — normal)"},{k:"PreAuthType",v:"15 (normal)"},{k:"🔍 Note",v:"This 4768 DOES exist — Golden Ticket detection (missing 4768) will NOT fire"}]}
      ],arrow:{to:0,proto:"kerberos"}},
      {n:3,d:0,label:"Diamond: Attacker decrypts TGT with KRBTGT hash, modifies PAC (adds Domain Admins group), re-encrypts. Sapphire: Replaces PAC with real admin PAC obtained via S4U2Self+U2U",events:[],why:"Local operation using KRBTGT key. Diamond modifies the existing PAC (may have discrepancies). Sapphire replaces it with a REAL admin PAC from S4U2Self+U2U (harder to detect). No network event for the modification itself.",arrow:{to:1,proto:"kerberos"}},
      {n:4,d:1,label:"Attacker uses modified TGT to request service tickets — DC validates it (KRBTGT signature is correct)",events:[
        {id:4769,t:"TGS issued — has matching 4768 (defeats Golden Ticket detection)",f:[{k:"TargetUserName",v:"lowpriv-user@CORP.LOCAL (or admin if cname changed)"},{k:"ServiceName",v:"cifs/SRV-DB01"},{k:"🔍 Detection Challenge",v:"4768 EXISTS, AES encryption — standard Golden Ticket detection fails"}]}
      ],arrow:{to:2,proto:"kerberos"}},
      {n:5,d:2,label:"Target server grants access based on forged PAC privileges",events:[
        {id:4624,t:"Logon with elevated privileges",logon:3,f:[{k:"TargetUserName",v:"lowpriv-user (but with admin rights via modified PAC)"},{k:"🔍 Detection",v:"4672 for non-admin user = PAC manipulation. Compare PAC groups vs actual AD group membership"}]},
        {id:4672,t:"Admin privileges for non-admin user",f:[{k:"SubjectUserName",v:"lowpriv-user"},{k:"🔍 Detection",v:"lowpriv-user getting admin privs = forged PAC"}]}
      ],arrow:null},
    ],
    notes:"Diamond/Sapphire defeat the classic Golden Ticket detection (missing 4768) because they START with a legitimate TGT. Detection requires: (1) PAC-level inspection — comparing PAC group memberships vs actual AD groups (requires advanced tooling like MDI). (2) 4672 for non-privileged users. (3) Sapphire: S4U2Self+U2U 4769 events (same indicators as RBCD S4U2Self). (4) Monitor access to KRBTGT keys (DCSync detection). Requires KRBTGT hash — same prerequisite as Golden Ticket.",
    mitre:"T1558.001 — Golden Ticket (evolved variant)",
  },
  { id:"ntdsdit", title:"NTDS.dit Extraction", desc:"Stealing the AD database via Volume Shadow Copy or ntdsutil", icon:"💾", cat:"attack",
    devices:["Domain Controller"],
    normal:{ label:"Legitimate DC Backup", steps:[
      {n:1,d:0,label:"Scheduled backup by authorized backup service creates VSS snapshot"},
      {n:2,d:0,label:"Backup agent copies NTDS.dit as part of system state backup"},
    ], key:"VSS operations from authorized backup software (Veeam, Windows Server Backup). During scheduled windows. By SYSTEM or backup service accounts." },
    steps:[
      {n:1,d:0,label:"Attacker with DC access runs vssadmin or ntdsutil to create Volume Shadow Copy",events:[
        {id:4688,t:"Process creation — vssadmin or ntdsutil",f:[{k:"NewProcessName",v:"C:\\Windows\\System32\\vssadmin.exe (or ntdsutil.exe)"},{k:"CommandLine",v:"vssadmin create shadow /for=C:"},{k:"SubjectUserName",v:"compromised-admin"},{k:"ParentProcessName",v:"cmd.exe"},{k:"🔍 Detection",v:"vssadmin/ntdsutil on DC outside backup windows = suspicious"}]},
        {id:8222,t:"Shadow copy created (VSS event)",f:[{k:"VolumeName",v:"C:\\"},{k:"🔍 Detection",v:"VSS snapshot creation on DC outside backup schedule"}]}
      ],arrow:null},
      {n:2,d:0,label:"Attacker copies NTDS.dit + SYSTEM hive from shadow copy",events:[
        {id:4663,t:"File access — NTDS.dit copied from shadow copy",f:[{k:"ObjectName",v:"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[N]\\Windows\\NTDS\\ntds.dit"},{k:"SubjectUserName",v:"compromised-admin"},{k:"AccessMask",v:"0x1 (ReadData)"},{k:"ProcessName",v:"cmd.exe"},{k:"🔍 Detection",v:"Access to NTDS.dit via shadow copy path = credential theft"}]},
        {id:4663,t:"SYSTEM registry hive copied",f:[{k:"ObjectName",v:"...\\config\\SYSTEM"},{k:"🔍 Detection",v:"SYSTEM hive needed to decrypt NTDS.dit hashes"}]}
      ],arrow:null},
      {n:3,d:0,label:"Attacker exfiltrates files and extracts all domain hashes offline with secretsdump",events:[],why:"Offline extraction using Impacket secretsdump or DSInternals. Generates zero events once files leave the DC. All domain user hashes, computer account hashes, and historical passwords are now compromised.",arrow:null},
    ],
    notes:"Detection: 4688 with vssadmin.exe/ntdsutil.exe on DC outside backup windows. 4663 showing access to NTDS.dit path via shadow copy. ESENT Events 325/327 in Application log. Event 7036 (Volume Shadow Copy Service start) in System log. Alternative to DCSync — works even if DRS replication is monitored. Requires local admin or Backup Operators on DC.",
    mitre:"T1003.003 — NTDS.dit",
  },
  { id:"gpoabuse", title:"GPO Abuse", desc:"Modifying Group Policy for domain-wide code execution or persistence", icon:"📋", cat:"attack",
    devices:["Attacker Machine","Domain Controller","All Domain Members"],
    normal:{ label:"Legitimate GPO Change", steps:[
      {n:1,d:1,label:"IT admin modifies GPO via GPMC from admin workstation"},
      {n:2,d:1,label:"5136 logged — from known admin account, documented change"},
    ], key:"GPO changes by authorized admin accounts, from known admin workstations, with change management ticket." },
    steps:[
      {n:1,d:0,label:"Attacker with write access to a GPO adds a scheduled task or startup script for code execution",events:[],why:"LDAP modification to the GPO object. Some changes are to SYSVOL (file-level) which requires file audit. The AD object modification is logged in step 2.",arrow:{to:1,proto:"kerberos"}},
      {n:2,d:1,label:"DC logs GPO object modification",events:[
        {id:5136,t:"Directory service object modified — GPO changed",f:[{k:"SubjectUserName",v:"compromised-admin"},{k:"ObjectDN",v:"CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=local"},{k:"ObjectClass",v:"groupPolicyContainer"},{k:"AttributeLDAPDisplayName",v:"versionNumber or gPCFileSysPath"},{k:"🔍 Detection",v:"GPO modification by unexpected account = abuse"}]},
        {id:5145,t:"SYSVOL file modified (scripts/scheduled tasks added)",f:[{k:"ShareName",v:"\\\\DC01\\SYSVOL"},{k:"RelativeTargetName",v:"corp.local\\Policies\\{GUID}\\Machine\\Scripts\\Startup\\malicious.bat"},{k:"SubjectUserName",v:"compromised-admin"},{k:"AccessMask",v:"0x2 (WriteData)"},{k:"🔍 Detection",v:"New scripts in SYSVOL policy folder = persistence"}]}
      ],arrow:null},
      {n:3,d:2,label:"GPO applies at next refresh (90 min default) — all domain members execute attacker's code",events:[
        {id:4688,t:"Process created by Group Policy on every affected machine",f:[{k:"NewProcessName",v:"malicious.bat or scheduled task executable"},{k:"ParentProcessName",v:"gpscript.exe or svchost.exe -k netsvcs"},{k:"SubjectUserName",v:"SYSTEM"},{k:"🔍 Detection",v:"Unexpected processes spawned by gpscript.exe across many machines simultaneously"}]}
      ],arrow:null},
    ],
    notes:"GPO abuse gives domain-wide code execution. Detection: 5136 on groupPolicyContainer objects by non-admin accounts. 5145 showing new files in SYSVOL policy directories. 4688 showing unexpected processes from gpscript.exe on multiple machines. Event 4900 = GPO template permissions changed. Monitor SYSVOL for unauthorized file changes. GPO refresh is every ~90 min (gpupdate /force to accelerate).",
    mitre:"T1484.001 — Domain Policy Modification: Group Policy",
  },
  { id:"sidhistory", title:"SID History Injection", desc:"Persistence by injecting privileged SIDs into user accounts", icon:"🪪", cat:"attack",
    devices:["Attacker Machine","Domain Controller"],
    normal:{ label:"Legitimate SID History", steps:[
      {n:1,d:1,label:"SID History populated only during domain migration by authorized admin"},
      {n:2,d:1,label:"sIDHistory attribute contains SIDs from OLD domain only"},
    ], key:"sIDHistory only from domain migrations. Contains SIDs from a DIFFERENT (old) domain. Set by migration tools." },
    steps:[
      {n:1,d:0,label:"Attacker with admin access uses Mimikatz misc::addsid or modifies sIDHistory attribute to inject Domain Admins SID",events:[],why:"Mimikatz directly patches AD or uses DCShadow to inject. The SID History modification is logged on the DC in step 2. Any account with sIDHistory containing a privileged SID from the SAME domain is suspicious.",arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"DC logs SID History modification",events:[
        {id:4765,t:"SID History was added to an account",f:[{k:"TargetUserName",v:"backdoor-user"},{k:"SubjectUserName",v:"compromised-admin"},{k:"SidHistory",v:"S-1-5-21-...-512 (Domain Admins SID from SAME domain!)"},{k:"🔍 Detection",v:"SID History containing SID from SAME domain = injection attack"}]},
        {id:4766,t:"Attempt to add SID History failed (if it fails)",f:[{k:"TargetUserName",v:"backdoor-user"},{k:"🔍 Detection",v:"Even failed attempts indicate attack activity"}]}
      ],arrow:null},
      {n:3,d:0,label:"Attacker logs in as backdoor-user — Kerberos includes Domain Admins SID from SID History in PAC",events:[],why:"The injected SID is included in the user's Kerberos ticket PAC automatically. From this point forward, backdoor-user has Domain Admin privileges transparently, with no group membership change visible in standard tools.",arrow:{to:1,proto:"kerberos"}},
      {n:4,d:1,label:"Authentication looks normal but access token includes injected privileged SID",events:[
        {id:4624,t:"Normal-looking logon — but effective privileges include Domain Admin",logon:3,f:[{k:"TargetUserName",v:"backdoor-user"},{k:"🔍 Detection",v:"Token includes DA SID via SID History — not visible in group membership queries"}]},
        {id:4672,t:"Special privileges assigned (from SID History)",f:[{k:"SubjectUserName",v:"backdoor-user"},{k:"🔍 Detection",v:"4672 for user not in any admin group = SID History injection"}]}
      ],arrow:null},
    ],
    notes:"SID History provides INVISIBLE persistence — user isn't in Domain Admins group but has DA privileges via SID History. Detection: 4765/4766 events. Audit: Get-ADUser -Filter * -Properties sIDHistory | Where-Object {$_.sIDHistory -ne $null}. Any sIDHistory containing SIDs from the SAME domain is almost certainly malicious. SIDs from different domains may be legitimate migration artifacts. Tools: Mimikatz misc::addsid, DCShadow.",
    mitre:"T1134.005 — SID-History Injection",
  },
  // ───── DETECTION ─────
  { id:"failure", title:"Failed Logons / Spray", desc:"Bad passwords, lockouts, password spray & brute force detection", icon:"🚫", cat:"detection",
    devices:["Source Machine","Domain Controller"],
    steps:[
      {n:1,d:0,label:"Authentication attempt with incorrect credentials",events:[
        {id:4625,t:"Logon failure",f:[{k:"TargetUserName",v:"targeted-user"},{k:"Status",v:"0xC000006D (bad user/pass)"},{k:"SubStatus",v:"0xC000006A (wrong password)"},{k:"IpAddress",v:"10.1.2.99"},{k:"LogonType",v:"2/3/10"},{k:"FailureReason",v:"%%2313"}]}
      ],arrow:{to:1,proto:"ntlm"}},
      {n:2,d:1,label:"DC rejects authentication — logs failure with sub-status code",events:[
        {id:4771,t:"Kerberos pre-auth failed",f:[{k:"TargetUserName",v:"targeted-user"},{k:"Status",v:"0x18 (wrong password)"},{k:"IpAddress",v:"::ffff:10.1.2.99"}]},
        {id:4776,t:"NTLM validation failed",f:[{k:"TargetUserName",v:"targeted-user"},{k:"Workstation",v:"ATKR-PC"},{k:"Status",v:"0xC000006A"}]}
      ],arrow:null},
      {n:3,d:1,label:"If threshold reached: account lockout",events:[
        {id:4740,t:"Account locked out",f:[{k:"TargetUserName",v:"targeted-user"},{k:"CallerComputerName",v:"WS-SOURCE (lockout source)"}]}
      ],arrow:null},
    ],
    notes:"Sub-statuses: 0xC0000064=no user, 0xC000006A=wrong pass, 0xC0000072=disabled, 0xC0000234=locked, 0xC0000071=expired, 0xC000006F=outside hours. Password spray: many 4625 from ONE source → MANY different accounts. Brute force: many 4625 → ONE account. 4740 CallerComputerName reveals lockout source.",
    mitre:"T1110 — Brute Force / T1110.003 — Password Spraying",
  },
];

const LM={2:{n:"Interactive",c:"#1d4ed8"},3:{n:"Network",c:"#6d28d9"},4:{n:"Batch",c:"#a16207"},5:{n:"Service",c:"#047857"},9:{n:"NewCreds",c:"#be185d"},10:{n:"RDP",c:"#0e7490"}};
const PC={kerberos:"#1d4ed8",ntlm:"#b91c1c",rdp:"#0e7490",smb:"#a16207"};
const CC={normal:{c:"#047857",bg:"#ecfdf5",bd:"#a7f3d0",l:"Normal Auth"},attack:{c:"#b91c1c",bg:"#fef2f2",bd:"#fecaca",l:"Threat"},detection:{c:"#a16207",bg:"#fffbeb",bd:"#fde68a",l:"Detection"}};

const IMP={
  kerberoast:{tool:"GetUserSPNs.py",cmd:"GetUserSPNs.py -request -dc-ip 10.0.0.1 CORP.LOCAL/user:pass",logs:[
    "4769 on DC — burst of TGS requests with EncType 0x17 (RC4) for user-based SPNs",
    "4624 Type 3 on DC (NTLM auth) — Impacket uses NTLM by default for initial auth",
    "No service installation, no file writes on target — runs entirely from attacker machine",
  ],sig:"Impacket authenticates via NTLM (4776+4624 Type 3), then requests multiple TGS tickets in rapid succession. All 4769 events originate from one IP with RC4 encryption."},
  asrep:{tool:"GetNPUsers.py",cmd:"GetNPUsers.py CORP.LOCAL/ -usersfile users.txt -dc-ip 10.0.0.1 -format hashcat",logs:[
    "4768 on DC — PreAuthType=0, TicketEncryptionType=0x17, ServiceName=krbtgt",
    "No 4624 on any target — attacker never logs on, just collects hashes",
    "Can run WITHOUT any credentials — only needs username list + network access to DC port 88",
  ],sig:"Multiple 4768 events with PreAuthType=0 from same source IP in seconds. No subsequent 4769 or 4624. Tool can be run fully unauthenticated."},
  golden:{tool:"ticketer.py + secretsdump.py (for KRBTGT hash)",cmd:"ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain CORP.LOCAL Administrator",logs:[
    "secretsdump.py first: 4662 (DCSync) to get KRBTGT hash — see DCSync scenario",
    "ticketer.py: ZERO events — forges TGT entirely offline on attacker machine",
    "When TGT is used: 4769 on DC without preceding 4768 — ticket appeared from nowhere",
  ],sig:"Two-stage: secretsdump.py generates DCSync artifacts (4662), then ticketer.py is silent. The forged ticket only generates events when USED (4769 without 4768)."},
  silver:{tool:"ticketer.py",cmd:"ticketer.py -nthash <SERVICE_HASH> -domain-sid S-1-5-21-... -domain CORP.LOCAL -spn cifs/target.corp.local Administrator",logs:[
    "ZERO events on DC — Silver Ticket never contacts the DC",
    "4624 Type 3 (Kerberos) on target server — but no 4769 on DC for this logon",
    "Domain field anomaly: blank or FQDN instead of NetBIOS in 4624/4634",
  ],sig:"Entirely silent on DC. Detection requires cross-correlation: 4624 (Kerberos) on target with NO matching 4769 on DC."},
  pth:{tool:"psexec.py / smbexec.py / wmiexec.py (with -hashes flag)",cmd:"psexec.py -hashes :NTLM_HASH CORP/admin@10.1.3.20",logs:[
    "4624 Type 3 on target — AuthPackage=NTLM, LogonProcess=NtLmSsp, KeyLength=0",
    "4776 on DC — NTLM validation without preceding 4768 (no Kerberos TGT)",
    "psexec.py: 7045 (service install) + 5145 (ADMIN$ + IPC$ access via svcctl)",
    "smbexec.py: 7045 (BTOBTO service) + cmd.exe /Q /c output to \\\\127.0.0.1\\C$\\__output",
    "wmiexec.py: 4688 wmiprvse.exe → cmd.exe /Q /c with output to C:\\Windows\\Temp\\__<epoch>",
  ],sig:"All PtH via Impacket shows KeyLength=0 + NTLM auth. Each exec tool has unique service/process signature. psexec=random .exe to ADMIN$. smbexec=BTOBTO service name. wmiexec=__<epoch> temp file."},
  psexec:{tool:"psexec.py / smbexec.py",cmd:"psexec.py CORP/admin:password@10.1.3.20\nsmbexec.py CORP/admin:password@10.1.3.20",logs:[
    "psexec.py: Uploads randomly-named .exe (8 chars) to C:\\Windows via ADMIN$ share",
    "psexec.py: 7045 — service with random name installed, ImagePath = random .exe",
    "psexec.py: 5145 — RelativeTargetName = 'svcctl' (Service Control Manager pipe)",
    "smbexec.py: 7045 — service named 'BTOBTO' (default) with cmd.exe /Q /c command",
    "smbexec.py: Output written to \\\\127.0.0.1\\C$\\__output then read back via SMB",
    "Both: 4624 Type 3 + 4672 + 5140 (IPC$ share access)",
  ],sig:"psexec.py signature: random 8-char .exe in ADMIN$ + service with matching random name. smbexec.py signature: 'BTOBTO' service name + cmd.exe /Q /c pattern. Both trigger svcctl pipe access (5145)."},
  dcsync:{tool:"secretsdump.py (with -just-dc flag)",cmd:"secretsdump.py -just-dc CORP.LOCAL/admin:password@10.0.0.1",logs:[
    "4662 on DC — DS-Replication-Get-Changes-All from non-DC account (definitive DCSync)",
    "4624 Type 3 on DC — NTLM auth from attacker IP",
    "Without -just-dc: Also enables RemoteRegistry service → 7040 (service state change)",
    "Without -just-dc: svchost.exe creates 8-char .tmp file in System32 (SAM/LSA dump)",
    "5145 — RelativeTargetName = 'winreg' (Remote Registry pipe) + 'svcctl'",
  ],sig:"secretsdump -just-dc = pure DCSync (4662). Without flag = also dumps local SAM/LSA via RemoteRegistry: look for 7040 (RemoteRegistry start) + svchost.exe writing 8-char .tmp files."},
  adcs:{tool:"certipy (Python) / Certify.exe",cmd:"certipy find -u user@corp.local -p pass -dc-ip 10.0.0.1\ncertipy req -u user@corp.local -p pass -ca CORP-CA -template VulnTemplate -upn administrator@corp.local",logs:[
    "certipy find: LDAP queries for certificate templates — may generate 1644 (expensive LDAP search)",
    "certipy req: 4886 + 4887 on CA — Requester ≠ SAN UPN (ESC1 indicator)",
    "certipy auth: 4768 on DC — PreAuthType=16 (PKINIT certificate auth)",
    "ESC8 (ntlmrelayx.py → HTTP enrollment): 4776 (NTLM relay) + 4886/4887 on CA",
  ],sig:"certipy req generates 4886/4887 with SAN mismatch. certipy auth generates 4768 with PreAuthType=16 from unexpected IP. ESC8 uses ntlmrelayx.py targeting the CA's HTTP enrollment endpoint."},
  ntlmrelay:{tool:"ntlmrelayx.py",cmd:"ntlmrelayx.py -t ldap://10.0.0.1 -smb2support\nntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp -template VulnTemplate",logs:[
    "4624 Type 3 on target — IpAddress = ATTACKER (not victim), but TargetUserName = VICTIM",
    "4776 on DC — Workstation mismatch (victim account from attacker's machine)",
    "If relayed to LDAP: 5136 (directory object modified — may set RBCD attribute)",
    "If relayed to ADCS HTTP: 4886/4887 on CA (certificate request with relayed creds)",
    "Coercion source (PetitPotam): 5145 on target — access to \\pipe\\lsarpc or \\pipe\\efsrpc",
  ],sig:"Key: 4624 source IP ≠ expected for that account. ntlmrelayx.py commonly relays to LDAP (for RBCD setup) or ADCS HTTP (for ESC8). PetitPotam triggers 5145 for lsarpc/efsrpc pipe access."},
  delegation:{tool:"getST.py (Impacket) + findDelegation.py",cmd:"findDelegation.py CORP.LOCAL/user:pass -dc-ip 10.0.0.1\ngetST.py -spn cifs/target.corp.local -impersonate Administrator CORP.LOCAL/FAKEPC$:pass",logs:[
    "findDelegation.py: LDAP queries — no Security events (enumeration only)",
    "getST.py (S4U): Two 4769 events — S4U2Self (ServiceName=AccountName) + S4U2Proxy (TransitedServices not empty)",
    "4624 Type 3 on target with impersonated user from delegation server IP",
  ],sig:"getST.py generates the same S4U2Self+S4U2Proxy 4769 pair as Rubeus. findDelegation.py is LDAP-only enumeration."},
  rbcd:{tool:"rbcd.py (Impacket) / ntlmrelayx.py (--delegate-access)",cmd:"addcomputer.py CORP.LOCAL/user:pass -computer-name FAKEPC$ -computer-pass Passw0rd!\nrbcd.py -delegate-to TARGET$ -delegate-from FAKEPC$ -dc-ip 10.0.0.1 CORP.LOCAL/user:pass\ngetST.py -spn cifs/TARGET.corp.local -impersonate Administrator CORP.LOCAL/FAKEPC$:Passw0rd!",logs:[
    "addcomputer.py: 4741 (computer account created) by non-admin user",
    "rbcd.py: 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity modified) on target computer object",
    "getST.py: Paired 4769 events — S4U2Self + S4U2Proxy (same as delegation scenario)",
    "ntlmrelayx.py --delegate-access: Combines relay (4624 IP mismatch) + 5136 (RBCD attribute set) in one step",
  ],sig:"Full chain: addcomputer.py (4741) → rbcd.py (5136 on delegation attribute) → getST.py (S4U 4769 pair). ntlmrelayx.py with --delegate-access automates the relay + RBCD setup in one command."},
  opth:{tool:"getTGT.py / Rubeus asktgt",cmd:"getTGT.py -hashes :NTLM_HASH CORP.LOCAL/admin -dc-ip 10.0.0.1",logs:[
    "4768 on DC — TicketEncryptionType=0x17 (RC4) because hash is NTLM, not AES",
    "PreAuthType=15 (looks normal — encrypted timestamp with the hash)",
    "All subsequent 4769/4624 events use standard Kerberos — indistinguishable from normal",
  ],sig:"getTGT.py with NTLM hash generates RC4 TGT (4768 EncType=0x17). After this, all activity is pure Kerberos. Detection must catch the initial RC4 TGT request."},
  wmi:{tool:"wmiexec.py / dcomexec.py / atexec.py",cmd:"wmiexec.py CORP/admin:password@10.1.3.20\natexec.py CORP/admin:password@10.1.3.20 'whoami'",logs:[
    "wmiexec.py: 4624 Type 3 + 4688 wmiprvse.exe → cmd.exe /Q /c <command> 1> \\\\127.0.0.1\\ADMIN$\\__<epoch> 2>&1",
    "wmiexec.py: Output file = '__' + epoch timestamp in ADMIN$ share (unique signature)",
    "wmiexec.py: 5145 with RelativeTargetName matching __<epoch> pattern",
    "atexec.py: 4698 (scheduled task created) + 4688 cmd.exe /C <command> > C:\\Windows\\Temp\\<8chars>.tmp",
    "atexec.py: Task name = random 8 chars, output redirected to 8-char .tmp file",
    "dcomexec.py: Multiple 4624 Type 3 via DCOM — process spawned by mmc.exe or explorer.exe (depending on DCOM object)",
  ],sig:"wmiexec.py: __<epoch> output file in ADMIN$. atexec.py: random 8-char task name + 8-char .tmp output. dcomexec.py: DCOM parent process (MMC20.Application → mmc.exe, ShellWindows → explorer.exe)."},
  dcshadow:{tool:"lsadump::dcshadow (Mimikatz — not Impacket)",cmd:"mimikatz # lsadump::dcshadow /object:user /attribute:primaryGroupID /value:512",logs:[
    "4742 — GC/ and DRS GUID SPNs added to non-DC computer (registration)",
    "5137 + 5141 — nTDSDSA object created then deleted within seconds (rogue DC lifecycle)",
    "4929 — Replica source naming context removed from non-DC source",
    "Note: DCShadow is Mimikatz-only — no Impacket equivalent exists",
  ],sig:"Mimikatz-only attack. No Impacket tool for DCShadow. Detection via SPN changes (4742) and short-lived DC objects (5137→5141)."},
  diamond:{tool:"ticketer.py -request (Diamond) / ticketer.py -request -impersonate (Sapphire)",cmd:"ticketer.py -request -domain CORP.LOCAL -user lowpriv -password pass -aesKey <KRBTGT_AES> -domain-sid S-1-5-21-... -groups 512 fakeadmin",logs:[
    "Diamond: 4768 on DC (legitimate TGT request — this EXISTS unlike Golden Ticket)",
    "Diamond: PAC modified offline — no event for the modification itself",
    "Sapphire: 4768 (TGT) + 4769 (S4U2Self+U2U to get admin PAC) in rapid succession",
    "Both: 4672 for non-admin user when modified ticket is used (forged PAC indicator)",
  ],sig:"Diamond generates a real 4768 (defeats Golden Ticket detection). Sapphire adds a 4769 with S4U2Self+U2U indicators. Both require KRBTGT key."},
  ntdsdit:{tool:"secretsdump.py -use-vss / ntdsutil (built-in)",cmd:"secretsdump.py -use-vss -just-dc CORP.LOCAL/admin:password@10.0.0.1\nOR on DC: ntdsutil 'ac i ntds' 'ifm' 'create full C:\\temp' q q",logs:[
    "secretsdump.py -use-vss: Creates VSS snapshot remotely via WMI — 8222 (VSS event) + 4688 (vssadmin.exe)",
    "secretsdump.py: 4663 — access to \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\\Windows\\NTDS\\ntds.dit",
    "ntdsutil: 4688 with CommandLine containing 'ifm' and 'create full'",
    "Both: 7036 (Volume Shadow Copy Service started) in System log",
    "secretsdump.py remote: 5145 with svcctl + winreg pipe access",
  ],sig:"secretsdump.py -use-vss creates shadow copies remotely (WMI-based — may evade EDR). Look for 8222 + 4663 on NTDS.dit path. ntdsutil 'ifm' is the built-in alternative."},
  gpoabuse:{tool:"No specific Impacket tool — uses dacledit.py / owneredit.py for ACL abuse",cmd:"dacledit.py -action write -rights WriteAll -principal attacker -target-dn 'CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=local' CORP.LOCAL/admin:pass",logs:[
    "dacledit.py: 5136 (directory object modified) on GPO object — ACL changed",
    "Manual GPO edit: 5136 (groupPolicyContainer modified) + 5145 (SYSVOL file write)",
    "Payload delivery: 4688 on affected machines when GPO refreshes (gpscript.exe parent)",
  ],sig:"Impacket's dacledit.py modifies GPO ACLs (5136). Actual GPO content changes require SMB writes to SYSVOL (5145). No single Impacket tool automates full GPO abuse chain."},
  sidhistory:{tool:"No Impacket tool — Mimikatz misc::addsid or DCShadow",cmd:"mimikatz # sid::add /sam:backdoor-user /new:S-1-5-21-...-512",logs:[
    "4765 — SID History added to account",
    "4766 — SID History addition failed (if blocked)",
    "If via DCShadow: Same DCShadow artifacts (4742 SPN change + 5137/5141)",
    "Note: No Impacket equivalent — Mimikatz or DCShadow only",
  ],sig:"Mimikatz-only. Monitor 4765/4766 events. SID History containing SIDs from the SAME domain = confirmed attack."},
  skeleton:{tool:"No Impacket tool — Mimikatz misc::skeleton",cmd:"mimikatz # privilege::debug\nmimikatz # misc::skeleton",logs:[
    "7045 — Service installed on DC (if deployed as service)",
    "4673 — LsaRegisterLogonProcess() privileged service called",
    "4611 — Trusted logon process registered with LSA",
    "Note: Mimikatz-only — no Impacket equivalent",
  ],sig:"Mimikatz-only LSASS patch. No Impacket tool. Detection via 7045/4673/4611 on DC. Auth logs look normal after installation."},
  shadow:{tool:"No Impacket native tool — pyWhisker (Python) or Certipy",cmd:"pywhisker.py -d CORP.LOCAL -u attacker -p pass --target admin-user --action add",logs:[
    "5136 — msDS-KeyCredentialLink attribute modified on target account",
    "4768 — TGT with PreAuthType=16 (PKINIT) from unexpected IP",
    "pyWhisker is not part of Impacket but follows same Python LDAP patterns",
  ],sig:"pyWhisker modifies KeyCredentialLink (5136). Subsequent PKINIT auth (4768 PreAuthType=16). Not Impacket-native but commonly used alongside it."},
};


function SwimLane({sc,activeStep,onStep,showNormal}){
  const devs=sc.devices;
  const steps=showNormal&&sc.normal?sc.normal.steps:sc.steps;
  const laneH=56,padL=160,stepW=100,padT=10;
  const W=padL+steps.length*stepW+60;
  const H=devs.length*laneH+padT*2+10;
  return(
    <div style={{overflowX:"auto",padding:"0 0 4px"}}>
    <svg width={Math.max(W,500)} height={H} style={{display:"block",minWidth:500}}>
      <defs>
        <filter id="ss"><feDropShadow dx="0" dy="1" stdDeviation="2" floodColor="rgba(0,0,0,.06)"/></filter>
        <marker id="mK" viewBox="0 0 8 6" refX="7" refY="3" markerWidth="6" markerHeight="5" orient="auto"><path d="M0,.5 L7,3 L0,5.5Z" fill="#1d4ed8" opacity=".6"/></marker>
        <marker id="mN" viewBox="0 0 8 6" refX="7" refY="3" markerWidth="6" markerHeight="5" orient="auto"><path d="M0,.5 L7,3 L0,5.5Z" fill="#b91c1c" opacity=".6"/></marker>
        <marker id="mR" viewBox="0 0 8 6" refX="7" refY="3" markerWidth="6" markerHeight="5" orient="auto"><path d="M0,.5 L7,3 L0,5.5Z" fill="#0e7490" opacity=".6"/></marker>
        <marker id="mS" viewBox="0 0 8 6" refX="7" refY="3" markerWidth="6" markerHeight="5" orient="auto"><path d="M0,.5 L7,3 L0,5.5Z" fill="#a16207" opacity=".6"/></marker>
      </defs>
      {/* Lanes */}
      {devs.map((dev,i)=>{
        const y=padT+i*laneH;
        return(<g key={i}>
          <rect x="0" y={y} width="100%" height={laneH} fill={i%2===0?"#fdfcfa":"#f9f6f2"} stroke="#e8e3db" strokeWidth=".5"/>
          <text x="12" y={y+laneH/2+4} fill="#475569" fontSize="11" fontWeight="700" fontFamily="'Libre Franklin',sans-serif">{dev}</text>
          <line x1={padL-10} y1={y} x2={padL-10} y2={y+laneH} stroke="#e0dbd2" strokeWidth="1"/>
        </g>);
      })}
      {/* Arrows between steps */}
      {steps.map((s,i)=>{
        if(!s.arrow)return null;
        const x1=padL+i*stepW+stepW/2;
        const y1=padT+s.d*laneH+laneH/2;
        const x2=padL+i*stepW+stepW/2+(s.arrow.to>s.d?12:s.arrow.to<s.d?12:stepW);
        const y2=padT+s.arrow.to*laneH+laneH/2;
        const col=PC[s.arrow.proto]||"#94a3b8";
        const mk={kerberos:"mK",ntlm:"mN",rdp:"mR",smb:"mS"}[s.arrow.proto]||"mK";
        if(s.arrow.to===s.d){
          const nx=padL+(i+1)*stepW+stepW/2;
          return <line key={`a${i}`} x1={x1+16} y1={y1} x2={nx-16} y2={y2} stroke={col} strokeWidth="1.5" markerEnd={`url(#${mk})`} opacity=".5"/>;
        }
        const midX=x1+20;
        return <path key={`a${i}`} d={`M${x1+16},${y1} L${midX},${y1} L${midX},${y2} L${x1+16},${y2}`} fill="none" stroke={col} strokeWidth="1.5" strokeDasharray={s.arrow.proto==="ntlm"?"5,3":"none"} markerEnd={`url(#${mk})`} opacity=".45"/>;
      })}
      {/* Step markers */}
      {steps.map((s,i)=>{
        const x=padL+i*stepW+stepW/2;
        const y=padT+s.d*laneH+laneH/2;
        const isAct=activeStep===i;
        const hasEvents=s.events&&s.events.length>0;
        const hasWhy=!!s.why;
        const isClickable=hasEvents||hasWhy;
        const r=isAct?18:15;
        return(<g key={`s${i}`} onClick={()=>isClickable&&onStep(isAct?null:i)} style={{cursor:isClickable?"pointer":"default"}}>
          <circle cx={x} cy={y} r={r} fill={isAct?"#1e293b":hasEvents?"#fff":hasWhy?"#fefce8":"#f5f2ed"} stroke={isAct?"#1e293b":hasEvents?"#64748b":hasWhy?"#ca8a04":"#c4bdb2"} strokeWidth={isAct?2.5:1.5} filter="url(#ss)"/>
          <text x={x} y={y+4.5} textAnchor="middle" fill={isAct?"#fff":hasEvents?"#1e293b":hasWhy?"#854d0e":"#94a3b8"} fontSize="12" fontWeight="800" fontFamily="'Source Code Pro',monospace">{s.n}</text>
          {hasEvents&&!isAct&&<circle cx={x+11} cy={y-11} r="5" fill="#ef4444" stroke="#fff" strokeWidth="1.5"/>}
          {hasEvents&&!isAct&&<text x={x+11} y={y-7.5} textAnchor="middle" fill="#fff" fontSize="7" fontWeight="700">{s.events.length}</text>}
          {!hasEvents&&hasWhy&&!isAct&&<circle cx={x+11} cy={y-11} r="5" fill="#ca8a04" stroke="#fff" strokeWidth="1.5"/>}
          {!hasEvents&&hasWhy&&!isAct&&<text x={x+11} y={y-7.5} textAnchor="middle" fill="#fff" fontSize="7.5" fontWeight="700">i</text>}
        </g>);
      })}
    </svg>
    </div>
  );
}

function FieldTable({fields,accent}){
  return(<div style={{margin:"8px 0 4px 0",borderRadius:8,border:"1.5px solid #ebe5db",overflow:"hidden",background:"#fdfbf7"}}>
    {fields.map((fi,j)=>(<div key={j} style={{display:"flex",borderBottom:j<fields.length-1?"1px solid #f0ebe3":"none",fontSize:12}}>
      <div style={{minWidth:160,maxWidth:200,padding:"5px 10px",background:fi.k.startsWith("🔍")?"#fef3c7":"#f7f3ed",fontFamily:"'Source Code Pro',monospace",fontWeight:600,color:fi.k.startsWith("🔍")?"#92400e":accent,fontSize:10.5,wordBreak:"break-word",borderRight:"1px solid #ebe5db"}}>{fi.k}</div>
      <div style={{flex:1,padding:"5px 10px",color:fi.v.includes("CRITICAL")||fi.v.includes("SMOKING")||fi.v.includes("ATTACK")||fi.v.includes("mismatch")||fi.v.includes("KEY INDICATOR")||fi.v.includes("dead giveaway")?"#b91c1c":"#334155",fontWeight:fi.v.includes("CRITICAL")||fi.v.includes("SMOKING")||fi.v.includes("KEY")?700:400,fontFamily:"'Source Code Pro',monospace",fontSize:10.5,wordBreak:"break-all"}}>{fi.v}</div>
    </div>))}
  </div>);
}

export default function App(){
  const [aId,setAId]=useState("interactive");
  const [activeStep,setActiveStep]=useState(null);
  const [showNormal,setShowNormal]=useState(false);
  const [collapsed,setCollapsed]=useState({});

  const sc=scenarios.find(s=>s.id===aId);
  const cat=CC[sc.cat];
  const steps=showNormal&&sc.normal?sc.normal.steps:sc.steps;
  const curStep=activeStep!==null?steps[activeStep]:null;

  const groups={normal:scenarios.filter(s=>s.cat==="normal"),attack:scenarios.filter(s=>s.cat==="attack"),detection:scenarios.filter(s=>s.cat==="detection")};

  const toggle=g=>setCollapsed(p=>({...p,[g]:!p[g]}));

  return(
    <div style={{height:"100vh",background:"#f5f2ed",color:"#1e293b",fontFamily:"'Libre Franklin',sans-serif",display:"flex",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Libre+Franklin:wght@300;400;500;600;700;800&family=Source+Code+Pro:wght@400;500;600;700&family=Playfair+Display:wght@700;800&display=swap');
        *{box-sizing:border-box;margin:0}
        ::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:#ede8e0}::-webkit-scrollbar-thumb{background:#c4bdb2;border-radius:3px}
        .sb-item{padding:8px 16px 8px 24px;cursor:pointer;border-left:3px solid transparent;transition:all .15s;font-size:12.5px;color:#64748b;display:flex;align-items:center;gap:8px}
        .sb-item:hover{background:#f0ebe4;color:#334155}
        .sb-item.active{background:#fff;color:#0f172a;font-weight:700;border-left-color:#1d4ed8;box-shadow:inset 0 0 0 0}
        .grp-hd{padding:10px 16px;cursor:pointer;font-size:10.5px;font-weight:700;letter-spacing:1px;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #e5e0d8;user-select:none}
        .grp-hd:hover{background:#f0ebe4}
        .step-card{padding:12px 16px;border-bottom:1px solid #eee8e0;cursor:default}
        .step-card.clickable{cursor:pointer}.step-card.clickable:hover{background:#faf7f3}
        .step-card.active{background:#f0f7ff;border-left:3px solid #1d4ed8}
        .cmp-tog{display:inline-flex;border-radius:8px;overflow:hidden;border:1.5px solid #e0dbd2}
        .cmp-btn{padding:6px 16px;font-size:11.5px;font-weight:600;cursor:pointer;border:none;transition:all .15s;font-family:'Libre Franklin',sans-serif}
        .cmp-btn.on{background:#1e293b;color:#fff}.cmp-btn.off{background:#fff;color:#64748b}
        .cmp-btn.off:hover{background:#f5f2ed}
        @media(max-width:800px){.sidebar{display:none!important}}
      `}</style>

      {/* ─── Sidebar ─── */}
      <aside className="sidebar" style={{width:260,minWidth:260,background:"#faf8f5",borderRight:"1.5px solid #e0dbd2",overflowY:"auto",display:"flex",flexDirection:"column",height:"100%"}}>
        <div style={{padding:"20px 16px 16px",borderBottom:"1.5px solid #e0dbd2"}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:34,height:34,borderRadius:8,background:"linear-gradient(145deg,#1e293b,#334155)",display:"flex",alignItems:"center",justifyContent:"center"}}>
              <span style={{color:"#f8fafc",fontSize:13,fontWeight:900,fontFamily:"'Playfair Display',serif"}}>Ev</span>
            </div>
            <div>
              <div style={{fontFamily:"'Playfair Display',serif",fontSize:15,fontWeight:800,color:"#0f172a"}}>Auth Events</div>
              <div style={{fontSize:10,color:"#94a3b8"}}>Training Reference</div>
            </div>
          </div>
        </div>

        {[{key:"normal",label:"Normal Authentication",icon:"✓",color:"#047857"},{key:"attack",label:"Attacks & Threats",icon:"⚠",color:"#b91c1c"},{key:"detection",label:"Detection Patterns",icon:"🔍",color:"#a16207"}].map(g=>(
          <div key={g.key}>
            <div className="grp-hd" onClick={()=>toggle(g.key)} style={{color:g.color}}>
              <span>{g.icon} {g.label} ({groups[g.key].length})</span>
              <span style={{fontSize:14,transition:"transform .2s",transform:collapsed[g.key]?"rotate(-90deg)":"rotate(0)"}}>{collapsed[g.key]?"›":"▾"}</span>
            </div>
            {!collapsed[g.key]&&groups[g.key].map(s=>(
              <div key={s.id} className={`sb-item ${aId===s.id?"active":""}`}
                onClick={()=>{setAId(s.id);setActiveStep(null);setShowNormal(false);}}>
                <span style={{fontSize:14,flexShrink:0}}>{s.icon}</span>
                <span>{s.title}</span>
              </div>
            ))}
          </div>
        ))}
      </aside>

      {/* ─── Main ─── */}
      <main style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",minWidth:0}}>
        {/* Header bar */}
        <div style={{padding:"16px 24px",borderBottom:"1.5px solid #e0dbd2",background:cat.bg,display:"flex",alignItems:"center",gap:14,flexWrap:"wrap",flexShrink:0}}>
          <span style={{fontSize:26}}>{sc.icon}</span>
          <div style={{flex:1,minWidth:200}}>
            <div style={{fontSize:16,fontWeight:800,color:"#0f172a",fontFamily:"'Playfair Display',serif"}}>{sc.title}</div>
            <div style={{fontSize:12,color:"#475569",marginTop:2}}>{sc.desc}</div>
          </div>
          <span style={{padding:"4px 12px",borderRadius:6,fontSize:10,fontWeight:700,letterSpacing:".5px",textTransform:"uppercase",background:"#fff",color:cat.c,border:`1.5px solid ${cat.bd}`,fontFamily:"'Source Code Pro',monospace"}}>{cat.l}</span>
          {sc.normal&&(
            <div className="cmp-tog">
              <button className={`cmp-btn ${showNormal?"off":"on"}`} onClick={()=>{setShowNormal(false);setActiveStep(null);}}>🔴 Attack Flow</button>
              <button className={`cmp-btn ${showNormal?"on":"off"}`} onClick={()=>{setShowNormal(true);setActiveStep(null);}}>🟢 Normal Flow</button>
            </div>
          )}
        </div>

        {/* Normal comparison key */}
        {showNormal&&sc.normal&&(
          <div style={{padding:"10px 24px",background:"#ecfdf5",borderBottom:"1.5px solid #a7f3d0",fontSize:12.5,color:"#047857",flexShrink:0}}>
            <strong>What normal looks like:</strong> {sc.normal.key}
          </div>
        )}

        {/* Swim lane timeline */}
        <div style={{padding:"16px 24px 8px",background:"#fdfcfa",borderBottom:"1.5px solid #e0dbd2",flexShrink:0}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",color:"#94a3b8",marginBottom:8,fontFamily:"'Source Code Pro',monospace"}}>
            {showNormal?"🟢 Normal Event Sequence":"Event Sequence Timeline"} — click any step to inspect (🔴 = events, 🟡 = forensic insight)
          </div>
          <SwimLane sc={sc} activeStep={activeStep} onStep={setActiveStep} showNormal={showNormal}/>
        </div>

        {/* Step detail + sidebar */}
        <div style={{display:"flex",flex:1,minHeight:0,overflow:"hidden"}}>
          {/* Steps list */}
          <div style={{flex:1,overflowY:"auto",background:"#fffefa",borderRight:"1.5px solid #e5e0d8"}}>
            <div style={{padding:"10px 16px",borderBottom:"1.5px solid #e5e0d8",background:"#f9f6f2",position:"sticky",top:0,zIndex:2}}>
              <span style={{fontSize:11,fontWeight:700,color:"#475569",fontFamily:"'Source Code Pro',monospace"}}>
                {showNormal?"NORMAL":"ATTACK"} WALKTHROUGH — {steps.length} steps
              </span>
            </div>
            {steps.map((s,i)=>{
              const hasEv=s.events&&s.events.length>0;
              const hasWhy=!!s.why;
              const isClickable=hasEv||hasWhy;
              const isAct=activeStep===i;
              return(
                <div key={i} className={`step-card ${isClickable?"clickable":""} ${isAct?"active":""}`}
                  onClick={()=>isClickable&&setActiveStep(isAct?null:i)}>
                  <div style={{display:"flex",gap:12,alignItems:"flex-start"}}>
                    <div style={{width:28,height:28,borderRadius:"50%",background:isAct?"#1e293b":hasEv?"#eff6ff":hasWhy?"#fefce8":"#f0ebe4",border:hasEv?"1.5px solid #93c5fd":hasWhy?"1.5px solid #fde68a":"1.5px solid #e0dbd2",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                      <span style={{fontSize:12,fontWeight:800,color:isAct?"#fff":hasEv?"#1d4ed8":hasWhy?"#854d0e":"#475569",fontFamily:"'Source Code Pro',monospace"}}>{s.n}</span>
                    </div>
                    <div style={{flex:1}}>
                      <div style={{fontSize:10,fontWeight:600,color:"#94a3b8",fontFamily:"'Source Code Pro',monospace",marginBottom:2}}>{sc.devices[s.d]?.toUpperCase()}</div>
                      <div style={{fontSize:13,color:"#1e293b",lineHeight:1.5,fontWeight:isAct?600:400}}>{s.label}</div>
                      {isClickable&&<div style={{fontSize:10,color:isAct?"#1d4ed8":hasEv?"#64748b":"#a16207",marginTop:4}}>
                        {hasEv?`${s.events.map(e=>e.id).join(", ")} ${isAct?"▾ expanded":"▸ click to expand"}`:`${isAct?"▾":"▸"} ${hasWhy?"Why no events?":""}`}
                      </div>}
                    </div>
                  </div>
                  {/* Expanded: show events OR why explanation */}
                  {isAct&&hasEv&&s.events.map((evt,ei)=>(
                    <div key={ei} style={{marginTop:10,marginLeft:40,padding:"10px 14px",background:"#f8f5f0",borderRadius:8,border:"1px solid #e5e0d8"}}>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                        <code style={{fontSize:15,fontWeight:700,color:"#1d4ed8",fontFamily:"'Source Code Pro',monospace"}}>{evt.id}</code>
                        {evt.logon!=null&&<span style={{fontSize:9.5,padding:"2px 7px",borderRadius:4,fontWeight:700,fontFamily:"'Source Code Pro',monospace",background:(LM[evt.logon]?.c||"#666")+"14",color:LM[evt.logon]?.c,border:`1.5px solid ${LM[evt.logon]?.c}30`}}>T{evt.logon} {LM[evt.logon]?.n}</span>}
                        <span style={{fontSize:12,color:"#334155"}}>{evt.t}</span>
                      </div>
                      {evt.f&&<FieldTable fields={evt.f} accent="#1d4ed8"/>}
                    </div>
                  ))}
                  {isAct&&!hasEv&&hasWhy&&(
                    <div style={{marginTop:10,marginLeft:40,padding:"12px 16px",background:"#fefce8",borderRadius:8,border:"1.5px solid #fde68a"}}>
                      <div style={{display:"flex",alignItems:"flex-start",gap:8}}>
                        <span style={{fontSize:14,flexShrink:0}}>💡</span>
                        <div>
                          <div style={{fontSize:10,fontWeight:700,color:"#854d0e",letterSpacing:".5px",textTransform:"uppercase",marginBottom:4,fontFamily:"'Source Code Pro',monospace"}}>Why no Windows Security event here</div>
                          <div style={{fontSize:12.5,color:"#713f12",lineHeight:1.65}}>{s.why}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Right panel */}
          <div style={{width:340,minWidth:300,padding:"16px 20px",background:"#f8f5f0",overflowY:"auto"}}>
            <div style={{background:"#fffdf9",border:"1.5px solid #ebe3d5",borderRadius:10,padding:"14px 18px",borderLeft:`4px solid ${cat.c}`,marginBottom:16}}>
              <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:6,color:cat.c,fontFamily:"'Source Code Pro',monospace"}}>
                {sc.cat==="attack"?"⚠ Detection Notes":"📋 Analysis Notes"}
              </div>
              <p style={{fontSize:12.5,color:"#3f3f46",lineHeight:1.7,margin:0}}>{sc.notes}</p>
            </div>

            <div style={{marginBottom:16}}>
              <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:6,color:"#78716c",fontFamily:"'Source Code Pro',monospace"}}>MITRE ATT&CK</div>
              <div style={{fontSize:11.5,color:"#475569",fontFamily:"'Source Code Pro',monospace",padding:"6px 10px",background:"#fff",borderRadius:6,border:"1px solid #e5e0d8"}}>{sc.mitre}</div>
            </div>

            <div style={{marginBottom:16}}>
              <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:6,color:"#78716c",fontFamily:"'Source Code Pro',monospace"}}>Devices in Scenario</div>
              <div style={{display:"flex",flexDirection:"column",gap:4}}>
                {sc.devices.map((d,i)=>(<div key={i} style={{fontSize:11.5,padding:"5px 10px",background:"#fff",borderRadius:6,border:"1px solid #e5e0d8",color:"#334155",fontWeight:500}}>{d}</div>))}
              </div>
            </div>

            {IMP[sc.id]&&(
              <div style={{marginBottom:16,background:"#1e293b",border:"1.5px solid #334155",borderRadius:10,padding:"14px 18px",color:"#e2e8f0"}}>
                <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:8,color:"#f59e0b",fontFamily:"'Source Code Pro',monospace"}}>🐍 Impacket / Tool Signatures</div>
                <div style={{marginBottom:10}}>
                  <div style={{fontSize:10,color:"#94a3b8",fontWeight:600,marginBottom:3}}>TOOL</div>
                  <div style={{fontSize:12,color:"#fbbf24",fontFamily:"'Source Code Pro',monospace",fontWeight:600}}>{IMP[sc.id].tool}</div>
                </div>
                <div style={{marginBottom:10}}>
                  <div style={{fontSize:10,color:"#94a3b8",fontWeight:600,marginBottom:3}}>COMMAND</div>
                  <div style={{fontSize:10.5,color:"#cbd5e1",fontFamily:"'Source Code Pro',monospace",background:"#0f172a",padding:"8px 10px",borderRadius:6,whiteSpace:"pre-wrap",wordBreak:"break-all",lineHeight:1.5}}>{IMP[sc.id].cmd}</div>
                </div>
                <div style={{marginBottom:10}}>
                  <div style={{fontSize:10,color:"#94a3b8",fontWeight:600,marginBottom:3}}>LOG ARTIFACTS ON TARGET</div>
                  <div style={{display:"flex",flexDirection:"column",gap:4}}>
                    {IMP[sc.id].logs.map((l,i)=>(<div key={i} style={{fontSize:10.5,color:"#e2e8f0",lineHeight:1.5,paddingLeft:10,borderLeft:"2px solid #475569",fontFamily:"'Source Code Pro',monospace"}}>{l}</div>))}
                  </div>
                </div>
                <div>
                  <div style={{fontSize:10,color:"#94a3b8",fontWeight:600,marginBottom:3}}>DETECTION SIGNATURE</div>
                  <div style={{fontSize:11,color:"#fbbf24",lineHeight:1.55,fontStyle:"italic"}}>{IMP[sc.id].sig}</div>
                </div>
              </div>
            )}

            {sc.normal&&!showNormal&&(
              <div style={{background:"#ecfdf5",border:"1.5px solid #a7f3d0",borderRadius:10,padding:"14px 18px"}}>
                <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:6,color:"#047857",fontFamily:"'Source Code Pro',monospace"}}>🟢 How Normal Looks Different</div>
                <p style={{fontSize:12,color:"#065f46",lineHeight:1.6,margin:0}}>{sc.normal.key}</p>
                <button onClick={()=>{setShowNormal(true);setActiveStep(null);}} style={{marginTop:8,padding:"5px 12px",borderRadius:6,border:"1.5px solid #a7f3d0",background:"#fff",color:"#047857",fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"'Libre Franklin',sans-serif"}}>View Normal Flow →</button>
              </div>
            )}
            {showNormal&&(
              <div style={{background:"#fef2f2",border:"1.5px solid #fecaca",borderRadius:10,padding:"14px 18px"}}>
                <div style={{fontSize:9.5,fontWeight:700,letterSpacing:"1px",textTransform:"uppercase",marginBottom:6,color:"#b91c1c",fontFamily:"'Source Code Pro',monospace"}}>🔴 View Attack Flow</div>
                <p style={{fontSize:12,color:"#7f1d1d",lineHeight:1.6,margin:0}}>Switch back to see how the attacker exploits this scenario.</p>
                <button onClick={()=>{setShowNormal(false);setActiveStep(null);}} style={{marginTop:8,padding:"5px 12px",borderRadius:6,border:"1.5px solid #fecaca",background:"#fff",color:"#b91c1c",fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"'Libre Franklin',sans-serif"}}>View Attack Flow →</button>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
