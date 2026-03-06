
<body>

<h1>CRT Modernized Edition — Release Notes</h1>
<h3>v1.1 — Public Fork of CrowdStrike Reporting Tool for Azure/M365</h3>
<hr>

<h2>Overview</h2>
<p>This is a community-maintained, modernized fork of the <a href="https://github.com/CrowdStrike/CRT">CrowdStrike Reporting Tool for Azure/M365 (CRT)</a>, originally authored by CrowdStrike Endpoint Recovery Services. The original tool relied on the <code>AzureAD</code> and <code>MSOnline</code> PowerShell modules, both of which Microsoft has deprecated and removed. This release replaces those dependencies entirely with the <strong>Microsoft Graph SDK</strong> and <strong>Microsoft Graph REST API</strong>, restoring full functionality and extending the tool with new reports, risk classification, and a browser-based dashboard.</p>
<blockquote>
<p><strong>License:</strong> This fork retains the original CrowdStrike MIT license. See the license header in the script for full terms.</p>
</blockquote>
<hr>

<h2>What's New in v1.1</h2>
<h3>Core Modernization</h3>
<ul>
<li><strong>AzureAD module fully replaced</strong> with <code>Microsoft.Graph</code> SDK (<code>Connect-MgGraph</code>). All Graph calls use the v1.0 endpoint with automatic pagination via <code>@odata.nextLink</code>.</li>
<li><strong>MSOnline module fully replaced</strong> with Microsoft Graph REST API equivalents.</li>
<li><strong>ExchangeOnlineManagement v3+</strong> retained and required. All Exchange cmdlets use the modern <code>Get-EXO*</code> variants (<code>Get-EXOMailbox</code>, <code>Get-EXOCASMailbox</code>, <code>Get-EXOMailboxPermission</code>, <code>Get-EXORecipientPermission</code>) which are significantly faster than their legacy counterparts for large tenants.</li>
<li><strong>Single authentication session</strong> — one <code>Connect-MgGraph</code> call and one <code>Connect-ExchangeOnline</code> call at startup with all required scopes declared up front, replacing the scattered, per-report auth calls in the original.</li>
<li><strong>App-only (unattended) authentication</strong> added via <code>-TenantId</code>, <code>-AppId</code>, and <code>-CertificateThumbprint</code> parameters, enabling scheduled/automated runs without interactive sign-in.</li>
<li><strong>Full transcript logging</strong> — all console output, warnings, and errors are captured to <code>CRTTranscript.txt</code> in the output folder. A structured <code>CRTRun.log</code> is also written with per-report timing and completion status.</li>
<li><strong>Resilient execution</strong> — individual report failures no longer abort the run. Failed reports are logged and skipped; all other reports continue to completion.</li>
</ul>

<h3>New Reports</h3>
<p>Four reports have been added that did not exist in the original CRT:</p>

<p><strong><code>MailboxRules</code></strong> — Audits inbox rules across all user mailboxes in the tenant.</p>
<ul>
<li>Classifies each rule's action type: <code>ExternalForward</code>, <code>ExternalRedirect</code>, <code>ExternalForwardAsAttach</code>, <code>Forward</code>, <code>Redirect</code>, <code>Delete</code>, <code>Move</code>, <code>Copy</code>, <code>MarkRead</code>, <code>Multiple</code>, or <code>Other</code>.</li>
<li>Detects external vs. internal forward/redirect targets by comparing against all verified tenant domains.</li>
<li>Flags rules whose conditions match security-related keywords (<code>password</code>, <code>MFA</code>, <code>reset</code>, <code>security alert</code>, <code>Microsoft</code>, etc.) — a common attacker technique for suppressing authentication and breach notifications.</li>
<li>Risk levels: <strong>HIGH</strong> (external forward/redirect, delete), <strong>MEDIUM</strong> (internal forward, security keyword conditions), <strong>LOW</strong> (passive rules).</li>
</ul>

<p><strong><code>EnterpriseApps</code></strong> — Audits all service principals (Enterprise Applications) registered in the tenant.</p>
<ul>
<li>Surfaces publisher verification status, multi-tenant vs. single-tenant classification, credential inventory (secrets and certificates with expiry status), and permission summary.</li>
<li>Cross-references delegated OAuth2 grants and application role assignments to produce a per-app permission risk tier.</li>
<li>Risk levels: <strong>CRITICAL</strong> (tenant-takeover-capable permissions), <strong>HIGH</strong> (broad mail/file/user write permissions or multi-tenant unverified with credentials), <strong>MEDIUM</strong> (sensitive read-only permissions or expired credentials), <strong>LOW</strong>, <strong>INFO</strong> (no permissions).</li>
<li>Excludes Microsoft first-party service principals by default to reduce noise and focus on third-party and custom apps.</li>
</ul>

<p><strong><code>SignInSummary</code></strong> — Per-user summary of sign-in activity over the past 30 days (configurable via parameter).</p>
<ul>
<li>Aggregates risk signals per user: foreign countries accessed from, legacy authentication usage, MFA-skipped count, impossible travel detections, and password spray indicators.</li>
<li>Surfaces privileged accounts (via <code>PrivilegedRole</code> column) for elevated scrutiny — foreign logins or legacy auth on admin accounts warrant immediate review.</li>
<li>Intended as the starting point for sign-in investigation. Foreign logins and legacy auth are common in legitimate environments (VPNs, travel, service accounts); the goal is to identify accounts where the pattern cannot be explained by normal business activity.</li>
<li>Accounts with both impossible travel and a successful sign-in are the highest priority. Multiple unrelated foreign countries within the same period is more notable than a single country.</li>
<li>Risk level: <strong>HIGH</strong>.</li>
</ul>

<p><strong><code>SignInFlagged</code></strong> — Individual sign-in events classified as MEDIUM, HIGH, or CRITICAL. Produced alongside <code>SignInSummary</code> as a drill-down companion file.</p>
<ul>
<li>Captures specific events with one or more risk signals: foreign location, legacy auth protocol, MFA not satisfied, Identity Protection elevated risk, impossible travel, or a success-after-failures pattern.</li>
<li>Intended for use after identifying accounts of interest in <code>SignInSummary</code> — filter by <code>UserPrincipalName</code> to see all flagged events for a specific account.</li>
<li>Each event includes <code>IPAddress</code>, <code>Country</code>, <code>ResourceDisplayName</code>, MFA status, and <code>ErrorCode</code>. Error code <code>0</code> indicates success; non-zero values are failed attempts.</li>
<li>A CRITICAL row (foreign successful sign-in on a privileged account) should be investigated by confirming the sign-in with the account owner directly.</li>
<li>Risk level: <strong>HIGH</strong>.</li>
</ul>

<h3>Enhanced Existing Reports</h3>
<p>All original reports are preserved with the following enhancements:</p>
<table>
<thead>
<tr><th>Report</th><th>Enhancement</th></tr>
</thead>
<tbody>
<tr><td>O365AdminGroups</td><td>Role sensitivity tiers (CRITICAL / HIGH / MEDIUM) added. Member-level risk flags for guest accounts, service principals, and accounts with no UPN assigned to admin roles.</td></tr>
<tr><td>DelegateAppPerms</td><td>Permission risk tiers (CRITICAL / HIGH / MEDIUM / LOW) added for both delegated and application permission types. Distinguishes admin-consented (AllPrincipals) from user-consented (Principal) grants.</td></tr>
<tr><td>SMTPForward</td><td>External vs. internal forwarding detection against verified tenant domains. Risk classification (HIGH / MEDIUM / LOW) with flags for missing DeliverToMailboxAndForward on internal forwards.</td></tr>
<tr><td>TransportRules</td><td>Action type classification (ExternalForward, ExternalBCC, Delete, ModifyHeader, etc.). Flags disabled rules with dangerous actions as potentially staged. Detects SCL=-1 spam filter bypass.</td></tr>
<tr><td>KeyCredentials</td><td>Expiry tracking for both key credentials (certificates) and password credentials (client secrets) on all app registrations and service principals. IsExpired and DaysUntilExpiry fields added.</td></tr>
<tr><td>All reports</td><td>Structured investigative tips written to the summary file with finding counts, risk breakdowns, and analyst guidance for each report section.</td></tr>
</tbody>
</table>
<hr>

<h2>Available Report Names (for <code>-Commands</code>)</h2>
<pre><code>FedConfig           FedTrust            ClientAccess        RemoteDomains
SMTPForward         TransportRules      FullAccessGranted   AnyAccessGranted
SendAsGranted       EXOPowerShell       AuditBypassEnabled  HiddenMailboxes
KeyCredentials      O365AdminGroups     DelegateAppPerms    AdminAuditLogConfig
MailboxRules        EnterpriseApps      SignInSummary       SignInFlagged</code></pre>
<hr>

<h2>Known Limitations</h2>
<ul>
<li><strong>Partner/GDAP delegated admin information</strong> is no longer retrievable via PowerShell. Manual review steps are documented in the <code>PartnerInfo_MANUAL.txt</code> output file.</li>
<li><strong>Mailbox rule creation dates</strong> are not exposed by Exchange Online. <code>DateLastModified</code> is included where available but may be null for rules that have never been edited.</li>
<li><strong><code>MailboxRules</code> and <code>FullAccessGranted</code></strong> are resource-intensive in large tenants as they enumerate every mailbox individually. Plan for extended run times in environments with thousands of mailboxes.</li>
<li><strong>PIM (Privileged Identity Management) eligible roles</strong> are surfaced on a best-effort basis depending on tenant license level. The <code>O365AdminGroups</code> report reflects currently <em>active</em> role assignments.</li>
<li><strong>Federation configuration detail</strong> varies depending on tenant license level.</li>
</ul>

<h2>New: Report Dashboard and Technician Runbook</h2>
<ul>
<li><strong>CRT-Dashboard-V2.html</strong> is a self-contained web page that loads the JSON output files and renders them as filterable, color-coded tables. No internet connection or server is required — open it directly in a browser.</li>
<li><strong>CRT-Technician-Runbook-V2.docx</strong> is a technician guide to using and interpreting the reports in this tool.</li>
</ul>
<hr>

<h2>Acknowledgements</h2>
<p>Original tool written by <strong>CrowdStrike Endpoint Recovery Services</strong>. This fork modernizes the tooling for continued use following Microsoft's deprecation of the AzureAD and MSOnline PowerShell modules. All credit for the original report design and investigative methodology belongs to the CrowdStrike CRT team.</p>

</body>
</html>
