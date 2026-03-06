<#
.SYNOPSIS
    CrowdStrike Reporting Tool for Azure/M365 (CRT) - Modernized Edition
    Replaces deprecated AzureAD/MSOnline modules with Microsoft Graph SDK and REST API.

.DESCRIPTION
    Queries M365/Azure AD tenant configurations to surface hard-to-find permissions
    and settings relevant to incident response and security auditing.

    Modernization changes (V2.0):
      - AzureAD module replaced with Microsoft.Graph SDK (Connect-MgGraph)
      - MSOnline module replaced with Microsoft.Graph SDK
      - ExchangeOnlineManagement v3+ retained (EXO cmdlets still current)
      - Single Connect-MgGraph call at startup with all required scopes declared
      - Single Connect-ExchangeOnline call at startup
      - Added -TenantId / -AppId / -CertificateThumbprint for app-only (unattended) auth
      - All report output formats (JSON, CSV, TXT) and filenames preserved
      - Field names mapped to match original AzureAD cmdlet output names where possible

    Required Graph Permission Scopes (Delegated or Application):
      Directory.Read.All
      AuditLog.Read.All
      RoleManagement.Read.Directory
      Domain.Read.All
      Application.Read.All
      Policy.Read.All
      Organization.Read.All
      User.Read.All
      Group.Read.All
      PrivilegedAccess.Read.AzureAD  (for PIM role data if available)

    Required Exchange Online permissions:
      View-Only Organization Management  (minimum)
      OR Global Admin / Exchange Admin

    Known Limitations vs V1.x:
      - Partner/GDAP delegated admin info is no longer queryable via PowerShell;
        see the note in the PartnerInfo placeholder output for manual steps.
      - Some AzureAD property names differ slightly in Graph; field mapping comments
        are included inline where this occurs.
      - Federation configuration detail depends on tenant license level.

.PARAMETER JobName
    [OPTIONAL] Name for this audit job. Used as the output folder name prefix.
    Defaults to a UTC timestamp (YYYYDDMMTHHmm).

.PARAMETER WorkingDirectory
    [OPTIONAL] Path where the output folder will be created.
    Defaults to the directory the script is run from.

.PARAMETER Commands
    [OPTIONAL] Comma- or space-separated list of specific report names to run.
    Valid values: FedConfig, FedTrust, ClientAccess, RemoteDomains, SMTPForward,
    TransportRules, FullAccessGranted, AnyAccessGranted, SendAsGranted,
    EXOPowerShell, AuditBypassEnabled, HiddenMailboxes, KeyCredentials,
    O365AdminGroups, DelegateAppPerms, AdminAuditLogConfig
    If omitted, all reports are run.

.PARAMETER Interactive
    [OPTIONAL] Switch. Reserved for compatibility; in V2 all auth is handled
    at the start of the script via Connect-MgGraph / Connect-ExchangeOnline.

.PARAMETER ExchangeEnvironmentName
    [OPTIONAL] Exchange Online environment. Default: O365Default.
    Valid: O365China, O365Default, O365GermanyCloud, O365USGovDoD, O365USGovGCCHigh

.PARAMETER AzureEnvironmentName
    [OPTIONAL] Azure/Graph environment. Default: Global.
    Valid: Global, China, USGov, USGovDoD

.PARAMETER TenantId
    [OPTIONAL] Azure AD Tenant ID (GUID or domain). Required for app-only auth.

.PARAMETER AppId
    [OPTIONAL] Application (client) ID for app-only authentication.

.PARAMETER CertificateThumbprint
    [OPTIONAL] Certificate thumbprint for app-only authentication.

.NOTES
    CrowdStrike Reporting Tool for Azure (CRT) - Modernized Edition
    Original tool written by CrowdStrike Endpoint Recovery Services
    Modernization: V2.0 - Graph API migration

    Version History:
    V2.0 - Current - AzureAD/MSOnline replaced with Microsoft.Graph SDK
                     Single-session authentication
                     App-only auth support added

    V1.3, 04/06/2023 (original)
    V1.0, 12/23/2020 (original)

    License: Copyright (c) 2020 CrowdStrike
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

.EXAMPLE
    # Run all reports, interactive delegated auth
    .\Get-CRTReport.ps1

.EXAMPLE
    # Run all reports with a named job and specific output path
    .\Get-CRTReport.ps1 -JobName MyAudit -WorkingDirectory 'C:\Audits'

.EXAMPLE
    # Run only specific reports
    .\Get-CRTReport.ps1 -Commands "KeyCredentials,O365AdminGroups,DelegateAppPerms"

.EXAMPLE
    # App-only (unattended) authentication with certificate
    .\Get-CRTReport.ps1 -TenantId "contoso.onmicrosoft.com" -AppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -CertificateThumbprint "AABBCC..."

.EXAMPLE
    # GCC High tenant
    .\Get-CRTReport.ps1 -ExchangeEnvironmentName O365USGovGCCHigh -AzureEnvironmentName USGov
#>

#Requires -Version 5.1

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [string]$JobName,

    [Parameter(Mandatory = $false)]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $false)]
    [string]$Commands,

    [Parameter(Mandatory = $false)]
    [Switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [ValidateSet("O365China", "O365Default", "O365GermanyCloud", "O365USGovDoD", "O365USGovGCCHigh")]
    [String]$ExchangeEnvironmentName = "O365Default",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Global", "China", "USGov", "USGovDoD")]
    [String]$AzureEnvironmentName = "Global",

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string]$HomeCountry = "US",

    [Parameter(Mandatory = $false)]
    [int]$SignInDays = 30
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

#region ── CONSTANTS & VALID COMMANDS ──────────────────────────────────────────

$ValidCommands = @(
    "FedConfig", "FedTrust", "ClientAccess", "RemoteDomains", "SMTPForward",
    "TransportRules", "FullAccessGranted", "AnyAccessGranted", "SendAsGranted",
    "EXOPowerShell", "AuditBypassEnabled", "HiddenMailboxes", "KeyCredentials",
    "O365AdminGroups", "DelegateAppPerms", "AdminAuditLogConfig", "MailboxRules", "EnterpriseApps", "SignInActivity"
)

# Required Graph scopes — all declared up-front so Connect-MgGraph can request them in one call
$GraphScopes = @(
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "Domain.Read.All",
    "Application.Read.All",
    "Policy.Read.All",
    "Organization.Read.All",
    "User.Read.All",
    "Group.Read.All"
)

#endregion

#region ── HELPER FUNCTIONS ────────────────────────────────────────────────────

# Script-scoped log file path - set once the output directory is created
$script:LogFile = $null

function Write-Log {
    Param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ssZ")
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line

    if ($script:LogFile) {
        try {
            $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        } catch {
            Write-Host "[LOG WRITE FAILED] $_"
        }
    }
}

function Write-LogError {
    Param(
        [string]$Message,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    Write-Log -Message $Message -Level "ERROR"
    if ($ErrorRecord -and $script:LogFile) {
        $detail = "  Exception  : " + $ErrorRecord.Exception.GetType().FullName + "`n"
        $detail += "  Message    : " + $ErrorRecord.Exception.Message + "`n"
        $detail += "  ScriptLine : " + $ErrorRecord.InvocationInfo.ScriptLineNumber + "`n"
        $detail += "  Statement  : " + $ErrorRecord.InvocationInfo.Line.Trim() + "`n"
        $detail += "  StackTrace :`n" + $ErrorRecord.ScriptStackTrace
        $detail | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
}

function Out-Summary {
    Param([string]$String, [string]$SummaryFile)
    $String | Out-File -FilePath $SummaryFile -Append -Encoding UTF8
}

function Save-Report {
    <#
    .SYNOPSIS Saves a report object to JSON, CSV, and TXT files.
    #>
    Param(
        [string]$ReportName,
        [object]$Data,
        [string]$ReportsDir,
        [string]$SummaryFile,
        [string]$SectionHeader = "",
        [string]$InvestigativeTip = ""
    )

    $jsonPath = Join-Path $ReportsDir "$ReportName.json"
    $csvPath  = Join-Path $ReportsDir "$ReportName.csv"
    $txtPath  = Join-Path $ReportsDir "$ReportName.txt"

    # Sanitize: remove any null entries that would crash Export-Csv
    $cleanData = @($Data | Where-Object { $_ -ne $null })

    # JSON
    $cleanData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Log "[+] Saved $ReportName JSON  -> $jsonPath"

    # CSV
    if ($cleanData.Count -gt 0) {
        try {
            $cleanData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "[+] Saved $ReportName CSV   -> $csvPath"
        } catch {
            Write-LogError -Message "[!] CSV export failed for $ReportName" -ErrorRecord $_
        }
    } else {
        "No data returned" | Out-File -FilePath $csvPath -Encoding UTF8
        Write-Log "[+] Saved $ReportName CSV   -> $csvPath (empty)"
    }

    # TXT (human-readable table)
    if ($cleanData.Count -gt 0) {
        try {
            $cleanData | Format-List | Out-File -FilePath $txtPath -Encoding UTF8
            Write-Log "[+] Saved $ReportName TXT   -> $txtPath"
        } catch {
            Write-LogError -Message "[!] TXT export failed for $ReportName" -ErrorRecord $_
        }
    } else {
        "No data returned" | Out-File -FilePath $txtPath -Encoding UTF8
        Write-Log "[+] Saved $ReportName TXT   -> $txtPath (empty)"
    }

    # Append to summary
    if ($SectionHeader) {
        Out-Summary -String "`r`n$SectionHeader" -SummaryFile $SummaryFile
    }
    if ($InvestigativeTip) {
        Out-Summary -String $InvestigativeTip -SummaryFile $SummaryFile
    }
    if ($Data) {
        ($Data | Format-List | Out-String) | Out-File -FilePath $SummaryFile -Append -Encoding UTF8
    } else {
        Out-Summary -String "(No results returned for $ReportName)" -SummaryFile $SummaryFile
    }
}

function Invoke-GraphRequestAll {
    <#
    .SYNOPSIS Wraps Invoke-MgGraphRequest with automatic @odata.nextLink pagination.
    Returns all results across all pages.
    #>
    Param(
        [string]$Uri,
        [string]$Method = "GET"
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    do {
        try {
            $response = Invoke-MgGraphRequest -Method $Method -Uri $nextUri -OutputType PSObject
            if ($response.value) {
                foreach ($item in $response.value) { $results.Add($item) }
            }
            $nextUri = $response.'@odata.nextLink'
        } catch {
            Write-Log "[!] Graph request failed for $nextUri : $_"
            break
        }
    } while ($nextUri)
    return $results
}

#endregion

#region ── MODULE MANAGEMENT ───────────────────────────────────────────────────

function Install-RequiredModules {
    Write-Log "Checking required PowerShell modules..."

    # Microsoft.Graph (meta-module pulls sub-modules needed)
    $graphModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.Governance"
    )

    foreach ($mod in $graphModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Log "Installing $mod ..."
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            } catch {
                Write-Log "[!] Failed to install $mod : $_"
            }
        }
    }

    # ExchangeOnlineManagement v3+
    $exoMod = Get-Module -ListAvailable -Name "ExchangeOnlineManagement" |
              Sort-Object Version -Descending | Select-Object -First 1
    if (-not $exoMod -or $exoMod.Version -lt [Version]"3.0.0") {
        Write-Log "Installing/updating ExchangeOnlineManagement (v3+)..."
        try {
            Install-Module -Name ExchangeOnlineManagement -MinimumVersion "3.0.0" `
                -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        } catch {
            Write-Log "[!] Failed to install ExchangeOnlineManagement: $_"
        }
    }

    # Import modules
    foreach ($mod in $graphModules) {
        try { Import-Module $mod -Force -ErrorAction Stop } catch {
            Write-Log "[!] Could not import $mod : $_"
        }
    }
    try { Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop } catch {
        Write-Log "[!] Could not import ExchangeOnlineManagement: $_"
    }

    Write-Log "Module check complete."
}

#endregion

#region ── AUTHENTICATION ──────────────────────────────────────────────────────

function Connect-AllServices {
    Param(
        [string]$AzureEnv,
        [string]$ExchangeEnv,
        [string]$TenantId,
        [string]$AppId,
        [string]$CertThumbprint
    )

    # ── Graph ─────────────────────────────────────────────────────────────────
    Write-Log "Connecting to Microsoft Graph..."

    # Map AzureEnvironmentName to Graph -Environment parameter name
    $graphEnvMap = @{
        "Global"   = "Global"
        "China"    = "China"
        "USGov"    = "USGov"
        "USGovDoD" = "USGovDoD"
    }
    $graphEnv = $graphEnvMap[$AzureEnv]

    $connectParams = @{ Scopes = $GraphScopes; Environment = $graphEnv; NoWelcome = $true }

    if ($AppId -and $CertThumbprint -and $TenantId) {
        # App-only / unattended
        Write-Log "Using app-only authentication (AppId + Certificate)."
        $connectParams = @{
            TenantId              = $TenantId
            ClientId              = $AppId
            CertificateThumbprint = $CertThumbprint
            Environment           = $graphEnv
            NoWelcome             = $true
        }
    } elseif ($TenantId) {
        $connectParams["TenantId"] = $TenantId
    }

    try {
        Connect-MgGraph @connectParams
        Write-Log "Successfully connected to Microsoft Graph."
    } catch {
        Write-Log "[!] Failed to connect to Microsoft Graph: $_"
        throw
    }

    # ── Exchange Online ────────────────────────────────────────────────────────
    Write-Log "Connecting to Exchange Online..."

    # Device:$true forces device code flow, bypassing the WAM broker which crashes
    # with NullReferenceException in embedded terminals and OneDrive-synced paths.
    # You will be prompted once to visit https://microsoft.com/devicelogin with a short code.
    $exoParams = @{
        ShowBanner   = $false
        ShowProgress = $false
    }

    # Non-interactive app-only path — no device code needed
    if ($AppId -and $CertThumbprint -and $TenantId) {
        $exoParams["AppId"]                 = $AppId
        $exoParams["CertificateThumbprint"] = $CertThumbprint
        $exoParams["Organization"]          = $TenantId
    } else {
        # Force device code auth to avoid WAM broker crash in non-windowed contexts
        $exoParams["Device"] = $true
    }

    # Map non-default Exchange environments
    switch ($ExchangeEnv) {
        "O365USGovGCCHigh" { $exoParams["ExchangeEnvironmentName"] = "O365USGovGCCHigh" }
        "O365USGovDoD"     { $exoParams["ExchangeEnvironmentName"] = "O365USGovDoD" }
        "O365GermanyCloud" { $exoParams["ExchangeEnvironmentName"] = "O365GermanyCloud" }
        "O365China"        { $exoParams["ExchangeEnvironmentName"] = "O365China" }
        default            { }
    }

    try {
        Connect-ExchangeOnline @exoParams
        Write-Log "Successfully connected to Exchange Online."
    } catch {
        Write-Log "[!] Failed to connect to Exchange Online: $_"
        Write-Log "    If this persists, try running from a standard PowerShell window (not embedded terminal)."
        throw
    }
}

#endregion

#region ── GRAPH-BASED REPORT FUNCTIONS ────────────────────────────────────────

function Get-FedConfigReport {
    <#
    .SYNOPSIS
    Federation configuration for all verified domains in the tenant.
    Replaces: Get-MsolFederationProperty / Get-AzureADDomainFederationSettings
    New API:  GET /domains  +  GET /domains/{id}/federationConfiguration
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Federation Configuration..."

    $domains = Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/domains"
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($domain in $domains) {
        $fedConfig = $null
        if ($domain.authenticationType -eq "Federated") {
            try {
                $fedDetails = Invoke-GraphRequestAll `
                    -Uri "https://graph.microsoft.com/v1.0/domains/$($domain.id)/federationConfiguration"
                $fedConfig = $fedDetails | Select-Object -First 1
            } catch {
                Write-Log "[!] Could not retrieve federation config for $($domain.id): $_"
            }
        }

        $results.Add([PSCustomObject]@{
            # Field mapping: Graph domain.id == MSOnline/AzureAD domain name
            Domain                     = $domain.id
            AuthenticationType         = $domain.authenticationType       # "Managed" or "Federated"
            IsDefault                  = $domain.isDefault
            IsVerified                 = $domain.isVerified
            IsInitial                  = $domain.isInitial
            # Federation details (null for Managed domains)
            IssuerUri                  = $fedConfig.issuerUri
            PassiveSignInUri           = $fedConfig.passiveSignInUri       # was: FederationServiceIdentifier
            ActiveSignInUri            = $fedConfig.activeSignInUri        # was: ActiveLogOnUri
            MetadataExchangeUri        = $fedConfig.metadataExchangeUri    # was: MetadataExchangeUri
            SigningCertificate         = $fedConfig.signingCertificate
            NextSigningCertificate     = $fedConfig.nextSigningCertificate
            FederatedIdpMfaBehavior    = $fedConfig.federatedIdpMfaBehavior
            PromptLoginBehavior        = $fedConfig.promptLoginBehavior
            PreferredAuthenticationProtocol = $fedConfig.preferredAuthenticationProtocol
        })
    }

    Save-Report -ReportName "FedConfig" -Data $results `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Federation Configuration #######" `
        -InvestigativeTip "Review federated domains for unexpected or unauthorized federation configurations. Investigate any federation endpoints pointing to unknown identity providers."
}

function Get-FedTrustReport {
    <#
    .SYNOPSIS
    Federation trust information from Exchange Online.
    Get-FederationTrust is still a valid Exchange Online cmdlet.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Federation Trust information..."

    try {
        $fedTrusts = Get-FederationTrust -ErrorAction Stop
        $results = $fedTrusts | Select-Object Name, ApplicationIdentifier, ApplicationUri,
            TokenIssuerUri, TokenIssuerCertificate, TokenIssuerMetadataEPR,
            TokenIssuerType, OrgCertificate, OrgPrivCertificate, PolicyReferenceUri,
            Enabled, NamespaceProvisioned

        Save-Report -ReportName "FedTrust" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Federation Trust #######" `
            -InvestigativeTip "Review federation trusts for any unexpected or unauthorized trust relationships."
    } catch {
        Write-LogError -Message "[!] FedTrust error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "FedTrust" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Federation Trust #######"
    }
}

function Get-EnterpriseAppsReport {
    <#
    .SYNOPSIS
    All service principals (Enterprise Applications) in the tenant with publisher verification,
    permission summary, credential status, and risk classification.
    API: GET /servicePrincipals (Graph v1.0)

    Excludes Microsoft first-party service principals by default (appOwnerOrganizationId matching
    Microsoft's known tenant ID f8cdef31-a31e-4b4a-93e4-5f571e91255a) to focus on third-party
    and custom apps. Set -IncludeMicrosoftApps to include them.

    RiskLevel:
      CRITICAL - App has CRITICAL-tier permissions (see DelegateAppPerms for definition)
      HIGH     - Multi-tenant app with HIGH permissions, OR unverified publisher with credentials,
                 OR recently created app with sensitive permissions
      MEDIUM   - Multi-tenant app with no credentials, OR single-tenant with HIGH permissions,
                 OR app with credentials expiring/expired
      LOW      - Single-tenant, verified publisher, low-sensitivity permissions
      INFO     - No permissions assigned (passive / SSO-only apps)
    #>
    Param(
        [string]$ReportsDir,
        [string]$SummaryFile,
        [switch]$IncludeMicrosoftApps
    )

    Write-Log "Retrieving Enterprise Applications (Service Principals)..."

    # Microsoft's first-party tenant ID - used to identify built-in MS apps
    $microsoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

    # Permission risk lookups (same sets as DelegateAppPerms for consistency)
    $criticalPerms = @(
        'RoleManagement.ReadWrite.Directory','Directory.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All','Application.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All','PrivilegedAccess.ReadWrite.AzureAD',
        'Policy.ReadWrite.Authorization','Organization.ReadWrite.All',
        'UserAuthenticationMethod.ReadWrite.All','full_access_as_app','full_access_as_user'
    )
    $highPerms = @(
        'Mail.ReadWrite','Mail.ReadWrite.All','Mail.Send','Mail.Send.All',
        'MailboxSettings.ReadWrite','Files.ReadWrite.All','Sites.ReadWrite.All',
        'Sites.FullControl.All','User.ReadWrite.All','User.ManageIdentities.All',
        'Group.ReadWrite.All','GroupMember.ReadWrite.All','AuditLog.Read.All',
        'SecurityEvents.ReadWrite.All','SecurityAlert.ReadWrite.All',
        'IdentityRiskEvent.ReadWrite.All','DeviceManagementApps.ReadWrite.All',
        'DeviceManagementConfiguration.ReadWrite.All','AccessReview.ReadWrite.All',
        'Chat.ReadWrite.All','TeamSettings.ReadWrite.All'
    )

    function Get-PermRiskTier {
        param([string]$Perm)
        if ($criticalPerms -contains $Perm) { return "CRITICAL" }
        if ($highPerms     -contains $Perm) { return "HIGH" }
        return "OTHER"
    }

    # Load all SPs with the fields we need
    Write-Log "  Loading service principal list..."
    $allSPs = Invoke-GraphRequestAll -Uri (
        "https://graph.microsoft.com/v1.0/servicePrincipals" +
        "?`$select=id,displayName,appId,appOwnerOrganizationId,servicePrincipalType," +
        "accountEnabled,createdDateTime,verifiedPublisher,homepage,replyUrls," +
        "passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes," +
        "publisherName,description,notes,tags"
    )

    # Load all app role assignments for permission summary (already done in DelegateAppPerms
    # but we need counts here - load freshly to be self-contained)
    Write-Log "  Loading OAuth2 delegated grants for permission summary..."
    $allGrants = @{}
    try {
        $grants = Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
        foreach ($g in $grants) {
            if (-not $allGrants.ContainsKey($g.clientId)) { $allGrants[$g.clientId] = @() }
            $allGrants[$g.clientId] += ($g.scope -split ' ' | Where-Object { $_ })
        }
    } catch {
        Write-Log "  [WARN] Could not load OAuth2 grants for permission summary." -Level "WARN"
    }

    Write-Log "  Loading app role assignments for permission summary..."
    $appRolePerms = @{}
    try {
        foreach ($sp in $allSPs) {
            $assignments = Invoke-GraphRequestAll -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
            ) -ErrorAction SilentlyContinue 2>$null
            if ($assignments) {
                $appRolePerms[$sp.id] = $assignments
            }
        }
    } catch { }

    Write-Log "  Processing $($allSPs.Count) service principals..."
    $results = [System.Collections.Generic.List[object]]::new()
    $now     = [DateTime]::UtcNow

    foreach ($sp in $allSPs) {
        # Skip Microsoft first-party unless requested
        $isMicrosoftFirstParty = ($sp.appOwnerOrganizationId -eq $microsoftTenantId)
        if ($isMicrosoftFirstParty -and -not $IncludeMicrosoftApps) { continue }

        # ── Publisher / ownership info ─────────────────────────────────────────
        $isMultiTenant     = ($sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $microsoftTenantId -and $sp.appOwnerOrganizationId -ne '')
        $isVerified        = ($null -ne $sp.verifiedPublisher -and $sp.verifiedPublisher.verifiedPublisherId)
        $publisherName     = if ($isVerified) { $sp.verifiedPublisher.displayName } elseif ($sp.publisherName) { $sp.publisherName } else { "" }
        $verifiedStatus    = if ($isVerified) { "Verified" } else { "Unverified" }

        # ── Credential summary ─────────────────────────────────────────────────
        $secrets = @($sp.passwordCredentials | Where-Object { $_ })
        $certs   = @($sp.keyCredentials      | Where-Object { $_ })

        $hasCredentials  = ($secrets.Count + $certs.Count) -gt 0
        $expiredCreds    = 0
        $noExpiryCreds   = 0
        $soonExpireCreds = 0

        foreach ($cred in ($secrets + $certs)) {
            if ($cred.endDateTime) {
                $expDate = [DateTime]$cred.endDateTime
                if ($expDate -lt $now)                          { $expiredCreds++    }
                elseif ($expDate -lt $now.AddDays(30))         { $soonExpireCreds++ }
                # Check for very long validity (over 2 years from now) - suspicious
            } else {
                $noExpiryCreds++
            }
        }

        $credSummary = if (-not $hasCredentials) { "None" }
                       else {
                           $parts = @()
                           if ($secrets.Count -gt 0) { $parts += "$($secrets.Count) secret(s)" }
                           if ($certs.Count   -gt 0) { $parts += "$($certs.Count) cert(s)" }
                           if ($expiredCreds   -gt 0) { $parts += "$expiredCreds EXPIRED" }
                           if ($soonExpireCreds -gt 0) { $parts += "$soonExpireCreds expiring <30d" }
                           if ($noExpiryCreds  -gt 0) { $parts += "$noExpiryCreds no-expiry" }
                           $parts -join ', '
                       }

        # ── Permission summary ─────────────────────────────────────────────────
        $delegatedScopes = if ($allGrants.ContainsKey($sp.id)) { $allGrants[$sp.id] } else { @() }
        $appRoleList     = if ($appRolePerms.ContainsKey($sp.id)) {
            # Resolve role names from assignments - quick pass
            @($appRolePerms[$sp.id]) | ForEach-Object { $_.appRoleId }
        } else { @() }

        $totalPermCount  = $delegatedScopes.Count + $appRoleList.Count
        $highestPermTier = "NONE"
        $critPermList    = @()
        $highPermList    = @()

        foreach ($perm in $delegatedScopes) {
            $tier = Get-PermRiskTier $perm
            if ($tier -eq "CRITICAL") { $critPermList += $perm; $highestPermTier = "CRITICAL" }
            elseif ($tier -eq "HIGH" -and $highestPermTier -ne "CRITICAL") { $highPermList += $perm; $highestPermTier = "HIGH" }
        }
        # For app roles we only have IDs at this point; permission names resolved in DelegateAppPerms
        # Flag count here, full detail in DelegateAppPerms report
        $appRoleCount = $appRoleList.Count

        $permSummary = if ($totalPermCount -eq 0) { "No permissions" }
                       else {
                           $p = "$totalPermCount total"
                           if ($critPermList.Count -gt 0) { $p += " [CRITICAL: $($critPermList -join ', ')]" }
                           elseif ($highPermList.Count -gt 0) { $p += " [HIGH: $($highPermList -join ', ')]" }
                           $p
                       }

        # ── App age ────────────────────────────────────────────────────────────
        $createdDate  = $sp.createdDateTime
        $ageInDays    = if ($createdDate) { ($now - [DateTime]$createdDate).TotalDays } else { $null }
        $isRecent     = ($ageInDays -ne $null -and $ageInDays -le 30)

        # ── Risk classification ────────────────────────────────────────────────
        $riskReasons = [System.Collections.Generic.List[string]]::new()

        if ($highestPermTier -eq "CRITICAL") {
            $riskReasons.Add("CRITICAL permission(s): $($critPermList -join ', ')")
        }
        if ($highestPermTier -eq "HIGH") {
            $riskReasons.Add("HIGH sensitivity permission(s): $($highPermList -join ', ')")
        }
        if ($isMultiTenant -and -not $isVerified -and $hasCredentials) {
            $riskReasons.Add("Multi-tenant app with unverified publisher and credentials registered")
        } elseif ($isMultiTenant -and -not $isVerified) {
            $riskReasons.Add("Multi-tenant app with unverified publisher")
        } elseif ($isMultiTenant) {
            $riskReasons.Add("Multi-tenant app (external publisher)")
        }
        if ($expiredCreds -gt 0) {
            $riskReasons.Add("Has $expiredCreds expired credential(s) - should be removed if app still active")
        }
        if ($noExpiryCreds -gt 0) {
            $riskReasons.Add("Has $noExpiryCreds credential(s) with no expiry date set")
        }
        if ($isRecent -and $highestPermTier -in @("CRITICAL","HIGH")) {
            $riskReasons.Add("Recently created (<30 days) with sensitive permissions - verify legitimacy")
        }
        if (-not $sp.accountEnabled) {
            $riskReasons.Add("Account disabled - verify credentials and permissions have been revoked")
        }

        $riskLevel = if ($highestPermTier -eq "CRITICAL") { "CRITICAL" }
                     elseif ($highestPermTier -eq "HIGH" -and $isMultiTenant -and -not $isVerified) { "HIGH" }
                     elseif ($highestPermTier -eq "HIGH") { "HIGH" }
                     elseif ($isMultiTenant -and -not $isVerified -and $hasCredentials) { "HIGH" }
                     elseif ($riskReasons.Count -gt 0) { "MEDIUM" }
                     elseif ($totalPermCount -eq 0) { "INFO" }
                     else { "LOW" }

        $results.Add([PSCustomObject]@{
            DisplayName              = $sp.displayName
            AppId                    = $sp.appId
            ObjectId                 = $sp.id
            ServicePrincipalType     = $sp.servicePrincipalType
            AccountEnabled           = $sp.accountEnabled
            # Publisher info
            PublisherName            = $publisherName
            PublisherVerified        = $verifiedStatus
            AppOwnerTenantId         = $sp.appOwnerOrganizationId
            IsMultiTenant            = $isMultiTenant
            IsMicrosoftFirstParty    = $isMicrosoftFirstParty
            Homepage                 = $sp.homepage
            # Dates
            CreatedDateTime          = $createdDate
            AgeInDays                = if ($ageInDays) { [int]$ageInDays } else { $null }
            # Credentials
            HasCredentials           = $hasCredentials
            CredentialSummary        = $credSummary
            SecretCount              = $secrets.Count
            CertCount                = $certs.Count
            ExpiredCredentials       = $expiredCreds
            NoExpiryCredentials      = $noExpiryCreds
            # Permissions
            TotalPermissions         = $totalPermCount
            DelegatedPermCount       = $delegatedScopes.Count
            AppRolePermCount         = $appRoleCount
            HighestPermissionTier    = $highestPermTier
            PermissionSummary        = $permSummary
            # Risk
            RiskLevel                = $riskLevel
            RiskFlag                 = ($riskReasons -join ' | ')
        })
    }

    $sortRisk = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
    $sorted   = $results | Sort-Object { $sortRisk[$_.RiskLevel] }, DisplayName

    $critCount  = @($results | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highCount  = @($results | Where-Object { $_.RiskLevel -eq "HIGH"     }).Count
    $medCount   = @($results | Where-Object { $_.RiskLevel -eq "MEDIUM"   }).Count
    $multiCount = @($results | Where-Object { $_.IsMultiTenant             }).Count
    $credCount  = @($results | Where-Object { $_.HasCredentials            }).Count
    $recentCount= @($results | Where-Object { $_.AgeInDays -ne $null -and $_.AgeInDays -le 30 }).Count

    Write-Log "[+] EnterpriseApps: $($results.Count) apps (CRITICAL: $critCount, HIGH: $highCount, Multi-tenant: $multiCount, WithCredentials: $credCount, Recent: $recentCount)"

    $tip  = "SUMMARY: $($results.Count) enterprise apps (Microsoft first-party excluded).`r`n"
    $tip += "  CRITICAL risk: $critCount | HIGH risk: $highCount | MEDIUM risk: $medCount`r`n"
    $tip += "  Multi-tenant apps: $multiCount | Apps with credentials: $credCount`r`n"
    $tip += "  Apps created in last 30 days: $recentCount`r`n`r`n"
    $tip += "INVESTIGATIVE TIPS:`r`n"
    $tip += "- CRITICAL/HIGH: Cross-reference with DelegateAppPerms for full permission detail.`r`n"
    $tip += "  Any unfamiliar app with Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory`r`n"
    $tip += "  can create admin accounts - this is a common persistence technique post-compromise.`r`n"
    $tip += "- Multi-tenant + Unverified + Credentials: High-risk combination. The app can`r`n"
    $tip += "  authenticate to your tenant as itself (no user needed) and is from an unknown publisher.`r`n"
    $tip += "- Recently created apps (<30 days): Attackers register malicious app registrations`r`n"
    $tip += "  and consent them to the tenant during active compromise. Sort by AgeInDays ascending.`r`n"
    $tip += "- Expired credentials on active apps: Credentials that are expired but not removed`r`n"
    $tip += "  may indicate an abandoned app that still holds permissions - cleanup reduces attack surface.`r`n"
    $tip += "- No-expiry credentials: Best practice requires expiry dates. No-expiry secrets on`r`n"
    $tip += "  high-privilege apps are indefinite backdoors if leaked.`r`n"
    $tip += "- AccountEnabled=False with credentials/permissions: Disabled apps should have`r`n"
    $tip += "  their credentials revoked and permissions removed, not just disabled.`r`n"
    $tip += "- ServicePrincipalType='ManagedIdentity': Azure managed identities - lower risk`r`n"
    $tip += "  since credentials are platform-managed, but permissions still warrant review.`r`n"
    $tip += "- To include Microsoft first-party apps in this report, run with -Commands EnterpriseApps`r`n"
    $tip += "  parameter and add -IncludeMicrosoftApps to the script call (useful for verifying`r`n"
    $tip += "  Microsoft's own apps have not been tampered with)."

    Save-Report -ReportName "EnterpriseApps" -Data $sorted `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Enterprise Applications (Service Principals) #######" `
        -InvestigativeTip $tip
}

function Get-SignInActivityReport {
    <#
    .SYNOPSIS
    Sign-in activity for all accounts over the past N days (default 30), with risk classification.
    API: GET /auditLogs/signIns (Microsoft Graph)

    REQUIRES: Azure AD P1 or P2 license (included in M365 E3/E5/Business Premium).
              Basic/Essentials tenants have no sign-in log API access.
    SCOPE:    AuditLog.Read.All (already requested by this script)

    Produces TWO output files:
      SignInSummary   - One row per user, aggregated risk flags and sign-in statistics.
                        Start here for the overview.
      SignInFlagged   - One row per individual flagged sign-in event (HIGH/CRITICAL only).
                        Use for forensic drill-down on specific events.

    Risk signals evaluated per sign-in event:
      CRITICAL  - Successful sign-in from outside HomeCountry on a CRITICAL-role account
                  (Global Admin, Privileged Role Admin, Privileged Auth Admin)
      HIGH      - Sign-in from outside HomeCountry (foreign login)
                - Legacy authentication protocol (BasicAuth, SMTP, IMAP, POP - no MFA support)
                - Successful sign-in with MFA not performed (MFA skipped/not enforced)
                - Azure Identity Protection elevated risk (riskLevelDuringSignIn: medium/high)
                - Impossible travel (same user, two countries within 6 hours)
      MEDIUM    - Sign-in from outside HomeCountry that failed (may indicate credential probing)
                - Success after 5+ consecutive failures in same session window (spray indicator)
                - Conditional Access policy failed/not applied
                - Sign-in to admin account from a non-compliant or unmanaged device
      LOW       - All other sign-in events (baseline)
    #>
    Param(
        [string]$ReportsDir,
        [string]$SummaryFile,
        [string]$HomeCountry   = "US",
        [int]$SignInDays        = 30
    )

    Write-Log "Retrieving Sign-In Activity (past $SignInDays days, HomeCountry=$HomeCountry)..."
    Write-Log "  NOTE: Requires Azure AD P1/P2 license. Will report clearly if unavailable."

    # ── Date filter ────────────────────────────────────────────────────────────
    # ISO 8601 UTC without milliseconds. Build query params manually — EscapeDataString
    # on the full filter string has caused BadRequest on some tenants. $select is omitted
    # entirely; requesting unlicensed fields (riskLevel*, mfaDetail) causes 400 on non-P2.
    $since = [DateTime]::UtcNow.AddDays(-$SignInDays).ToString('yyyy-MM-ddTHH:mm:ss') + 'Z'
    $signInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime+ge+$since&`$top=1000"

    # ── Retrieve sign-ins ──────────────────────────────────────────────────────
    $allSignIns = [System.Collections.Generic.List[object]]::new()
    try {
        Write-Log "  Paging through sign-in log (this may take several minutes for large tenants)..."
        Write-Log "  Query: $signInUri"
        $page = Invoke-MgGraphRequest -Uri $signInUri -OutputType PSObject -ErrorAction Stop
        while ($page) {
            if ($page.value) {
                foreach ($s in $page.value) { $allSignIns.Add($s) }
            }
            $nextLink = $page.'@odata.nextLink'
            if ($nextLink) {
                Write-Log "  Retrieved $($allSignIns.Count) sign-ins so far, fetching next page..."
                $page = Invoke-MgGraphRequest -Uri $nextLink -OutputType PSObject -ErrorAction Stop
            } else {
                break
            }
        }
        Write-Log "  Total sign-in events retrieved: $($allSignIns.Count)"
    } catch {
        $errMsg = $_.Exception.Message
        # Log the full error detail to help diagnose future failures
        $errDetail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $errMsg }
        Write-Log "  [DEBUG] Graph error detail: $errDetail" -Level "WARN"
        Write-Log "  [DEBUG] URI attempted: $signInUri" -Level "WARN"

        if ($errMsg -like '*Authorization_RequestDenied*' -or $errMsg -like '*Forbidden*' -or $errMsg -like '*403*') {
            Write-Log "[WARN] Sign-in log access denied. This tenant likely does not have an Azure AD P1/P2 license, or the account lacks AuditLog.Read.All. Saving explanation to SignInActivity report." -Level "WARN"
            $noAccess = [PSCustomObject]@{
                Status       = "ACCESS DENIED"
                Reason       = "Azure AD P1 or P2 license required for sign-in log API access."
                License      = "Included in: Microsoft 365 E3, E5, Business Premium, or standalone Azure AD P1/P2."
                Scope        = "AuditLog.Read.All scope is required (already requested by this script if license is present)."
                ManualCheck  = "You can review sign-in logs manually at: https://entra.microsoft.com > Monitoring > Sign-in logs"
            }
            Save-Report -ReportName "SignInActivity" -Data @($noAccess) `
                -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
                -SectionHeader "####### Sign-In Activity #######" `
                -InvestigativeTip "Sign-in log access requires Azure AD P1 or P2 license. See report for details."
            return
        }
        Write-LogError -Message "[!] SignInActivity: unexpected error retrieving sign-in log" -ErrorRecord $_
        Save-Report -ReportName "SignInActivity" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Sign-In Activity #######"
        return
    }

    if ($allSignIns.Count -eq 0) {
        Write-Log "  No sign-in events returned for the specified period."
        Save-Report -ReportName "SignInActivity" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Sign-In Activity #######" `
            -InvestigativeTip "No sign-in events were returned. Verify the account has AuditLog.Read.All and an Azure AD P1/P2 license."
        return
    }

    # ── Load privileged accounts for cross-reference ───────────────────────────
    $criticalRoleNames = @('Global Administrator','Privileged Role Administrator','Privileged Authentication Administrator')
    $highRoleNames     = @('Exchange Administrator','SharePoint Administrator','Application Administrator',
                           'Security Administrator','User Administrator','Authentication Administrator',
                           'Cloud Application Administrator','Teams Administrator','Intune Administrator')
    $privilegedUserIds = @{}  # userId -> roleLevel (CRITICAL / HIGH)
    try {
        $roles = Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/directoryRoles"
        foreach ($role in $roles) {
            $level = if ($criticalRoleNames -contains $role.displayName) { "CRITICAL" }
                     elseif ($highRoleNames -contains $role.displayName) { "HIGH" }
                     else { $null }
            if (-not $level) { continue }
            $members = Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
            foreach ($m in $members) {
                if ($m.id -and -not $privilegedUserIds.ContainsKey($m.id)) {
                    $privilegedUserIds[$m.id] = $level
                } elseif ($m.id -and $level -eq "CRITICAL") {
                    $privilegedUserIds[$m.id] = "CRITICAL"  # Upgrade to CRITICAL if applicable
                }
            }
        }
        Write-Log "  Loaded $($privilegedUserIds.Count) privileged account(s) for cross-reference."
    } catch {
        Write-Log "  [WARN] Could not load privileged accounts for cross-reference." -Level "WARN"
    }

    # ── Legacy auth protocols (no MFA support) ─────────────────────────────────
    $legacyProtocols = @(
        'Exchange ActiveSync','IMAP4','MAPI','MAPI Over HTTP','Mobile Apps and Desktop Clients',
        'Offline Address Book','Outlook Anywhere','SMTP','POP3','Authenticated SMTP',
        'Exchange Web Services','Exchange Online PowerShell','AutoDiscover'
    )

    # ── Process sign-ins ───────────────────────────────────────────────────────
    # Group by user for impossible travel and spray detection
    $byUser = @{}
    foreach ($s in $allSignIns) {
        $upn = $s.userPrincipalName
        if (-not $byUser.ContainsKey($upn)) { $byUser[$upn] = [System.Collections.Generic.List[object]]::new() }
        $byUser[$upn].Add($s)
    }

    # ── Detect impossible travel per user ──────────────────────────────────────
    # Returns a HashSet of sign-in IDs flagged as impossible travel
    $impossibleTravelIds = [System.Collections.Generic.HashSet[string]]::new()
    $impossibleHours = 6   # Must be physically impossible within this window

    foreach ($upn in $byUser.Keys) {
        $userEvents = $byUser[$upn] | Sort-Object { $_.createdDateTime }
        for ($i = 1; $i -lt $userEvents.Count; $i++) {
            $prev = $userEvents[$i - 1]
            $curr = $userEvents[$i]

            $prevCountry = $prev.location.countryOrRegion
            $currCountry = $curr.location.countryOrRegion

            if (-not $prevCountry -or -not $currCountry -or $prevCountry -eq $currCountry) { continue }

            try {
                $prevTime = [DateTime]$prev.createdDateTime
                $currTime = [DateTime]$curr.createdDateTime
                $hoursDiff = ($currTime - $prevTime).TotalHours

                if ($hoursDiff -ge 0 -and $hoursDiff -le $impossibleHours) {
                    [void]$impossibleTravelIds.Add($prev.id)
                    [void]$impossibleTravelIds.Add($curr.id)
                }
            } catch { }
        }
    }

    # ── Detect password spray: 5+ failures then success within 1 hour ─────────
    $sprayIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($upn in $byUser.Keys) {
        $userEvents = $byUser[$upn] | Sort-Object { $_.createdDateTime }
        $failStreak = 0
        $failStart  = $null
        foreach ($evt in $userEvents) {
            $isSuccess = ($evt.status.errorCode -eq 0)
            if (-not $isSuccess) {
                if ($failStreak -eq 0) { $failStart = $evt.createdDateTime }
                $failStreak++
            } else {
                if ($failStreak -ge 5 -and $failStart) {
                    try {
                        $window = ([DateTime]$evt.createdDateTime - [DateTime]$failStart).TotalHours
                        if ($window -le 1) { [void]$sprayIds.Add($evt.id) }
                    } catch { }
                }
                $failStreak = 0; $failStart = $null
            }
        }
    }

    # ── Classify each sign-in event ────────────────────────────────────────────
    $flaggedEvents = [System.Collections.Generic.List[object]]::new()
    $allSummaryData = @{}   # upn -> summary object

    foreach ($s in $allSignIns) {
        $upn         = $s.userPrincipalName
        $isSuccess   = ($s.status.errorCode -eq 0)
        $country     = $s.location.countryOrRegion
        $city        = $s.location.city
        $state       = $s.location.state
        $isForeign   = ($country -and $country -ne $HomeCountry)
        $isLegacy    = $legacyProtocols -contains $s.clientAppUsed
        # authenticationRequirement: "multiFactorAuthentication" = MFA enforced, "singleFactorAuthentication" = MFA not required
        $mfaSkipped  = $isSuccess -and ($s.authenticationRequirement -eq 'singleFactorAuthentication') -and -not $isLegacy
        # riskLevelDuringSignIn requires P2 and is not in $select - access via null-safe property lookup
        $idpRisk     = if ($s.PSObject.Properties['riskLevelDuringSignIn']) { $s.riskLevelDuringSignIn } else { $null }
        $privLevel   = $privilegedUserIds[$s.userId]
        $isImpTravel = $impossibleTravelIds.Contains($s.id)
        $isSpray     = $sprayIds.Contains($s.id)
        $caFailed    = ($s.conditionalAccessStatus -eq 'failure')

        # ── Risk classification ────────────────────────────────────────────────
        $riskReasons = [System.Collections.Generic.List[string]]::new()

        if ($isForeign -and $isSuccess -and $privLevel -eq "CRITICAL") {
            $riskReasons.Add("Foreign sign-in SUCCESS on CRITICAL admin account from $country")
        }
        if ($isForeign -and $isSuccess) {
            $riskReasons.Add("Foreign sign-in SUCCESS from $country (HomeCountry=$HomeCountry)")
        } elseif ($isForeign -and -not $isSuccess) {
            $riskReasons.Add("Foreign sign-in FAILURE from $country - possible credential probing")
        }
        if ($isLegacy) {
            $riskReasons.Add("Legacy auth protocol: $($s.clientAppUsed) - MFA cannot be enforced")
        }
        if ($mfaSkipped) {
            $riskReasons.Add("Successful sign-in with MFA NOT performed (singleFactorAuthentication)")
        }
        if ($idpRisk -and $idpRisk -notin @('none','','low')) {
            $riskReasons.Add("Identity Protection risk level: $idpRisk")
        }
        if ($isImpTravel) {
            $riskReasons.Add("Impossible travel: sign-in from $country within $impossibleHours hours of a different country sign-in")
        }
        if ($isSpray) {
            $riskReasons.Add("Password spray indicator: successful sign-in after 5+ consecutive failures within 1 hour")
        }
        if ($caFailed) {
            $riskReasons.Add("Conditional Access policy FAILED - access may have been blocked or policy gap exists")
        }

        # Assign risk level
        $riskLevel = if ($riskReasons | Where-Object { $_ -like "*CRITICAL admin*" }) { "CRITICAL" }
                     elseif ($riskReasons | Where-Object {
                         $_ -like "Foreign sign-in SUCCESS*" -or
                         $_ -like "*Legacy auth*" -or
                         $_ -like "*MFA NOT performed*" -or
                         $_ -like "*Identity Protection*" -or
                         $_ -like "*Impossible travel*" -or
                         $_ -like "*spray indicator*"
                     }) { "HIGH" }
                     elseif ($riskReasons.Count -gt 0) { "MEDIUM" }
                     else { "LOW" }

        $riskFlag = ($riskReasons -join ' | ')

        # ── Per-user summary accumulation ──────────────────────────────────────
        if (-not $allSummaryData.ContainsKey($upn)) {
            $allSummaryData[$upn] = [PSCustomObject]@{
                UserPrincipalName   = $upn
                UserDisplayName     = $s.userDisplayName
                UserId              = $s.userId
                PrivilegedRole      = $privLevel
                TotalSignIns        = 0
                SuccessCount        = 0
                FailureCount        = 0
                ForeignCountries    = [System.Collections.Generic.HashSet[string]]::new()
                LegacyAuthCount     = 0
                MFASkippedCount     = 0
                ImpossibleTravelHit = $false
                SprayIndicatorHit   = $false
                HighestRisk         = "LOW"
                RiskFlags           = [System.Collections.Generic.List[string]]::new()
                LastSignIn          = $s.createdDateTime
                LastCountry         = $country
                LastApp             = $s.appDisplayName
            }
        }

        $summary = $allSummaryData[$upn]
        $summary.TotalSignIns++
        if ($isSuccess) { $summary.SuccessCount++ } else { $summary.FailureCount++ }
        if ($isForeign -and $country) { [void]$summary.ForeignCountries.Add($country) }
        if ($isLegacy) { $summary.LegacyAuthCount++ }
        if ($mfaSkipped) { $summary.MFASkippedCount++ }
        if ($isImpTravel) { $summary.ImpossibleTravelHit = $true }
        if ($isSpray)     { $summary.SprayIndicatorHit = $true }

        # Update highest risk
        $riskOrder = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3 }
        if (($riskOrder[$riskLevel] ?? 3) -lt ($riskOrder[$summary.HighestRisk] ?? 3)) {
            $summary.HighestRisk = $riskLevel
        }

        # Accumulate unique risk reasons
        foreach ($r in $riskReasons) {
            if (-not $summary.RiskFlags.Contains($r)) { $summary.RiskFlags.Add($r) }
        }

        # Update last sign-in if more recent
        if ($s.createdDateTime -gt $summary.LastSignIn) {
            $summary.LastSignIn  = $s.createdDateTime
            $summary.LastCountry = $country
            $summary.LastApp     = $s.appDisplayName
        }

        # ── Add to flagged events if HIGH or CRITICAL ──────────────────────────
        if ($riskLevel -in @("CRITICAL","HIGH","MEDIUM")) {
            $flaggedEvents.Add([PSCustomObject]@{
                CreatedDateTime         = $s.createdDateTime
                RiskLevel               = $riskLevel
                RiskFlag                = $riskFlag
                UserPrincipalName       = $upn
                UserDisplayName         = $s.userDisplayName
                PrivilegedRole          = $privLevel
                AppDisplayName          = $s.appDisplayName
                ClientAppUsed           = $s.clientAppUsed
                IPAddress               = $s.ipAddress
                Country                 = $country
                City                    = $city
                State                   = $state
                SignInSuccess           = $isSuccess
                ErrorCode               = $s.status.errorCode
                FailureReason           = $s.status.failureReason
                MFADetail               = if ($s.PSObject.Properties['mfaDetail'] -and $s.mfaDetail) { "$($s.mfaDetail.authMethod) / $($s.mfaDetail.authDetail)" } else { "" }
                AuthRequirement         = $s.authenticationRequirement
                ConditionalAccessStatus = $s.conditionalAccessStatus
                RiskLevelDuringSignIn   = $idpRisk
                DeviceOS                = $s.deviceDetail.operatingSystem
                DeviceCompliant         = $s.deviceDetail.isCompliant
                ResourceDisplayName     = $s.resourceDisplayName
                SignInId                = $s.id
            })
        }
    }

    # ── Build summary output rows ──────────────────────────────────────────────
    $summaryRows = [System.Collections.Generic.List[object]]::new()
    foreach ($upn in $allSummaryData.Keys) {
        $s = $allSummaryData[$upn]
        $summaryRows.Add([PSCustomObject]@{
            UserPrincipalName    = $s.UserPrincipalName
            UserDisplayName      = $s.UserDisplayName
            PrivilegedRole       = $s.PrivilegedRole
            HighestRisk          = $s.HighestRisk
            RiskFlags            = ($s.RiskFlags -join ' | ')
            TotalSignIns         = $s.TotalSignIns
            SuccessCount         = $s.SuccessCount
            FailureCount         = $s.FailureCount
            ForeignCountries     = ($s.ForeignCountries | Sort-Object) -join ', '
            LegacyAuthCount      = $s.LegacyAuthCount
            MFASkippedCount      = $s.MFASkippedCount
            ImpossibleTravel     = $s.ImpossibleTravelHit
            SprayIndicator       = $s.SprayIndicatorHit
            LastSignIn           = $s.LastSignIn
            LastCountry          = $s.LastCountry
            LastApp              = $s.LastApp
        })
    }

    $riskOrder = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3 }
    $sortedSummary = $summaryRows | Sort-Object { $riskOrder[$_.HighestRisk] }, UserPrincipalName
    $sortedFlagged = $flaggedEvents | Sort-Object { $riskOrder[$_.RiskLevel] }, CreatedDateTime

    # ── Stats ──────────────────────────────────────────────────────────────────
    $critCount    = @($summaryRows | Where-Object { $_.HighestRisk -eq "CRITICAL" }).Count
    $highCount    = @($summaryRows | Where-Object { $_.HighestRisk -eq "HIGH"     }).Count
    $medCount     = @($summaryRows | Where-Object { $_.HighestRisk -eq "MEDIUM"   }).Count
    $foreignUsers = @($summaryRows | Where-Object { $_.ForeignCountries -ne ''     }).Count
    $legacyUsers  = @($summaryRows | Where-Object { $_.LegacyAuthCount -gt 0       }).Count
    $mfaSkipUsers = @($summaryRows | Where-Object { $_.MFASkippedCount -gt 0       }).Count
    $itUsers      = @($summaryRows | Where-Object { $_.ImpossibleTravel             }).Count
    $sprayUsers   = @($summaryRows | Where-Object { $_.SprayIndicator               }).Count
    $privForeign  = @($summaryRows | Where-Object { $_.ForeignCountries -ne '' -and $_.PrivilegedRole }).Count

    Write-Log "[+] SignInActivity: $($allSignIns.Count) events / $($summaryRows.Count) users / $($flaggedEvents.Count) flagged events (CRITICAL: $critCount, HIGH: $highCount, MEDIUM: $medCount)"
    Write-Log "    Foreign logins: $foreignUsers users | Privileged+foreign: $privForeign | Legacy auth: $legacyUsers | MFA skipped: $mfaSkipUsers | Impossible travel: $itUsers | Spray indicators: $sprayUsers"

    # ── Save summary report ────────────────────────────────────────────────────
    $tip  = "REPORT PERIOD: Last $SignInDays days | HOME COUNTRY: $HomeCountry | Total events: $($allSignIns.Count)`r`n"
    $tip += "LICENSE NOTE: This report requires Azure AD P1 or P2 (M365 E3/E5/Business Premium).`r`n`r`n"
    $tip += "USER SUMMARY ($($summaryRows.Count) users with sign-ins):`r`n"
    $tip += "  CRITICAL risk users : $critCount  (foreign success on CRITICAL admin accounts)`r`n"
    $tip += "  HIGH risk users     : $highCount  (foreign logins, legacy auth, MFA skipped, impossible travel)`r`n"
    $tip += "  MEDIUM risk users   : $medCount`r`n"
    $tip += "  Users with foreign logins          : $foreignUsers`r`n"
    $tip += "  Privileged users with foreign login : $privForeign (CRITICAL finding)`r`n"
    $tip += "  Users with legacy auth              : $legacyUsers (cannot enforce MFA)`r`n"
    $tip += "  Users with MFA skipped              : $mfaSkipUsers`r`n"
    $tip += "  Impossible travel detected          : $itUsers users`r`n"
    $tip += "  Password spray indicators           : $sprayUsers accounts`r`n`r`n"
    $tip += "TWO REPORT FILES ARE PRODUCED:`r`n"
    $tip += "  SignInSummary  - One row per user with aggregated risk. Start here.`r`n"
    $tip += "  SignInFlagged  - Individual flagged sign-in events. Use for drill-down.`r`n`r`n"
    $tip += "INVESTIGATIVE TIPS:`r`n"
    $tip += "- CRITICAL: Any admin account (especially Global Admin) with a foreign successful`r`n"
    $tip += "  sign-in is an immediate escalation. Cross-reference with the user's known travel.`r`n"
    $tip += "- Impossible Travel: Two logins from different countries within $impossibleHours hours on the same`r`n"
    $tip += "  account means either the account is compromised or a VPN is being used. Verify both.`r`n"
    $tip += "- Legacy Auth: Accounts using IMAP, POP3, SMTP, or ActiveSync bypass MFA entirely.`r`n"
    $tip += "  These protocols should be blocked via Conditional Access for all users.`r`n"
    $tip += "- MFA Skipped: Successful logins without MFA may indicate a Conditional Access gap,`r`n"
    $tip += "  a legacy protocol, or a trusted location policy that is too broadly defined.`r`n"
    $tip += "- Password Spray: A successful login after 5+ failures in 1 hour is a strong indicator.`r`n"
    $tip += "  Check what resource was accessed and whether it was a privileged account.`r`n"
    $tip += "- ForeignCountries column: Multiple distinct foreign countries in one period is more`r`n"
    $tip += "  suspicious than a single foreign country (which could be business travel).`r`n"
    $tip += "- Identity Protection Risk (riskLevelDuringSignIn): Requires Azure AD P2. Values of`r`n"
    $tip += "  'medium' or 'high' indicate Microsoft's own risk engine flagged the sign-in.`r`n"
    $tip += "- To change the home country or lookback period, run with:`r`n"
    $tip += "  -Commands SignInActivity (and set HomeCountry/SignInDays params in script header)"

    Save-Report -ReportName "SignInSummary" -Data $sortedSummary `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Sign-In Activity — User Summary #######" `
        -InvestigativeTip $tip

    # ── Save flagged events report ─────────────────────────────────────────────
    if ($sortedFlagged.Count -gt 0) {
        Save-Report -ReportName "SignInFlagged" -Data $sortedFlagged `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Sign-In Activity — Flagged Events #######" `
            -InvestigativeTip "Flagged sign-in events (CRITICAL/HIGH/MEDIUM only). Sorted by severity then date. Use this file to drill into specific sign-in events identified in the SignInSummary report."
    } else {
        Write-Log "  No flagged sign-in events to save (no CRITICAL/HIGH/MEDIUM findings)."
    }
}

function Get-KeyCredentialsReport {
    <#
    .SYNOPSIS
    Applications and service principals with key credentials and password credentials.
    Replaces: Get-AzureADApplication | select KeyCredentials, PasswordCredentials
    New API:  GET /applications?$select=displayName,appId,keyCredentials,passwordCredentials
              GET /servicePrincipals?$select=displayName,appId,keyCredentials,passwordCredentials
    Field mapping: AzureAD KeyCredential properties match Graph KeyCredential object names.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Key Credentials for applications and service principals..."

    $results = [System.Collections.Generic.List[object]]::new()
    $now = [DateTime]::UtcNow

    # App registrations
    $apps = Invoke-GraphRequestAll -Uri (
        "https://graph.microsoft.com/v1.0/applications" +
        "?`$select=id,displayName,appId,keyCredentials,passwordCredentials,createdDateTime"
    )

    foreach ($app in $apps) {
        # Key credentials (certificates)
        foreach ($kc in $app.keyCredentials) {
            $endDt = if ($kc.endDateTime) { [DateTime]$kc.endDateTime } else { $null }
            $results.Add([PSCustomObject]@{
                ObjectType       = "Application"
                DisplayName      = $app.displayName
                AppId            = $app.appId          # was: ApplicationId
                ObjectId         = $app.id             # was: ObjectId
                CredentialType   = "KeyCredential"
                KeyId            = $kc.keyId
                # Graph: customKeyIdentifier == AzureAD: CustomKeyIdentifier
                CustomKeyIdentifier = $kc.customKeyIdentifier
                DisplayNameCred  = $kc.displayName
                Type             = $kc.type            # e.g. "AsymmetricX509Cert"
                Usage            = $kc.usage           # e.g. "Verify"
                StartDateTime    = $kc.startDateTime
                EndDateTime      = $kc.endDateTime
                IsExpired        = ($endDt -and $endDt -lt $now)
                DaysUntilExpiry  = if ($endDt) { [int]($endDt - $now).TotalDays } else { $null }
            })
        }
        # Password credentials (client secrets)
        foreach ($pc in $app.passwordCredentials) {
            $endDt = if ($pc.endDateTime) { [DateTime]$pc.endDateTime } else { $null }
            $results.Add([PSCustomObject]@{
                ObjectType       = "Application"
                DisplayName      = $app.displayName
                AppId            = $app.appId
                ObjectId         = $app.id
                CredentialType   = "PasswordCredential"
                KeyId            = $pc.keyId
                CustomKeyIdentifier = $pc.customKeyIdentifier
                DisplayNameCred  = $pc.displayName
                Type             = "ClientSecret"
                Usage            = "Verify"
                StartDateTime    = $pc.startDateTime
                EndDateTime      = $pc.endDateTime
                IsExpired        = ($endDt -and $endDt -lt $now)
                DaysUntilExpiry  = if ($endDt) { [int]($endDt - $now).TotalDays } else { $null }
            })
        }
    }

    # Service principals (enterprise apps) with credentials
    $sps = Invoke-GraphRequestAll -Uri (
        "https://graph.microsoft.com/v1.0/servicePrincipals" +
        "?`$select=id,displayName,appId,keyCredentials,passwordCredentials"
    )
    foreach ($sp in $sps) {
        foreach ($kc in $sp.keyCredentials) {
            $endDt = if ($kc.endDateTime) { [DateTime]$kc.endDateTime } else { $null }
            $results.Add([PSCustomObject]@{
                ObjectType       = "ServicePrincipal"
                DisplayName      = $sp.displayName
                AppId            = $sp.appId
                ObjectId         = $sp.id
                CredentialType   = "KeyCredential"
                KeyId            = $kc.keyId
                CustomKeyIdentifier = $kc.customKeyIdentifier
                DisplayNameCred  = $kc.displayName
                Type             = $kc.type
                Usage            = $kc.usage
                StartDateTime    = $kc.startDateTime
                EndDateTime      = $kc.endDateTime
                IsExpired        = ($endDt -and $endDt -lt $now)
                DaysUntilExpiry  = if ($endDt) { [int]($endDt - $now).TotalDays } else { $null }
            })
        }
        foreach ($pc in $sp.passwordCredentials) {
            $endDt = if ($pc.endDateTime) { [DateTime]$pc.endDateTime } else { $null }
            $results.Add([PSCustomObject]@{
                ObjectType       = "ServicePrincipal"
                DisplayName      = $sp.displayName
                AppId            = $sp.appId
                ObjectId         = $sp.id
                CredentialType   = "PasswordCredential"
                KeyId            = $pc.keyId
                CustomKeyIdentifier = $pc.customKeyIdentifier
                DisplayNameCred  = $pc.displayName
                Type             = "ClientSecret"
                Usage            = "Verify"
                StartDateTime    = $pc.startDateTime
                EndDateTime      = $pc.endDateTime
                IsExpired        = ($endDt -and $endDt -lt $now)
                DaysUntilExpiry  = if ($endDt) { [int]($endDt - $now).TotalDays } else { $null }
            })
        }
    }

    Save-Report -ReportName "KeyCredentials" -Data $results `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Application Key Credentials #######" `
        -InvestigativeTip "Review for expired credentials, credentials with unusually long validity periods, or credentials on apps/service principals not recognized by your team. Credentials near or past expiry may indicate abandoned applications still holding permissions."
}

function Get-O365AdminGroupsReport {
    <#
    .SYNOPSIS
    Members of all Azure AD directory roles with role sensitivity tiers and member risk flagging.
    Replaces: Get-AzureADDirectoryRole | Get-AzureADDirectoryRoleMember
    New API:  GET /directoryRoles  +  GET /directoryRoles/{id}/members

    RoleSensitivity:
      CRITICAL - Roles with unrestricted tenant-wide control (Global Admin, Privileged Role Admin)
      HIGH     - Roles with broad data/service control (Exchange Admin, SharePoint Admin,
                 Application Admin, Cloud App Security Admin, Security Admin, etc.)
      MEDIUM   - Roles with limited but notable elevated access
      LOW      - Informational/read-only roles

    MemberRiskFlag:
      - Guest accounts in admin roles (MemberType = guest)
      - Service principals in admin roles (MemberType = servicePrincipal)
      - Members with no UPN (may indicate broken/deleted accounts still assigned roles)
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving O365 Admin Role Group memberships..."

    # Role sensitivity classification
    $criticalRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Privileged Authentication Administrator'
    )
    $highRoles = @(
        'Exchange Administrator',
        'SharePoint Administrator',
        'Teams Administrator',
        'Application Administrator',
        'Cloud Application Administrator',
        'Security Administrator',
        'Compliance Administrator',
        'User Administrator',
        'Authentication Administrator',
        'Helpdesk Administrator',
        'Password Administrator',
        'Billing Administrator',
        'License Administrator',
        'Directory Synchronization Accounts',
        'Partner Tier1 Support',
        'Partner Tier2 Support',
        'Azure AD Joined Device Local Administrator',
        'Intune Administrator',
        'Hybrid Identity Administrator'
    )

    $roles   = Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/directoryRoles"
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($role in $roles) {
        Write-Progress -Activity "Retrieving admin role members..." `
            -Status "Role: $($role.displayName)"

        # Assign role sensitivity
        $roleSensitivity = if ($criticalRoles -contains $role.displayName)   { "CRITICAL" }
                           elseif ($highRoles -contains $role.displayName)   { "HIGH" }
                           else                                               { "MEDIUM" }

        $members = Invoke-GraphRequestAll `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"

        if ($members.Count -eq 0) {
            $results.Add([PSCustomObject]@{
                RoleDisplayName  = $role.displayName
                RoleId           = $role.id
                RoleDescription  = $role.description
                RoleSensitivity  = $roleSensitivity
                MemberUPN        = "(No members)"
                MemberDisplayName = ""
                MemberObjectId   = ""
                MemberType       = ""
                MemberRiskLevel  = "INFO"
                MemberRiskFlag   = ""
            })
        } else {
            foreach ($member in $members) {
                $memberType = ($member.'@odata.type' -replace '#microsoft.graph.', "")

                # Member-level risk flags
                $memberRiskReasons = [System.Collections.Generic.List[string]]::new()

                if ($memberType -eq "guest") {
                    $memberRiskReasons.Add("GUEST account holds admin role - external user with elevated privileges")
                }
                if ($memberType -eq "servicePrincipal") {
                    $memberRiskReasons.Add("SERVICE PRINCIPAL holds admin role - verify this app assignment is intentional")
                }
                if (-not $member.userPrincipalName -and $memberType -eq "user") {
                    $memberRiskReasons.Add("No UPN found - may be a broken or deleted account still assigned to role")
                }

                # Combined risk: role sensitivity + member anomaly
                $memberRiskLevel = if ($memberRiskReasons.Count -gt 0 -and $roleSensitivity -eq "CRITICAL") { "CRITICAL" }
                                   elseif ($memberRiskReasons.Count -gt 0)                                  { "HIGH" }
                                   elseif ($roleSensitivity -eq "CRITICAL")                                 { "HIGH" }
                                   elseif ($roleSensitivity -eq "HIGH")                                     { "MEDIUM" }
                                   else                                                                     { "LOW" }

                $results.Add([PSCustomObject]@{
                    RoleDisplayName   = $role.displayName
                    RoleId            = $role.id
                    RoleDescription   = $role.description
                    RoleSensitivity   = $roleSensitivity
                    MemberUPN         = $member.userPrincipalName
                    MemberDisplayName = $member.displayName
                    MemberObjectId    = $member.id
                    MemberType        = $memberType
                    MemberRiskLevel   = $memberRiskLevel
                    MemberRiskFlag    = ($memberRiskReasons -join ' | ')
                })
            }
        }
    }
    Write-Progress -Activity "Retrieving admin role members..." -Completed

    $sortSensitivity = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
    $sortRisk        = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
    $sorted = $results | Sort-Object {
        $sortRisk[$_.MemberRiskLevel]
    }, { $sortSensitivity[$_.RoleSensitivity] }, RoleDisplayName

    $criticalCount = @($results | Where-Object { $_.MemberRiskLevel -eq "CRITICAL" }).Count
    $highCount     = @($results | Where-Object { $_.MemberRiskLevel -eq "HIGH"     }).Count
    $totalMembers  = @($results | Where-Object { $_.MemberUPN -ne "(No members)"   }).Count
    $guestAdmins   = @($results | Where-Object { $_.MemberType -eq "guest"         }).Count
    $spAdmins      = @($results | Where-Object { $_.MemberType -eq "servicePrincipal" }).Count

    Write-Log "[+] O365AdminGroups: $totalMembers role assignments (CRITICAL risk: $criticalCount, HIGH: $highCount, Guest admins: $guestAdmins, SP admins: $spAdmins)"

    $tip  = "SUMMARY: $totalMembers admin role assignments across $($roles.Count) active roles.`r`n"
    $tip += "  Guest accounts in admin roles:      $guestAdmins`r`n"
    $tip += "  Service principals in admin roles:  $spAdmins`r`n"
    $tip += "  CRITICAL risk assignments:          $criticalCount`r`n"
    $tip += "  HIGH risk assignments:              $highCount`r`n`r`n"
    $tip += "ROLE SENSITIVITY GUIDE:`r`n"
    $tip += "  CRITICAL: Global Administrator, Privileged Role Administrator,`r`n"
    $tip += "            Privileged Authentication Administrator`r`n"
    $tip += "  HIGH:     Exchange Admin, SharePoint Admin, Application Admin, Security Admin,`r`n"
    $tip += "            User Admin, Authentication Admin, Partner Tier1/2 Support, and others`r`n`r`n"
    $tip += "INVESTIGATIVE TIPS:`r`n"
    $tip += "- CRITICAL roles should have the fewest members possible - ideally 2-5 break-glass`r`n"
    $tip += "  accounts plus dedicated admin identities. General user accounts should not be here.`r`n"
    $tip += "- Guest accounts (external users) in ANY admin role is unusual and high risk.`r`n"
    $tip += "  Attackers invited as guests may retain role membership even after compromise is`r`n"
    $tip += "  remediated if the guest account itself is not removed.`r`n"
    $tip += "- Service principals in admin roles may be legitimate (e.g., sync tools) but should`r`n"
    $tip += "  be explicitly documented and verified against known approved applications.`r`n"
    $tip += "- Partner Tier1/2 Support roles indicate Microsoft partner (GDAP/DAP) access.`r`n"
    $tip += "  Cross-reference with PartnerInfo_MANUAL.txt."

    Save-Report -ReportName "O365AdminGroups" -Data $sorted `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### O365 Admin Groups / Directory Role Memberships #######" `
        -InvestigativeTip $tip
}


function Get-DelegateAppPermsReport {
    <#
    .SYNOPSIS
    Delegated OAuth2 permissions and application role assignments with permission sensitivity
    tiers and risk classification.
    Replaces: AzureADPSPermissions script / Get-AzureADOAuth2PermissionGrant
    New API:  GET /oauth2PermissionGrants  (delegated grants)
              GET /servicePrincipals/{id}/appRoleAssignments  (application grants)

    PermissionRisk tiers based on the permission value:
      CRITICAL - Permissions enabling full tenant takeover or unrestricted data access
                 (RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, etc.)
      HIGH     - Permissions enabling broad read/write of mail, files, users, or identity
                 (Mail.ReadWrite, Files.ReadWrite.All, User.ReadWrite.All, etc.)
      MEDIUM   - Read-only access to sensitive data (Mail.Read, Files.Read.All, etc.)
      LOW      - Low-sensitivity or well-understood delegated scopes (openid, profile, etc.)
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Delegated Application Permissions (OAuth2 grants)..."

    # Permission sensitivity lookup - covers the most common/dangerous Graph permissions
    $criticalPerms = @(
        'RoleManagement.ReadWrite.Directory',
        'Directory.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'Application.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'PrivilegedAccess.ReadWrite.AzureAD',
        'Policy.ReadWrite.Authorization',
        'Organization.ReadWrite.All',
        'UserAuthenticationMethod.ReadWrite.All',
        'full_access_as_app',
        'full_access_as_user'
    )
    $highPerms = @(
        'Mail.ReadWrite',
        'Mail.ReadWrite.All',
        'Mail.Send',
        'Mail.Send.All',
        'MailboxSettings.ReadWrite',
        'Files.ReadWrite.All',
        'Sites.ReadWrite.All',
        'Sites.FullControl.All',
        'User.ReadWrite.All',
        'User.ManageIdentities.All',
        'Group.ReadWrite.All',
        'GroupMember.ReadWrite.All',
        'DeviceManagementApps.ReadWrite.All',
        'DeviceManagementConfiguration.ReadWrite.All',
        'AuditLog.Read.All',
        'SecurityEvents.ReadWrite.All',
        'SecurityAlert.ReadWrite.All',
        'IdentityRiskEvent.ReadWrite.All',
        'Calendars.ReadWrite',
        'Contacts.ReadWrite',
        'Notes.ReadWrite.All',
        'Tasks.ReadWrite',
        'Chat.ReadWrite.All',
        'ChatMessage.Send',
        'ChannelMessage.Send',
        'TeamSettings.ReadWrite.All',
        'AccessReview.ReadWrite.All'
    )
    $mediumPerms = @(
        'Mail.Read',
        'Mail.Read.All',
        'Mail.ReadBasic',
        'Mail.ReadBasic.All',
        'Files.Read.All',
        'Sites.Read.All',
        'User.Read.All',
        'Group.Read.All',
        'Directory.Read.All',
        'AuditLog.Read.All',
        'Reports.Read.All',
        'SecurityEvents.Read.All',
        'IdentityRiskEvent.Read.All',
        'Calendars.Read',
        'Contacts.Read',
        'Notes.Read.All',
        'Tasks.Read',
        'Chat.Read.All',
        'ChannelMessage.Read.All',
        'TeamMember.Read.All',
        'OnlineMeetings.Read.All',
        'CallRecords.Read.All',
        'Device.Read.All',
        'DeviceManagementApps.Read.All'
    )

    function Get-PermissionRisk {
        param([string]$Permission)
        if ($criticalPerms -contains $Permission) { return "CRITICAL" }
        if ($highPerms     -contains $Permission) { return "HIGH" }
        if ($mediumPerms   -contains $Permission) { return "MEDIUM" }
        return "LOW"
    }

    # ── Build SP lookup table ──────────────────────────────────────────────────
    Write-Log "  Loading service principal list for name resolution..."
    $allSPs = Invoke-GraphRequestAll -Uri (
        "https://graph.microsoft.com/v1.0/servicePrincipals" +
        "?`$select=id,displayName,appId,appDisplayName,appRoles"
    )
    $spById = @{}
    foreach ($sp in $allSPs) { $spById[$sp.id] = $sp }

    # ── Build user lookup table ────────────────────────────────────────────────
    Write-Log "  Loading user list for principal name resolution..."
    $allUsers = Invoke-GraphRequestAll -Uri (
        "https://graph.microsoft.com/v1.0/users" +
        "?`$select=id,displayName,userPrincipalName"
    )
    $usersById = @{}
    foreach ($u in $allUsers) { $usersById[$u.id] = $u }

    $results = [System.Collections.Generic.List[object]]::new()

    # ── Part 1: Delegated permission grants (OAuth2PermissionGrants) ──────────
    Write-Log "  Retrieving OAuth2 delegated permission grants..."
    $grants = Invoke-GraphRequestAll `
        -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"

    foreach ($grant in $grants) {
        $clientSP   = $spById[$grant.clientId]
        $resourceSP = $spById[$grant.resourceId]
        $scopes     = ($grant.scope -split ' ') | Where-Object { $_ -ne '' }

        foreach ($scope in $scopes) {
            $principalName = ""
            if ($grant.consentType -eq "Principal" -and $grant.principalId) {
                $u = $usersById[$grant.principalId]
                $principalName = if ($u) { $u.userPrincipalName } else { $grant.principalId }
            }

            $permRisk = Get-PermissionRisk $scope

            # Additional risk flags
            $riskReasons = [System.Collections.Generic.List[string]]::new()
            if ($permRisk -eq "CRITICAL") {
                $riskReasons.Add("CRITICAL permission - tenant-wide control or full data access")
            } elseif ($permRisk -eq "HIGH") {
                $riskReasons.Add("HIGH sensitivity permission - broad read/write access")
            }
            if ($grant.consentType -eq "AllPrincipals") {
                if ($permRisk -in @("CRITICAL","HIGH")) {
                    $riskReasons.Add("Admin-consented for ALL users - affects entire tenant")
                }
            }

            $results.Add([PSCustomObject]@{
                PermissionType      = "Delegated"
                ClientObjectId      = $grant.clientId
                ClientDisplayName   = if ($clientSP)   { $clientSP.displayName   } else { $grant.clientId }
                ClientAppId         = if ($clientSP)   { $clientSP.appId         } else { "" }
                ResourceObjectId    = $grant.resourceId
                ResourceDisplayName = if ($resourceSP) { $resourceSP.displayName } else { $grant.resourceId }
                Permission          = $scope
                PermissionRisk      = $permRisk
                ConsentType         = $grant.consentType
                PrincipalObjectId   = $grant.principalId
                PrincipalName       = $principalName
                RiskLevel           = $permRisk
                RiskFlag            = ($riskReasons -join ' | ')
            })
        }
    }

    # ── Part 2: Application role assignments (app-to-app permissions) ─────────
    Write-Log "  Retrieving application role assignments (app permissions)..."
    $spCount = $allSPs.Count
    $i = 0

    foreach ($sp in $allSPs) {
        Write-Progress -Activity "Retrieving app role assignments..." `
            -Status ("Checked {0}/{1} service principals" -f $i++, $spCount) `
            -PercentComplete (($i / [Math]::Max($spCount, 1)) * 100)

        try {
            $assignments = Invoke-GraphRequestAll -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
            )
            foreach ($assign in $assignments) {
                $resourceSP = $spById[$assign.resourceId]

                $roleName = $assign.appRoleId
                if ($resourceSP -and $resourceSP.appRoles) {
                    $roleObj = $resourceSP.appRoles | Where-Object { $_.id -eq $assign.appRoleId }
                    if ($roleObj) { $roleName = $roleObj.value }
                } else {
                    try {
                        $resSPDetail = Invoke-MgGraphRequest -Uri (
                            "https://graph.microsoft.com/v1.0/servicePrincipals/$($assign.resourceId)" +
                            "?`$select=displayName,appRoles"
                        ) -OutputType PSObject
                        $roleObj = $resSPDetail.appRoles | Where-Object { $_.id -eq $assign.appRoleId }
                        if ($roleObj) { $roleName = $roleObj.value }
                    } catch { }
                }

                $permRisk    = Get-PermissionRisk $roleName
                $riskReasons = [System.Collections.Generic.List[string]]::new()
                if ($permRisk -eq "CRITICAL") {
                    $riskReasons.Add("CRITICAL app permission - no user present, runs without oversight")
                } elseif ($permRisk -eq "HIGH") {
                    $riskReasons.Add("HIGH sensitivity app permission - broad automated access")
                }
                # Application permissions are inherently broader than delegated
                if ($permRisk -in @("CRITICAL","HIGH")) {
                    $riskReasons.Add("Application permission type - acts as itself with no user scope limit")
                }

                $results.Add([PSCustomObject]@{
                    PermissionType      = "Application"
                    ClientObjectId      = $sp.id
                    ClientDisplayName   = $sp.displayName
                    ClientAppId         = $sp.appId
                    ResourceObjectId    = $assign.resourceId
                    ResourceDisplayName = if ($resourceSP) { $resourceSP.displayName } else { $assign.resourceId }
                    Permission          = $roleName
                    PermissionRisk      = $permRisk
                    ConsentType         = "Application"
                    PrincipalObjectId   = ""
                    PrincipalName       = ""
                    RiskLevel           = $permRisk
                    RiskFlag            = ($riskReasons -join ' | ')
                })
            }
        } catch { }
    }
    Write-Progress -Activity "Retrieving app role assignments..." -Completed

    $sortRisk = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3 }
    $sorted = $results | Sort-Object { $sortRisk[$_.RiskLevel] }, ClientDisplayName, Permission

    $critCount   = @($results | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highCount   = @($results | Where-Object { $_.RiskLevel -eq "HIGH"     }).Count
    $medCount    = @($results | Where-Object { $_.RiskLevel -eq "MEDIUM"   }).Count
    $appPerms    = @($results | Where-Object { $_.PermissionType -eq "Application" }).Count
    $delegPerms  = @($results | Where-Object { $_.PermissionType -eq "Delegated"   }).Count

    Write-Log "[+] DelegateAppPerms: $($results.Count) permissions (CRITICAL: $critCount, HIGH: $highCount, App: $appPerms, Delegated: $delegPerms)"

    $tip  = "SUMMARY: $($results.Count) total permission grants.`r`n"
    $tip += "  CRITICAL: $critCount | HIGH: $highCount | MEDIUM: $medCount`r`n"
    $tip += "  Application permissions: $appPerms | Delegated permissions: $delegPerms`r`n`r`n"
    $tip += "INVESTIGATIVE TIPS:`r`n"
    $tip += "- CRITICAL permissions (RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All,`r`n"
    $tip += "  Application.ReadWrite.All, etc.) enable an app to escalate to Global Admin or`r`n"
    $tip += "  create backdoor app registrations. Any unknown app with these is a critical finding.`r`n"
    $tip += "- Application permissions (PermissionType=Application) run as the app itself with`r`n"
    $tip += "  no user context - they access data for ALL users in scope, not just one.`r`n"
    $tip += "- Admin-consented Delegated grants (ConsentType=AllPrincipals) apply to all users.`r`n"
    $tip += "  User-consented grants (ConsentType=Principal) show the specific user in PrincipalName.`r`n"
    $tip += "- Mail.ReadWrite + Mail.Send at Application level means the app can read and send`r`n"
    $tip += "  as ANY mailbox in the tenant without any user interaction.`r`n"
    $tip += "- Cross-reference high-risk apps here with the EnterpriseApps report to check`r`n"
    $tip += "  publisher, creation date, and whether the app has credentials registered."

    Save-Report -ReportName "DelegateAppPerms" -Data $sorted `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Delegated and Application Permissions #######" `
        -InvestigativeTip $tip
}


#endregion

function Get-MailboxRulesReport {
    <#
    .SYNOPSIS
    All inbox rules across all user mailboxes, classified by action type with risk flagging.
    Uses: Get-InboxRule (still current in ExchangeOnlineManagement v3)
    NOTE: Rule creation date is not exposed by Exchange Online - DateLastModified is included
    where available but may also be null for older rules.

    ActionType values:
      ExternalForward          - ForwardTo containing an external (non-tenant) address
      ExternalRedirect         - RedirectTo an external address
      ExternalForwardAsAttach  - ForwardAsAttachmentTo an external address
      Forward                  - ForwardTo an internal address
      Redirect                 - RedirectTo an internal address
      ForwardAsAttachment      - ForwardAsAttachmentTo internal
      Delete                   - DeleteMessage = True
      Move                     - MoveToFolder set
      Copy                     - CopyToFolder set
      MarkRead                 - MarkAsRead only
      Multiple                 - Rule performs more than one of the above
      Other                    - No classified action detected

    RiskLevel:
      HIGH   - External forward/redirect, or DeleteMessage
      MEDIUM - Internal forward/redirect, or conditions matching security keywords
      LOW    - Move, Copy, MarkRead, or other passive actions
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Inbox Rules for all mailboxes..."

    try {
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox `
            -PropertySets Minimum -ErrorAction Stop
    } catch {
        Write-LogError -Message "[!] MailboxRules: failed to retrieve mailbox list" -ErrorRecord $_
        Save-Report -ReportName "MailboxRules" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Mailbox Inbox Rules #######"
        return
    }

    # Keywords suggesting a rule targets security/IT communications.
    # Attackers create rules to suppress MFA prompts, password resets, and security alerts.
    $securityKeywords = @(
        'password', 'reset', 'verify', 'verification', 'mfa', 'multi-factor',
        'authenticator', 'security', 'alert', 'unusual', 'suspicious', 'sign-in',
        'signin', 'access', 'microsoft', 'helpdesk', 'it support', 'admin',
        'breach', 'compromised', 'phish', 'malware', 'virus'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $count   = $mailboxes.Count
    $i       = 0

    # Collect tenant domains once for external address detection
    $tenantDomains = @()
    try {
        $tenantDomains = @(Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/domains" |
            Where-Object { $_.isVerified } | Select-Object -ExpandProperty id)
        Write-Log "  Loaded $($tenantDomains.Count) tenant domain(s) for external address detection."
    } catch {
        Write-Log "  [WARN] Could not load tenant domains - external forward detection may be incomplete." -Level "WARN"
    }

    foreach ($mbx in $mailboxes) {
        Write-Progress -Activity "Retrieving inbox rules..." `
            -Status ("{0}/{1}: {2}" -f $i++, $count, $mbx.PrimarySmtpAddress) `
            -PercentComplete (($i / [Math]::Max($count, 1)) * 100)

        try {
            $rules = Get-InboxRule -Mailbox $mbx.PrimarySmtpAddress `
                -IncludeHidden -ErrorAction SilentlyContinue

            foreach ($rule in $rules) {

                # ── Resolve action fields to readable strings ──────────────────
                $forwardTo       = (@($rule.ForwardTo)             | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
                $forwardAsAttach = (@($rule.ForwardAsAttachmentTo) | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
                $redirectTo      = (@($rule.RedirectTo)            | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
                $moveToFolder    = if ($rule.MoveToFolder) { $rule.MoveToFolder.ToString() } else { '' }
                $copyToFolder    = if ($rule.CopyToFolder) { $rule.CopyToFolder.ToString() } else { '' }

                # ── Check if any forward/redirect target is external ───────────
                $allTargets = @($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo) |
                    Where-Object { $_ }

                $isExternal = $false
                if ($allTargets.Count -gt 0 -and $tenantDomains.Count -gt 0) {
                    foreach ($target in $allTargets) {
                        $targetStr  = $target.ToString()
                        $addrMatch  = [regex]::Match($targetStr, '[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})')
                        if ($addrMatch.Success) {
                            $domain = $addrMatch.Groups[1].Value.ToLower()
                            if ($tenantDomains -notcontains $domain) {
                                $isExternal = $true
                                break
                            }
                        }
                    }
                } elseif ($allTargets.Count -gt 0) {
                    $isExternal = $null   # Targets exist but can't determine if external
                }

                # ── Classify ActionType ────────────────────────────────────────
                $actionTypes = [System.Collections.Generic.List[string]]::new()

                if ($rule.DeleteMessage) { $actionTypes.Add("Delete") }

                if ($rule.ForwardTo) {
                    if ($isExternal -eq $true) { $actionTypes.Add("ExternalForward") }
                    else                       { $actionTypes.Add("Forward") }
                }
                if ($rule.RedirectTo) {
                    if ($isExternal -eq $true) { $actionTypes.Add("ExternalRedirect") }
                    else                       { $actionTypes.Add("Redirect") }
                }
                if ($rule.ForwardAsAttachmentTo) {
                    if ($isExternal -eq $true) { $actionTypes.Add("ExternalForwardAsAttach") }
                    else                       { $actionTypes.Add("ForwardAsAttachment") }
                }
                if ($moveToFolder)                             { $actionTypes.Add("Move") }
                if ($copyToFolder)                             { $actionTypes.Add("Copy") }
                if ($rule.MarkAsRead -and $actionTypes.Count -eq 0) { $actionTypes.Add("MarkRead") }

                $actionType = if     ($actionTypes.Count -eq 0) { "Other" }
                              elseif ($actionTypes.Count -eq 1)  { $actionTypes[0] }
                              else                               { "Multiple: " + ($actionTypes -join ', ') }

                # ── Determine RiskLevel ────────────────────────────────────────
                $riskReasons = [System.Collections.Generic.List[string]]::new()

                if ($actionTypes | Where-Object { $_ -like "External*" }) {
                    $riskReasons.Add("External forwarding/redirect - potential data exfiltration")
                }
                if ($rule.DeleteMessage) {
                    $riskReasons.Add("DeleteMessage - may be hiding inbound communications")
                }
                if ($actionTypes | Where-Object { $_ -eq "Forward" -or $_ -eq "Redirect" -or $_ -eq "ForwardAsAttachment" }) {
                    $riskReasons.Add("Internal forwarding/redirect")
                }

                # Check conditions for security-related keywords
                $allConditionText = (
                    (@($rule.SubjectContainsWords)        -join ' ') + ' ' +
                    (@($rule.BodyContainsWords)           -join ' ') + ' ' +
                    (@($rule.SubjectOrBodyContainsWords)  -join ' ') + ' ' +
                    (@($rule.From)                        -join ' ')
                ).ToLower()

                $matchedKeywords = $securityKeywords | Where-Object { $allConditionText -like "*$_*" }
                if ($matchedKeywords) {
                    $riskReasons.Add("Conditions match security keywords: " + ($matchedKeywords -join ', '))
                }

                $riskLevel = if ($riskReasons | Where-Object { $_ -like "*External*" -or $_ -like "*DeleteMessage*" }) {
                    "HIGH"
                } elseif ($riskReasons.Count -gt 0) {
                    "MEDIUM"
                } else {
                    "LOW"
                }
                $riskFlag = ($riskReasons -join ' | ')

                # ── Build output object ────────────────────────────────────────
                $results.Add([PSCustomObject]@{
                    # Mailbox owner
                    MailboxUPN           = $mbx.UserPrincipalName
                    MailboxDisplayName   = $mbx.DisplayName
                    PrimarySmtpAddress   = $mbx.PrimarySmtpAddress

                    # Rule identity
                    RuleName             = $rule.Name
                    RuleId               = $rule.RuleIdentity
                    Enabled              = $rule.Enabled
                    Priority             = $rule.Priority
                    StopProcessingRules  = $rule.StopProcessingRules

                    # Date (creation not available in EXO)
                    DateLastModified     = $rule.DateLastModified

                    # Risk classification
                    ActionType           = $actionType
                    RiskLevel            = $riskLevel
                    RiskFlag             = $riskFlag

                    # Conditions
                    CondFrom                     = (@($rule.From)                        -join '; ')
                    CondSubjectContains          = (@($rule.SubjectContainsWords)        -join '; ')
                    CondBodyContains             = (@($rule.BodyContainsWords)           -join '; ')
                    CondSubjectOrBodyContains    = (@($rule.SubjectOrBodyContainsWords)  -join '; ')
                    CondSentTo                   = (@($rule.SentTo)                      -join '; ')
                    CondRecipientAddressContains = (@($rule.RecipientAddressContainsWords) -join '; ')
                    CondHasAttachment            = $rule.HasAttachment

                    # Actions (raw values for full detail)
                    ActionForwardTo              = $forwardTo
                    ActionForwardAsAttachmentTo  = $forwardAsAttach
                    ActionRedirectTo             = $redirectTo
                    ActionMoveToFolder           = $moveToFolder
                    ActionCopyToFolder           = $copyToFolder
                    ActionDeleteMessage          = $rule.DeleteMessage
                    ActionMarkAsRead             = $rule.MarkAsRead
                })
            }
        } catch {
            Write-Log "[WARN] Could not retrieve inbox rules for $($mbx.PrimarySmtpAddress): $($_.Exception.Message)" -Level "WARN"
        }
    }
    Write-Progress -Activity "Retrieving inbox rules..." -Completed

    # Sort HIGH risk first, then MEDIUM, then LOW, then by mailbox UPN
    $sortOrder = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
    $sortedResults = $results | Sort-Object { $sortOrder[$_.RiskLevel] }, MailboxUPN, RuleName

    $highCount   = @($results | Where-Object { $_.RiskLevel -eq "HIGH"   }).Count
    $mediumCount = @($results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowCount    = @($results | Where-Object { $_.RiskLevel -eq "LOW"    }).Count

    Write-Log "[+] MailboxRules: $($results.Count) rules across $(@($results.MailboxUPN | Select-Object -Unique).Count) mailboxes (HIGH: $highCount / MEDIUM: $mediumCount / LOW: $lowCount)"

    $tip = "SUMMARY: $($results.Count) inbox rules found.`r`n"
    $tip += "  HIGH:   $highCount (external forwards, deletes)`r`n"
    $tip += "  MEDIUM: $mediumCount (internal forwards, security keyword conditions)`r`n"
    $tip += "  LOW:    $lowCount (move, copy, mark-read)`r`n`r`n"
    $tip += "INVESTIGATIVE TIPS:`r`n"
    $tip += "- HIGH/ExternalForward: Rules forwarding email externally are a critical finding.`r`n"
    $tip += "  Attackers create these immediately after compromise for persistent mail access.`r`n"
    $tip += "- HIGH/Delete: Rules deleting mail matching certain senders/subjects hide password`r`n"
    $tip += "  reset emails, MFA prompts, and security alerts from the legitimate user.`r`n"
    $tip += "- MEDIUM/Forward: Internal forwards may indicate unauthorized monitoring.`r`n"
    $tip += "- MEDIUM/SecurityKeywords: Conditions matching words like 'password', 'MFA',`r`n"
    $tip += "  or 'Microsoft' suggest the attacker is targeting security communications.`r`n"
    $tip += "- Review Enabled=False rules: attackers sometimes create rules and disable them`r`n"
    $tip += "  temporarily to avoid detection, re-enabling them as needed.`r`n"
    $tip += "- NOTE: Rule creation date is unavailable in Exchange Online. DateLastModified`r`n"
    $tip += "  is shown where populated but may be null for unedited rules."

    Save-Report -ReportName "MailboxRules" -Data $sortedResults `
        -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
        -SectionHeader "####### Mailbox Inbox Rules #######" `
        -InvestigativeTip $tip
}

#region ── EXCHANGE ONLINE REPORT FUNCTIONS ────────────────────────────────────

function Get-ClientAccessReport {
    <#
    .SYNOPSIS
    Client access settings per mailbox (OWA, ActiveSync, IMAP, POP, MAPI, EWS).
    Uses: Get-EXOCASMailbox (modern Exchange cmdlet, replaces Get-CASMailbox)
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Client Access Settings (CAS Mailboxes)..."

    try {
        $casMailboxes = Get-EXOCASMailbox -ResultSize Unlimited `
            -PropertySets All -ErrorAction Stop

        $results = $casMailboxes | Select-Object `
            DisplayName, PrimarySmtpAddress, SamAccountName,
            OWAEnabled, OWAforDevicesEnabled,
            ActiveSyncEnabled, ActiveSyncMailboxPolicy,
            ImapEnabled, ImapUseProtocolDefaults,
            PopEnabled, PopUseProtocolDefaults,
            MapiEnabled, MapiHttpEnabled,
            EwsEnabled, EwsAllowOutlook, EwsApplicationAccessPolicy,
            ECPEnabled, UniversalOutlookEnabled, OutlookMobileEnabled

        Save-Report -ReportName "ClientAccess" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Client Access Settings #######" `
            -InvestigativeTip "Review mailboxes with unexpected legacy protocols enabled (IMAP, POP, ActiveSync). These protocols bypass MFA and can be used in password spray attacks. Investigate accounts where EwsEnabled is True but no known business reason exists."
    } catch {
        Write-LogError -Message "[!] ClientAccess error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "ClientAccess" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Client Access Settings #######"
    }
}

function Get-RemoteDomainsReport {
    <#
    .SYNOPSIS
    Remote domain configuration. Get-RemoteDomain is still current.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Remote Domain configuration..."

    try {
        $remoteDomains = Get-RemoteDomain -ErrorAction Stop
        $results = $remoteDomains | Select-Object `
            Name, DomainName, AllowedOOFType, AutoReplyEnabled,
            AutoForwardEnabled, DeliveryReportEnabled, NDREnabled,
            MeetingForwardNotificationEnabled, ContentType,
            DisplaySenderName, IsInternal, TargetDeliveryDomain,
            TNEFEnabled, TrustedMailInboundEnabled, TrustedMailOutboundEnabled,
            UseSimpleDisplayName

        Save-Report -ReportName "RemoteDomains" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Remote Domains #######" `
            -InvestigativeTip "Review remote domains where AutoForwardEnabled=True. This can allow sensitive email to be automatically forwarded to external addresses. Verify all remote domains are known/expected."
    } catch {
        Write-LogError -Message "[!] RemoteDomains error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "RemoteDomains" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Remote Domains #######"
    }
}

function Get-SMTPForwardReport {
    <#
    .SYNOPSIS
    Mailboxes with SMTP forwarding set, classified as Internal or External with risk tiering.
    Uses: Get-EXOMailbox (modern cmdlet, replaces Get-Mailbox for this query)

    RiskLevel:
      HIGH   - Forwarding to an external (non-tenant) address
      MEDIUM - Forwarding to an internal address with DeliverToMailboxAndForward=False
               (original copy NOT kept — mail silently redirected)
      LOW    - Forwarding to an internal address, original copy kept
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving SMTP Forwarding configurations..."

    # Load tenant domains for external detection
    $tenantDomains = @()
    try {
        $tenantDomains = @(Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/domains" |
            Where-Object { $_.isVerified } | Select-Object -ExpandProperty id)
    } catch {
        Write-Log "  [WARN] Could not load tenant domains - external detection may be incomplete." -Level "WARN"
    }

    try {
        $forwardingMailboxes = Get-EXOMailbox -ResultSize Unlimited `
            -Filter { ForwardingAddress -ne $null -or ForwardingSmtpAddress -ne $null } `
            -PropertySets Delivery -ErrorAction Stop

        $results = [System.Collections.Generic.List[object]]::new()

        foreach ($mbx in $forwardingMailboxes) {
            # Determine the forwarding target address for external check
            $fwdTarget = if ($mbx.ForwardingSmtpAddress) {
                # ForwardingSmtpAddress is always an SMTP address string
                $mbx.ForwardingSmtpAddress -replace '^smtp:', ''
            } elseif ($mbx.ForwardingAddress) {
                $mbx.ForwardingAddress.ToString()
            } else { '' }

            # Check if target is external
            $isExternal = $false
            if ($fwdTarget -and $tenantDomains.Count -gt 0) {
                $addrMatch = [regex]::Match($fwdTarget, '@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})')
                if ($addrMatch.Success) {
                    $domain = $addrMatch.Groups[1].Value.ToLower()
                    $isExternal = $tenantDomains -notcontains $domain
                }
            }

            $forwardType = if ($isExternal) { "External" } else { "Internal" }

            # Risk classification
            $riskLevel  = ""
            $riskFlag   = ""
            if ($isExternal) {
                $riskLevel = "HIGH"
                $riskFlag  = "External forwarding to $fwdTarget - potential data exfiltration"
            } elseif (-not $mbx.DeliverToMailboxAndForward) {
                $riskLevel = "MEDIUM"
                $riskFlag  = "Internal forward with DeliverToMailboxAndForward=False - original mail not retained in source mailbox"
            } else {
                $riskLevel = "LOW"
                $riskFlag  = "Internal forward, copy kept in source mailbox"
            }

            $results.Add([PSCustomObject]@{
                DisplayName                = $mbx.DisplayName
                UserPrincipalName          = $mbx.UserPrincipalName
                PrimarySmtpAddress         = $mbx.PrimarySmtpAddress
                ForwardingAddress          = $mbx.ForwardingAddress
                ForwardingSmtpAddress      = $mbx.ForwardingSmtpAddress
                DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
                ForwardType                = $forwardType
                RiskLevel                  = $riskLevel
                RiskFlag                   = $riskFlag
                RecipientType              = $mbx.RecipientType
                RecipientTypeDetails       = $mbx.RecipientTypeDetails
            })
        }

        # Sort HIGH first
        $sortOrder = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
        $sorted = $results | Sort-Object { $sortOrder[$_.RiskLevel] }, PrimarySmtpAddress

        $highCount   = @($results | Where-Object { $_.RiskLevel -eq "HIGH"   }).Count
        $medCount    = @($results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowCount    = @($results | Where-Object { $_.RiskLevel -eq "LOW"    }).Count

        Write-Log "[+] SMTPForward: $($results.Count) forwarding mailboxes (HIGH: $highCount, MEDIUM: $medCount, LOW: $lowCount)"

        $tip  = "SUMMARY: $($results.Count) mailboxes with forwarding configured.`r`n"
        $tip += "  HIGH:   $highCount (external forwarding)`r`n"
        $tip += "  MEDIUM: $medCount (internal, original copy not retained)`r`n"
        $tip += "  LOW:    $lowCount (internal, copy retained)`r`n`r`n"
        $tip += "INVESTIGATIVE TIPS:`r`n"
        $tip += "- HIGH/External: Any external SMTP forward is a critical finding. Attackers set`r`n"
        $tip += "  these via compromised accounts or PowerShell to exfiltrate all incoming mail.`r`n"
        $tip += "  Verify every external forward has an approved business justification.`r`n"
        $tip += "- MEDIUM/Internal (no copy): Forwarding with DeliverToMailboxAndForward=False`r`n"
        $tip += "  means the original mailbox never receives the mail - the user may not know`r`n"
        $tip += "  their mail is being redirected. Investigate these carefully.`r`n"
        $tip += "- LOW/Internal (copy kept): Lower risk but still warrants verification. Could`r`n"
        $tip += "  indicate shared mailbox access or legitimate delegation."

        Save-Report -ReportName "SMTPForward" -Data $sorted `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### SMTP Forwarding #######" `
            -InvestigativeTip $tip
    } catch {
        Write-LogError -Message "[!] SMTPForward error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "SMTPForward" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### SMTP Forwarding #######"
    }
}


function Get-TransportRulesReport {
    <#
    .SYNOPSIS
    Mail transport rules with action classification and risk tiering.
    Uses: Get-TransportRule (still current)

    ActionType values (same classification logic as MailboxRules for consistency):
      ExternalForward   - ForwardTo/ForwardAsAttachmentTo with external address
      ExternalRedirect  - RedirectMessageTo with external address
      ExternalBCC       - BlindCopyTo with external address
      Forward           - ForwardTo internal
      Redirect          - RedirectMessageTo internal
      BCC               - BlindCopyTo internal
      Delete            - DeleteMessage = True
      Quarantine        - Quarantine action set
      Reject            - RejectMessageEnhancedStatusCode set
      ModifyHeader      - SetHeaderName/RemoveHeader (can suppress security headers)
      Multiple          - More than one of the above
      Other             - No classified action

    RiskLevel:
      HIGH   - External forward/redirect/BCC, or DeleteMessage, or Quarantine of inbound
      MEDIUM - Internal forward/redirect, header modification, Reject bypass, Disabled rules
               with high-risk actions (may be re-enabled), BypassSpamFiltering
      LOW    - Moderation, classification labels, OME, subject prepend, other passive rules
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Transport Rules..."

    # Load tenant domains for external detection
    $tenantDomains = @()
    try {
        $tenantDomains = @(Invoke-GraphRequestAll -Uri "https://graph.microsoft.com/v1.0/domains" |
            Where-Object { $_.isVerified } | Select-Object -ExpandProperty id)
    } catch {
        Write-Log "  [WARN] Could not load tenant domains - external detection may be incomplete." -Level "WARN"
    }

    # Helper: check if any address in a collection is external
    function Test-HasExternalAddress {
        param($Addresses, $TenantDomains)
        if (-not $Addresses -or $TenantDomains.Count -eq 0) { return $false }
        foreach ($addr in $Addresses) {
            $str   = $addr.ToString()
            $match = [regex]::Match($str, '@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})')
            if ($match.Success -and $TenantDomains -notcontains $match.Groups[1].Value.ToLower()) {
                return $true
            }
        }
        return $false
    }

    try {
        $rules   = Get-TransportRule -ResultSize Unlimited -ErrorAction Stop
        $results = [System.Collections.Generic.List[object]]::new()

        foreach ($rule in $rules) {

            # ── Resolve address fields to strings ──────────────────────────────
            $forwardToStr     = (@($rule.ForwardTo)             | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
            $fwdAttachStr     = (@($rule.ForwardAsAttachmentTo) | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
            $redirectToStr    = (@($rule.RedirectMessageTo)     | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
            $bccStr           = (@($rule.BlindCopyTo)           | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
            $copyToStr        = (@($rule.CopyTo)                | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '
            $addRecipientsStr = (@($rule.AddToRecipients)       | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join '; '

            # ── External checks ────────────────────────────────────────────────
            $fwdExternal      = Test-HasExternalAddress $rule.ForwardTo $tenantDomains
            $fwdAttExternal   = Test-HasExternalAddress $rule.ForwardAsAttachmentTo $tenantDomains
            $redirExternal    = Test-HasExternalAddress $rule.RedirectMessageTo $tenantDomains
            $bccExternal      = Test-HasExternalAddress $rule.BlindCopyTo $tenantDomains

            # ── Classify action types ──────────────────────────────────────────
            $actionTypes = [System.Collections.Generic.List[string]]::new()

            if ($rule.DeleteMessage)                        { $actionTypes.Add("Delete") }
            if ($rule.Quarantine)                           { $actionTypes.Add("Quarantine") }
            if ($rule.RejectMessageEnhancedStatusCode)      { $actionTypes.Add("Reject") }

            if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo) {
                if ($fwdExternal -or $fwdAttExternal)      { $actionTypes.Add("ExternalForward") }
                else                                        { $actionTypes.Add("Forward") }
            }
            if ($rule.RedirectMessageTo) {
                if ($redirExternal)                         { $actionTypes.Add("ExternalRedirect") }
                else                                        { $actionTypes.Add("Redirect") }
            }
            if ($rule.BlindCopyTo) {
                if ($bccExternal)                           { $actionTypes.Add("ExternalBCC") }
                else                                        { $actionTypes.Add("BCC") }
            }
            if ($rule.SetHeaderName -or $rule.RemoveHeader) { $actionTypes.Add("ModifyHeader") }
            if ($rule.PrependSubject)                       { $actionTypes.Add("PrependSubject") }
            if ($rule.ApplyOME -or $rule.RemoveOME)         { $actionTypes.Add("EncryptionChange") }

            $actionType = if ($actionTypes.Count -eq 0)    { "Other" }
                          elseif ($actionTypes.Count -eq 1) { $actionTypes[0] }
                          else                              { "Multiple: " + ($actionTypes -join ', ') }

            # ── Risk classification ────────────────────────────────────────────
            $riskReasons = [System.Collections.Generic.List[string]]::new()

            if ($actionTypes | Where-Object { $_ -like "External*" }) {
                $riskReasons.Add("External recipient in forward/redirect/BCC - potential data exfiltration")
            }
            if ($rule.DeleteMessage) {
                $riskReasons.Add("DeleteMessage - suppresses mail delivery entirely")
            }
            if ($rule.Quarantine -and $rule.SentToScope -ne 'InOrganization') {
                $riskReasons.Add("Quarantine applied to inbound mail - review scope")
            }
            if ($rule.SetSCL -eq -1) {
                $riskReasons.Add("SCL=-1 bypass spam filtering - whitelists mail from detection")
            }
            if ($actionTypes | Where-Object { $_ -eq "Forward" -or $_ -eq "Redirect" -or $_ -eq "BCC" }) {
                $riskReasons.Add("Internal forward/redirect/BCC on transport rule")
            }
            if ($rule.SetHeaderName -or $rule.RemoveHeader) {
                $riskReasons.Add("Header modification - could suppress security/warning banners")
            }
            # Disabled rules with dangerous actions are notable - may be staged for re-enabling
            $hasDangerousAction = ($actionTypes | Where-Object {
                $_ -like "External*" -or $_ -eq "Delete" -or $_ -eq "Forward" -or $_ -eq "Redirect"
            }).Count -gt 0
            if ($rule.State -eq 'Disabled' -and $hasDangerousAction) {
                $riskReasons.Add("Rule is DISABLED but has high-risk action - may be staged by attacker")
            }

            $riskLevel = if ($riskReasons | Where-Object {
                $_ -like "External*" -or $_ -like "*DeleteMessage*" -or $_ -like "*Quarantine*"
            }) { "HIGH" }
            elseif ($riskReasons.Count -gt 0) { "MEDIUM" }
            else                              { "LOW" }

            $riskFlag = ($riskReasons -join ' | ')

            $results.Add([PSCustomObject]@{
                RuleName                     = $rule.Name
                RuleIdentity                 = $rule.Identity
                State                        = $rule.State
                Mode                         = $rule.Mode
                Priority                     = $rule.Priority
                ActionType                   = $actionType
                RiskLevel                    = $riskLevel
                RiskFlag                     = $riskFlag
                FromScope                    = $rule.FromScope
                SentToScope                  = $rule.SentToScope
                Description                  = $rule.Description
                Comments                     = $rule.Comments
                # Conditions
                CondFrom                     = (@($rule.From)                  -join '; ')
                CondFromMemberOf             = (@($rule.FromMemberOf)          -join '; ')
                CondSentTo                   = (@($rule.SentTo)                -join '; ')
                CondSubjectContains          = (@($rule.SubjectContainsWords)  -join '; ')
                CondAttachmentContains       = (@($rule.AttachmentContainsWords) -join '; ')
                # Actions
                ActionForwardTo              = $forwardToStr
                ActionForwardAsAttachmentTo  = $fwdAttachStr
                ActionRedirectTo             = $redirectToStr
                ActionBlindCopyTo            = $bccStr
                ActionCopyTo                 = $copyToStr
                ActionAddToRecipients        = $addRecipientsStr
                ActionDeleteMessage          = $rule.DeleteMessage
                ActionQuarantine             = $rule.Quarantine
                ActionRejectCode             = $rule.RejectMessageEnhancedStatusCode
                ActionSetHeaderName          = $rule.SetHeaderName
                ActionSetHeaderValue         = $rule.SetHeaderValue
                ActionRemoveHeader           = $rule.RemoveHeader
                ActionPrependSubject         = $rule.PrependSubject
                ActionSetSCL                 = $rule.SetSCL
                ActionApplyOME               = $rule.ApplyOME
                ActionRemoveOME              = $rule.RemoveOME
            })
        }

        $sortOrder = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
        $sorted = $results | Sort-Object { $sortOrder[$_.RiskLevel] }, Priority

        $highCount = @($results | Where-Object { $_.RiskLevel -eq "HIGH"   }).Count
        $medCount  = @($results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowCount  = @($results | Where-Object { $_.RiskLevel -eq "LOW"    }).Count

        Write-Log "[+] TransportRules: $($results.Count) rules (HIGH: $highCount, MEDIUM: $medCount, LOW: $lowCount)"

        $tip  = "SUMMARY: $($results.Count) transport rules found.`r`n"
        $tip += "  HIGH:   $highCount (external forward/redirect/BCC, delete, or quarantine)`r`n"
        $tip += "  MEDIUM: $medCount (internal forward/redirect, header modification, spam bypass)`r`n"
        $tip += "  LOW:    $lowCount (moderation, labeling, OME, other passive rules)`r`n`r`n"
        $tip += "INVESTIGATIVE TIPS:`r`n"
        $tip += "- HIGH/External: Transport rules forwarding to external addresses affect ALL`r`n"
        $tip += "  mail matching conditions tenant-wide - far broader impact than inbox rules.`r`n"
        $tip += "- HIGH/Delete: Tenant-wide message suppression. Verify the business purpose.`r`n"
        $tip += "- MEDIUM/SCL=-1: Rules bypassing spam filtering can whitelist phishing domains.`r`n"
        $tip += "- MEDIUM/HeaderModify: Rules removing headers like X-MS-Exchange-Organization-SCL`r`n"
        $tip += "  or warning banners weaken security posture for all users.`r`n"
        $tip += "- Review DISABLED rules with dangerous actions (flagged MEDIUM) - attackers`r`n"
        $tip += "  sometimes create rules and disable them, re-enabling during active exfiltration.`r`n"
        $tip += "- Check Mode field: 'Audit' and 'AuditAndNotify' rules don't enforce actions.`r`n"
        $tip += "  A rule set to Audit that should be Enforce is a misconfiguration finding."

        Save-Report -ReportName "TransportRules" -Data $sorted `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Mail Transport Rules #######" `
            -InvestigativeTip $tip
    } catch {
        Write-LogError -Message "[!] TransportRules error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "TransportRules" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Mail Transport Rules #######"
    }
}


function Get-FullAccessGrantedReport {
    <#
    .SYNOPSIS
    Mailboxes where FullAccess has been delegated to another account.
    Uses Get-EXOMailboxPermission (modern, replaces Get-MailboxPermission for bulk queries).
    Note: This is resource-intensive for large tenants. Uses server-side filtering.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving FullAccess mailbox delegations (this may take a while for large tenants)..."

    try {
        # Get all user mailboxes
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox `
            -PropertySets Minimum -ErrorAction Stop

        $results = [System.Collections.Generic.List[object]]::new()
        $count = $mailboxes.Count
        $i = 0

        foreach ($mbx in $mailboxes) {
            Write-Progress -Activity "Checking FullAccess permissions..." `
                -Status ("{0}/{1}: {2}" -f $i++, $count, $mbx.PrimarySmtpAddress) `
                -PercentComplete (($i / [Math]::Max($count, 1)) * 100)

            try {
                $perms = Get-EXOMailboxPermission -Identity $mbx.PrimarySmtpAddress `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.AccessRights -contains "FullAccess" -and
                        $_.IsInherited -eq $false -and
                        $_.User -notmatch "NT AUTHORITY"
                    }

                foreach ($perm in $perms) {
                    $results.Add([PSCustomObject]@{
                        MailboxDisplayName   = $mbx.DisplayName
                        MailboxUPN           = $mbx.UserPrincipalName
                        PrimarySmtpAddress   = $mbx.PrimarySmtpAddress
                        DelegateUser         = $perm.User
                        AccessRights         = ($perm.AccessRights -join ', ')
                        IsInherited          = $perm.IsInherited
                        Deny                 = $perm.Deny
                    })
                }
            } catch { }
        }
        Write-Progress -Activity "Checking FullAccess permissions..." -Completed

        Save-Report -ReportName "FullAccessGranted" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Full Access Mailbox Delegations #######" `
            -InvestigativeTip "Review all FullAccess delegations, especially where the delegate is a service account, shared mailbox, or unfamiliar user. FullAccess to executive or sensitive mailboxes from unexpected accounts is a common post-compromise persistence technique."
    } catch {
        Write-LogError -Message "[!] FullAccessGranted error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "FullAccessGranted" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Full Access Mailbox Delegations #######"
    }
}

function Get-AnyAccessGrantedReport {
    <#
    .SYNOPSIS
    Any non-default, non-inherited mailbox permission (all access types).
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving all non-default mailbox access delegations..."

    try {
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox `
            -PropertySets Minimum -ErrorAction Stop

        $results = [System.Collections.Generic.List[object]]::new()
        $count = $mailboxes.Count
        $i = 0

        foreach ($mbx in $mailboxes) {
            Write-Progress -Activity "Checking all mailbox access permissions..." `
                -Status ("{0}/{1}: {2}" -f $i++, $count, $mbx.PrimarySmtpAddress) `
                -PercentComplete (($i / [Math]::Max($count, 1)) * 100)

            try {
                $perms = Get-EXOMailboxPermission -Identity $mbx.PrimarySmtpAddress `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.IsInherited -eq $false -and
                        $_.User -notmatch "NT AUTHORITY" -and
                        $_.Deny -eq $false
                    }

                foreach ($perm in $perms) {
                    $results.Add([PSCustomObject]@{
                        MailboxDisplayName = $mbx.DisplayName
                        MailboxUPN         = $mbx.UserPrincipalName
                        PrimarySmtpAddress = $mbx.PrimarySmtpAddress
                        DelegateUser       = $perm.User
                        AccessRights       = ($perm.AccessRights -join ', ')
                        IsInherited        = $perm.IsInherited
                        Deny               = $perm.Deny
                    })
                }
            } catch { }
        }
        Write-Progress -Activity "Checking all mailbox access permissions..." -Completed

        Save-Report -ReportName "AnyAccessGranted" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Any Mailbox Access Delegations #######" `
            -InvestigativeTip "Review all non-default, non-inherited mailbox permissions. Cross-reference with FullAccessGranted to identify any other access types (e.g. DeleteItem, ReadPermission) granted to unexpected accounts."
    } catch {
        Write-LogError -Message "[!] AnyAccessGranted error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "AnyAccessGranted" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Any Mailbox Access Delegations #######"
    }
}

function Get-SendAsGrantedReport {
    <#
    .SYNOPSIS
    SendAs permissions granted on mailboxes.
    Uses Get-EXORecipientPermission (modern, replaces Get-RecipientPermission).
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving SendAs permissions..."

    try {
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox `
            -PropertySets Minimum -ErrorAction Stop

        $results = [System.Collections.Generic.List[object]]::new()
        $count = $mailboxes.Count
        $i = 0

        foreach ($mbx in $mailboxes) {
            Write-Progress -Activity "Checking SendAs permissions..." `
                -Status ("{0}/{1}: {2}" -f $i++, $count, $mbx.PrimarySmtpAddress) `
                -PercentComplete (($i / [Math]::Max($count, 1)) * 100)

            try {
                $perms = Get-EXORecipientPermission -Identity $mbx.PrimarySmtpAddress `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.AccessRights -contains "SendAs" -and
                        $_.IsInherited -eq $false -and
                        $_.Trustee -notmatch "NT AUTHORITY" -and
                        $_.Trustee -notmatch "S-1-5"
                    }

                foreach ($perm in $perms) {
                    $results.Add([PSCustomObject]@{
                        MailboxDisplayName = $mbx.DisplayName
                        MailboxUPN         = $mbx.UserPrincipalName
                        PrimarySmtpAddress = $mbx.PrimarySmtpAddress
                        Trustee            = $perm.Trustee
                        AccessRights       = ($perm.AccessRights -join ', ')
                        IsInherited        = $perm.IsInherited
                    })
                }
            } catch { }
        }
        Write-Progress -Activity "Checking SendAs permissions..." -Completed

        Save-Report -ReportName "SendAsGranted" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### SendAs Permissions #######" `
            -InvestigativeTip "SendAs permission allows one account to send email appearing to come from another mailbox. Review for unexpected delegations, especially on executive or shared mailboxes. This capability is heavily abused in BEC (Business Email Compromise) attacks."
    } catch {
        Write-LogError -Message "[!] SendAsGranted error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "SendAsGranted" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### SendAs Permissions #######"
    }
}

function Get-EXOPowerShellReport {
    <#
    .SYNOPSIS
    Users with Exchange Online Remote PowerShell access enabled.
    Uses Get-User (still current in ExchangeOnlineManagement v3).
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving EXO PowerShell access settings..."

    try {
        $allUsers = Get-User -ResultSize Unlimited -ErrorAction Stop

        $results = $allUsers | Select-Object `
            DisplayName, UserPrincipalName, PrimarySmtpAddress,
            RemotePowerShellEnabled,
            # EWSEnabled was relevant historically; include if available
            RecipientType, RecipientTypeDetails,
            @{n='EXOPowerShellEnabled'; e={$_.RemotePowerShellEnabled}}

        $enabledUsers = $results | Where-Object { $_.RemotePowerShellEnabled -eq $true }

        Save-Report -ReportName "EXOPowerShell" -Data $enabledUsers `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Exchange Online Remote PowerShell Access #######" `
            -InvestigativeTip "Users with RemotePowerShellEnabled=True can use EXO PowerShell, providing powerful administrative capabilities. Review this list for non-admin accounts. Disable for any user who does not explicitly require programmatic Exchange access."
    } catch {
        Write-LogError -Message "[!] EXOPowerShell error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "EXOPowerShell" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Exchange Online Remote PowerShell Access #######"
    }
}

function Get-AuditBypassReport {
    <#
    .SYNOPSIS
    Accounts with mailbox audit logging bypassed.
    Get-MailboxAuditBypassAssociation is still current.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Mailbox Audit Bypass configurations..."

    try {
        $auditBypass = Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.AuditBypassEnabled -eq $true }

        $results = $auditBypass | Select-Object `
            Name, AuditBypassEnabled,
            @{n='AccountType'; e={ try { (Get-User $_.Name -ErrorAction SilentlyContinue).RecipientTypeDetails } catch { "" } }}

        Save-Report -ReportName "AuditBypassEnabled" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Mailbox Audit Bypass #######" `
            -InvestigativeTip "Accounts with AuditBypassEnabled=True do not generate mailbox audit log events when accessing mailboxes. This effectively creates a blind spot in your audit trail. Service accounts are common here, but any non-essential account should be investigated."
    } catch {
        Write-LogError -Message "[!] AuditBypassEnabled error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "AuditBypassEnabled" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Mailbox Audit Bypass #######"
    }
}

function Get-HiddenMailboxesReport {
    <#
    .SYNOPSIS
    Mailboxes hidden from the Global Address List.
    Uses Get-EXOMailbox with filter (modern, replaces Get-Mailbox).
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving mailboxes hidden from the Global Address List..."

    try {
        $hidden = Get-EXOMailbox -ResultSize Unlimited `
            -Filter { HiddenFromAddressListsEnabled -eq $true } `
            -PropertySets Minimum -ErrorAction Stop

        $results = $hidden | Select-Object `
            DisplayName, PrimarySmtpAddress, UserPrincipalName,
            HiddenFromAddressListsEnabled, RecipientType, RecipientTypeDetails,
            WhenCreated, WhenMailboxCreated

        Save-Report -ReportName "HiddenMailboxes" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Hidden Mailboxes (Hidden from GAL) #######" `
            -InvestigativeTip "Mailboxes hidden from the address book may be used by attackers as drop accounts for data collection or forwarded mail. Verify all hidden mailboxes are known, approved configurations (e.g. service accounts, admin mailboxes, room resources). Investigate any recently created or renamed hidden mailboxes."
    } catch {
        Write-LogError -Message "[!] HiddenMailboxes error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "HiddenMailboxes" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Hidden Mailboxes (Hidden from GAL) #######"
    }
}

function Get-AdminAuditLogConfigReport {
    <#
    .SYNOPSIS
    Admin audit logging configuration.
    Get-AdminAuditLogConfig is still current in ExchangeOnlineManagement v3.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "Retrieving Admin Audit Log configuration..."

    try {
        $config = Get-AdminAuditLogConfig -ErrorAction Stop

        $results = $config | Select-Object `
            AdminAuditLogEnabled, LogLevel, AdminAuditLogAgeLimit,
            AdminAuditLogCmdlets, AdminAuditLogParameters,
            AdminAuditLogExclusions, TestCmdletLoggingEnabled,
            UnifiedAuditLogIngestionEnabled

        Save-Report -ReportName "AdminAuditLogConfig" -Data $results `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Admin Audit Log Configuration #######" `
            -InvestigativeTip "Verify AdminAuditLogEnabled=True and UnifiedAuditLogIngestionEnabled=True. A short AdminAuditLogAgeLimit or restricted cmdlet logging scope reduces your ability to investigate historical activity. An attacker with Exchange admin access may disable or restrict audit logging to cover their tracks."
    } catch {
        Write-LogError -Message "[!] AdminAuditLogConfig error: $($_.Exception.Message)" -ErrorRecord $_
        Save-Report -ReportName "AdminAuditLogConfig" -Data @() `
            -ReportsDir $ReportsDir -SummaryFile $SummaryFile `
            -SectionHeader "####### Admin Audit Log Configuration #######"
    }
}

#endregion

#region ── PARTNER INFO PLACEHOLDER ────────────────────────────────────────────

function Get-PartnerInfoNotice {
    <#
    .SYNOPSIS
    Tenant partner / GDAP delegated admin information.
    NOTE: This information is NO LONGER queryable via PowerShell (MSOnline deprecated).
    This function produces a placeholder report with manual investigation guidance.
    #>
    Param([string]$ReportsDir, [string]$SummaryFile)

    Write-Log "[!] PartnerInfo: Delegated admin partner data cannot be retrieved via PowerShell API."
    Write-Log "    See PartnerInfo_MANUAL.txt in the Reports folder for instructions."

    $notice = @(
        [PSCustomObject]@{
            Notice = "MANUAL STEPS REQUIRED"
            Detail = "Tenant partner and delegated admin (GDAP) information is no longer available via PowerShell. The MSOnline cmdlets that provided this data (Get-MsolPartnerInformation, Get-MsolPartnerContract) have been decommissioned."
            ManualStep1 = "Sign in to https://admin.microsoft.com as Global Admin."
            ManualStep2 = "Navigate to: Settings > Partner relationships."
            ManualStep3 = "Review all listed partner organizations and their delegated permission levels."
            ManualStep4 = "For GDAP detail: https://admin.microsoft.com/AdminPortal/Home#/partners/granular"
            Reference = "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/admin-partners"
        }
    )

    $noticePath = Join-Path $ReportsDir "PartnerInfo_MANUAL.txt"
    $notice | Format-List | Out-File -FilePath $noticePath -Encoding UTF8
    Write-Log "[+] Saved partner info notice -> $noticePath"

    Out-Summary -String "`r`n####### Tenant Partner / GDAP Information #######" -SummaryFile $SummaryFile
    Out-Summary -String "** MANUAL REVIEW REQUIRED **" -SummaryFile $SummaryFile
    Out-Summary -String "Partner/GDAP data is no longer accessible via PowerShell. Navigate to:" -SummaryFile $SummaryFile
    Out-Summary -String "  https://admin.microsoft.com > Settings > Partner relationships" -SummaryFile $SummaryFile
    Out-Summary -String "  https://admin.microsoft.com/AdminPortal/Home#/partners/granular" -SummaryFile $SummaryFile
}

#endregion

#region ── TRAP: catch fatal terminating errors that would close PowerShell ────

trap {
    $errMsg = $_.Exception.Message
    $errLine = $_.InvocationInfo.ScriptLineNumber
    $errStmt = $_.InvocationInfo.Line.Trim()

    $fatalMsg = "[FATAL] Unhandled terminating error at line $errLine`: $errMsg | Statement: $errStmt"
    Write-Host $fatalMsg -ForegroundColor Red

    if ($script:LogFile) {
        "[FATAL ERROR - Script terminated]" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        $fatalMsg | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        $_.ScriptStackTrace | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        "[Log closed: $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC]" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }

    # Attempt clean disconnect before dying
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    # NOTE: Disconnect-ExchangeOnline is intentionally omitted.
    # It calls ClearAllTokensAsync() internally via a background thread which throws a
    # WAM broker NullReferenceException that cannot be caught by try/catch (background thread
    # exceptions bypass PS error handling entirely and crash the process).
    # The EXO session is automatically cleaned up when the PowerShell process exits.

    continue  # Prevent PowerShell window from closing; allow graceful exit
}

#endregion

#region ── MAIN EXECUTION ──────────────────────────────────────────────────────

Write-Host "`r`n##################################################################"
Write-Host "####### CrowdStrike Reporting Tool for Azure (CRT) V2.0  #######"
Write-Host "##################################################################`r`n"
Write-Host "This make take awhile; please be patient...`r`n"

# ── Determine commands to run ─────────────────────────────────────────────────
if ($Commands) {
    $commandList = $Commands -split '[,\s]+' | Where-Object { $_ -ne '' }
    # Validate each command
    $invalidCmds = $commandList | Where-Object { $_ -notin $ValidCommands }
    if ($invalidCmds) {
        Write-Log "[!] Unknown commands specified: $($invalidCmds -join ', ')"
        Write-Log "    Valid commands: $($ValidCommands -join ', ')"
        exit 1
    }
} else {
    $commandList = $ValidCommands
}

# ── Set up output directory ───────────────────────────────────────────────────
if (-not $WorkingDirectory) {
    $WorkingDirectory = (Get-Location).Path
}

if ($JobName) {
    $jobFolder = $JobName
} else {
    $jobFolder = [DateTime]::UtcNow.ToString("yyyyddMMTHHmm")
}

$outputDir  = Join-Path $WorkingDirectory $jobFolder
$reportsDir = Join-Path $outputDir "Reports"

New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null

# ── Initialize log file (do this first so all subsequent Write-Log calls persist) ──
$script:LogFile = Join-Path $outputDir "CRTRun.log"
"CRT Run Log - Started $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $script:LogFile -Encoding UTF8
"Job     : $jobFolder" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
"Commands: $($commandList -join ', ')" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
("-" * 70) | Out-File -FilePath $script:LogFile -Append -Encoding UTF8

# ── Start transcript (captures ALL console output including errors and warnings) ──
$script:TranscriptFile = Join-Path $outputDir "CRTTranscript.txt"
try {
    Start-Transcript -Path $script:TranscriptFile -Force -ErrorAction Stop
} catch {
    Write-Host "[WARN] Could not start transcript: $_"
}

Write-Log "Output directory: $outputDir"
Write-Log "Log file: $($script:LogFile)"

# ── Summary file setup ────────────────────────────────────────────────────────
$summaryFile = Join-Path $outputDir "CRTSummary.txt"

$reportHeader = @"
##################################################################
####### CrowdStrike Reporting Tool for Azure (CRT) Summary #######
##################################################################
V2.0 Modernized - AzureAD/MSOnline replaced with Microsoft Graph SDK

Review the following findings from your query for anomalies.
Refer to the investigative tips in each section for guidance.

Run Date  : $([DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")) UTC
Job Name  : $jobFolder
Commands  : $($commandList -join ', ')

NOTE: Tenant Partner/GDAP information requires manual review.
      See PartnerInfo_MANUAL.txt in the Reports folder.

"@
$reportHeader | Out-File -FilePath $summaryFile -Encoding UTF8

# ── Install and import modules ────────────────────────────────────────────────
Install-RequiredModules

# ── Authenticate (once each to Graph and Exchange) ────────────────────────────
Write-Log "Beginning authentication..."
try {
    Connect-AllServices `
        -AzureEnv $AzureEnvironmentName `
        -ExchangeEnv $ExchangeEnvironmentName `
        -TenantId $TenantId `
        -AppId $AppId `
        -CertThumbprint $CertificateThumbprint
} catch {
    Write-Log "[!] Authentication failed. Cannot continue."
    Write-Log "    Error: $_"
    exit 1
}

# ── Run requested reports ─────────────────────────────────────────────────────
$reportParams = @{
    ReportsDir  = $reportsDir
    SummaryFile = $summaryFile
}

$completedReports = [System.Collections.Generic.List[string]]::new()
$failedReports    = [System.Collections.Generic.List[string]]::new()

try {
    foreach ($cmd in $commandList) {
        Write-Log "Starting report: $cmd"
        $reportStart = [DateTime]::UtcNow
        try {
            switch ($cmd) {
                "FedConfig"          { Get-FedConfigReport        @reportParams }
                "FedTrust"           { Get-FedTrustReport         @reportParams }
                "ClientAccess"       { Get-ClientAccessReport      @reportParams }
                "RemoteDomains"      { Get-RemoteDomainsReport     @reportParams }
                "SMTPForward"        { Get-SMTPForwardReport       @reportParams }
                "TransportRules"     { Get-TransportRulesReport    @reportParams }
                "FullAccessGranted"  { Get-FullAccessGrantedReport @reportParams }
                "AnyAccessGranted"   { Get-AnyAccessGrantedReport  @reportParams }
                "SendAsGranted"      { Get-SendAsGrantedReport     @reportParams }
                "EXOPowerShell"      { Get-EXOPowerShellReport     @reportParams }
                "AuditBypassEnabled" { Get-AuditBypassReport       @reportParams }
                "HiddenMailboxes"    { Get-HiddenMailboxesReport   @reportParams }
                "KeyCredentials"     { Get-KeyCredentialsReport    @reportParams }
                "O365AdminGroups"    { Get-O365AdminGroupsReport   @reportParams }
                "DelegateAppPerms"   { Get-DelegateAppPermsReport  @reportParams }
                "AdminAuditLogConfig"{ Get-AdminAuditLogConfigReport @reportParams }
            "MailboxRules"       { Get-MailboxRulesReport         @reportParams }
            "EnterpriseApps"    { Get-EnterpriseAppsReport       @reportParams }
            "SignInActivity"    { Get-SignInActivityReport       @reportParams -HomeCountry $HomeCountry -SignInDays $SignInDays }
            }
            $elapsed = [int]([DateTime]::UtcNow - $reportStart).TotalSeconds
            Write-Log "Completed report: $cmd (${elapsed}s)"
            $completedReports.Add($cmd)
        } catch {
            $errRecord = $_
            Write-LogError -Message "Report '$cmd' failed — continuing to next report" -ErrorRecord $errRecord
            Out-Summary -String "`r`n[ERROR] Report '$cmd' failed: $($errRecord.Exception.Message)" -SummaryFile $summaryFile
            $failedReports.Add($cmd)
            # Continue to next report rather than aborting
        }
    }
} finally {
    # This block runs whether reports finish normally, error out, or crash
    Write-Log "--- Report run complete ---" -Level "INFO"
    Write-Log "Completed : $($completedReports -join ', ')"
    if ($failedReports.Count -gt 0) {
        Write-Log "Failed    : $($failedReports -join ', ')" -Level "WARN"
    }

    if ($script:LogFile) {
        ("-" * 70) | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        "Completed reports : $($completedReports -join ', ')" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        "Failed reports    : $($failedReports -join ', ')"    | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        "Log closed        : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }

    # ── Always output partner info notice (inside finally so it's always logged) ──
    try {
        Get-PartnerInfoNotice @reportParams
    } catch {
        Write-LogError -Message "PartnerInfoNotice failed" -ErrorRecord $_
    }

    # Always disconnect
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    # NOTE: Disconnect-ExchangeOnline is intentionally omitted.
    # It calls ClearAllTokensAsync() internally via a background thread which throws a
    # WAM broker NullReferenceException that cannot be caught by try/catch (background thread
    # exceptions bypass PS error handling entirely and crash the process).
    # The EXO session is automatically cleaned up when the PowerShell process exits.

    # Stop transcript so the file is fully flushed before the window closes
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
}

# ── Final output ──────────────────────────────────────────────────────────────
Write-Host "`r`n##################################################################"
Write-Log "CRT run complete."
Write-Log "Reports saved to: $outputDir"
Write-Log "Summary file:     $summaryFile"
Write-Log "Run log:          $($script:LogFile)"
Write-Log "Full transcript:  $($script:TranscriptFile)"
Write-Host "##################################################################`r`n"

# Keep window open if launched directly.
# Use Read-Host instead of RawUI.ReadKey - ReadKey crashes when the PowerShell
# window was spawned by the Windows security prompt ("Run once") because that
# host context does not initialize a proper RawUI interface.
try {
    $null = Read-Host "Press Enter to exit"
} catch {
    # Read-Host itself failed (e.g. non-interactive pipeline) - just exit cleanly
}

#endregion
