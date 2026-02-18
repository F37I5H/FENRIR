#Requires -Version 5.1
<#
.SYNOPSIS
    FENRIR v2.0 - Entra ID Privilege Escalation Scanner
.DESCRIPTION
    Comprehensive Entra ID / Azure reconnaissance and attack vector identification.
    Pure PowerShell - ZERO modules required. Uses Graph API + Azure Management REST API.
.PARAMETER OutputFile
    Path to save full report (optional)
.EXAMPLE
    .\fenrir.ps1
    .\fenrir.ps1 -OutputFile "C:\temp\fenrir_report.txt"
#>
param(
    [string]$OutputFile = ""
)

# ============================================================================
#  GLOBALS
# ============================================================================
$script:graphToken    = $null
$script:mgmtToken     = $null
$script:refreshToken  = $null
$script:tenantId      = $null
$script:subscriptions = @()
$script:findings      = @()
$script:attackPaths   = @()
$script:logBuffer     = @()
$script:startTime     = $null
$script:totalSections = 40
$script:currentSection = 0
$ErrorActionPreference = "SilentlyContinue"

$script:clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# ============================================================================
#  VISUAL OUTPUT ENGINE
# ============================================================================
$script:W = 78  # box inner width

# PS 5.1 compatible Unicode characters (backtick-u syntax requires PS 7+)
$cTL=[char]0x2554; $cTR=[char]0x2557; $cBL=[char]0x255A; $cBR=[char]0x255D
$cV=[char]0x2551;  $cML=[char]0x2560; $cMR=[char]0x2563
$bTL=[char]0x250C; $bTR=[char]0x2510; $bBL=[char]0x2514; $bBR=[char]0x2518
$bT=[char]0x251C;  $bH=[char]0x2500;  $bV=[char]0x2502;  $bHH=[char]0x2501
$iSQ=[char]0x25A0; $iTRI=[char]0x25B2; $iCI=[char]0x25CF; $iRI=[char]0x25CB
$iCK=[char]0x2713; $iCR=[char]0x2717;  $iAR=[char]0x25B8; $iPL=[char]0x25B6
$iRA=[char]0x2192; $iWA=[char]0x26A0;  $iTM=[char]0x23F1

function Log($msg) {
    $script:logBuffer += $msg
    if ($OutputFile) { $msg | Out-File -Append -FilePath $OutputFile -Encoding UTF8 }
}

function Write-C($text, $color) {
    Write-Host $text -ForegroundColor $color -NoNewline
    Log $text
}

function Write-CL($text, $color) {
    Write-Host $text -ForegroundColor $color
    Log $text
}

function Write-Banner {
    # Fix font for ASCII art - Raster Fonts garbles pipe/underscore alignment
    try {
        $key = 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe'
        $current = (Get-ItemProperty $key -Name 'FaceName' -ErrorAction SilentlyContinue).FaceName
        if (-not $current -or $current -eq 'Terminal') {
            Set-ItemProperty $key -Name 'FaceName' -Value 'Consolas' -ErrorAction SilentlyContinue
            Set-ItemProperty $key -Name 'FontSize' -Value 0x000e0000 -ErrorAction SilentlyContinue
        }
    } catch {}

    Write-Host ''
    $bdr = [string]::new([char]0x2500, 47)
    Write-Host "    $bTL$bdr$bTR" -ForegroundColor DarkCyan
    Write-Host "    $bV" -NoNewline -ForegroundColor DarkCyan
    Write-Host '  ' -NoNewline
    Write-Host ([char]0x2591 + [string][char]0x2588 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2588 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2584 + [char]0x2591 + [char]0x2580 + [char]0x2588 + [char]0x2580 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2584) -NoNewline -ForegroundColor Red
    Write-Host '                     ' -NoNewline
    Write-Host "$bV" -ForegroundColor DarkCyan

    Write-Host "    $bV" -NoNewline -ForegroundColor DarkCyan
    Write-Host '  ' -NoNewline
    Write-Host ([char]0x2591 + [string][char]0x2588 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2588 + [char]0x2591 + [char]0x2588 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2584 + [char]0x2591 + [char]0x2591 + [char]0x2588 + [char]0x2591 + [char]0x2591 + [char]0x2588 + [char]0x2580 + [char]0x2584) -NoNewline -ForegroundColor Yellow
    Write-Host '                     ' -NoNewline
    Write-Host "$bV" -ForegroundColor DarkCyan

    Write-Host "    $bV" -NoNewline -ForegroundColor DarkCyan
    Write-Host '  ' -NoNewline
    Write-Host ([char]0x2591 + [string][char]0x2580 + [char]0x2591 + [char]0x2591 + [char]0x2591 + [char]0x2580 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2580 + [char]0x2580 + [char]0x2591 + [char]0x2580 + [char]0x2591 + [char]0x2580) -NoNewline -ForegroundColor White
    Write-Host '                     ' -NoNewline
    Write-Host "$bV" -ForegroundColor DarkCyan

    Write-Host "    $bV" -NoNewline -ForegroundColor DarkCyan
    Write-Host '  >> Entra ID Privilege Escalation Scanner <<' -NoNewline -ForegroundColor Cyan
    Write-Host '  ' -NoNewline
    Write-Host "$bV" -ForegroundColor DarkCyan
    Write-Host "    $bV" -NoNewline -ForegroundColor DarkCyan
    Write-Host '  Pure PowerShell | Graph + Azure REST API  ' -NoNewline -ForegroundColor DarkGray
    Write-Host '   ' -NoNewline
    Write-Host "$bV" -ForegroundColor DarkCyan
    Write-Host "    $bBL$bdr$bBR" -ForegroundColor DarkCyan
    Write-Host ""

    Log "FENRIR v2.0"

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "  $bTL$bH " -NoNewline -ForegroundColor DarkGray
    Write-Host "Started" -NoNewline -ForegroundColor DarkCyan
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ts" -ForegroundColor Cyan
    Write-Host "  $bT$bH " -NoNewline -ForegroundColor DarkGray
    Write-Host "Host   " -NoNewline -ForegroundColor DarkCyan
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  $bBL$bH " -NoNewline -ForegroundColor DarkGray
    Write-Host "User   " -NoNewline -ForegroundColor DarkCyan
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$env:USERNAME" -ForegroundColor White
    Write-Host ""
    Log "  Started: $ts | Host: $env:COMPUTERNAME | User: $env:USERNAME"
}

function Write-SectionHeader([int]$num, [string]$title) {
    $script:currentSection = $num
    $script:sectionTimer = [System.Diagnostics.Stopwatch]::StartNew()

    $total = $script:totalSections
    $pct = [math]::Round(($num / $total) * 100)

    # Progress bar
    $barLen = 40
    $filled = [math]::Round(($num / $total) * $barLen)
    $empty = $barLen - $filled
    $bar = "$([string]::new([char]0x2501, $filled))$([string]::new([char]0x2500, $empty))"

    Write-Host ""
    Write-Host "  $bar " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$num/$total]" -NoNewline -ForegroundColor DarkCyan
    Write-Host " $pct%" -ForegroundColor DarkGray

    # Box header
    $w = $script:W
    $border = [string]::new([char]0x2550, $w)
    $label = "  [$("{0:D2}" -f $num)/$total]  $($title.ToUpper())"
    $pad = $w - $label.Length
    if ($pad -lt 0) { $pad = 0; $label = $label.Substring(0, $w) }

    Write-Host "  $cTL$border$cTR" -ForegroundColor Yellow
    Write-Host "  $cV" -NoNewline -ForegroundColor Yellow
    Write-Host "$label$(' ' * $pad)" -NoNewline -ForegroundColor Yellow
    Write-Host "$cV" -ForegroundColor Yellow
    Write-Host "  $cBL$border$cBR" -ForegroundColor Yellow
    Write-Host ""

    Log ""
    Log "=== [$num/$total] $($title.ToUpper()) ==="
}

function Write-SectionFooter {
    $elapsed = $script:sectionTimer.Elapsed
    $time = if ($elapsed.TotalSeconds -lt 1) { "$([math]::Round($elapsed.TotalMilliseconds))ms" }
            elseif ($elapsed.TotalSeconds -lt 60) { "$([math]::Round($elapsed.TotalSeconds, 1))s" }
            else { "$([math]::Floor($elapsed.TotalMinutes))m $([math]::Round($elapsed.Seconds))s" }

    Write-Host "  $iTM " -NoNewline -ForegroundColor DarkGray
    Write-Host "completed in $time" -ForegroundColor DarkGray
    Log "  >> completed in $time"
}

function Write-Sub([string]$title) {
    Write-Host ""
    Write-Host "  $bH$bH$bH " -NoNewline -ForegroundColor DarkYellow
    Write-Host $title -ForegroundColor DarkYellow
    Write-Host ""
    Log "  --- $title ---"
}

function Add-Finding($severity, $category, $message) {
    $script:findings += [PSCustomObject]@{ Severity=$severity; Category=$category; Message=$message }

    switch ($severity) {
        "PE" {
            Write-Host "  " -NoNewline
            Write-Host " PE!! " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
            Write-Host " [$category] " -NoNewline -ForegroundColor Red
            Write-Host $message -ForegroundColor Red
        }
        "RED" {
            Write-Host "  " -NoNewline
            Write-Host " $iSQ " -NoNewline -ForegroundColor Red
            Write-Host "[$category] " -NoNewline -ForegroundColor Red
            Write-Host $message -ForegroundColor White
        }
        "LOW" {
            Write-Host "  " -NoNewline
            Write-Host " $iTRI " -NoNewline -ForegroundColor Yellow
            Write-Host "[$category] " -NoNewline -ForegroundColor Yellow
            Write-Host $message -ForegroundColor DarkGray
        }
        "INFO" {
            Write-Host "  " -NoNewline
            Write-Host " $iRI " -NoNewline -ForegroundColor Cyan
            Write-Host "[$category] " -NoNewline -ForegroundColor DarkCyan
            Write-Host $message -ForegroundColor DarkGray
        }
    }
    Log "  [$severity] [$category] $message"
}

function Add-AttackPath($path) {
    $script:attackPaths += $path
}

function Write-OK([string]$msg) {
    Write-Host "  $iCK " -NoNewline -ForegroundColor Green
    Write-Host $msg -ForegroundColor Green
    Log "  [OK] $msg"
}

function Write-Inf([string]$msg) {
    Write-Host "  $iAR " -NoNewline -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Log "  [*] $msg"
}

function Write-Err([string]$msg) {
    Write-Host "  $iCR " -NoNewline -ForegroundColor DarkGray
    Write-Host $msg -ForegroundColor DarkGray
    Log "  [x] $msg"
}

function Write-Dat([string]$msg, [switch]$last) {
    $connector = if ($last) { "$bBL$bH" } else { "$bT$bH" }
    Write-Host "    $connector " -NoNewline -ForegroundColor DarkGray
    Write-Host $msg -ForegroundColor White
    Log "    $msg"
}

function Write-DatKV([string]$key, [string]$value, [switch]$last) {
    $connector = if ($last) { "$bBL$bH" } else { "$bT$bH" }
    Write-Host "    $connector " -NoNewline -ForegroundColor DarkGray
    Write-Host "$key" -NoNewline -ForegroundColor DarkCyan
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host $value -ForegroundColor White
    Log "    $key : $value"
}

function Write-DatSub([string]$msg) {
    Write-Host "    $bV  " -NoNewline -ForegroundColor DarkGray
    Write-Host $msg -ForegroundColor Gray
    Log "      $msg"
}

function Write-Highlight([string]$msg) {
    Write-Host "    $iPL " -NoNewline -ForegroundColor Magenta
    Write-Host $msg -ForegroundColor White
    Log "    > $msg"
}

# ============================================================================
#  AUTHENTICATION - Device Code Flow
# ============================================================================
function Get-DeviceCodeToken($resource, $prompt=$true) {
    if ($prompt) {
        Write-Inf "Requesting device code for: $resource"
    }

    $body = @{
        client_id = $script:clientId
        resource  = $resource
    }

    $deviceCode = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/devicecode" -Method POST -Body $body

    if ($prompt) {
        Write-Host ""
        Write-Host "  [!] " -NoNewline
        Write-Host $deviceCode.message -ForegroundColor Yellow
        Write-Host ""
    }

    $tokenBody = @{
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        client_id  = $script:clientId
        code       = $deviceCode.device_code
    }

    $timeout = [DateTime]::Now.AddSeconds($deviceCode.expires_in)
    while ([DateTime]::Now -lt $timeout) {
        Start-Sleep -Seconds $deviceCode.interval
        try {
            $tokenResult = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method POST -Body $tokenBody -ErrorAction Stop
            Write-OK "Token acquired!"
            return $tokenResult
        } catch {
            $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($err.error -eq "authorization_pending") { continue }
            if ($err.error -eq "slow_down") { Start-Sleep -Seconds 5; continue }
            Write-Err "Auth Error: $($err.error_description)"
            return $null
        }
    }
    Write-Err "Timeout waiting for authentication"
    return $null
}

function Get-TokenFromRefresh($resource) {
    $body = @{
        grant_type    = "refresh_token"
        client_id     = $script:clientId
        refresh_token = $script:refreshToken
        resource      = $resource
    }
    try {
        $result = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method POST -Body $body -ErrorAction Stop
        return $result.access_token
    } catch {
        return $null
    }
}

function Initialize-Auth {
    Write-SectionHeader 0 "AUTHENTICATION"
    Write-Inf "Authenticate once - script gets Graph API + Azure Management tokens"
    Write-Inf "Using Device Code Flow (supports MFA, Conditional Access)"

    $graphResult = Get-DeviceCodeToken "https://graph.microsoft.com"
    if (-not $graphResult) {
        Write-Host ""
        Write-Host "  " -NoNewline
        Write-Host " FATAL " -ForegroundColor White -BackgroundColor DarkRed
        Write-Host " Cannot continue without Graph token. Exiting." -ForegroundColor Red
        exit 1
    }
    $script:graphToken   = $graphResult.access_token
    $script:refreshToken = $graphResult.refresh_token

    try {
        $payload = $graphResult.access_token.Split('.')[1]
        $padding = 4 - ($payload.Length % 4)
        if ($padding -ne 4) { $payload += '=' * $padding }
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $script:tenantId = $decoded.tid
        Write-DatKV "Tenant ID" $script:tenantId
        Write-DatKV "User" $decoded.upn -last
    } catch {}

    Write-Host ""
    Write-Inf "Getting Azure Management token (silent, no second login)..."
    $script:mgmtToken = Get-TokenFromRefresh "https://management.azure.com"
    if ($script:mgmtToken) {
        Write-OK "Azure Management token acquired!"
    } else {
        Write-Err "Could not get Management token - Azure sections will be skipped"
    }

    Write-SectionFooter
}

# ============================================================================
#  API HELPERS
# ============================================================================
function Invoke-Graph($uri, $method="GET", $allPages=$false) {
    $headers = @{ Authorization = "Bearer $($script:graphToken)"; "Content-Type" = "application/json" }
    $results = @()
    $url = if ($uri.StartsWith("http")) { $uri } else { "https://graph.microsoft.com/v1.0$uri" }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method $method -ErrorAction Stop
        if ($response.value) { $results += $response.value } else { return $response }

        if ($allPages) {
            while ($response.'@odata.nextLink') {
                $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Headers $headers -ErrorAction Stop
                if ($response.value) { $results += $response.value }
            }
        }
        return $results
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 403) { Write-Err "Access denied: $uri" }
        elseif ($code -eq 404) { Write-Err "Not found: $uri" }
        else { Write-Err "Error $code on $uri" }
        return $null
    }
}

function Invoke-AzMgmt($uri, [switch]$allPages) {
    if (-not $script:mgmtToken) { return $null }
    $headers = @{ Authorization = "Bearer $($script:mgmtToken)"; "Content-Type" = "application/json" }
    $url = if ($uri.StartsWith("http")) { $uri } else { "https://management.azure.com$uri" }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
        if ($null -ne $response.value) {
            $results = @() + $response.value
            if ($allPages) {
                while ($response.nextLink) {
                    $response = Invoke-RestMethod -Uri $response.nextLink -Headers $headers -ErrorAction Stop
                    if ($response.value) { $results += $response.value }
                }
            }
            return $results
        } else {
            return $response
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -ne 404) { Write-Err "Error $code on $uri" }
        return $null
    }
}

# Helper: parse actual binary path from service PathName (handles unquoted paths with spaces)
function Get-ServiceBinaryPath($pathName) {
    if (-not $pathName) { return $null }
    if ($pathName.StartsWith('"')) {
        # Quoted path - extract between quotes
        $m = [regex]::Match($pathName, '^"([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    # Unquoted - match everything up to .exe (case insensitive)
    $m = [regex]::Match($pathName, '(?i)^(.+?\.exe)')
    if ($m.Success) { return $m.Groups[1].Value }
    # Fallback - no .exe found, take first token
    return $pathName.Split(' ')[0]
}

# Helper: filter ACL for effective write access (excludes InheritOnly ACEs that don't apply to the object itself)
function Test-WritableACL($acl, $identitySIDs, [switch]$IncludeWellKnown) {
    $acl.Access | Where-Object {
        $_.FileSystemRights -match "Write|FullControl|Modify|CreateFiles" -and
        $_.AccessControlType -eq "Allow" -and
        # Exclude InheritOnly ACEs - they apply to children, not to this object
        -not ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -and
        ($identitySIDs -contains $_.IdentityReference.Value -or
         ($IncludeWellKnown -and $_.IdentityReference.Value -match 'Everyone|Authenticated Users|BUILTIN\\Users'))
    }
}

$script:dangerousPerms = @{
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d" = "User.Read (Delegated)"
    "df021288-bdef-4463-88db-98f22de89214" = "User.Read.All (Application)"
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61" = "Directory.Read.All (Application)"
    "19dbc75e-c2e2-444c-a770-ec596d67a097" = "Directory.ReadWrite.All (Application)"
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read (Application)"
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite (Application)"
    "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Mail.Send (Application)"
    "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All (Application)"
    "01d4f6ba-6a36-4f63-95e0-6a95a5692ab7" = "Files.Read.All (Application)"
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory (Application)"
    "62a82d76-70ea-41e2-9197-370581804d09" = "Group.ReadWrite.All (Application)"
    "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All (Application)"
    "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All (Application)"
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All (Application)"
}

$script:criticalRoles = @(
    "Global Administrator", "Privileged Role Administrator", "Application Administrator",
    "Cloud Application Administrator", "Exchange Administrator", "Intune Administrator",
    "Azure AD Joined Device Local Administrator", "Hybrid Identity Administrator",
    "Authentication Administrator", "Password Administrator", "Security Administrator",
    "Conditional Access Administrator", "Directory Synchronization Accounts",
    "Partner Tier2 Support", "Groups Administrator", "User Administrator"
)

# ============================================================================
#  LAYER 1: ENTRA ID RECON (Sections 1-12)
# ============================================================================

function Test-CurrentUser {
    Write-SectionHeader 1 "CURRENT USER IDENTITY & PRIVILEGES"

    $me = Invoke-Graph "/me?`$select=displayName,userPrincipalName,id,userType,accountEnabled,jobTitle,department,assignedLicenses,onPremisesSyncEnabled"
    if (-not $me) { Write-Err "Cannot read own profile"; Write-SectionFooter; return }

    Write-DatKV "Display Name" $me.displayName
    Write-DatKV "UPN" $me.userPrincipalName
    Write-DatKV "Object ID" $me.id
    Write-DatKV "User Type" $me.userType
    Write-DatKV "Enabled" "$($me.accountEnabled)"
    Write-DatKV "Job Title" "$($me.jobTitle)"
    Write-DatKV "Department" "$($me.department)"
    Write-DatKV "On-Prem Sync" "$($me.onPremisesSyncEnabled)" -last

    if ($me.userType -eq "Guest") {
        Add-Finding "INFO" "UserType" "You are a GUEST user - limited permissions expected"
    }

    Write-Sub "Group Memberships & Roles"
    $memberOf = Invoke-Graph "/me/memberOf?`$select=displayName,roleTemplateId" -allPages $true
    if ($memberOf) {
        $roles = $memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
        $groups = $memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }

        if ($roles) {
            Write-Highlight "Directory Roles:"
            foreach ($role in $roles) {
                Write-Dat "ROLE: $($role.displayName)"
                if ($role.displayName -in $script:criticalRoles) {
                    Add-Finding "PE" "OwnRole" "You have critical role: $($role.displayName)"
                    Add-AttackPath "You have '$($role.displayName)' role - check what this enables"
                }
            }
        } else {
            Write-Inf "No directory roles assigned"
        }

        if ($groups) {
            Write-Highlight "Groups ($($groups.Count)):"
            $showGroups = $groups | Select-Object -First 30
            for ($i = 0; $i -lt $showGroups.Count; $i++) {
                if ($i -eq $showGroups.Count - 1 -and $groups.Count -le 30) {
                    Write-Dat $showGroups[$i].displayName -last
                } else {
                    Write-Dat $showGroups[$i].displayName
                }
            }
            if ($groups.Count -gt 30) { Write-Dat "... and $($groups.Count - 30) more" -last }
        }
    }

    Write-Sub "Assigned Licenses"
    $licenses = Invoke-Graph "/me/licenseDetails"
    if ($licenses) {
        for ($i = 0; $i -lt $licenses.Count; $i++) {
            if ($i -eq $licenses.Count - 1) { Write-Dat "License: $($licenses[$i].skuPartNumber)" -last }
            else { Write-Dat "License: $($licenses[$i].skuPartNumber)" }
        }
    } else { Write-Inf "No licenses or cannot read" }

    Write-SectionFooter
}

function Test-DirectoryRoles {
    Write-SectionHeader 2 "DIRECTORY ROLES - WHO HAS POWER"

    $roles = Invoke-Graph "/directoryRoles?`$expand=members(`$select=displayName,userPrincipalName,id,userType)"
    if (-not $roles) { Write-Err "Cannot enumerate directory roles"; Write-SectionFooter; return }

    foreach ($role in ($roles | Sort-Object displayName)) {
        $members = $role.members
        if ($members.Count -eq 0) { continue }

        $isCritical = $role.displayName -in $script:criticalRoles
        $color = if ($isCritical) { "Yellow" } else { "White" }

        Write-Host ""
        Write-Host "    $iPL " -NoNewline -ForegroundColor $color
        Write-Host $role.displayName -NoNewline -ForegroundColor $color
        Write-Host " ($($members.Count))" -ForegroundColor DarkGray

        foreach ($m in $members) {
            $prefix = if ($m.userType -eq "Guest") { "$iWA [GUEST] " } else { "" }
            Write-Dat "$prefix$($m.displayName) ($($m.userPrincipalName))"

            if ($isCritical -and $m.userType -eq "Guest") {
                Add-Finding "LOW" "GuestAdmin" "Guest '$($m.userPrincipalName)' has critical role: $($role.displayName)"
                Add-AttackPath "Guest '$($m.userPrincipalName)' is $($role.displayName) - compromise external account"
            }
        }

        if ($isCritical -and $members.Count -gt 5) {
            Add-Finding "INFO" "RoleSprawl" "Critical role '$($role.displayName)' has $($members.Count) members"
        }
    }

    Write-Sub "Custom Roles with Dangerous Permissions"
    $customRoles = Invoke-Graph "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false&`$select=id,displayName,rolePermissions"
    if ($customRoles -and $customRoles.Count -gt 0) {
        $dangerousPatterns = @(
            "*/credentials/update", "*/owners/update", "*/allProperties/allTasks",
            "*/appRoleAssignedTo/update", "*/permissions/update"
        )
        $meId = (Invoke-Graph "/me?`$select=id").id
        foreach ($cr in $customRoles) {
            $allActions = @()
            foreach ($rp in $cr.rolePermissions) { $allActions += $rp.allowedResourceActions }
            $matched = @($allActions | Where-Object { $act = $_; ($dangerousPatterns | Where-Object { $act -like $_ }).Count -gt 0 })
            if ($matched.Count -gt 0) {
                Write-Highlight "Custom Role: $($cr.displayName)"
                foreach ($d in $matched) { Write-DatSub "Action: $d" }
                $assignments = Invoke-Graph "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($cr.id)'&`$select=principalId"
                if ($assignments -and $assignments.Count -gt 0) {
                    foreach ($a in $assignments) {
                        $principal = Invoke-Graph "/directoryObjects/$($a.principalId)?`$select=displayName,userPrincipalName"
                        $pName = if ($principal) { "$($principal.displayName)" } else { $a.principalId }
                        Write-DatSub "Assigned to: $pName"
                        if ($meId -eq $a.principalId) {
                            Add-Finding "PE" "CustomRole" "YOU have custom role '$($cr.displayName)' with: $($matched -join ', ')"
                            Add-AttackPath "Custom role '$($cr.displayName)' $iRA modify app creds/owners $iRA PE to higher privileges"
                        }
                    }
                    if (-not ($assignments | Where-Object { $_.principalId -eq $meId })) {
                        Add-Finding "RED" "CustomRole" "Custom role '$($cr.displayName)' grants: $($matched -join ', ') ($($assignments.Count) assignee(s))"
                    }
                }
            }
        }
    } else {
        Write-Inf "No custom roles defined or insufficient permissions"
    }

    Write-SectionFooter
}

function Test-MFAStatus {
    Write-SectionHeader 3 "MFA & AUTHENTICATION METHODS"

    $regDetails = Invoke-Graph "/reports/authenticationMethods/userRegistrationDetails?`$top=999" -allPages $true

    if ($regDetails) {
        $noMFA = $regDetails | Where-Object { $_.isMfaRegistered -eq $false -and $_.userType -ne "Guest" }
        $smsOnly = $regDetails | Where-Object { $_.methodsRegistered -contains "mobilePhone" -and $_.methodsRegistered.Count -eq 1 }

        Write-Inf "Total users checked: $($regDetails.Count)"
        Write-Inf "Users WITHOUT MFA: $($noMFA.Count)"
        Write-Inf "Users with SMS-only MFA: $($smsOnly.Count)"

        if ($noMFA.Count -gt 0) {
            Add-Finding "RED" "NoMFA" "$($noMFA.Count) users without MFA registered"
            Write-Sub "Users WITHOUT MFA"
            foreach ($u in ($noMFA | Select-Object -First 20)) {
                Write-Dat "$($u.userPrincipalName) (Admin: $($u.isAdmin))"
                if ($u.isAdmin) {
                    Add-Finding "RED" "AdminNoMFA" "Admin without MFA: $($u.userPrincipalName)"
                    Add-AttackPath "Admin '$($u.userPrincipalName)' has no MFA - password spray/phish target"
                }
            }
        } else {
            Add-Finding "INFO" "MFA" "All users have MFA registered"
        }

        if ($smsOnly.Count -gt 0) {
            Add-Finding "INFO" "SMSOnly" "$($smsOnly.Count) users use SMS-only MFA (SIM swap vulnerable)"
        }
    } else {
        Write-Err "Cannot read MFA registration details (requires admin)"
        Write-Inf "Checking own auth methods..."
        $myMethods = Invoke-Graph "/me/authentication/methods"
        if ($myMethods) {
            foreach ($m in $myMethods) {
                Write-Dat "Method: $($m.'@odata.type'.Split('.')[-1])"
            }
        }
    }

    Write-SectionFooter
}

function Test-ConditionalAccess {
    Write-SectionHeader 4 "CONDITIONAL ACCESS POLICIES"

    $policies = Invoke-Graph "/identity/conditionalAccess/policies"
    if (-not $policies) { Write-Err "Cannot read CA policies (requires admin)"; Write-SectionFooter; return }

    $enabled = $policies | Where-Object { $_.state -eq "enabled" }
    $disabled = $policies | Where-Object { $_.state -eq "disabled" }
    $reportOnly = $policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }

    Write-Inf "Total: $($policies.Count) | Enabled: $(@($enabled).Count) | Disabled: $(@($disabled).Count) | Report-only: $(@($reportOnly).Count)"

    # Track MFA coverage
    $mfaPolicies = @()
    $legacyAuthBlocked = $false
    $totalExclusions = 0

    foreach ($p in $enabled) {
        Write-Host ""
        Write-Highlight "Policy: $($p.displayName)"
        Write-DatKV "State" $p.state

        $excludedUsers = @($p.conditions.users.excludeUsers)
        $excludedGroups = @($p.conditions.users.excludeGroups)
        $totalExclusions += $excludedUsers.Count + $excludedGroups.Count

        if ($excludedUsers.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            # Resolve excluded user names
            foreach ($exId in $excludedUsers) {
                if ($exId -eq "GuestsOrExternalUsers") { Write-DatSub "Excludes: Guests/External Users"; continue }
                $exUser = Invoke-Graph "/directoryObjects/$exId?`$select=displayName,userPrincipalName"
                if ($exUser) { Write-DatSub "Excludes user: $($exUser.displayName) ($($exUser.userPrincipalName))" }
                else { Write-DatSub "Excludes user ID: $exId" }
            }
            foreach ($exGrp in $excludedGroups) {
                $grp = Invoke-Graph "/groups/$exGrp?`$select=displayName"
                if ($grp) { Write-DatSub "Excludes group: $($grp.displayName)" }
                else { Write-DatSub "Excludes group ID: $exGrp" }
            }
            Add-Finding "INFO" "CA-Exclusion" "Policy '$($p.displayName)' excludes $($excludedUsers.Count) users, $($excludedGroups.Count) groups"
        }

        $includesAll = $p.conditions.users.includeUsers -contains "All"
        if (-not $includesAll -and $p.conditions.users.includeRoles.Count -eq 0) {
            Write-DatSub "WARNING: Does not target all users or admin roles"
        }

        # MFA tracking
        if ($p.grantControls.builtInControls -contains "mfa") {
            Write-DatKV "Requires" "MFA"
            $mfaPolicies += $p
        }
        if ($p.grantControls.builtInControls -contains "compliantDevice") {
            Write-DatKV "Requires" "Compliant device"
        }

        # Legacy auth detection
        $clientAppTypes = $p.conditions.clientAppTypes
        if ($clientAppTypes -contains "exchangeActiveSync" -or $clientAppTypes -contains "other") {
            if ($p.grantControls.builtInControls -contains "block" -or
                ($p.grantControls.operator -eq "OR" -and $p.sessionControls)) {
                Write-DatKV "Blocks" "Legacy authentication"
                $legacyAuthBlocked = $true
            }
        }
        if ($p.conditions.clientAppTypes -contains "all" -and $p.grantControls.builtInControls -contains "block") {
            # This might be a blanket block with conditions
            Write-DatKV "Action" "Block (conditional)"
        }

        # Named location conditions
        $includeLocs = $p.conditions.locations.includeLocations
        $excludeLocs = $p.conditions.locations.excludeLocations
        if ($excludeLocs -and $excludeLocs.Count -gt 0) {
            foreach ($loc in $excludeLocs) {
                if ($loc -eq "AllTrusted") {
                    Write-DatSub "Excludes: All Trusted Locations (MFA bypass!)"
                } else {
                    Write-DatSub "Excludes location ID: $loc"
                }
            }
        }
    }

    Write-Host ""

    # MFA coverage analysis
    Write-Sub "MFA Coverage Analysis"
    $mfaAllUsers = $mfaPolicies | Where-Object { $_.conditions.users.includeUsers -contains "All" }
    if ($mfaAllUsers.Count -gt 0) {
        Write-OK "MFA required for ALL users via $($mfaAllUsers.Count) policy(ies)"
    } elseif ($mfaPolicies.Count -gt 0) {
        Add-Finding "LOW" "MFAGap" "MFA policies exist ($($mfaPolicies.Count)) but none target ALL users"
    } else {
        Add-Finding "RED" "NoMFA" "No CA policy enforces MFA!"
    }

    # Legacy auth analysis
    Write-Sub "Legacy Authentication"
    if ($legacyAuthBlocked) {
        Write-OK "Legacy authentication blocked by CA policy"
    } else {
        $hasLegacyBlock = $enabled | Where-Object {
            ($_.conditions.clientAppTypes -contains "exchangeActiveSync" -or $_.conditions.clientAppTypes -contains "other") -and
            $_.grantControls.builtInControls -contains "block"
        }
        if ($hasLegacyBlock) {
            Write-OK "Legacy auth blocked"
            $legacyAuthBlocked = $true
        } else {
            Add-Finding "RED" "LegacyAuth" "No CA policy blocks legacy authentication - password spray without MFA!"
        }
    }

    # Exclusion summary
    if ($totalExclusions -gt 5) {
        Add-Finding "LOW" "CA-ManyExcl" "$totalExclusions total user/group exclusions across CA policies - review for bypass opportunities"
    }

    # Named Locations
    Write-Sub "Named Locations / Trusted IPs"
    $namedLocations = Invoke-Graph "/identity/conditionalAccess/namedLocations"
    if ($namedLocations) {
        foreach ($nl in $namedLocations) {
            $locType = $nl.'@odata.type'
            if ($locType -match 'ipNamedLocation') {
                $trusted = if ($nl.isTrusted) { "TRUSTED" } else { "untrusted" }
                $ranges = @($nl.ipRanges | ForEach-Object { $_.cidrAddress }) -join ", "
                if ($ranges.Length -gt 80) { $ranges = $ranges.Substring(0,77) + "..." }
                Write-DatKV "$($nl.displayName) ($trusted)" $ranges
                if ($nl.isTrusted) {
                    # Check for overly broad ranges
                    foreach ($r in $nl.ipRanges) {
                        $cidr = $r.cidrAddress
                        if ($cidr -match '/(\d+)$') {
                            $prefix = [int]$Matches[1]
                            if ($prefix -le 16) {
                                Add-Finding "RED" "BroadTrustedIP" "Named location '$($nl.displayName)' has /$prefix range ($cidr) - very broad trusted network"
                            }
                        }
                        if ($cidr -match '^0\.0\.0\.0') {
                            Add-Finding "RED" "TrustedAll" "Named location '$($nl.displayName)' trusts 0.0.0.0 - effectively all IPs!"
                        }
                    }
                }
            } elseif ($locType -match 'countryNamedLocation') {
                $countries = ($nl.countriesAndRegions -join ", ")
                Write-DatKV "$($nl.displayName)" "Countries: $countries"
            }
        }
        # Check if trusted locations are used to bypass MFA
        $mfaBypassLoc = $enabled | Where-Object {
            $_.grantControls.builtInControls -contains "mfa" -and
            $_.conditions.locations.excludeLocations -contains "AllTrusted"
        }
        if ($mfaBypassLoc.Count -gt 0) {
            Add-Finding "RED" "MFABypassLoc" "$($mfaBypassLoc.Count) MFA policies exclude trusted locations - MFA bypass from trusted IPs!"
        }
    } else {
        Write-Inf "No named locations defined (or insufficient permissions)"
    }

    if ($policies.Count -eq 0) {
        Add-Finding "RED" "NoCA" "No Conditional Access policies found!"
    }

    Write-SectionFooter
}

function Test-AppRegistrations {
    Write-SectionHeader 5 "APP REGISTRATIONS - SECRETS & PERMISSIONS"

    $apps = Invoke-Graph "/applications?`$select=id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess,signInAudience&`$top=999" -allPages $true
    if (-not $apps) { Write-Err "Cannot enumerate app registrations"; Write-SectionFooter; return }

    Write-Inf "Total app registrations: $($apps.Count)"
    $appsWithSecrets = $apps | Where-Object { $_.passwordCredentials.Count -gt 0 -or $_.keyCredentials.Count -gt 0 }
    Write-Inf "Apps with secrets/certificates: $($appsWithSecrets.Count)"

    foreach ($app in $appsWithSecrets) {
        Write-Host ""
        Write-Highlight "App: $($app.displayName)"
        Write-DatKV "AppId" $app.appId
        Write-DatKV "Audience" $app.signInAudience

        foreach ($secret in $app.passwordCredentials) {
            $endDate = [DateTime]$secret.endDateTime
            $daysLeft = ($endDate - (Get-Date)).Days
            $hint = $secret.hint

            if ($daysLeft -lt 0) {
                Add-Finding "INFO" "ExpiredSecret" "App '$($app.displayName)' EXPIRED secret (hint: $hint, $([Math]::Abs($daysLeft))d ago)"
            } elseif ($daysLeft -gt 365) {
                Add-Finding "LOW" "LongSecret" "App '$($app.displayName)' secret valid $daysLeft days (hint: $hint)"
            } else {
                Write-DatKV "Secret" "hint=$hint, expires in $daysLeft days"
            }
        }

        foreach ($cert in $app.keyCredentials) {
            $endDate = [DateTime]$cert.endDateTime
            $daysLeft = ($endDate - (Get-Date)).Days
            Write-DatKV "Certificate" "$($cert.displayName), expires in $daysLeft days"
        }

        $owners = Invoke-Graph "/applications/$($app.id)/owners?`$select=displayName,userPrincipalName"
        if ($owners) {
            foreach ($owner in $owners) {
                Write-DatKV "Owner" "$($owner.displayName) ($($owner.userPrincipalName))"
            }
        }

        foreach ($resource in $app.requiredResourceAccess) {
            foreach ($perm in $resource.resourceAccess) {
                $permName = $script:dangerousPerms[$perm.id]
                if ($permName) {
                    $permType = $perm.type
                    if ($permName -match "ReadWrite|Send|RoleManagement") {
                        Add-Finding "LOW" "DangerousPerm" "App '$($app.displayName)' has $permName ($permType)"
                        if ($owners) {
                            foreach ($o in $owners) {
                                Add-AttackPath "Compromise '$($o.userPrincipalName)' (owner of '$($app.displayName)') -> add secret -> use $permName"
                            }
                        }
                    }
                }
            }
        }
    }

    $multiTenant = $apps | Where-Object { $_.signInAudience -match "AzureADMultipleOrgs|AzureADandPersonalMicrosoftAccount" }
    if ($multiTenant.Count -gt 0) {
        Add-Finding "INFO" "MultiTenant" "$($multiTenant.Count) apps accept sign-ins from other tenants"
        foreach ($mt in $multiTenant) {
            Write-Dat "Multi-tenant: $($mt.displayName)"
        }
    }

    Write-SectionFooter
}

function Test-ServicePrincipals {
    Write-SectionHeader 6 "SERVICE PRINCIPALS & MANAGED IDENTITIES"

    $sps = Invoke-Graph "/servicePrincipals?`$select=id,displayName,appId,appRoleAssignedTo,servicePrincipalType&`$top=999" -allPages $true
    if (-not $sps) { Write-Err "Cannot enumerate service principals"; Write-SectionFooter; return }

    Write-Inf "Total service principals: $($sps.Count)"

    $managedIdentities = $sps | Where-Object { $_.servicePrincipalType -eq "ManagedIdentity" }
    if ($managedIdentities.Count -gt 0) {
        Write-Sub "Managed Identities"
        foreach ($mi in $managedIdentities) {
            Write-Highlight "MI: $($mi.displayName)"
            Write-DatKV "AppId" $mi.appId
            $assignments = Invoke-Graph "/servicePrincipals/$($mi.id)/appRoleAssignments"
            if ($assignments -and $assignments.Count -gt 0) {
                foreach ($a in $assignments) {
                    $roleName = $a.appRoleId
                    # Resolve role GUID to name
                    try {
                        $resSP = Invoke-Graph "/servicePrincipals/$($a.resourceId)?`$select=appRoles"
                        if ($resSP -and $resSP.appRoles) {
                            $role = $resSP.appRoles | Where-Object { $_.id -eq $a.appRoleId }
                            if ($role) { $roleName = $role.value }
                        }
                    } catch {}
                    Write-DatSub "$iRA $($a.resourceDisplayName): $roleName"
                }
            } else {
                Write-DatSub "No app role assignments"
            }
        }
        Add-Finding "INFO" "ManagedIdentity" "$($managedIdentities.Count) Managed Identities found"

        Write-Sub "Managed Identity Effective Permissions"
        foreach ($mi in $managedIdentities) {
            $appRoles = Invoke-Graph "/servicePrincipals/$($mi.id)/appRoleAssignments?`$select=resourceDisplayName,appRoleId,resourceId"
            if ($appRoles -and $appRoles.Count -gt 0) {
                Write-Highlight "MI: $($mi.displayName)"
                foreach ($ar in $appRoles) {
                    $roleName = $ar.appRoleId
                    try {
                        $resSP = Invoke-Graph "/servicePrincipals/$($ar.resourceId)?`$select=appRoles"
                        if ($resSP -and $resSP.appRoles) {
                            $role = $resSP.appRoles | Where-Object { $_.id -eq $ar.appRoleId }
                            if ($role) { $roleName = $role.value }
                        }
                    } catch {}
                    Write-DatSub "$($ar.resourceDisplayName): $roleName"
                    if ($roleName -match 'ReadWrite\.All|FullControl|RoleManagement') {
                        Add-Finding "RED" "MI-HighPerm" "MI '$($mi.displayName)' has $roleName on $($ar.resourceDisplayName)"
                        Add-AttackPath "Compromise host with MI '$($mi.displayName)' $iRA IMDS token $iRA $roleName"
                    }
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-DangerousPermissions {
    Write-SectionHeader 7 "DANGEROUS PERMISSION GRANTS (EFFECTIVE)"

    $grants = Invoke-Graph "/oauth2PermissionGrants?`$top=999" -allPages $true
    if ($grants) {
        Write-Inf "Total OAuth2 permission grants: $($grants.Count)"

        $dangerousScopes = @("Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "User.ReadWrite.All", "Group.ReadWrite.All", "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Sites.ReadWrite.All", "MailboxSettings.ReadWrite")

        foreach ($grant in $grants) {
            if ($grant.scope) {
                $scopes = $grant.scope.Trim().Split(' ')
                $dangerous = $scopes | Where-Object { $_ -in $dangerousScopes }

                if ($dangerous) {
                    $sp = Invoke-Graph "/servicePrincipals/$($grant.clientId)?`$select=displayName"
                    $spName = if ($sp) { $sp.displayName } else { $grant.clientId }
                    $consentType = if ($grant.consentType -eq "AllPrincipals") { "ADMIN CONSENT" } else { "User consent" }

                    foreach ($d in $dangerous) {
                        Add-Finding "LOW" "GrantedPerm" "App '$spName' has $d ($consentType)"
                        if ($d -match "Mail\.(Read|Send)") {
                            Add-AttackPath "App '$spName' can read/send mail - compromise credentials for email access"
                        }
                        if ($d -match "RoleManagement|AppRoleAssignment") {
                            Add-AttackPath "App '$spName' can modify roles - compromise for Entra ID takeover"
                        }
                    }
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-GuestUsers {
    Write-SectionHeader 8 "GUEST USERS ANALYSIS"

    $guests = Invoke-Graph "/users?`$filter=userType eq 'Guest'&`$select=displayName,userPrincipalName,mail,createdDateTime,accountEnabled,id&`$top=999" -allPages $true
    if (-not $guests) { Write-Err "Cannot enumerate guest users"; Write-SectionFooter; return }

    Write-Inf "Total guest users: $($guests.Count)"

    if ($guests.Count -gt 50) {
        Add-Finding "INFO" "GuestSprawl" "$($guests.Count) guest users - review external access"
    }

    $guestAdmins = @()
    foreach ($g in $guests | Select-Object -First 100) {
        $gRoles = Invoke-Graph "/users/$($g.id)/memberOf/microsoft.graph.directoryRole?`$select=displayName"
        if ($gRoles -and $gRoles.Count -gt 0) {
            $guestAdmins += [PSCustomObject]@{ Guest=$g.userPrincipalName; Roles=($gRoles.displayName -join ", ") }
            foreach ($role in $gRoles) {
                Add-Finding "LOW" "GuestRole" "Guest '$($g.userPrincipalName)' has role: $($role.displayName)"
            }
        }
    }

    if ($guestAdmins.Count -eq 0) {
        Add-Finding "INFO" "GuestRoles" "No guest users with directory roles"
    }

    Write-SectionFooter
}

function Test-PasswordPolicy {
    Write-SectionHeader 9 "PASSWORD & DOMAIN POLICIES"

    $org = Invoke-Graph "/organization?`$select=displayName,verifiedDomains"
    if ($org) {
        foreach ($o in $org) {
            Write-Highlight "Organization: $($o.displayName)"
            foreach ($d in $o.verifiedDomains) {
                $default = if ($d.isDefault) { " [DEFAULT]" } else { "" }
                Write-DatKV "Domain" "$($d.name)$default (type: $($d.type))"
            }
        }
    }

    Write-Sub "Self-Service Password Reset"
    $sspr = Invoke-Graph "/policies/authenticationMethodsPolicy"
    if ($sspr) {
        Write-DatKV "Registration" "$($sspr.registrationEnforcement.authenticationMethodsRegistrationCampaign.state)" -last
    }

    $pwPolicy = Invoke-Graph "/settings"
    if ($pwPolicy) {
        foreach ($s in $pwPolicy) {
            if ($s.displayName -match "Password") {
                Write-Highlight "Policy: $($s.displayName)"
                foreach ($v in $s.values) {
                    Write-DatKV $v.name "$($v.value)"
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-StaleAccounts {
    Write-SectionHeader 10 "STALE & RISKY ACCOUNTS"

    $users = Invoke-Graph "/users?`$select=displayName,userPrincipalName,accountEnabled,userType,signInActivity,createdDateTime&`$top=999" -allPages $true
    if (-not $users) { Write-Err "Cannot enumerate users"; Write-SectionFooter; return }

    Write-Inf "Total users: $($users.Count)"

    $now = Get-Date
    $stale90 = @()
    $neverLoggedIn = @()

    foreach ($u in $users) {
        if ($u.userType -eq "Guest") { continue }
        if ($u.signInActivity.lastSignInDateTime) {
            $lastSignIn = [DateTime]$u.signInActivity.lastSignInDateTime
            $daysSince = ($now - $lastSignIn).Days
            if ($daysSince -gt 90) {
                $stale90 += [PSCustomObject]@{ User=$u.userPrincipalName; DaysInactive=$daysSince; Enabled=$u.accountEnabled }
            }
        } elseif ($u.accountEnabled) {
            $neverLoggedIn += $u.userPrincipalName
        }
    }

    if ($stale90.Count -gt 0) {
        Write-Sub "Stale Accounts (90+ days inactive)"
        Add-Finding "INFO" "StaleAccounts" "$($stale90.Count) member accounts inactive for 90+ days"
        foreach ($s in ($stale90 | Sort-Object DaysInactive -Descending | Select-Object -First 15)) {
            $enabledTag = if ($s.Enabled) { "$iWA ENABLED" } else { "disabled" }
            Write-Dat "$($s.User) - $($s.DaysInactive)d inactive [$enabledTag]"
        }
    }

    if ($neverLoggedIn.Count -gt 0) {
        Write-Sub "Never Logged In (enabled)"
        Add-Finding "INFO" "NeverLoggedIn" "$($neverLoggedIn.Count) enabled accounts never signed in"
        foreach ($n in ($neverLoggedIn | Select-Object -First 10)) {
            Write-Dat $n
        }
    }

    Write-Sub "Risky Users (Identity Protection)"
    $riskyUsers = Invoke-Graph "/identityProtection/riskyUsers?`$filter=riskLevel ne 'none' and riskLevel ne 'hidden'&`$select=userDisplayName,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime&`$top=50"
    if ($riskyUsers -and $riskyUsers.Count -gt 0) {
        $atRisk = $riskyUsers | Where-Object { $_.riskState -eq 'atRisk' -or $_.riskState -eq 'confirmedCompromised' }
        foreach ($ru in ($riskyUsers | Select-Object -First 20)) {
            Write-DatKV "$($ru.userDisplayName)" "$($ru.riskLevel) ($($ru.riskState))"
        }
        if ($atRisk.Count -gt 0) {
            Add-Finding "RED" "RiskyUsers" "$($atRisk.Count) users at risk or confirmed compromised"
            $confirmed = $atRisk | Where-Object { $_.riskState -eq 'confirmedCompromised' }
            if ($confirmed.Count -gt 0) {
                foreach ($c in $confirmed) {
                    Add-Finding "RED" "Compromised" "User '$($c.userPrincipalName)' marked as CONFIRMED COMPROMISED"
                }
            }
        } else {
            Add-Finding "INFO" "RiskyUsers" "$($riskyUsers.Count) users with risk signals (all remediated/dismissed)"
        }
    } else {
        Write-Inf "No risky users detected or insufficient permissions (requires P2)"
    }

    Write-SectionFooter
}

function Test-OnPremFlags {
    Write-SectionHeader 11 "ON-PREM AD FLAGS (PASSWD_NOTREQD, MAQ)"

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domain = $rootDSE.defaultNamingContext
        Write-Inf "Domain: $domain"
    } catch {
        Write-Err "Not domain-joined or cannot reach DC - skipping LDAP checks"
        Write-SectionFooter; return
    }

    Write-Sub "Machine Account Quota"
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $searcher.Filter = "(objectClass=domain)"
        $searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota") | Out-Null
        $searcher.SearchScope = "Base"
        $domResult = $searcher.FindOne()
        $maqValue = $domResult.Properties.'ms-ds-machineaccountquota'[0]
        Write-DatKV "MAQ" "$maqValue" -last
        if ([int]$maqValue -gt 0) {
            Add-Finding "RED" "MAQ" "MachineAccountQuota = $maqValue - RBCD attack vector"
        } else {
            Add-Finding "INFO" "MAQ" "MachineAccountQuota = 0"
        }
    } catch { Write-Err "Cannot read MAQ: $_" }

    Write-Sub "Accounts with PASSWD_NOTREQD Flag"
    try {
        $pwSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $pwSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
        $pwSearcher.PropertiesToLoad.AddRange(@("samaccountname","distinguishedname","useraccountcontrol","admincount"))
        $pwSearcher.PageSize = 1000
        $pwSearcher.SizeLimit = 0
        $results = $pwSearcher.FindAll()

        $count = 0
        $adminPwNotReq = @()
        foreach ($r in $results) {
            $count++
            $sam = $r.Properties.samaccountname[0]
            $admin = if ($r.Properties.admincount[0] -eq 1) { " [ADMIN]" } else { "" }
            if ($count -le 30) { Write-Dat "$sam$admin" }
            if ($admin) { $adminPwNotReq += $sam }
        }

        if ($count -gt 0) {
            if ($count -gt 30) { Write-Dat "... and $($count - 30) more" -last }
            Add-Finding "RED" "PASSWD_NOTREQD" "$count accounts with PASSWD_NOTREQD flag"
            foreach ($adm in $adminPwNotReq) {
                Add-Finding "RED" "AdminPWNotReq" "Admin '$adm' has PASSWD_NOTREQD!"
                Add-AttackPath "Admin '$adm' has PASSWD_NOTREQD - may have empty/weak password"
            }
        } else {
            Add-Finding "INFO" "PASSWD_NOTREQD" "No accounts with PASSWD_NOTREQD"
        }
        $results.Dispose()
    } catch { Write-Err "Cannot query PASSWD_NOTREQD: $_" }

    Write-Sub "Kerberoastable Accounts (user SPNs)"
    try {
        $krbSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $krbSearcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(samaccountname=krbtgt)))"
        $krbSearcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","admincount"))
        $krbSearcher.PageSize = 1000
        $results = $krbSearcher.FindAll()

        if ($results.Count -gt 0) {
            Add-Finding "RED" "Kerberoast" "$($results.Count) Kerberoastable accounts found"
            foreach ($r in $results) {
                $sam = $r.Properties.samaccountname[0]
                $spn = $r.Properties.serviceprincipalname[0]
                $admin = if ($r.Properties.admincount[0] -eq 1) { " [ADMIN]" } else { "" }
                Write-Dat "$sam $iRA $spn$admin"
                if ($admin) {
                    Add-AttackPath "Kerberoast admin '$sam' (SPN: $spn) - crack hash for admin"
                }
            }
        } else {
            Add-Finding "INFO" "Kerberoast" "No Kerberoastable user accounts"
        }
    } catch { Write-Err "Cannot query SPNs" }

    Write-Sub "AS-REP Roastable (no preauth)"
    try {
        $asrepSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $asrepSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $asrepSearcher.PropertiesToLoad.AddRange(@("samaccountname","admincount"))
        $asrepSearcher.PageSize = 1000
        $results = $asrepSearcher.FindAll()

        if ($results.Count -gt 0) {
            Add-Finding "RED" "ASREPRoast" "$($results.Count) accounts without Kerberos preauth"
            foreach ($r in $results) { Write-Dat $r.Properties.samaccountname[0] }
        } else {
            Add-Finding "INFO" "ASREPRoast" "No AS-REP roastable accounts"
        }
    } catch { Write-Err "Cannot query preauth flag" }

    Write-Sub "Domain & Forest Trusts"
    try {
        $trustSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $trustSearcher.Filter = "(objectClass=trustedDomain)"
        $trustSearcher.PropertiesToLoad.AddRange(@("cn","trustdirection","trusttype","trustattributes","trustpartner","securityidentifier"))
        $trusts = $trustSearcher.FindAll()

        if ($trusts -and $trusts.Count -gt 0) {
            foreach ($t in $trusts) {
                $tName = "$($t.Properties.cn[0])"
                $tPartner = "$($t.Properties.trustpartner[0])"
                $tDir = [int]"$($t.Properties.trustdirection[0])"
                $tType = [int]"$($t.Properties.trusttype[0])"
                $tAttr = [int]"$($t.Properties.trustattributes[0])"

                $dirLabel = switch ($tDir) { 1 {"Inbound (they trust us)"} 2 {"Outbound (we trust them)"} 3 {"Bidirectional"} default {"Unknown ($tDir)"} }
                $typeLabel = switch ($tType) { 1 {"Downlevel (NTLM)"} 2 {"Uplevel (Kerberos)"} 3 {"MIT (non-Windows)"} default {"Type $tType"} }

                # Trust attributes flags
                $sidFiltering = ($tAttr -band 0x4) -ne 0  # QUARANTINED_DOMAIN = SID filtering enabled
                $forestTransitive = ($tAttr -band 0x8) -ne 0  # FOREST_TRANSITIVE

                Write-DatKV "Trust" "$tPartner"
                Write-DatKV "Direction" $dirLabel
                Write-DatKV "Type" "$typeLabel$(if ($forestTransitive) {' (Forest Transitive)'})"
                Write-DatKV "SID Filtering" "$(if ($sidFiltering) {'Enabled (secure)'} else {'DISABLED - SID History injection possible!'})"

                if (-not $sidFiltering -and $tDir -ne 1) {
                    Add-Finding "RED" "TrustSIDFilter" "Trust to '$tPartner' has SID filtering DISABLED - cross-domain PE via SID History"
                    Add-AttackPath "Compromise $tPartner $iRA inject DA SID into SID History $iRA DA in this domain"
                }
                if ($forestTransitive) {
                    Add-Finding "LOW" "ForestTrust" "Forest transitive trust to '$tPartner'"
                }
            }
            Add-Finding "INFO" "Trusts" "$($trusts.Count) domain/forest trust(s) found"
        } else {
            Write-OK "No domain or forest trusts"
        }
        $trustSearcher.Dispose()
    } catch { Write-Err "Cannot enumerate trusts: $($_.Exception.Message)" }

    Write-SectionFooter
}

function Test-PIM {
    Write-SectionHeader 12 "PRIVILEGED IDENTITY MANAGEMENT (PIM)"

    $eligible = Invoke-Graph "/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition"
    if (-not $eligible) {
        Write-Err "Cannot read PIM assignments (requires PIM P2 or admin)"
        Write-SectionFooter; return
    }

    Write-Inf "PIM eligible role assignments: $($eligible.Count)"

    foreach ($e in $eligible) {
        $roleName = $e.roleDefinition.displayName
        $principalId = $e.principalId
        $user = Invoke-Graph "/directoryObjects/$principalId?`$select=displayName,userPrincipalName"
        $userName = if ($user) { "$($user.displayName) ($($user.userPrincipalName))" } else { $principalId }

        Write-DatKV "PIM Eligible" "$userName $iRA $roleName"

        if ($roleName -in $script:criticalRoles) {
            Add-Finding "INFO" "PIM" "PIM eligible for '$roleName': $userName"
        }
    }

    Write-SectionFooter
}

# ============================================================================
#  LAYER 2: AZURE RESOURCES (Sections 13-18)
# ============================================================================

function Test-AzureRBAC {
    Write-SectionHeader 13 "AZURE SUBSCRIPTIONS & RBAC ROLES"

    if (-not $script:mgmtToken) { Write-Err "No Azure Management token - skipping"; Write-SectionFooter; return }

    $subs = Invoke-AzMgmt "/subscriptions?api-version=2022-12-01" -allPages
    if (-not $subs -or $subs.Count -eq 0) { Write-Err "Cannot list subscriptions or no access"; Write-SectionFooter; return }

    $subs = @($subs | Where-Object { $_.subscriptionId })
    if ($subs.Count -eq 0) { Write-Err "No accessible subscriptions found"; Write-SectionFooter; return }

    $script:subscriptions = $subs
    Write-Inf "Accessible subscriptions: $($subs.Count)"

    foreach ($sub in $subs) {
        Write-Host ""
        Write-Highlight "Subscription: $($sub.displayName)"
        Write-DatKV "ID" $sub.subscriptionId
        Write-DatKV "State" $sub.state

        $roles = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        if ($roles) {
            Write-DatKV "Role assignments" "$($roles.Count)"

            foreach ($ra in $roles) {
                $roleDefId = $ra.properties.roleDefinitionId.Split('/')[-1]
                $roleDef = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Authorization/roleDefinitions/${roleDefId}?api-version=2022-04-01"
                $roleName = if ($roleDef) { $roleDef.properties.roleName } else { "Unknown" }

                if ($roleName -match "Owner|Contributor|User Access Administrator|Virtual Machine Contributor") {
                    $principalId = $ra.properties.principalId
                    Write-DatSub "$iWA $roleName $iRA $principalId"

                    $meObj = Invoke-Graph "/me?`$select=id"
                    if ($meObj -and $meObj.id -eq $principalId) {
                        Add-Finding "PE" "AzureRole" "YOU have '$roleName' on $($sub.displayName)!"
                        if ($roleName -match "Contributor|Owner") {
                            Add-AttackPath "You have '$roleName' $iRA VM Run Command = SYSTEM on any VM"
                            Add-AttackPath "You have '$roleName' $iRA deploy resources, read Key Vault, modify NSGs"
                        }
                    }
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-AzureVMs {
    Write-SectionHeader 14 "AZURE VIRTUAL MACHINES"

    if (-not $script:mgmtToken) { Write-Err "No Azure Management token - skipping"; Write-SectionFooter; return }

    foreach ($sub in $script:subscriptions) {
        $vms = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
        if (-not $vms) { continue }

        foreach ($vm in $vms) {
            Write-Host ""
            Write-Highlight "VM: $($vm.name)"
            Write-DatKV "RG" $vm.id.Split('/')[4]
            Write-DatKV "Location" $vm.location
            Write-DatKV "Size" $vm.properties.hardwareProfile.vmSize
            Write-DatKV "OS" $vm.properties.storageProfile.osDisk.osType

            if ($vm.identity) {
                $idType = $vm.identity.type
                Write-DatKV "Managed Identity" $idType

                if ($idType -match "SystemAssigned") {
                    Add-Finding "LOW" "ManagedIdentity" "VM '$($vm.name)' has System-Assigned MI"
                    Add-AttackPath "RDP to '$($vm.name)' $iRA IMDS token $iRA abuse MI permissions"
                }
                if ($vm.identity.userAssignedIdentities) {
                    foreach ($uai in $vm.identity.userAssignedIdentities.PSObject.Properties) {
                        Write-DatKV "User-Assigned MI" $uai.Name.Split('/')[-1]
                        Add-Finding "LOW" "UserAssignedMI" "VM '$($vm.name)' UA-MI: $($uai.Name.Split('/')[-1])"
                    }
                }
            } else {
                Write-DatKV "Managed Identity" "None"
            }

            $adminUser = $vm.properties.osProfile.adminUsername
            if ($adminUser) { Write-DatKV "Admin user" $adminUser -last }
        }
    }

    Write-SectionFooter
}

function Test-KeyVault {
    Write-SectionHeader 15 "AZURE KEY VAULT"

    if (-not $script:mgmtToken) { Write-Err "No Azure Management token - skipping"; Write-SectionFooter; return }

    foreach ($sub in $script:subscriptions) {
        $vaults = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        if (-not $vaults) { continue }

        foreach ($vault in $vaults) {
            Write-Host ""
            Write-Highlight "Vault: $($vault.name)"
            Write-DatKV "URI" $vault.properties.vaultUri
            Write-DatKV "SKU" $vault.properties.sku.name
            Write-DatKV "RBAC" "$($vault.properties.enableRbacAuthorization)"

            Add-Finding "INFO" "KeyVault" "Key Vault: $($vault.name) ($($vault.properties.vaultUri))"

            if ($vault.properties.accessPolicies) {
                foreach ($ap in $vault.properties.accessPolicies) {
                    $perms = @()
                    if ($ap.permissions.secrets) { $perms += "Secrets: $($ap.permissions.secrets -join ',')" }
                    if ($ap.permissions.keys) { $perms += "Keys: $($ap.permissions.keys -join ',')" }
                    if ($ap.permissions.certificates) { $perms += "Certs: $($ap.permissions.certificates -join ',')" }
                    Write-DatSub "ObjectId=$($ap.objectId) | $($perms -join ' | ')"
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-StorageAccounts {
    Write-SectionHeader 16 "AZURE STORAGE ACCOUNTS"

    if (-not $script:mgmtToken) { Write-Err "No Azure Management token - skipping"; Write-SectionFooter; return }

    foreach ($sub in $script:subscriptions) {
        $storage = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
        if (-not $storage) { continue }

        foreach ($sa in $storage) {
            Write-Host ""
            Write-Highlight "Storage: $($sa.name)"
            Write-DatKV "Kind" $sa.kind
            Write-DatKV "HTTPS only" "$($sa.properties.supportsHttpsTrafficOnly)"

            if ($sa.properties.allowBlobPublicAccess -eq $true) {
                Add-Finding "LOW" "PublicBlob" "Storage '$($sa.name)' allows public blob access!"
                Add-AttackPath "Storage '$($sa.name)' has public blobs $iRA enumerate for data exfil"
            }
            if ($sa.properties.supportsHttpsTrafficOnly -eq $false) {
                Add-Finding "INFO" "StorageHTTP" "Storage '$($sa.name)' allows HTTP"
            }
        }
    }

    Write-SectionFooter
}

function Test-Intune {
    Write-SectionHeader 17 "INTUNE / ENDPOINT MANAGER"

    $configs = Invoke-Graph "/deviceManagement/deviceConfigurations?`$select=displayName,id,lastModifiedDateTime"
    if ($configs) {
        Write-Inf "Device configuration profiles: $($configs.Count)"
        foreach ($c in ($configs | Select-Object -First 10)) {
            Write-Dat "Config: $($c.displayName)"
        }
    } else {
        Write-Err "Cannot read Intune configs (requires admin)"
    }

    $compliance = Invoke-Graph "/deviceManagement/deviceCompliancePolicies?`$select=displayName,id"
    if ($compliance) { Write-Inf "Compliance policies: $($compliance.Count)" }

    $scripts = Invoke-Graph "/deviceManagement/deviceManagementScripts?`$select=displayName,id,runAsAccount"
    if ($scripts) {
        Write-Inf "Deployed scripts: $($scripts.Count)"
        foreach ($s in $scripts) {
            Write-DatKV "Script" "$($s.displayName) (RunAs: $($s.runAsAccount))"
            if ($s.runAsAccount -eq "system") {
                Add-Finding "LOW" "IntuneScript" "Intune script '$($s.displayName)' runs as SYSTEM"
                Add-AttackPath "Modify Intune script '$($s.displayName)' $iRA SYSTEM on managed devices"
            }
        }
    }

    Write-SectionFooter
}

function Test-MailPermissions {
    Write-SectionHeader 18 "MAIL PERMISSIONS & DELEGATIONS"

    Write-Sub "Mail-enabled apps from OAuth grants"

    $mailFindings = $script:findings | Where-Object { $_.Message -match "Mail\." }
    if ($mailFindings.Count -gt 0) {
        Write-Inf "$($mailFindings.Count) mail-related findings from Section 7"
        foreach ($f in $mailFindings) {
            Write-DatSub "$iRA $($f.Message)"
        }
    } else {
        Add-Finding "INFO" "MailPerms" "No dangerous mail permissions in app grants"
    }

    $folders = Invoke-Graph "/me/mailFolders?`$select=displayName,totalItemCount&`$top=5"
    if ($folders) {
        Write-Sub "Own Mailbox (accessible)"
        foreach ($f in $folders) {
            Write-DatKV $f.displayName "$($f.totalItemCount) items"
        }
    }

    Write-SectionFooter
}

# ============================================================================
#  LAYER 3: CLOUD -> LOCAL PIVOTING (Sections 19-25)
# ============================================================================

function Test-VMRunCommand {
    Write-SectionHeader 19 "CLOUD -> LOCAL: VM RUN COMMAND"

    if (-not $script:mgmtToken) { Write-Err "No Azure Management token - skipping"; Write-SectionFooter; return }

    foreach ($sub in $script:subscriptions) {
        $vms = Invoke-AzMgmt "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
        if (-not $vms) { continue }

        foreach ($vm in $vms) {
            $headers = @{ Authorization = "Bearer $($script:mgmtToken)"; "Content-Type" = "application/json" }
            try {
                $null = Invoke-RestMethod -Uri "https://management.azure.com$($vm.id)/runCommands?api-version=2024-03-01" -Headers $headers -Method GET -ErrorAction Stop
                Add-Finding "PE" "VMRunCmd" "Run Commands available on '$($vm.name)' = SYSTEM!"
                Add-AttackPath "VM Run Command on '$($vm.name)' $iRA NT AUTHORITY\SYSTEM"
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                if ($code -eq 403) {
                    Write-Dat "VM '$($vm.name)' - Run Command: Access Denied"
                } else {
                    Write-Dat "VM '$($vm.name)' - Run Command: Error $code"
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-IMDSToken {
    Write-SectionHeader 20 "CLOUD -> LOCAL: IMDS MANAGED IDENTITY"

    Write-Inf "Checking IMDS on this machine..."

    try {
        $metadata = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{Metadata="true"} -TimeoutSec 3 -ErrorAction Stop
        Write-DatKV "VM Name" $metadata.compute.name
        Write-DatKV "Resource Group" $metadata.compute.resourceGroupName
        Write-DatKV "Subscription" $metadata.compute.subscriptionId
        Write-DatKV "Location" $metadata.compute.location
        Write-DatKV "VM Size" $metadata.compute.vmSize
        Write-DatKV "Admin User" "$($metadata.compute.osProfile.adminUsername)" -last
        Add-Finding "INFO" "IMDS" "Azure IMDS accessible - VM: $($metadata.compute.name)"
    } catch {
        Write-Err "IMDS not accessible (not Azure VM or blocked)"
        Write-SectionFooter; return
    }

    $resources = @(
        @{ Name="Azure Management"; URL="https://management.azure.com/" },
        @{ Name="Microsoft Graph";  URL="https://graph.microsoft.com/" },
        @{ Name="Key Vault";        URL="https://vault.azure.net" },
        @{ Name="Storage";          URL="https://storage.azure.com/" }
    )

    Write-Host ""
    foreach ($r in $resources) {
        try {
            $token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$($r.URL)" -Headers @{Metadata="true"} -TimeoutSec 3 -ErrorAction Stop
            Add-Finding "PE" "IMDSToken" "MI token available for $($r.Name)!"
            Write-DatSub "Token type: $($token.token_type), expires: $($token.expires_on)"
            Add-AttackPath "IMDS token for $($r.Name) $iRA abuse MI permissions without credentials"
        } catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 400) {
                Write-DatKV $r.Name "No MI assigned"
            } else {
                Write-DatKV $r.Name "Error $statusCode"
            }
        }
    }

    Write-SectionFooter
}

function Test-HybridJoinPRT {
    Write-SectionHeader 21 "CLOUD -> LOCAL: DEVICE JOIN & PRT STATUS"

    try {
        $dsreg = cmd /c "dsregcmd /status" 2>&1

        Write-Sub "Device Join Status"
        $joinFields = @(
            @{Key="AzureAdJoined";     Label="Azure AD Joined"},
            @{Key="DomainJoined";      Label="Domain Joined"},
            @{Key="WorkplaceJoined";   Label="Workplace Joined (BYOD)"},
            @{Key="DeviceId";          Label="Device ID"},
            @{Key="Thumbprint";        Label="Device Certificate Thumbprint"},
            @{Key="TenantId";          Label="Tenant ID"},
            @{Key="TenantName";        Label="Tenant Name"}
        )
        $joinValues = @{}
        foreach ($f in $joinFields) {
            $match = ($dsreg | Select-String "$($f.Key)\s*:\s*(.+)").Matches
            $val = if ($match) { $match[0].Groups[1].Value.Trim() } else { "N/A" }
            $joinValues[$f.Key] = $val
            Write-DatKV $f.Label $val
        }

        $isAADJoined = $joinValues["AzureAdJoined"]
        $isDomainJoined = $joinValues["DomainJoined"]

        if ($isAADJoined -eq "YES") {
            Add-Finding "INFO" "AADJoined" "Machine is Azure AD Joined - Global Admins = local admin"
        }
        if ($isDomainJoined -eq "YES" -and $isAADJoined -eq "YES") {
            Add-Finding "INFO" "HybridJoin" "Hybrid Azure AD Joined - both on-prem AD and Entra ID trust"
        }

        Write-Sub "PRT (Primary Refresh Token) Analysis"
        $prtFields = @(
            @{Key="AzureAdPrt";               Label="PRT Present"},
            @{Key="AzureAdPrtUpdateTime";      Label="PRT Last Update"},
            @{Key="AzureAdPrtExpiryTime";      Label="PRT Expiry"},
            @{Key="AzureAdPrtAuthority";       Label="PRT Authority"},
            @{Key="EnterprisePrt";             Label="Enterprise PRT"},
            @{Key="EnterprisePrtUpdateTime";   Label="Enterprise PRT Update"},
            @{Key="CloudTGT";                  Label="Cloud TGT (Kerberos)"},
            @{Key="KerbTopLevelNames";         Label="Kerberos Realm Names"}
        )
        foreach ($f in $prtFields) {
            $match = ($dsreg | Select-String "$($f.Key)\s*:\s*(.+)").Matches
            if ($match) {
                $val = $match[0].Groups[1].Value.Trim()
                Write-DatKV $f.Label $val
            }
        }

        $hasPRT = $joinValues.AzureAdPrt
        if (-not $hasPRT -or $hasPRT -eq "N/A") {
            $prtMatch = ($dsreg | Select-String "AzureAdPrt\s*:\s*(\w+)").Matches
            $hasPRT = if ($prtMatch) { $prtMatch[0].Groups[1].Value } else { "NO" }
        }

        if ($hasPRT -eq "YES") {
            Add-Finding "RED" "PRT" "PRT present - extractable with admin (ROADtoken/AADInternals) for pass-the-PRT"

            # Check if PRT has MFA claim (SSO without MFA prompt)
            $prtMFA = ($dsreg | Select-String "MFA\s*:\s*(.+)").Matches
            if ($prtMFA -and $prtMFA[0].Groups[1].Value.Trim() -eq "YES") {
                Add-Finding "RED" "PRTwithMFA" "PRT has MFA claim - token theft = full SSO without MFA challenge"
            }
        }

        # Cloud TGT = Kerberos cloud trust
        $cloudTGT = ($dsreg | Select-String "CloudTGT\s*:\s*(\w+)").Matches
        if ($cloudTGT -and $cloudTGT[0].Groups[1].Value.Trim() -eq "1") {
            Add-Finding "INFO" "CloudTGT" "Cloud TGT present - Kerberos cloud trust enabled (silver ticket risk if keys compromised)"
        }

        Write-Sub "SSO State"
        $ssoFields = @(
            @{Key="AzureAdPrtAuthority";   Label="SSO Authority"},
            @{Key="SSOEnabled";            Label="Seamless SSO"},
            @{Key="NgcSet";                Label="Windows Hello (NGC)"},
            @{Key="NgcKeyId";              Label="NGC Key ID"}
        )
        foreach ($f in $ssoFields) {
            $match = ($dsreg | Select-String "$($f.Key)\s*:\s*(.+)").Matches
            if ($match) { Write-DatKV $f.Label $match[0].Groups[1].Value.Trim() }
        }

    } catch {
        Write-Err "Cannot run dsregcmd"
    }

    Write-SectionFooter
}

function Test-CloudLAPS {
    Write-SectionHeader 22 "CLOUD -> LOCAL: LAPS (LOCAL ADMIN PASSWORD)"

    $devices = Invoke-Graph "/devices?`$select=displayName,id,operatingSystem,isManaged&`$top=10"
    if ($devices) {
        Write-Inf "Checking LAPS configuration..."

        $hostname = $env:COMPUTERNAME
        $device = Invoke-Graph "/devices?`$filter=displayName eq '$hostname'&`$select=id,displayName"
        if ($device -and $device.Count -gt 0) {
            $deviceId = $device[0].id
            Write-DatKV "Device" "$hostname (ID: $deviceId)"

            try {
                $laps = Invoke-Graph "/devices/$deviceId/localCredentials"
                if ($laps) {
                    Add-Finding "PE" "LAPS" "Can read LAPS password for $hostname!"
                    Add-AttackPath "LAPS password readable $iRA local admin on $hostname"
                }
            } catch {
                Write-DatKV "LAPS Read" "Denied (expected)" -last
            }
        } else {
            Write-DatKV "Device" "'$hostname' not found in Entra" -last
        }
    } else {
        Write-Err "Cannot enumerate devices"
    }

    Write-Sub "On-Prem LAPS Check"
    try {
        $rootDSE2 = [ADSI]"LDAP://RootDSE"
        $domDN = $rootDSE2.defaultNamingContext.ToString()
        $lapsSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domDN")
        $lapsSearcher.Filter = "(&(objectClass=computer)(ms-MCS-AdmPwd=*))"
        $lapsSearcher.PropertiesToLoad.AddRange(@("cn","ms-MCS-AdmPwd"))
        $lapsSearcher.PageSize = 1000
        $lapsResults = $lapsSearcher.FindAll()

        $lapsCount = 0
        foreach ($lr in $lapsResults) {
            $lapsCount++
            Write-Dat "$($lr.Properties.cn) : $($lr.Properties.'ms-mcs-admpwd')"
        }

        if ($lapsCount -gt 0) {
            Add-Finding "PE" "LAPSReadable" "Can read LAPS passwords for $lapsCount computers!"
            Add-AttackPath "LAPS passwords readable $iRA local admin on $lapsCount computers"
        } else {
            $lapsSchemaCheck = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domDN")
            $lapsSchemaCheck.Filter = "(objectClass=computer)"
            $lapsSchemaCheck.PropertiesToLoad.Add("ms-MCS-AdmPwd") | Out-Null
            $lapsSchemaCheck.SizeLimit = 1
            $anyComp = $lapsSchemaCheck.FindOne()
            if ($anyComp -and $anyComp.Properties.PropertyNames -contains 'ms-mcs-admpwd') {
                Write-Inf "LAPS deployed but cannot read passwords (good)"
            } else {
                Add-Finding "INFO" "NoLAPS" "LAPS does not appear to be deployed"
            }
        }
        $lapsResults.Dispose()
    } catch {
        Write-Err "Cannot check on-prem LAPS: $_"
    }

    Write-SectionFooter
}

function Test-SecurityDefaults {
    Write-SectionHeader 23 "SECURITY DEFAULTS & LEGACY AUTH"

    $secDefaults = Invoke-Graph "/policies/identitySecurityDefaultsEnforcementPolicy"
    if ($secDefaults) {
        $enabled = $secDefaults.isEnabled
        Write-DatKV "Security Defaults" "$(if ($enabled) {'ENABLED'} else {'DISABLED'})" -last

        if (-not $enabled) {
            Add-Finding "INFO" "SecDefaults" "Security Defaults DISABLED (should have CA policies)"
        } else {
            Add-Finding "INFO" "SecDefaults" "Security Defaults enabled"
        }
    }

    $locations = Invoke-Graph "/identity/conditionalAccess/namedLocations"
    if ($locations) {
        Write-Sub "Named Locations (CA Trusted Networks)"
        foreach ($loc in $locations) {
            Write-DatKV $loc.displayName "trusted: $($loc.isTrusted)"
            if ($loc.isTrusted) {
                Add-Finding "INFO" "TrustedLocation" "Trusted location: $($loc.displayName) - may bypass MFA"
            }
        }
    }

    Write-Sub "Token Lifetime Policies"
    $tokenPolicies = Invoke-Graph "/policies/tokenLifetimePolicies?`$select=id,displayName,definition,isOrganizationDefault"
    if ($tokenPolicies -and $tokenPolicies.Count -gt 0) {
        foreach ($tp in $tokenPolicies) {
            Write-Highlight "Policy: $($tp.displayName)"
            Write-DatKV "Org Default" "$($tp.isOrganizationDefault)"
            foreach ($def in $tp.definition) {
                try {
                    $parsed = $def | ConvertFrom-Json
                    if ($parsed.TokenLifetimePolicy) {
                        $tlp = $parsed.TokenLifetimePolicy
                        if ($tlp.AccessTokenLifetime) { Write-DatKV "Access Token Lifetime" "$($tlp.AccessTokenLifetime)" }
                        if ($tlp.MaxInactiveTime) { Write-DatKV "Max Inactive Time" "$($tlp.MaxInactiveTime)" }
                        if ($tlp.MaxAgeSessionSingleFactor) { Write-DatKV "Max Session (1FA)" "$($tlp.MaxAgeSessionSingleFactor)" }
                        if ($tlp.MaxAgeSessionMultiFactor) { Write-DatKV "Max Session (MFA)" "$($tlp.MaxAgeSessionMultiFactor)" }
                        # Check for excessively long lifetimes
                        foreach ($prop in @('MaxAgeSessionSingleFactor','MaxAgeSessionMultiFactor')) {
                            $val = $tlp.$prop
                            if ($val) {
                                try {
                                    $ts = [System.Xml.XmlConvert]::ToTimeSpan($val)
                                    if ($ts.TotalDays -gt 30) {
                                        Add-Finding "LOW" "TokenLifetime" "Policy '$($tp.displayName)': $prop = $val (>30 days - long persistence window)"
                                    }
                                } catch {}
                            }
                        }
                    }
                } catch { Write-DatSub "Definition: $def" }
            }
        }
    } else {
        Write-Inf "No custom token lifetime policies (using defaults)"
    }

    Write-SectionFooter
}

function Test-ADACLAbuse {
    Write-SectionHeader 24 "AD OBJECT ACL ABUSE VECTORS"

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domain = $rootDSE.defaultNamingContext
    } catch {
        Write-Err "Not domain-joined - skipping"
        Write-SectionFooter; return
    }

    # Build set of current user's identities (SID + group SIDs)
    Write-Inf "Resolving current user identity and group memberships..."
    $myIdentities = @{}
    try {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myIdentities[$currentIdentity.User.Value] = $currentIdentity.Name
        foreach ($group in $currentIdentity.Groups) {
            try {
                $translated = $group.Translate([System.Security.Principal.NTAccount]).Value
                $myIdentities[$group.Value] = $translated
            } catch {
                $myIdentities[$group.Value] = $group.Value
            }
        }
        # Also add the NTAccount name forms for matching
        $myNTNames = @($currentIdentity.Name)
        foreach ($v in $myIdentities.Values) { $myNTNames += $v }
        $myNTNames = $myNTNames | Select-Object -Unique
        Write-Inf "Checking ACLs as: $($currentIdentity.Name) ($($myIdentities.Count) identity/group SIDs)"
    } catch {
        Write-Err "Cannot resolve current identity - ACL check will be limited"
        Write-SectionFooter; return
    }

    # SIDs that EVERY user has in their token - not interesting for ACL abuse
    $everyoneSIDs = @(
        'S-1-1-0',          # Everyone
        'S-1-5-11',         # Authenticated Users
        'S-1-5-10',         # SELF
        'S-1-3-0',          # CREATOR OWNER
        'S-1-3-4'           # CREATOR GROUP
    )

    # Skip well-known default/high-priv identities
    $defaultSIDs = @(
        'S-1-5-18',         # SYSTEM
        'S-1-5-32-544',     # BUILTIN\Administrators
        'S-1-5-32-548',     # Account Operators
        'S-1-5-32-549',     # Server Operators
        'S-1-5-32-550',     # Print Operators
        'S-1-5-32-551'      # Backup Operators
    ) + $everyoneSIDs

    # Dangerous ExtendedRight GUIDs (only these matter, rest is benign)
    $dangerousExtRights = @(
        '00299570-246d-11d0-a768-00aa006e0529',  # User-Force-Change-Password
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c',  # DS-Replication-Get-Changes-In-Filtered-Set
        '00000000-0000-0000-0000-000000000000'   # All ExtendedRights
    )

    # Helper: check if ACE identity is the current user (not via Everyone/AuthUsers)
    $matchesMe = {
        param($ace)
        $ref = $ace.IdentityReference.Value
        # Exclude broad groups that match everyone
        if ($ref -in $everyoneSIDs) { return $false }
        if ($ref -match 'Everyone|Authenticated Users|CREATOR OWNER|Domain Users|\\Gebruikers|\\Utilisateurs') { return $false }
        # Match by SID
        if ($myIdentities.ContainsKey($ref)) { return $true }
        # Match by NTAccount name
        foreach ($n in $myNTNames) {
            if ($ref -eq $n) { return $true }
        }
        return $false
    }

    # Helper: check if identity is default/expected
    $isDefault = {
        param($ace)
        $ref = $ace.IdentityReference.Value
        foreach ($sid in $defaultSIDs) { if ($ref -eq $sid) { return $true } }
        if ($ref -match 'BUILTIN\\|NT AUTHORITY\\|SYSTEM|Domain Admins|Enterprise Admins|CREATOR OWNER|AAD DC|S-1-5-32-|Everyone|Authenticated Users|Domain Users') { return $true }
        return $false
    }

    # Helper: check if ExtendedRight ACE is actually dangerous
    $isDangerousExtRight = {
        param($ace)
        $rights = $ace.ActiveDirectoryRights.ToString()
        if ($rights -notmatch 'ExtendedRight') { return $true }  # not an ExtendedRight ACE, let other filters handle
        if ($rights -match 'GenericAll|WriteDacl|WriteOwner') { return $true }  # has other dangerous rights too
        # Pure ExtendedRight - check if the ObjectType GUID is actually dangerous
        $guid = $ace.ObjectType.ToString()
        return ($guid -in $dangerousExtRights)
    }

    $peComps = @()
    $redComps = @()
    $peAdmins = @()
    $redAdmins = @()

    Write-Sub "ACLs on Computer Objects"
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.PropertiesToLoad.Add("cn") | Out-Null
        $searcher.PageSize = 1000
        $computers = $searcher.FindAll()

        foreach ($comp in $computers) {
            $dn = $comp.Properties.distinguishedname[0]
            $cn = $comp.Properties.cn[0]
            try {
                $obj = [ADSI]"LDAP://$dn"
                $acl = $obj.ObjectSecurity
                $dangerousAces = $acl.Access | Where-Object {
                    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite" -and
                    $_.AccessControlType -eq "Allow" -and
                    -not (& $isDefault $_) -and
                    (& $isDangerousExtRight $_)
                }

                foreach ($d in $dangerousAces) {
                    $identity = $d.IdentityReference.Value
                    $rights = $d.ActiveDirectoryRights
                    if (& $matchesMe $d) {
                        $peComps += [PSCustomObject]@{Identity=$identity;Rights=$rights;Target=$cn}
                    } else {
                        $redComps += [PSCustomObject]@{Identity=$identity;Rights=$rights;Target=$cn}
                    }
                }
            } catch {}
        }
        $searcher.Dispose()
    } catch { Write-Err "Cannot enumerate computer ACLs" }

    # Report PE (you have the rights directly)
    foreach ($f in $peComps) {
        Add-Finding "PE" "ACLAbuse" "YOU have $($f.Rights) on computer $($f.Target)"
        Add-AttackPath "YOU $iRA $($f.Rights) on $($f.Target) $iRA RBCD/Shadow Creds $iRA SYSTEM"
    }
    # Report RED (non-default user/group has rights - interesting but not your direct PE)
    $redGrouped = $redComps | Group-Object Identity
    foreach ($g in $redGrouped) {
        $targets = ($g.Group | Select-Object -First 3 | ForEach-Object { $_.Target }) -join ", "
        $more = if ($g.Count -gt 3) { " (+$($g.Count - 3) more)" } else { "" }
        Add-Finding "LOW" "ACLAbuse" "'$($g.Name)' has dangerous ACLs on: $targets$more"
    }

    if ($peComps.Count -eq 0 -and $redComps.Count -eq 0) {
        Write-OK "No dangerous non-default ACLs on computers"
    }

    Write-Sub "ACLs on Admin Users"
    try {
        $adminSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $adminSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
        $adminSearcher.PropertiesToLoad.AddRange(@("distinguishedname","samaccountname"))
        $adminSearcher.PageSize = 1000
        $admins = $adminSearcher.FindAll()

        foreach ($admin in $admins) {
            $dn = $admin.Properties.distinguishedname[0]
            $sam = $admin.Properties.samaccountname[0]
            try {
                $obj = [ADSI]"LDAP://$dn"
                $acl = $obj.ObjectSecurity
                $dangerousAces = $acl.Access | Where-Object {
                    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty|ExtendedRight" -and
                    $_.AccessControlType -eq "Allow" -and
                    -not (& $isDefault $_) -and
                    (& $isDangerousExtRight $_)
                }

                foreach ($d in $dangerousAces) {
                    $identity = $d.IdentityReference.Value
                    $rights = $d.ActiveDirectoryRights
                    if (& $matchesMe $d) {
                        $peAdmins += [PSCustomObject]@{Identity=$identity;Rights=$rights;Target=$sam}
                    } else {
                        $redAdmins += [PSCustomObject]@{Identity=$identity;Rights=$rights;Target=$sam}
                    }
                }
            } catch {}
        }
        $adminSearcher.Dispose()
    } catch { Write-Err "Cannot enumerate admin user ACLs" }

    foreach ($f in $peAdmins) {
        Add-Finding "PE" "ACLAbuse" "YOU have $($f.Rights) on admin '$($f.Target)'"
        Add-AttackPath "YOU $iRA $($f.Rights) on '$($f.Target)' $iRA reset pw / Shadow Creds"
    }
    $redAdmGrouped = $redAdmins | Group-Object Identity
    foreach ($g in $redAdmGrouped) {
        $targets = ($g.Group | Select-Object -First 3 | ForEach-Object { $_.Target }) -join ", "
        $more = if ($g.Count -gt 3) { " (+$($g.Count - 3) more)" } else { "" }
        Add-Finding "LOW" "ACLAbuse" "'$($g.Name)' has dangerous ACLs on admins: $targets$more"
    }

    if ($peAdmins.Count -eq 0 -and $redAdmins.Count -eq 0) {
        Write-OK "No dangerous non-default ACLs on admin users"
    }

    Write-Sub "GPO Permissions (PE via GPO Abuse)"
    try {
        $gpoSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $gpoSearcher.Filter = "(objectClass=groupPolicyContainer)"
        $gpoSearcher.PropertiesToLoad.AddRange(@("displayname","distinguishedname","gpcfilesyspath","ntsecuritydescriptor"))
        $gpoSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $gpoSearcher.PageSize = 500
        $gpos = $gpoSearcher.FindAll()

        $peGPOs = @()
        $redGPOs = @()

        foreach ($gpo in $gpos) {
            $gpoName = "$($gpo.Properties.displayname[0])"
            $gpoDN = "$($gpo.Properties.distinguishedname[0])"
            $gpoPath = "$($gpo.Properties.gpcfilesyspath[0])"
            try {
                $gpoObj = [ADSI]"LDAP://$gpoDN"
                $acl = $gpoObj.ObjectSecurity
                $dangerousAces = $acl.Access | Where-Object {
                    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty" -and
                    $_.AccessControlType -eq "Allow" -and
                    -not (& $isDefault $_)
                }
                foreach ($d in $dangerousAces) {
                    if (& $matchesMe $d) {
                        $peGPOs += [PSCustomObject]@{Identity=$d.IdentityReference.Value;Rights=$d.ActiveDirectoryRights;GPO=$gpoName;Path=$gpoPath}
                    } else {
                        $redGPOs += [PSCustomObject]@{Identity=$d.IdentityReference.Value;Rights=$d.ActiveDirectoryRights;GPO=$gpoName}
                    }
                }
                # Also check SYSVOL path writability
                if ($gpoPath -and (Test-Path $gpoPath -ErrorAction SilentlyContinue)) {
                    try {
                        $fsAcl = Get-Acl $gpoPath -ErrorAction Stop
                        $meIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $meFSSIDs = @($meIdentity.User.Value) + @($meIdentity.Groups | ForEach-Object { $_.Value })
                        $writable = Test-WritableACL $fsAcl $meFSSIDs -IncludeWellKnown
                        if ($writable) {
                            $peGPOs += [PSCustomObject]@{Identity="FileSystem";Rights="Write";GPO=$gpoName;Path=$gpoPath}
                        }
                    } catch {}
                }
            } catch {}
        }

        foreach ($f in $peGPOs) {
            Add-Finding "PE" "GPOAbuse" "YOU can modify GPO '$($f.GPO)' ($($f.Rights))"
            Add-AttackPath "Modify GPO '$($f.GPO)' $iRA add scheduled task / startup script $iRA code exec on linked OUs"
        }
        $redGPOGrouped = $redGPOs | Group-Object Identity
        foreach ($g in $redGPOGrouped) {
            $targets = ($g.Group | Select-Object -First 3 | ForEach-Object { $_.GPO }) -join ", "
            $more = if ($g.Count -gt 3) { " (+$($g.Count - 3) more)" } else { "" }
            Add-Finding "LOW" "GPOAbuse" "'$($g.Name)' can modify GPOs: $targets$more"
        }

        if ($peGPOs.Count -eq 0 -and $redGPOs.Count -eq 0) {
            Write-OK "No dangerous GPO permissions"
        }
        $gpoSearcher.Dispose()
    } catch { Write-Err "Cannot enumerate GPO permissions: $_" }

    # DCSync permissions on domain head
    Write-Sub "DCSync Permissions (Replication Rights)"
    try {
        $domainDN = ([ADSI]"LDAP://$domain").distinguishedName[0]
        $domainObj = [ADSI]"LDAP://$domainDN"
        $domainSD = $domainObj.ObjectSecurity

        # DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        # DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $replGetChanges = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        $replGetChangesAll = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

        $defaultSIDs = @(
            "S-1-5-32-544",           # Administrators
            "S-1-5-9"                 # Enterprise Domain Controllers
        )

        $dcSyncUsers = @()
        $hasGetChanges = @{}
        $hasGetChangesAll = @{}

        foreach ($ace in $domainSD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            $rights = "$($ace.ActiveDirectoryRights)"

            if ($rights -match 'ExtendedRight' -or $rights -match 'GenericAll') {
                $objType = $ace.ObjectType
                if ($objType -eq $replGetChanges -or $objType -eq [guid]::Empty -or $rights -match 'GenericAll') {
                    $hasGetChanges[$sid] = $true
                }
                if ($objType -eq $replGetChangesAll -or $objType -eq [guid]::Empty -or $rights -match 'GenericAll') {
                    $hasGetChangesAll[$sid] = $true
                }
            }
        }

        # Find SIDs that have BOTH rights (= DCSync capable)
        foreach ($sid in $hasGetChanges.Keys) {
            if ($hasGetChangesAll.ContainsKey($sid)) {
                # Skip default principals (DCs, Enterprise DCs, domain admin SIDs ending in -500, -512, -519)
                if ($defaultSIDs -contains $sid -or $sid -match '-500$|-512$|-516$|-518$|-519$|-498$') { continue }
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                    $name = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                } catch { $name = $sid }

                # Check if it's the current user
                if ($mySIDs -contains $sid) {
                    $dcSyncUsers += [PSCustomObject]@{Name=$name; IsSelf=$true}
                    Add-Finding "PE" "DCSync" "YOU ($name) have DCSync rights - secretsdump.py to extract all hashes!"
                    Add-AttackPath "DCSync as $name $iRA secretsdump.py / Mimikatz lsadump::dcsync $iRA all NTLM hashes $iRA DA"
                } else {
                    $dcSyncUsers += [PSCustomObject]@{Name=$name; IsSelf=$false}
                }
            }
        }

        if ($dcSyncUsers.Count -gt 0) {
            $nonSelf = @($dcSyncUsers | Where-Object { -not $_.IsSelf })
            if ($nonSelf.Count -gt 0) {
                foreach ($u in $nonSelf | Select-Object -First 5) {
                    Write-DatSub "DCSync: $($u.Name)"
                }
                Add-Finding "RED" "DCSync" "$($nonSelf.Count) non-default principal(s) with DCSync rights"
            }
        } else {
            Write-OK "No non-default principals with DCSync rights"
        }
    } catch { Write-Err "Cannot check DCSync permissions: $($_.Exception.Message)" }

    # Password in AD description/info fields
    Write-Sub "Passwords in AD Description Fields"
    try {
        $passSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
        $passSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(description=*pass*)(description=*haslo*)(description=*hasło*)(description=*pwd*)(info=*pass*)(info=*pwd*)))"
        $passSearcher.PropertiesToLoad.AddRange(@("samaccountname","description","info","admincount"))
        $passSearcher.PageSize = 500
        $passResults = $passSearcher.FindAll()

        if ($passResults -and $passResults.Count -gt 0) {
            foreach ($pr in $passResults | Select-Object -First 10) {
                $sam = "$($pr.Properties.samaccountname[0])"
                $desc = "$($pr.Properties.description[0])"
                $isAdmin = "$($pr.Properties.admincount[0])" -eq "1"
                # Truncate description to avoid leaking full password in output
                $descPreview = if ($desc.Length -gt 60) { $desc.Substring(0, 60) + "..." } else { $desc }
                Write-DatKV $sam "desc: $descPreview"
                if ($isAdmin) {
                    Add-Finding "PE" "DescPass" "Admin account '$sam' has password-related description: $descPreview"
                }
            }
            Add-Finding "RED" "DescPass" "$($passResults.Count) user(s) with password hints in description/info field"
        } else {
            Write-OK "No passwords found in AD description fields"
        }
        $passSearcher.Dispose()
    } catch { Write-Err "Cannot search AD descriptions: $($_.Exception.Message)" }

    Write-SectionFooter
}

function Test-LocalPrivesc {
    Write-SectionHeader 25 "LOCAL MACHINE SECURITY POSTURE"

    Write-Sub "Token Privileges"
    try {
        $privOutput = whoami /priv 2>&1 | Out-String
        $pePrivs = @("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege","SeDebugPrivilege",
                      "SeBackupPrivilege","SeRestorePrivilege","SeTakeOwnershipPrivilege",
                      "SeLoadDriverPrivilege","SeCreateTokenPrivilege","SeTcbPrivilege")
        $foundPE = @()
        foreach ($p in $pePrivs) {
            if ($privOutput -match "$p\s+.+?(Enabled|Disabled)") {
                $state = $Matches[1]
                Write-DatKV $p $state
                if ($state -eq "Enabled") { $foundPE += $p }
            }
        }
        if ($foundPE.Count -gt 0) {
            $privList = $foundPE -join ", "
            if ($foundPE -contains "SeImpersonatePrivilege" -or $foundPE -contains "SeAssignPrimaryTokenPrivilege") {
                Add-Finding "PE" "TokenPriv" "PE via token: $privList (PrintSpoofer/GodPotato)"
            } elseif ($foundPE -contains "SeDebugPrivilege") {
                Add-Finding "PE" "TokenPriv" "SeDebugPrivilege enabled - can dump LSASS / inject into any process"
            } else {
                Add-Finding "RED" "TokenPriv" "Dangerous privileges: $privList"
            }
        } else {
            Write-OK "No dangerous token privileges"
        }
    } catch { Write-Err "Cannot query token privileges" }

    Write-Sub "Local Administrators Group"
    try {
        $admins = net localgroup Administrators 2>&1 | Out-String
        $members = [regex]::Matches($admins, '(?m)^(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }
        $inMembers = $false
        $adminList = @()
        foreach ($line in $members) {
            if ($line -match '^-+$') { $inMembers = $true; continue }
            if ($line -match '^The command completed') { $inMembers = $false; continue }
            if ($inMembers -and $line.Length -gt 0) {
                $adminList += $line
                Write-Dat $line
            }
        }
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = ([System.Security.Principal.WindowsPrincipal]$currentUser).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            Add-Finding "PE" "LocalAdmin" "Current user is LOCAL ADMIN"
        } else {
            Add-Finding "INFO" "LocalAdmin" "$($adminList.Count) local admin members"
        }
    } catch { Write-Err "Cannot enumerate local admins" }

    Write-Sub "Credential Protection"
    $runAsPPL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
    $credGuard = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity

    Write-DatKV "LSA Protection (RunAsPPL)" "$(if ($runAsPPL) {$runAsPPL} else {'NOT SET'})"
    Write-DatKV "Credential Guard" "$(if ($credGuard) {$credGuard} else {'NOT SET'})" -last

    if (-not $runAsPPL) {
        Add-Finding "RED" "LSA" "LSA Protection (RunAsPPL) not enabled"
    }
    if (-not $credGuard) {
        Add-Finding "RED" "CredGuard" "Credential Guard not enabled"
    }

    Write-Sub "PowerShell & AMSI"
    Write-DatKV "Language Mode" "$($ExecutionContext.SessionState.LanguageMode)" -last
    if ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage") {
        Add-Finding "RED" "CLM" "PowerShell in FullLanguage mode - no CLM restrictions"
    }

    Write-Sub "OS & Patch Level"
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $build = "$($os.Version) (Build $($os.BuildNumber))"
        Write-DatKV "OS" "$($os.Caption)"
        Write-DatKV "Version" $build
        $lastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
        Write-DatKV "Last Boot" "$($lastBoot.ToString('yyyy-MM-dd HH:mm'))"
        try {
            $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
            $latest = $hotfixes | Select-Object -First 1
            if ($latest) {
                $installedStr = if ($latest.InstalledOn) { $latest.InstalledOn.ToString('yyyy-MM-dd') } else { "unknown" }
                Write-DatKV "Latest Patch" "$($latest.HotFixID) ($installedStr)"
                $daysSincePatch = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
                if ($daysSincePatch -gt 90) {
                    Add-Finding "RED" "PatchLevel" "Last patch $($latest.HotFixID) installed $daysSincePatch days ago"
                }
            }
            Write-DatKV "Total Patches" "$($hotfixes.Count)" -last
        } catch { Write-DatKV "Patches" "Cannot enumerate (access denied)" -last }
    } catch { Write-Err "Cannot query OS info" }

    Write-Sub "Windows Defender"
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        Write-DatKV "Real-time" "$($defender.RealTimeProtectionEnabled)"
        Write-DatKV "Behavior" "$($defender.BehaviorMonitorEnabled)"
        Write-DatKV "Tamper" "$($defender.IsTamperProtected)"
        Write-DatKV "Signatures" "$($defender.AntivirusSignatureVersion)" -last

        if (-not $defender.RealTimeProtectionEnabled) {
            Add-Finding "RED" "DefenderOff" "Defender real-time protection DISABLED"
        }
    } catch {
        Write-Err "Cannot query Defender (not admin or not installed)"
    }

    Write-Sub "AppLocker Policy"
    try {
        $appLockerKeys = @(
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe"; Type="Executable (.exe)"},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi"; Type="Windows Installer (.msi)"},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script"; Type="Script (.ps1/.bat/.cmd)"},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll"; Type="DLL (.dll)"},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Appx"; Type="Packaged App (.appx)"}
        )
        $appLockerActive = $false
        foreach ($ak in $appLockerKeys) {
            if (Test-Path $ak.Path) {
                $rules = Get-ChildItem $ak.Path -ErrorAction SilentlyContinue
                if ($rules.Count -gt 0) {
                    $appLockerActive = $true
                    Write-DatKV $ak.Type "$($rules.Count) rules"
                }
            }
        }
        # Also check AppIDSvc service
        $appIdSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
        if ($appIdSvc) {
            Write-DatKV "AppIDSvc Status" "$($appIdSvc.Status) (StartType: $($appIdSvc.StartType))"
        }
        if ($appLockerActive) {
            if ($appIdSvc -and $appIdSvc.Status -eq "Running") {
                Add-Finding "INFO" "AppLocker" "AppLocker is configured and enforced - check for bypass paths"
            } else {
                Add-Finding "LOW" "AppLockerWeak" "AppLocker rules configured but AppIDSvc not running - NOT enforced"
            }
        } else {
            Add-Finding "RED" "NoAppLocker" "No AppLocker policies configured - unrestricted application execution"
        }
    } catch { Write-Err "Cannot query AppLocker" }

    Write-Sub "BitLocker Disk Encryption"
    try {
        $blStatus = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -ErrorAction Stop
        if ($blStatus) {
            foreach ($vol in $blStatus) {
                $protStatus = switch ($vol.ProtectionStatus) { 0 {"OFF"} 1 {"ON"} 2 {"UNKNOWN"} default {"$($vol.ProtectionStatus)"} }
                Write-DatKV "Volume $($vol.DriveLetter)" "Protection: $protStatus"
                if ($vol.DriveLetter -eq "$env:SystemDrive" -and $vol.ProtectionStatus -ne 1) {
                    Add-Finding "RED" "NoBitLocker" "System drive $($vol.DriveLetter) NOT encrypted - offline credential extraction possible"
                }
            }
        }
    } catch {
        # Try alternative check via manage-bde
        try {
            $bdeOutput = manage-bde -status $env:SystemDrive 2>&1 | Out-String
            if ($bdeOutput -match 'Protection Status:\s*(Protection On|Protection Off)') {
                $blState = $Matches[1]
                Write-DatKV "System Drive" $blState
                if ($blState -eq "Protection Off") {
                    Add-Finding "RED" "NoBitLocker" "System drive NOT BitLocker encrypted - offline credential extraction possible"
                }
            } else {
                Write-Err "Cannot determine BitLocker status"
            }
        } catch { Write-Err "Cannot query BitLocker (not admin or not available)" }
    }

    Write-Sub "Writable ProgramData Directories (with services)"
    try {
        $pdPath = "$env:ProgramData"
        $meIdent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mePDSIDs = @($meIdent.User.Value) + @($meIdent.Groups | ForEach-Object { $_.Value })
        # Get service binary paths that run from ProgramData
        $pdServices = Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {
            $_.PathName -and $_.PathName -match [regex]::Escape($pdPath) -and
            $_.StartName -and $_.StartName -match 'LocalSystem|SYSTEM|LOCAL SERVICE|NETWORK SERVICE'
        }
        $writablePD = @()
        foreach ($svc in $pdServices) {
            $binPath = Get-ServiceBinaryPath $svc.PathName
            if (-not $binPath -or -not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }
            $binDir = Split-Path $binPath -ErrorAction SilentlyContinue
            if (-not $binDir) { continue }
            try {
                $acl = Get-Acl $binDir -ErrorAction Stop
                $writable = Test-WritableACL $acl $mePDSIDs -IncludeWellKnown
                if ($writable) {
                    $writablePD += $svc
                    $who = ($writable | Select-Object -First 1).IdentityReference.Value
                    Add-Finding "PE" "WritablePD" "Service '$($svc.Name)' dir writable by $who ($binDir), runs as $($svc.StartName)"
                    Add-AttackPath "Drop DLL/replace binary in '$binDir' $iRA service '$($svc.Name)' $iRA $($svc.StartName)"
                }
            } catch {}
        }
        if ($writablePD.Count -eq 0) { Write-OK "No writable ProgramData service directories" }
    } catch { Write-Err "Cannot check ProgramData service directories" }

    Write-Sub "Process Token Analysis (Impersonation Targets)"
    try {
        $interestingProcs = @()
        # Use Get-CimInstance (faster) with fallback to Get-WmiObject
        $wmiProcs = $null
        try {
            $wmiProcs = Get-CimInstance Win32_Process -Property Name,ProcessId,CreationClassName -ErrorAction Stop
        } catch {
            $wmiProcs = Get-WmiObject Win32_Process -ErrorAction Stop
        }

        # Only call GetOwner on non-standard processes to avoid slow enumeration
        $skipNames = @('svchost.exe','csrss.exe','wininit.exe','services.exe','lsass.exe',
                       'smss.exe','System','winlogon.exe','dwm.exe','fontdrvhost.exe',
                       'RuntimeBroker.exe','System Idle Process','Memory Compression',
                       'Registry','conhost.exe','dllhost.exe','sihost.exe','taskhostw.exe')
        $candidateProcs = $wmiProcs | Where-Object { $_.Name -notin $skipNames }

        $systemProcs = @()
        foreach ($p in $candidateProcs) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                if (-not $o) { $o = $p.GetOwner() }
                if ($o.ReturnValue -eq 0 -and $o.User -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
                    $systemProcs += [PSCustomObject]@{
                        Name = $p.Name
                        ProcessId = $p.ProcessId
                        Owner = "$($o.Domain)\$($o.User)"
                    }
                }
            } catch {}
        }

        if ($systemProcs.Count -gt 0) {
            $grouped = $systemProcs | Group-Object Name | Sort-Object Count -Descending | Select-Object -First 15
            foreach ($g in $grouped) {
                $owner = ($g.Group | Select-Object -First 1).Owner
                Write-DatSub "$($g.Name) ($($g.Count)x) as $owner"
            }
            # Check if current user has SeImpersonate or SeAssignPrimaryToken
            $hasImpersonate = $privOutput -match 'SeImpersonatePrivilege\s+.+?Enabled'
            if ($hasImpersonate) {
                $interestingProcs = $systemProcs
                Add-Finding "PE" "Impersonate" "SeImpersonatePrivilege + $($systemProcs.Count) SYSTEM processes = Potato family PE"
                Add-AttackPath "SeImpersonatePrivilege $iRA GodPotato/PrintSpoofer/JuicyPotatoNG $iRA SYSTEM"
            } else {
                Add-Finding "INFO" "SysProcs" "$($systemProcs.Count) non-svchost SYSTEM processes running"
            }
        } else {
            Write-DatSub "No SYSTEM processes visible (access denied or non-admin)"
        }
    } catch { Write-Err "Cannot enumerate process tokens: $($_.Exception.Message)" }

    Write-Sub "Docker / WSL / Hyper-V Breakout"
    try {
        $dockerDesktop = Get-Service com.docker.service -ErrorAction SilentlyContinue
        $dockerEngine = Get-Service docker -ErrorAction SilentlyContinue
        $wslInstalled = Test-Path "$env:SystemRoot\System32\wsl.exe" -ErrorAction SilentlyContinue
        $hyperVSvc = Get-Service vmms -ErrorAction SilentlyContinue

        if ($dockerDesktop -or $dockerEngine) {
            $dockerSvc = if ($dockerDesktop) { $dockerDesktop } else { $dockerEngine }
            Write-DatKV "Docker" "$($dockerSvc.Status) (StartType: $($dockerSvc.StartType))"
            # Check if current user is in docker-users group
            $dockerGroup = net localgroup docker-users 2>&1 | Out-String
            if ($dockerGroup -match $env:USERNAME) {
                Add-Finding "PE" "DockerUser" "Current user in docker-users group - mount host filesystem for SYSTEM"
                Add-AttackPath "docker run -v C:\:C:\host ... $iRA read SAM/SYSTEM $iRA local admin hash"
            } else {
                Add-Finding "INFO" "Docker" "Docker installed but user not in docker-users group"
            }
        }
        if ($wslInstalled) {
            $wslList = wsl --list --quiet 2>&1 | Out-String
            if ($wslList -and $wslList.Trim() -ne '' -and $wslList -notmatch 'no installed') {
                Write-DatKV "WSL Distros" "$($wslList.Trim() -replace "`r`n", ', ')"
                Add-Finding "LOW" "WSL" "WSL installed with distro(s) - potential host filesystem access via /mnt/c/"
            }
        }
        if ($hyperVSvc -and $hyperVSvc.Status -eq 'Running') {
            Write-DatKV "Hyper-V VMMS" "Running"
            Add-Finding "INFO" "HyperV" "Hyper-V running - check for VM escape vectors if guest"
        }
        if (-not $dockerDesktop -and -not $dockerEngine -and -not $wslInstalled) {
            Write-OK "No Docker/WSL/container environment detected"
        }
    } catch { Write-Err "Cannot check container environments" }

    Write-Sub "Logged-In Sessions (Lateral Movement Targets)"
    try {
        # qwinsta / query user - who is logged in on this box
        $qwinsta = qwinsta 2>&1 | Out-String
        if ($qwinsta -and $qwinsta -notmatch 'not recognized|access is denied') {
            $sessions = $qwinsta -split "`n" | Where-Object { $_ -match '^\s*(>?\w+)\s+(\S+)\s+(\d+)\s+(Active|Disc)' }
            $otherSessions = @()
            foreach ($s in $sessions) {
                if ($s -match '^\s*>?(\S+)\s+(\S+)\s+(\d+)\s+(Active|Disc)') {
                    $sessName = $Matches[1]
                    $sessUser = $Matches[2]
                    $sessId = $Matches[3]
                    $sessState = $Matches[4]
                    Write-DatKV "$sessUser" "Session $sessId ($sessState) [$sessName]"
                    if ($sessUser -ne $env:USERNAME) {
                        $otherSessions += [PSCustomObject]@{User=$sessUser; Id=$sessId; State=$sessState}
                    }
                }
            }
            if ($otherSessions.Count -gt 0) {
                Add-Finding "LOW" "Sessions" "$($otherSessions.Count) other user session(s) active - token theft / session hijack target"
                # Check for disconnected sessions (tscon hijack)
                $disconnected = @($otherSessions | Where-Object { $_.State -eq 'Disc' })
                if ($disconnected.Count -gt 0) {
                    Add-Finding "RED" "SessionHijack" "$($disconnected.Count) disconnected session(s) - tscon $($disconnected[0].Id) as SYSTEM = session hijack without password"
                }
            }
        } else {
            Write-DatSub "Cannot enumerate sessions (access denied or not RDS)"
        }

        # net sessions - who is connecting TO this box
        $netSess = net sessions 2>&1 | Out-String
        if ($netSess -and $netSess -notmatch 'no entries|access is denied') {
            $incomingSessions = $netSess -split "`n" | Where-Object { $_ -match '^\s*\\\\' }
            if ($incomingSessions.Count -gt 0) {
                foreach ($is in $incomingSessions | Select-Object -First 5) {
                    Write-DatSub "Incoming: $($is.Trim())"
                }
                Add-Finding "INFO" "NetSessions" "$($incomingSessions.Count) incoming network session(s)"
            }
        }
    } catch { Write-Err "Cannot enumerate sessions" }

    Write-Sub "UAC Configuration"
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $enableLUA = (Get-ItemProperty $uacPath -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA
        $consentAdmin = (Get-ItemProperty $uacPath -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $filterToken = (Get-ItemProperty $uacPath -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy

        $consentLabels = @{
            0 = "Elevate without prompting (VULNERABLE!)"
            1 = "Prompt for credentials on secure desktop"
            2 = "Prompt for consent on secure desktop"
            3 = "Prompt for credentials"
            4 = "Prompt for consent"
            5 = "Prompt for consent for non-Windows binaries (default)"
        }
        $consentLabel = if ($consentLabels.ContainsKey([int]$consentAdmin)) { $consentLabels[[int]$consentAdmin] } else { "Unknown ($consentAdmin)" }

        Write-DatKV "UAC Enabled (EnableLUA)" "$(if ($enableLUA -eq 1) {'Yes'} elseif ($enableLUA -eq 0) {'NO (DISABLED!)'} else {'Not set'})"
        Write-DatKV "Admin Prompt Behavior" $consentLabel
        Write-DatKV "LocalAccountTokenFilterPolicy" "$(if ($filterToken -eq 1) {'DISABLED (pass-the-hash for local admins works!)'} else {'Enabled (default)'})"

        if ($enableLUA -eq 0) {
            Add-Finding "PE" "UAC" "UAC completely disabled - any admin process runs elevated without prompt!"
        } elseif ($consentAdmin -eq 0) {
            Add-Finding "RED" "UAC" "UAC auto-elevates for admins without prompting - UAC bypass trivial"
        }
        if ($filterToken -eq 1) {
            Add-Finding "RED" "UACFilter" "LocalAccountTokenFilterPolicy disabled - pass-the-hash works for local admin accounts over network"
        }
    } catch { Write-Err "Cannot check UAC settings" }

    Write-Sub "WDAC (Windows Defender Application Control)"
    try {
        $ciPolicies = @()
        $ciPolicyPath = "$env:SystemRoot\System32\CodeIntegrity"
        if (Test-Path "$ciPolicyPath\SIPolicy.p7b") {
            $ciPolicies += "SIPolicy.p7b (legacy format)"
        }
        if (Test-Path "$ciPolicyPath\CIPolicies\Active") {
            $activeP = Get-ChildItem "$ciPolicyPath\CIPolicies\Active\*.cip" -ErrorAction SilentlyContinue
            if ($activeP) { $ciPolicies += "$($activeP.Count) active CIP policy file(s)" }
        }
        # Check enforcement via registry
        $wdacEnforce = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name 'UMCIAuditMode' -ErrorAction SilentlyContinue).UMCIAuditMode
        $hvci = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled

        Write-DatKV "CI Policies" "$(if ($ciPolicies.Count -gt 0) {$ciPolicies -join ', '} else {'None found'})"
        Write-DatKV "UMCI Audit Mode" "$(if ($wdacEnforce -eq 1) {'Audit only (not blocking)'} elseif ($wdacEnforce -eq 0) {'Enforced'} else {'Not configured'})"
        Write-DatKV "HVCI (Memory Integrity)" "$(if ($hvci -eq 1) {'Enabled'} else {'Disabled/Not Set'})" -last

        if ($ciPolicies.Count -gt 0 -and $wdacEnforce -ne 1) {
            Add-Finding "INFO" "WDAC" "WDAC policies present and enforced"
        } elseif ($ciPolicies.Count -gt 0 -and $wdacEnforce -eq 1) {
            Add-Finding "LOW" "WDACAudit" "WDAC policies in AUDIT mode only - not blocking"
        } else {
            Add-Finding "RED" "NoWDAC" "No WDAC policies - no code integrity enforcement"
        }
        if ($hvci -ne 1) {
            Add-Finding "LOW" "NoHVCI" "HVCI (Memory Integrity) not enabled"
        }
    } catch { Write-Err "Cannot query WDAC status" }

    Write-SectionFooter
}

function Test-LocalServices {
    Write-SectionHeader 26 "WINDOWS SERVICES - PE VECTORS"

    Write-Sub "Unquoted Service Paths"
    $unquoted = @()
    try {
        $svcs = Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {
            $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' -and $_.PathName -match ' '
        }
        foreach ($svc in $svcs) {
            $unquoted += $svc
            Write-DatKV $svc.Name $svc.PathName
        }
        if ($unquoted.Count -gt 0) {
            Add-Finding "RED" "UnquotedSvc" "$($unquoted.Count) services with unquoted paths containing spaces"
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $unqSIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
            foreach ($u in $unquoted) {
                # Check if we can write to any intermediate directory
                $parts = $u.PathName.Split(' ')[0..($u.PathName.Split(' ').Count-2)]
                $testPath = ""
                foreach ($p in $parts) {
                    $testPath += $p
                    $parentDir = Split-Path $testPath -ErrorAction SilentlyContinue
                    if ($parentDir -and (Test-Path $parentDir)) {
                        try {
                            $acl = Get-Acl $parentDir -ErrorAction Stop
                            $writable = Test-WritableACL $acl $unqSIDs -IncludeWellKnown
                            if ($writable) {
                                Add-Finding "PE" "UnquotedSvc" "Writable dir '$parentDir' in unquoted path of '$($u.Name)'"
                                Add-AttackPath "Drop binary in '$parentDir' $iRA service '$($u.Name)' runs it $iRA SYSTEM"
                            }
                        } catch {}
                    }
                    $testPath += " "
                }
            }
        } else {
            Write-OK "No unquoted service paths"
        }
    } catch { Write-Err "Cannot enumerate services" }

    Write-Sub "Weak Service Permissions"
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
        $weakSvcs = @()
        foreach ($svc in (Get-WmiObject Win32_Service -ErrorAction Stop)) {
            if (-not $svc.PathName) { continue }
            $binPath = Get-ServiceBinaryPath $svc.PathName
            if (-not $binPath -or $binPath -match '^[A-Za-z]:\\Windows\\') { continue }
            if (-not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }

            try {
                $acl = Get-Acl $binPath -ErrorAction Stop
                $writable = Test-WritableACL $acl $mySIDs -IncludeWellKnown
                if ($writable) {
                    $weakSvcs += $svc
                    $who = ($writable | Select-Object -First 1).IdentityReference.Value
                    Add-Finding "PE" "WeakSvcBin" "Service '$($svc.Name)' binary writable by $who"
                    Add-AttackPath "Replace '$binPath' $iRA restart '$($svc.Name)' $iRA runs as $($svc.StartName)"
                }
            } catch {}
        }
        if ($weakSvcs.Count -eq 0) { Write-OK "No writable service binaries" }
    } catch { Write-Err "Cannot check service binaries" }

    Write-Sub "Writable Service Registry Keys"
    try {
        $weakReg = @()
        foreach ($svcName in (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            try {
                $acl = Get-Acl $regPath -ErrorAction Stop
                $writable = $acl.Access | Where-Object {
                    $_.RegistryRights -match "SetValue|FullControl" -and
                    $_.AccessControlType -eq "Allow" -and
                    ($mySIDs -contains $_.IdentityReference.Value -or $_.IdentityReference.Value -match 'Everyone|Authenticated Users|BUILTIN\\Users')
                }
                if ($writable) {
                    $weakReg += $svcName
                    Add-Finding "PE" "WeakSvcReg" "Service '$svcName' registry key writable"
                    Add-AttackPath "Modify ImagePath of '$svcName' $iRA restart $iRA code execution"
                }
            } catch {}
        }
        if ($weakReg.Count -eq 0) { Write-OK "No writable service registry keys" }
    } catch { Write-Err "Cannot enumerate service registry" }

    Write-SectionFooter
}

function Test-ScheduledTasks {
    Write-SectionHeader 27 "SCHEDULED TASKS - PE VECTORS"

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.State -ne 'Disabled' -and
            $_.Principal.UserId -match 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE' -and
            $_.Actions.Execute
        }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
        $found = @()

        foreach ($task in $tasks) {
            foreach ($action in $task.Actions) {
                $exe = $action.Execute
                if (-not $exe -or $exe -match '^%windir%|^%SystemRoot%|^C:\\Windows\\') { continue }
                # Resolve env vars
                $exe = [System.Environment]::ExpandEnvironmentVariables($exe)
                if (-not (Test-Path $exe -ErrorAction SilentlyContinue)) { continue }

                try {
                    $acl = Get-Acl $exe -ErrorAction Stop
                    $writable = Test-WritableACL $acl $mySIDs -IncludeWellKnown
                    if ($writable) {
                        $found += $task
                        Add-Finding "PE" "SchedTask" "Task '$($task.TaskName)' runs as $($task.Principal.UserId) - binary writable"
                        Add-AttackPath "Replace '$exe' $iRA task '$($task.TaskName)' runs it as $($task.Principal.UserId)"
                    }
                } catch {}
            }
        }
        if ($found.Count -eq 0) { Write-OK "No writable scheduled task binaries running as SYSTEM" }
    } catch { Write-Err "Cannot enumerate scheduled tasks" }

    Write-SectionFooter
}

function Test-StoredCredentials {
    Write-SectionHeader 28 "STORED CREDENTIALS & SECRETS"

    Write-Sub "AutoLogon Credentials"
    $wlKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $autoUser = (Get-ItemProperty $wlKey -Name 'DefaultUserName' -ErrorAction SilentlyContinue).DefaultUserName
    $autoPass = (Get-ItemProperty $wlKey -Name 'DefaultPassword' -ErrorAction SilentlyContinue).DefaultPassword
    $autoPassAlt = (Get-ItemProperty $wlKey -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue).AutoAdminLogon

    if ($autoPass) {
        Write-DatKV "AutoLogon User" $autoUser
        Write-DatKV "AutoLogon Pass" "*** PASSWORD FOUND ***" -last
        Add-Finding "PE" "AutoLogon" "AutoLogon password in registry for '$autoUser'"
        Add-AttackPath "AutoLogon creds: $autoUser $iRA use for lateral movement"
    } elseif ($autoUser -and $autoPassAlt -eq "1") {
        Write-DatKV "AutoLogon User" $autoUser
        Write-DatKV "AutoAdminLogon" "Enabled (password may be in LSA secrets)" -last
        Add-Finding "RED" "AutoLogon" "AutoAdminLogon enabled for '$autoUser' - password may be in LSA secrets"
    } else {
        Write-OK "No AutoLogon credentials in registry"
    }

    Write-Sub "Saved Credentials (cmdkey)"
    try {
        $cmdkey = cmdkey /list 2>&1 | Out-String
        $targets = [regex]::Matches($cmdkey, 'Target:\s*(.+)')
        $realTargets = @($targets | Where-Object { $_.Groups[1].Value.Trim() -notmatch 'virtualapp/didlogical|WindowsLive:target=virtualapp' })
        if ($realTargets.Count -gt 0) {
            foreach ($t in $realTargets) {
                Write-Dat "Saved: $($t.Groups[1].Value.Trim())"
            }
            Add-Finding "RED" "SavedCreds" "$($realTargets.Count) saved credentials found (usable with runas /savecred)"
        } else {
            Write-OK "No saved credentials"
        }
    } catch {}

    Write-Sub "WiFi Passwords"
    try {
        $profiles = netsh wlan show profiles 2>&1 | Select-String 'All User Profile\s*:\s*(.+)' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        $wifiCreds = @()
        foreach ($prof in $profiles) {
            $detail = netsh wlan show profile name="$prof" key=clear 2>&1 | Out-String
            $keyMatch = [regex]::Match($detail, 'Key Content\s*:\s*(.+)')
            if ($keyMatch.Success) {
                $wifiCreds += [PSCustomObject]@{SSID=$prof; Key=$keyMatch.Groups[1].Value.Trim()}
                Write-DatKV $prof $keyMatch.Groups[1].Value.Trim()
            }
        }
        if ($wifiCreds.Count -gt 0) {
            Add-Finding "RED" "WiFiCreds" "$($wifiCreds.Count) WiFi passwords extracted"
        } else {
            Write-OK "No WiFi passwords extractable"
        }
    } catch { Write-Err "Cannot enumerate WiFi profiles" }

    Write-Sub "Unattend/Sysprep Files"
    $unattendPaths = @(
        "$env:SystemDrive\unattend.xml",
        "$env:SystemDrive\unattend\unattend.xml",
        "$env:SystemRoot\Panther\unattend.xml",
        "$env:SystemRoot\Panther\Unattend\Unattend.xml",
        "$env:SystemRoot\System32\Sysprep\unattend.xml",
        "$env:SystemRoot\System32\Sysprep\Panther\unattend.xml"
    )
    $foundUnattend = @()
    foreach ($p in $unattendPaths) {
        if (Test-Path $p -ErrorAction SilentlyContinue) {
            $content = Get-Content $p -Raw -ErrorAction SilentlyContinue
            if ($content -match 'Password|AdministratorPassword|AutoLogon') {
                $foundUnattend += $p
                Write-Dat "Contains credentials: $p"
            }
        }
    }
    if ($foundUnattend.Count -gt 0) {
        Add-Finding "PE" "Unattend" "Unattend files with passwords found"
    } else {
        Write-OK "No unattend files with credentials"
    }

    Write-Sub "DPAPI Credential Blobs"
    try {
        $credPath = "$env:APPDATA\Microsoft\Credentials"
        $credFiles = @()
        if (Test-Path $credPath) { $credFiles += Get-ChildItem $credPath -Force -ErrorAction SilentlyContinue }
        $credPathLocal = "$env:LOCALAPPDATA\Microsoft\Credentials"
        if (Test-Path $credPathLocal) { $credFiles += Get-ChildItem $credPathLocal -Force -ErrorAction SilentlyContinue }
        if ($credFiles.Count -gt 0) {
            Write-DatKV "Roaming creds" "$((Get-ChildItem $credPath -Force -ErrorAction SilentlyContinue).Count) blobs"
            Write-DatKV "Local creds" "$((Get-ChildItem $credPathLocal -Force -ErrorAction SilentlyContinue).Count) blobs" -last
            Add-Finding "LOW" "DPAPI" "$($credFiles.Count) DPAPI credential blobs found (decryptable with user password/DPAPI key)"
        } else {
            Write-OK "No DPAPI credential blobs"
        }
    } catch { Write-Err "Cannot enumerate DPAPI blobs" }

    Write-Sub "SAM/SYSTEM Backup Files"
    $samPaths = @(
        "$env:SystemRoot\repair\SAM",
        "$env:SystemRoot\repair\SYSTEM",
        "$env:SystemRoot\repair\SECURITY",
        "$env:SystemRoot\System32\config\RegBack\SAM",
        "$env:SystemRoot\System32\config\RegBack\SYSTEM",
        "$env:SystemRoot\System32\config\RegBack\SECURITY"
    )
    $foundSAM = @()
    foreach ($sp in $samPaths) {
        if (Test-Path $sp -ErrorAction SilentlyContinue) {
            try {
                $null = Get-Content $sp -TotalCount 1 -ErrorAction Stop
                $foundSAM += $sp
                Write-Dat "READABLE: $sp"
            } catch {
                # File exists but can't read - expected for non-admin
            }
        }
    }
    if ($foundSAM.Count -gt 0) {
        Add-Finding "PE" "SAMBackup" "Readable SAM/SYSTEM backup files found - extract local hashes!"
        Add-AttackPath "Copy SAM+SYSTEM from backup $iRA secretsdump $iRA local admin NTLM hash"
    } else {
        Write-OK "No readable SAM/SYSTEM backup files"
    }

    # Shadow copies
    try {
        $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction Stop
        if ($shadows -and $shadows.Count -gt 0) {
            Write-DatKV "Volume Shadow Copies" "$($shadows.Count) found"
            $readableShadow = $false
            foreach ($s in ($shadows | Select-Object -First 3)) {
                $shadowPath = "$($s.DeviceObject)\Windows\System32\config\SAM"
                try {
                    if (Test-Path "\\?\$($s.DeviceObject)\Windows\System32\config\SAM" -ErrorAction SilentlyContinue) {
                        $readableShadow = $true
                    }
                } catch {}
            }
            if ($readableShadow) {
                Add-Finding "PE" "ShadowSAM" "SAM accessible via Volume Shadow Copy - extract hashes"
            } else {
                Add-Finding "INFO" "ShadowCopies" "$($shadows.Count) shadow copies exist (may contain SAM if admin)"
            }
        }
    } catch {}

    Write-Sub "Credential Files in Common Locations"
    $credLocations = @(
        @{Path="$env:USERPROFILE\.git-credentials"; Name="Git credentials (plaintext)"},
        @{Path="$env:USERPROFILE\.aws\credentials"; Name="AWS credentials"},
        @{Path="$env:USERPROFILE\.azure\accessTokens.json"; Name="Azure CLI tokens"},
        @{Path="$env:USERPROFILE\.azure\azureProfile.json"; Name="Azure CLI profile"},
        @{Path="$env:APPDATA\gcloud\credentials.db"; Name="GCloud credentials"},
        @{Path="$env:APPDATA\gcloud\access_tokens.db"; Name="GCloud tokens"},
        @{Path="$env:USERPROFILE\.kube\config"; Name="Kubernetes config"},
        @{Path="$env:USERPROFILE\.docker\config.json"; Name="Docker config"},
        @{Path="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; Name="PS history"},
        @{Path="$env:USERPROFILE\.pgpass"; Name="PostgreSQL password"},
        @{Path="$env:USERPROFILE\.my.cnf"; Name="MySQL config"},
        @{Path="$env:USERPROFILE\.ssh\id_rsa"; Name="SSH private key"},
        @{Path="$env:USERPROFILE\.ssh\id_ed25519"; Name="SSH private key (Ed25519)"},
        @{Path="$env:APPDATA\filezilla\sitemanager.xml"; Name="FileZilla saved sites"},
        @{Path="$env:APPDATA\filezilla\recentservers.xml"; Name="FileZilla recent servers"},
        @{Path="$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"; Name="RDCMan settings"},
        @{Path="$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"; Name="Recent files (JumpLists)"}
    )
    $foundCreds = @()
    foreach ($cl in $credLocations) {
        if (Test-Path $cl.Path -ErrorAction SilentlyContinue) {
            $foundCreds += $cl
            Write-Dat "FOUND: $($cl.Name) ($($cl.Path))"
        }
    }
    # Check for .rdp files with passwords
    $rdpFiles = @()
    $rdpFiles += Get-ChildItem "$env:USERPROFILE\Desktop\*.rdp" -ErrorAction SilentlyContinue
    $rdpFiles += Get-ChildItem "$env:USERPROFILE\Documents\*.rdp" -ErrorAction SilentlyContinue
    $rdpFiles += Get-ChildItem "$env:USERPROFILE\Downloads\*.rdp" -ErrorAction SilentlyContinue
    foreach ($rdp in $rdpFiles) {
        $rdpContent = Get-Content $rdp.FullName -Raw -ErrorAction SilentlyContinue
        if ($rdpContent -match 'password 51:') {
            $foundCreds += @{Path=$rdp.FullName; Name="RDP file with saved password"}
            Write-Dat "RDP with password: $($rdp.Name)"
        }
    }
    # Check for KeePass databases
    $kdbxFiles = @()
    $kdbxFiles += Get-ChildItem "$env:USERPROFILE" -Filter "*.kdbx" -Recurse -Depth 3 -ErrorAction SilentlyContinue
    foreach ($kf in $kdbxFiles) {
        $foundCreds += @{Path=$kf.FullName; Name="KeePass database"}
        Write-Dat "KeePass DB: $($kf.FullName)"
    }

    if ($foundCreds.Count -gt 0) {
        Add-Finding "RED" "CredFiles" "$($foundCreds.Count) credential/config files found in user profile"
        # Highlight the most critical ones
        $critical = $foundCreds | Where-Object { $_.Name -match 'Git credentials|AWS|Azure|SSH private|password' }
        if ($critical.Count -gt 0) {
            Add-AttackPath "Harvest credential files $iRA lateral movement / cloud access"
        }
    } else {
        Write-OK "No credential files found in common locations"
    }

    Write-Sub "SSH Private Keys"
    try {
        $sshDirs = @(
            "$env:USERPROFILE\.ssh",
            "$env:USERPROFILE",
            "$env:USERPROFILE\Documents"
        )
        $sshKeyPatterns = @("id_rsa","id_dsa","id_ecdsa","id_ed25519","*.pem","*.ppk")
        $foundKeys = @()
        foreach ($dir in $sshDirs) {
            if (Test-Path $dir -ErrorAction SilentlyContinue) {
                foreach ($pat in $sshKeyPatterns) {
                    $keys = Get-ChildItem -Path $dir -Filter $pat -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt 0 -and $_.Length -lt 50000 }
                    foreach ($k in $keys) {
                        # Verify it's actually a key file (check header)
                        $header = Get-Content $k.FullName -TotalCount 1 -ErrorAction SilentlyContinue
                        if ($header -match 'PRIVATE KEY|PuTTY-User-Key-File') {
                            $encrypted = (Get-Content $k.FullName -Raw -ErrorAction SilentlyContinue) -match 'ENCRYPTED|Encryption: aes'
                            $foundKeys += [PSCustomObject]@{
                                Path = $k.FullName
                                Name = $k.Name
                                Encrypted = $encrypted
                            }
                            $encLabel = if ($encrypted) { "encrypted" } else { "UNENCRYPTED!" }
                            Write-Dat "FOUND: $($k.Name) ($encLabel) - $($k.FullName)"
                        }
                    }
                }
            }
        }
        # Also check known_hosts and config for targets
        $knownHosts = "$env:USERPROFILE\.ssh\known_hosts"
        $sshConfig = "$env:USERPROFILE\.ssh\config"
        if (Test-Path $knownHosts -ErrorAction SilentlyContinue) {
            $hostCount = (Get-Content $knownHosts -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-DatSub "known_hosts: $hostCount entries (target list for lateral movement)"
        }
        if (Test-Path $sshConfig -ErrorAction SilentlyContinue) {
            $configHosts = Get-Content $sshConfig -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*Host\s+' }
            if ($configHosts) {
                Write-DatSub "SSH config: $($configHosts.Count) host entries"
            }
        }

        if ($foundKeys.Count -gt 0) {
            $unencrypted = @($foundKeys | Where-Object { -not $_.Encrypted })
            if ($unencrypted.Count -gt 0) {
                Add-Finding "RED" "SSHKeys" "$($unencrypted.Count) UNENCRYPTED SSH private key(s) - immediate lateral movement!"
                Add-AttackPath "SSH private key $iRA ssh -i key user@target $iRA lateral movement"
            } else {
                Add-Finding "LOW" "SSHKeys" "$($foundKeys.Count) encrypted SSH private key(s) found - crackable with john/hashcat"
            }
        } else {
            Write-OK "No SSH private keys found"
        }
    } catch { Write-Err "Cannot check SSH keys: $($_.Exception.Message)" }

    Write-Sub "GPP cpassword (Group Policy Preferences)"
    try {
        $domain = $env:USERDNSDOMAIN
        if ($domain) {
            $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
            if (Test-Path $sysvolPath -ErrorAction SilentlyContinue) {
                $gppFiles = @(
                    "Groups\Groups.xml",
                    "Services\Services.xml",
                    "ScheduledTasks\ScheduledTasks.xml",
                    "DataSources\DataSources.xml",
                    "Drives\Drives.xml",
                    "Printers\Printers.xml"
                )
                $foundGPP = @()
                $policies = Get-ChildItem $sysvolPath -Directory -ErrorAction SilentlyContinue
                foreach ($pol in $policies) {
                    foreach ($gppFile in $gppFiles) {
                        $machPath = Join-Path $pol.FullName "Machine\Preferences\$gppFile"
                        $userPath = Join-Path $pol.FullName "User\Preferences\$gppFile"
                        foreach ($testPath in @($machPath, $userPath)) {
                            if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                                $content = Get-Content $testPath -Raw -ErrorAction SilentlyContinue
                                if ($content -match 'cpassword="([^"]+)"') {
                                    $cpass = $Matches[1]
                                    if ($cpass -and $cpass.Length -gt 0) {
                                        $foundGPP += [PSCustomObject]@{
                                            Policy = $pol.Name
                                            File = $gppFile
                                            CPassword = $cpass
                                        }
                                        Write-Highlight "GPP cpassword in $($pol.Name)\$gppFile"
                                    }
                                }
                            }
                        }
                    }
                }
                if ($foundGPP.Count -gt 0) {
                    Add-Finding "PE" "GPPPassword" "$($foundGPP.Count) GPP cpassword(s) found - AES key is public, instant decrypt!"
                    Add-AttackPath "GPP cpassword $iRA gpp-decrypt / Get-GPPPassword $iRA plaintext credentials"
                    foreach ($g in $foundGPP | Select-Object -First 5) {
                        Write-DatSub "Policy: $($g.Policy) | File: $($g.File)"
                    }
                } else {
                    Write-OK "No GPP files contain cpassword"
                }
            } else {
                Write-DatSub "Cannot access SYSVOL at $sysvolPath"
            }
        } else {
            Write-DatSub "Not domain-joined - skipping GPP check"
        }
    } catch { Write-Err "Cannot check GPP: $($_.Exception.Message)" }

    Write-Sub "Password Manager Databases (KeePass)"
    try {
        $kdbxFiles = @()
        $searchDirs = @(
            $env:USERPROFILE,
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads",
            "$env:APPDATA",
            "$env:LOCALAPPDATA"
        )
        foreach ($dir in $searchDirs) {
            if (Test-Path $dir -ErrorAction SilentlyContinue) {
                $found = Get-ChildItem -Path $dir -Filter "*.kdbx" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                    Select-Object -First 10
                $kdbxFiles += $found
            }
        }
        # Also check for KeePass config (recently opened databases)
        $kpConfig = "$env:APPDATA\KeePass\KeePass.config.xml"
        $kpRecentDbs = @()
        if (Test-Path $kpConfig -ErrorAction SilentlyContinue) {
            $kpXml = Get-Content $kpConfig -Raw -ErrorAction SilentlyContinue
            $kpRecentDbs = [regex]::Matches($kpXml, '<Path>([^<]+\.kdbx)</Path>') | ForEach-Object { $_.Groups[1].Value }
            if ($kpRecentDbs.Count -gt 0) {
                Write-DatSub "KeePass config: $($kpRecentDbs.Count) recent database(s)"
                foreach ($rdb in $kpRecentDbs | Select-Object -First 5) {
                    Write-DatSub "  Recent: $rdb"
                }
            }
        }

        if ($kdbxFiles.Count -gt 0) {
            foreach ($kf in $kdbxFiles | Select-Object -First 5) {
                Write-Dat "FOUND: $($kf.FullName) ($([math]::Round($kf.Length / 1KB, 1)) KB)"
            }
            Add-Finding "RED" "KeePass" "$($kdbxFiles.Count) KeePass database(s) found - crackable with keepass2john + hashcat"
            Add-AttackPath "keepass2john db.kdbx $iRA hashcat -m 13400 $iRA master password $iRA all stored credentials"
        } elseif ($kpRecentDbs.Count -gt 0) {
            Add-Finding "LOW" "KeePass" "KeePass installed with $($kpRecentDbs.Count) recent database(s) - locate and crack"
        } else {
            Write-OK "No KeePass databases found"
        }
    } catch { Write-Err "Cannot search for KeePass databases: $($_.Exception.Message)" }

    Write-Sub "Browser Stored Credentials"
    $browserDBs = @(
        @{Browser="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"; Type="passwords"},
        @{Browser="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"; Type="cookies"},
        @{Browser="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"; Type="encryption key"},
        @{Browser="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"; Type="passwords"},
        @{Browser="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"; Type="cookies"},
        @{Browser="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"; Type="encryption key"},
        @{Browser="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"; Type="profile dir"},
        @{Browser="Brave";   Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"; Type="passwords"}
    )
    $foundBrowser = @()
    foreach ($db in $browserDBs) {
        if (Test-Path $db.Path -ErrorAction SilentlyContinue) {
            $foundBrowser += $db
            Write-Dat "$($db.Browser) $($db.Type): $($db.Path)"
        }
    }
    # Check Firefox profiles for key4.db + logins.json
    $ffProfileDir = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffProfileDir -ErrorAction SilentlyContinue) {
        $ffProfiles = Get-ChildItem $ffProfileDir -Directory -ErrorAction SilentlyContinue
        foreach ($fp in $ffProfiles) {
            $key4 = Join-Path $fp.FullName "key4.db"
            $logins = Join-Path $fp.FullName "logins.json"
            if ((Test-Path $key4) -and (Test-Path $logins)) {
                $foundBrowser += @{Browser="Firefox"; Path=$logins; Type="passwords ($($fp.Name))"}
                Write-Dat "Firefox passwords: $($fp.Name) (key4.db + logins.json)"
            }
        }
    }
    if ($foundBrowser.Count -gt 0) {
        $pwDbs = @($foundBrowser | Where-Object { $_.Type -match 'passwords' })
        if ($pwDbs.Count -gt 0) {
            Add-Finding "RED" "BrowserCreds" "$($pwDbs.Count) browser password databases found (DPAPI-decryptable as current user)"
            Add-AttackPath "SharpChromium / Mimikatz dpapi $iRA decrypt browser passwords $iRA credential harvest"
        } else {
            Add-Finding "INFO" "BrowserData" "Browser data files found but no password databases"
        }
    } else {
        Write-OK "No browser credential databases found"
    }

    Write-SectionFooter
}

function Test-AlwaysInstallElevated {
    Write-SectionHeader 29 "ALWAYS INSTALL ELEVATED & DLL HIJACK"

    Write-Sub "AlwaysInstallElevated"
    $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated

    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Write-DatKV "HKLM AlwaysInstallElevated" "1"
        Write-DatKV "HKCU AlwaysInstallElevated" "1" -last
        Add-Finding "PE" "MSIElevated" "AlwaysInstallElevated = 1 in BOTH HKLM and HKCU"
        Add-AttackPath "msfvenom -p windows/x64/shell_reverse_tcp -f msi $iRA msiexec /i evil.msi $iRA SYSTEM"
    } else {
        Write-OK "AlwaysInstallElevated not set"
    }

    Write-Sub "Writable Directories in PATH"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and $_ -notmatch '^C:\\Windows' }
    $writablePath = @()
    foreach ($dir in $pathDirs) {
        if (-not (Test-Path $dir -ErrorAction SilentlyContinue)) { continue }
        try {
            $acl = Get-Acl $dir -ErrorAction Stop
            $writable = Test-WritableACL $acl $mySIDs -IncludeWellKnown
            if ($writable) {
                $writablePath += $dir
                Write-Dat "WRITABLE: $dir"
            }
        } catch {}
    }
    if ($writablePath.Count -gt 0) {
        Add-Finding "PE" "WritablePATH" "$($writablePath.Count) writable directories in PATH - DLL hijacking"
        Add-AttackPath "Drop DLL in '$($writablePath[0])' $iRA process loads it $iRA code execution"
    } else {
        Write-OK "No writable non-system directories in PATH"
    }

    Write-Sub "DLL Hijacking - User-Writable Application Directories"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $meDLLSIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
    # Applications known to load DLLs from their install directory (user-writable installs)
    $dllHijackPaths = @(
        @{App="Microsoft Teams (classic)"; Path="$env:LOCALAPPDATA\Microsoft\Teams"; Priv="User context (credential theft)"},
        @{App="Microsoft Teams (new)"; Path="$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe"; Priv="User context"},
        @{App="Microsoft OneDrive"; Path="$env:LOCALAPPDATA\Microsoft\OneDrive"; Priv="User context + file sync tokens"},
        @{App="Slack"; Path="$env:LOCALAPPDATA\slack"; Priv="User context"},
        @{App="Discord"; Path="$env:LOCALAPPDATA\Discord"; Priv="User context"},
        @{App="VS Code"; Path="$env:LOCALAPPDATA\Programs\Microsoft VS Code"; Priv="User context"},
        @{App="Zoom"; Path="$env:APPDATA\Zoom"; Priv="User context"}
    )
    # Also check Program Files for writable directories with running services
    $svcBinDirs = @()
    try {
        $runningSvcs = Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {
            $_.State -eq 'Running' -and $_.PathName -and
            $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' -and
            ($_.StartName -match 'LocalSystem|SYSTEM|LOCAL SERVICE|NETWORK SERVICE' -or -not $_.StartName)
        }
        foreach ($svc in $runningSvcs) {
            $binPath = Get-ServiceBinaryPath $svc.PathName
            if (-not $binPath -or -not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }
            $binDir = Split-Path $binPath -ErrorAction SilentlyContinue
            if (-not $binDir -or $binDir -match '^[A-Za-z]:\\Windows' -or ($svcBinDirs -contains $binDir)) { continue }
            $svcBinDirs += $binDir
            if (-not (Test-Path $binDir -ErrorAction SilentlyContinue)) { continue }
            try {
                $acl = Get-Acl $binDir -ErrorAction Stop
                $writable = Test-WritableACL $acl $meDLLSIDs -IncludeWellKnown
                if ($writable) {
                    $who = ($writable | Select-Object -First 1).IdentityReference.Value
                    Add-Finding "PE" "DLLHijack" "Service '$($svc.Name)' dir writable by ${who} - $binDir (runs as $($svc.StartName))"
                    Add-AttackPath "Place DLL in '$binDir' $iRA service '$($svc.Name)' loads it $iRA $($svc.StartName)"
                }
            } catch {}
        }
    } catch {}

    # Check user-install apps (persistence/credential theft, not PE to SYSTEM but PE in user context)
    foreach ($app in $dllHijackPaths) {
        if (Test-Path $app.Path -ErrorAction SilentlyContinue) {
            # Check if actually writable (should be by default for LOCALAPPDATA apps)
            try {
                $testFile = Join-Path $app.Path ".__fenrir_test_$(Get-Random).tmp"
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                Write-Dat "$($app.App): writable ($($app.Priv))"
            } catch {
                # Not writable - skip
            }
        }
    }

    Write-Sub "Phantom DLL Hijacking (Known Missing DLLs)"
    # Known DLLs that processes try to load but don't exist by default
    # Only flag if the directory where the process looks is writable
    $phantomDLLs = @(
        @{DLL="wlbsctrl.dll";   Svc="IKEEXT";     Desc="IKE/AuthIP - loads missing wlbsctrl.dll"},
        @{DLL="wlanhlp.dll";    Svc="Wlansvc";     Desc="WLAN AutoConfig - loads missing wlanhlp.dll"},
        @{DLL="amsi.dll";       Svc="";             Desc="AMSI bypass - place in app dir to preempt System32"},
        @{DLL="DSPARSE.dll";    Svc="";             Desc="Loaded by many AD tools from CWD before System32"},
        @{DLL="profapi.dll";    Svc="";             Desc="User Profile Service - phantom load candidate"}
    )
    $phantomFound = @()
    foreach ($p in $phantomDLLs) {
        if ($p.Svc) {
            $svc = Get-Service $p.Svc -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -ne 'Running') { continue }
            $svcWmi = Get-WmiObject Win32_Service -Filter "Name='$($p.Svc)'" -ErrorAction SilentlyContinue
            if (-not $svcWmi -or -not $svcWmi.PathName) { continue }
            $binPath = Get-ServiceBinaryPath $svcWmi.PathName
            if (-not $binPath) { continue }
            $binDir = Split-Path $binPath -ErrorAction SilentlyContinue
            if (-not $binDir -or $binDir -match '^[A-Za-z]:\\Windows') { continue }
            # Check if DLL already exists in binDir
            $dllPath = Join-Path $binDir $p.DLL
            if (Test-Path $dllPath -ErrorAction SilentlyContinue) { continue }
            # Check if binDir is writable
            if (Test-Path $binDir -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-Acl $binDir -ErrorAction Stop
                    $writable = Test-WritableACL $acl $meDLLSIDs -IncludeWellKnown
                    if ($writable) {
                        $phantomFound += $p
                        Add-Finding "PE" "PhantomDLL" "Service '$($p.Svc)' loads missing $($p.DLL) from writable dir $binDir"
                        Add-AttackPath "Place $($p.DLL) in '$binDir' $iRA service '$($p.Svc)' loads it $iRA SYSTEM"
                    }
                } catch {}
            }
        }
    }
    if ($phantomFound.Count -eq 0) {
        Write-OK "No exploitable phantom DLL vectors found"
    }

    Write-Sub "Print Spooler (PrintNightmare)"
    try {
        $spooler = Get-Service Spooler -ErrorAction Stop
        $ppKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $ppRestrict = (Get-ItemProperty $ppKey -Name 'RestrictDriverInstallationToAdministrators' -ErrorAction SilentlyContinue).RestrictDriverInstallationToAdministrators
        $ppNoWarn = (Get-ItemProperty $ppKey -Name 'NoWarningNoElevationOnInstall' -ErrorAction SilentlyContinue).NoWarningNoElevationOnInstall
        $ppUpdate = (Get-ItemProperty $ppKey -Name 'UpdatePromptSettings' -ErrorAction SilentlyContinue).UpdatePromptSettings

        Write-DatKV "Spooler Status" $spooler.Status
        Write-DatKV "RestrictDriverInstall" "$(if ($ppRestrict -eq 1) {'Yes (mitigated)'} else {'No/Not Set'})"
        Write-DatKV "NoWarningNoElevation" "$(if ($ppNoWarn -eq 1) {'Yes (DANGEROUS)'} elseif ($ppNoWarn -eq 0) {'No (safe)'} else {'Not Set'})"
        Write-DatKV "UpdatePromptSettings" "$(if ($ppUpdate -eq 1) {'No elevation (DANGEROUS)'} elseif ($ppUpdate -eq 0) {'Elevation required'} else {'Not Set'})" -last

        if ($spooler.Status -eq 'Running') {
            if ($ppRestrict -eq 1) {
                Add-Finding "LOW" "PrintSpooler" "Print Spooler running but RestrictDriverInstallation=1 (mitigated)"
            } elseif ($ppNoWarn -eq 1 -or $ppUpdate -eq 1) {
                Add-Finding "PE" "PrintSpooler" "Print Spooler + PointAndPrint allows driver install WITHOUT elevation (CVE-2021-34527)"
            } else {
                Add-Finding "RED" "PrintSpooler" "Print Spooler running + PointAndPrint not restricted - verify if exploitable"
            }
        }
    } catch {}

    Write-SectionFooter
}

function Test-AutorunsStartup {
    Write-SectionHeader 30 "AUTORUNS & STARTUP PERSISTENCE"

    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })

    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    Write-Sub "Registry Run Keys"
    $writableRun = @()
    foreach ($key in $runKeys) {
        try {
            $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $val = $_.Value
                $binPath = if ($val -match '^"([^"]+)"') { $Matches[1] } elseif ($val -match '^(\S+)') { $Matches[1] }
                if ($binPath -and $binPath -notmatch '^C:\\Windows\\' -and (Test-Path $binPath -ErrorAction SilentlyContinue)) {
                    try {
                        $acl = Get-Acl $binPath -ErrorAction Stop
                        $writable = Test-WritableACL $acl $mySIDs -IncludeWellKnown
                        if ($writable) {
                            $writableRun += "$($_.Name) = $binPath"
                            Write-Dat "WRITABLE: $($_.Name) ($key)"
                            if ($key -match 'HKLM') {
                                Add-Finding "PE" "WritableAutorun" "HKLM autorun '$($_.Name)' binary writable"
                                Add-AttackPath "Replace '$binPath' $iRA runs on any user logon"
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    if ($writableRun.Count -eq 0) { Write-OK "No writable autorun binaries" }

    Write-Sub "Startup Folders"
    $startupDirs = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($dir in $startupDirs) {
        if (Test-Path $dir) {
            try {
                $acl = Get-Acl $dir -ErrorAction Stop
                $writable = Test-WritableACL $acl $mySIDs -IncludeWellKnown
                if ($writable) {
                    Write-Dat "WRITABLE: $dir"
                    if ($dir -match 'ProgramData') {
                        Add-Finding "RED" "StartupDir" "All-users Startup folder writable - drop exe for persistence"
                    }
                }
            } catch {}
        }
    }

    Write-Sub "COM Object Hijacking (CLSID InprocServer32)"
    try {
        # HKCU CLSID entries override HKLM - user can create HKCU entries for COM objects used by SYSTEM/elevated processes
        # Check for existing HKCU overrides with writable DLL paths
        $comHijacks = @()
        $hkcuCLSID = "HKCU:\SOFTWARE\Classes\CLSID"
        if (Test-Path $hkcuCLSID) {
            $clsidKeys = Get-ChildItem $hkcuCLSID -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($key in $clsidKeys) {
                $inproc = Join-Path $key.PSPath "InprocServer32"
                if (Test-Path $inproc -ErrorAction SilentlyContinue) {
                    $dllPath = (Get-ItemProperty $inproc -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                    if ($dllPath -and $dllPath -ne '' -and $dllPath -notmatch '^[A-Za-z]:\\Windows\\') {
                        $comHijacks += [PSCustomObject]@{CLSID=$key.PSChildName; DLL=$dllPath}
                        Write-Dat "HKCU override: $($key.PSChildName) -> $dllPath"
                    }
                }
            }
        }
        if ($comHijacks.Count -gt 0) {
            Add-Finding "LOW" "COMHijack" "$($comHijacks.Count) HKCU COM overrides found (check if any target elevated processes)"
        }

        # Check well-known hijackable CLSIDs that scheduled tasks / services use
        $knownHijackable = @(
            @{CLSID="{BCDE0395-E52F-467C-8E3D-C4579291692E}"; Name="MMDeviceEnumerator (audio)"; Task="Scheduled task / svchost"},
            @{CLSID="{4590F811-1D3A-11D0-891F-00AA004B2E24}"; Name="WBEM Locator"; Task="WMI calls from SYSTEM"},
            @{CLSID="{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}"; Name="TaskbarCom"; Task="Explorer shell"}
        )
        foreach ($h in $knownHijackable) {
            $hkcuPath = "HKCU:\SOFTWARE\Classes\CLSID\$($h.CLSID)\InprocServer32"
            $hklmPath = "HKLM:\SOFTWARE\Classes\CLSID\$($h.CLSID)\InprocServer32"
            # If HKCU override doesn't exist but HKLM does → user CAN create it for hijack
            if (-not (Test-Path $hkcuPath -ErrorAction SilentlyContinue) -and (Test-Path $hklmPath -ErrorAction SilentlyContinue)) {
                $origDll = (Get-ItemProperty $hklmPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                if ($origDll) {
                    Write-DatSub "Hijackable: $($h.Name) ($($h.CLSID)) - currently $origDll"
                }
            }
        }
        Add-Finding "INFO" "COMHijack" "COM hijack vector exists (HKCU CLSID overrides HKLM) - use for persistence"
    } catch { Write-Err "Cannot check COM hijacking" }

    Write-Sub "WMI Event Subscriptions (Persistence)"
    try {
        $wmiFilters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue
        $wmiConsumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
        $wmiActiveScript = Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        $wmiBindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

        $allConsumers = @()
        if ($wmiConsumers) { $allConsumers += $wmiConsumers }
        if ($wmiActiveScript) { $allConsumers += $wmiActiveScript }

        if ($allConsumers.Count -gt 0) {
            foreach ($c in $allConsumers) {
                $cName = $c.Name
                $cCmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { "Script: $($c.ScriptText.Substring(0, [Math]::Min(80, $c.ScriptText.Length)))..." } else { "Unknown" }
                Write-DatKV "Consumer" "$cName"
                Write-DatSub "Payload: $cCmd"
            }
            Add-Finding "RED" "WMIPersist" "$($allConsumers.Count) WMI event consumer(s) found - likely persistence mechanism"
        }

        if ($wmiFilters -and $wmiFilters.Count -gt 0 -and $allConsumers.Count -eq 0) {
            # Filters without CommandLine/ActiveScript consumers - may be legitimate or use other consumer types
            foreach ($f in $wmiFilters) {
                Write-DatKV "Filter" "$($f.Name)"
                Write-DatSub "Query: $($f.Query)"
            }
            Add-Finding "INFO" "WMIFilter" "$($wmiFilters.Count) WMI event filter(s) found"
        }

        if ((-not $wmiFilters -or $wmiFilters.Count -eq 0) -and $allConsumers.Count -eq 0) {
            Write-OK "No WMI event subscriptions (no persistence)"
        }
    } catch { Write-Err "Cannot check WMI subscriptions: $($_.Exception.Message)" }

    Write-SectionFooter
}

function Test-NetworkSecurity {
    Write-SectionHeader 31 "NETWORK & SMB SECURITY"

    Write-Sub "SMB Signing"
    try {
        $smbSign = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
        $smbClient = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
        Write-DatKV "SMB Server Signing Required" "$(if ($smbSign -eq 1) {'Yes'} else {'No'})"
        Write-DatKV "SMB Client Signing Required" "$(if ($smbClient -eq 1) {'Yes'} else {'No'})" -last
        if ($smbSign -ne 1) {
            Add-Finding "RED" "SMBSign" "SMB server signing not required - relay attacks possible"
        }
    } catch {}

    Write-Sub "LLMNR / NBT-NS / mDNS"
    $llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
    $nbtns = $null
    try {
        $adapter = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -eq $true } | Select-Object -First 1
        $nbtns = $adapter.TcpipNetbiosOptions  # 2 = disabled
    } catch {}
    Write-DatKV "LLMNR" "$(if ($llmnr -eq 0) {'Disabled'} else {'Enabled (poisoning risk)'})"
    Write-DatKV "NBT-NS" "$(if ($nbtns -eq 2) {'Disabled'} else {'Enabled (poisoning risk)'})" -last
    if ($llmnr -ne 0) {
        Add-Finding "RED" "LLMNR" "LLMNR enabled - Responder/poisoning attacks possible"
    }
    if ($nbtns -ne 2) {
        Add-Finding "RED" "NBTNS" "NBT-NS enabled - Responder/poisoning attacks possible"
    }

    Write-Sub "Windows Firewall"
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $fwProfiles) {
            $status = if ($p.Enabled) { "ON" } else { "OFF" }
            Write-DatKV "$($p.Name) Profile" $status
            if (-not $p.Enabled) {
                Add-Finding "RED" "Firewall" "Windows Firewall $($p.Name) profile DISABLED"
            }
        }
    } catch { Write-Err "Cannot query firewall" }

    Write-Sub "RDP Configuration"
    $rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
    Write-DatKV "RDP Enabled" "$(if ($rdpEnabled -eq 0) {'Yes'} else {'No'})"
    Write-DatKV "NLA Required" "$(if ($nla -eq 1) {'Yes'} else {'No'})" -last
    if ($rdpEnabled -eq 0 -and $nla -ne 1) {
        Add-Finding "RED" "RDP-NLA" "RDP enabled without NLA - BlueKeep/credential relay risk"
    }

    Write-Sub "WinRM (Remote Management)"
    try {
        $winrmSvc = Get-Service WinRM -ErrorAction Stop
        Write-DatKV "WinRM Service" "$($winrmSvc.Status) (StartType: $($winrmSvc.StartType))"
        if ($winrmSvc.Status -eq "Running") {
            # Check listeners
            try {
                $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop
                foreach ($l in $listeners) {
                    $transport = (Get-ChildItem "WSMan:\localhost\Listener\$($l.Name)" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Transport" }).Value
                    $port = (Get-ChildItem "WSMan:\localhost\Listener\$($l.Name)" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Port" }).Value
                    Write-DatKV "Listener" "$transport on port $port"
                }
            } catch {
                Write-DatKV "Listeners" "Cannot enumerate (access denied)"
            }
            # Check trusted hosts
            try {
                $trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
                if ($trustedHosts -and $trustedHosts -ne "") {
                    Write-DatKV "TrustedHosts" "$trustedHosts"
                    if ($trustedHosts -eq "*") {
                        Add-Finding "RED" "WinRMTrust" "WinRM TrustedHosts = * (any host trusted for remote management)"
                    }
                }
            } catch {}
            Add-Finding "INFO" "WinRM" "WinRM is running - remote management enabled (lateral movement vector)"
        } else {
            Write-OK "WinRM service not running"
        }
    } catch {
        Write-OK "WinRM service not found"
    }

    Write-Sub "Accessible Network Shares"
    try {
        # Enumerate local shares first
        $localShares = Get-WmiObject Win32_Share -ErrorAction Stop
        $interestingShares = @()
        foreach ($s in $localShares) {
            if ($s.Name -match '^[A-Z]\$$|^IPC\$$|^ADMIN\$$') { continue }  # skip default admin shares
            $interestingShares += $s
            Write-DatKV "$($s.Name)" "$($s.Path) (Type: $($s.Type))"
        }
        if ($interestingShares.Count -gt 0) {
            Add-Finding "INFO" "LocalShares" "$($interestingShares.Count) non-default local shares"
        }

        # Try to discover network machines and their shares via domain
        $domain = $env:USERDNSDOMAIN
        if ($domain) {
            try {
                $searcher = [adsisearcher]"(&(objectCategory=computer)(operatingSystem=*Server*))"
                $searcher.PageSize = 100
                $searcher.PropertiesToLoad.AddRange(@("cn","dnshostname"))
                $servers = $searcher.FindAll()
                $accessibleShares = @()
                $checkedCount = 0
                foreach ($srv in $servers) {
                    if ($checkedCount -ge 10) { break }  # limit to 10 servers to avoid timeout
                    $hostname = $srv.Properties["dnshostname"]
                    if (-not $hostname) { $hostname = $srv.Properties["cn"] }
                    $hostname = "$hostname"
                    if (-not $hostname -or $hostname -eq $env:COMPUTERNAME) { continue }
                    $checkedCount++
                    try {
                        $netView = net view "\\$hostname" 2>&1 | Out-String
                        $shareMatches = [regex]::Matches($netView, '(?m)^(\S+)\s+(Disk|Print)')
                        foreach ($sm in $shareMatches) {
                            $shareName = $sm.Groups[1].Value
                            if ($shareName -match '^-') { continue }
                            $sharePath = "\\$hostname\$shareName"
                            # Test if readable
                            $canRead = Test-Path $sharePath -ErrorAction SilentlyContinue
                            if ($canRead) {
                                $accessibleShares += $sharePath
                                Write-Dat "ACCESSIBLE: $sharePath"
                                # Quick check for interesting files
                                try {
                                    $sensitiveFiles = Get-ChildItem $sharePath -Recurse -Include "*.config","*.xml","*.ini","*.txt","*.ps1","*.bat","*.cmd","*.kdbx","*.pfx","*.key","web.config","appsettings.json","*.rdp" -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 5
                                    foreach ($sf in $sensitiveFiles) {
                                        Write-DatSub "Found: $($sf.FullName)"
                                    }
                                } catch {}
                            }
                        }
                    } catch {}
                }
                if ($accessibleShares.Count -gt 0) {
                    Add-Finding "RED" "NetShares" "$($accessibleShares.Count) accessible network shares (checked $checkedCount servers)"
                } else {
                    Write-OK "No accessible non-default shares on $checkedCount servers"
                }
            } catch {
                Write-Err "Cannot enumerate domain computers for share scan"
            }
        }
    } catch { Write-Err "Cannot enumerate shares" }

    Write-Sub "DNS Zone Transfer"
    try {
        $domain = $env:USERDNSDOMAIN
        if ($domain) {
            Write-DatKV "Domain" $domain
            # Get DNS servers
            $dnsServers = @()
            try {
                $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder }
                foreach ($nic in $nics) {
                    $dnsServers += $nic.DNSServerSearchOrder
                }
            } catch {}
            $dnsServers = $dnsServers | Select-Object -Unique

            $zoneTransferSuccess = $false
            foreach ($dns in $dnsServers) {
                Write-DatKV "Testing DNS" "$dns"
                try {
                    $axfr = nslookup "-type=AXFR" $domain $dns 2>&1 | Out-String
                    if ($axfr -match 'primary name server' -or ($axfr -match '\.' -and $axfr -notmatch 'refused|failed|REFUSED')) {
                        # Count records returned
                        $records = [regex]::Matches($axfr, '(?m)^\S+\s+')
                        if ($records.Count -gt 5) {
                            $zoneTransferSuccess = $true
                            Write-Dat "ZONE TRANSFER SUCCESSFUL from $dns ($($records.Count) records)"
                            Add-Finding "RED" "ZoneTransfer" "DNS zone transfer allowed from $dns - full domain enumeration"
                        }
                    }
                } catch {}
            }
            if (-not $zoneTransferSuccess) {
                Write-OK "Zone transfer refused (AXFR blocked)"
            }
        } else {
            Write-Inf "Not domain-joined or USERDNSDOMAIN not set"
        }
    } catch { Write-Err "Cannot test DNS zone transfer" }

    Write-SectionFooter
}

function Test-AppRedirectURIs {
    Write-SectionHeader 32 "APP REDIRECT URI & CONSENT ANALYSIS"

    Write-Sub "User Consent Settings"
    try {
        $authPolicy = Invoke-Graph "/policies/authorizationPolicy"
        if ($authPolicy) {
            $defaultConsent = $authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
            $canConsent = $authPolicy.defaultUserRolePermissions.allowedToCreateApps
            Write-DatKV "Users can consent to apps" "$(if ($defaultConsent -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {'YES (all permissions)'} elseif ($defaultConsent.Count -gt 0) {'Limited'} else {'No'})"
            Write-DatKV "Users can create apps" "$canConsent" -last
            if ($defaultConsent -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
                Add-Finding "RED" "ConsentAll" "Users can consent to ANY app permissions - illicit consent grant attack possible"
                Add-AttackPath "Create malicious app $iRA phish user to consent $iRA token theft (Mail.Read, Files.ReadWrite etc.)"
            }

            # Check admin consent workflow
            $adminConsentReqs = Invoke-Graph "/identityGovernance/appConsent/appConsentRequests?`$select=appDisplayName,appId"
            if ($adminConsentReqs -eq $null) {
                Write-DatKV "Admin Consent Workflow" "Not configured or no access"
                if ($defaultConsent -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
                    Add-Finding "RED" "NoConsentWorkflow" "No admin consent workflow + users can consent to all permissions = uncontrolled app access"
                }
            } else {
                Write-DatKV "Admin Consent Workflow" "Active ($(@($adminConsentReqs).Count) pending requests)"
            }

            # Check if users can register applications
            if ($canConsent -eq $true) {
                Add-Finding "LOW" "AppCreation" "Any user can register applications in Entra ID"
            }
        }
    } catch { Write-Err "Cannot read authorization policy" }

    Write-Sub "Dangerous Redirect URIs"
    $apps = Invoke-Graph "/applications?`$select=displayName,web,spa,publicClient,id" -allPages $true
    if (-not $apps) { Write-Err "Cannot read applications"; Write-SectionFooter; return }

    $dangerousApps = @()
    foreach ($app in $apps) {
        $allUris = @()
        if ($app.web.redirectUris) { $allUris += $app.web.redirectUris }
        if ($app.spa.redirectUris) { $allUris += $app.spa.redirectUris }
        if ($app.publicClient.redirectUris) { $allUris += $app.publicClient.redirectUris }

        foreach ($uri in $allUris) {
            $isDangerous = $false
            $reason = ""
            if ($uri -match 'http://(?!localhost|127\.0\.0\.1)') { $isDangerous = $true; $reason = "HTTP non-localhost" }
            elseif ($uri -match '\*') { $isDangerous = $true; $reason = "wildcard" }
            elseif ($uri -match 'http://localhost' -and $app.web.redirectUris -contains $uri) { } # localhost OK for dev
            if ($isDangerous) {
                $dangerousApps += [PSCustomObject]@{App=$app.displayName; URI=$uri; Reason=$reason}
            }
        }
    }

    if ($dangerousApps.Count -gt 0) {
        $grouped = $dangerousApps | Group-Object App
        foreach ($g in $grouped) {
            $uris = ($g.Group | Select-Object -First 2 | ForEach-Object { "$($_.Reason): $($_.URI)" }) -join "; "
            Write-Dat "'$($g.Name)' - $uris"
            Add-Finding "LOW" "RedirectURI" "App '$($g.Name)' has dangerous redirect URI ($($g.Group[0].Reason))"
        }
    } else {
        Write-OK "No dangerous redirect URIs found"
    }

    Write-Sub "Owned Service Principals & App Registrations"
    $ownedObjects = Invoke-Graph "/me/ownedObjects?`$select=id,displayName,appId&`$top=999" -allPages $true
    $ownedSPs = @()
    $ownedApps = @()
    if ($ownedObjects) {
        $ownedSPs = @($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' })
        $ownedApps = @($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' })
    }
    if ($ownedSPs.Count -gt 0) {
        foreach ($sp in $ownedSPs) {
            Write-Dat "YOU own SP: $($sp.displayName)"
        }
        Add-Finding "PE" "SPOwner" "You own $($ownedSPs.Count) service principals - can add credentials"
    }
    if ($ownedApps.Count -gt 0) {
        foreach ($app in $ownedApps) {
            Write-Highlight "YOU own App: $($app.displayName) (AppId: $($app.appId))"
            # Check what permissions this app has
            $appPerms = Invoke-Graph "/applications/$($app.id)?`$select=requiredResourceAccess"
            if ($appPerms -and $appPerms.requiredResourceAccess) {
                foreach ($resource in $appPerms.requiredResourceAccess) {
                    foreach ($perm in $resource.resourceAccess) {
                        $permName = $script:dangerousPerms[$perm.id]
                        if ($permName -and $permName -match 'ReadWrite|Send|RoleManagement|AppRoleAssignment') {
                            Write-DatSub "$iWA Has permission: $permName"
                            Add-Finding "PE" "OwnedAppPE" "YOU own app '$($app.displayName)' with $permName - add secret and use!"
                            Add-AttackPath "You own '$($app.displayName)' $iRA add client secret $iRA authenticate as app $iRA $permName"
                        }
                    }
                }
            }
            # Check if app has any directory role assignments via its SP
            $appSP = Invoke-Graph "/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id,appRoleAssignments"
            if ($appSP -and $appSP.Count -gt 0) {
                $spRoles = Invoke-Graph "/servicePrincipals/$($appSP[0].id)/appRoleAssignments?`$select=resourceDisplayName,appRoleId,resourceId"
                if ($spRoles) {
                    foreach ($sr in $spRoles) {
                        $roleName = $sr.appRoleId
                        try {
                            $resSP = Invoke-Graph "/servicePrincipals/$($sr.resourceId)?`$select=appRoles"
                            if ($resSP -and $resSP.appRoles) {
                                $role = $resSP.appRoles | Where-Object { $_.id -eq $sr.appRoleId }
                                if ($role) { $roleName = $role.value }
                            }
                        } catch {}
                        Write-DatSub "Granted: $($sr.resourceDisplayName) -> $roleName"
                        if ($roleName -match 'ReadWrite\.All|FullControl|RoleManagement|Directory\.ReadWrite') {
                            Add-Finding "PE" "OwnedAppPE" "Owned app '$($app.displayName)' has granted $roleName - PE via secret addition!"
                        }
                    }
                }
            }
        }
        if ($ownedApps.Count -gt 0 -and -not ($script:findings | Where-Object { $_.Category -eq "OwnedAppPE" })) {
            Add-Finding "LOW" "OwnedApps" "You own $($ownedApps.Count) app registrations (no dangerous permissions found)"
        }
    }
    if ($ownedSPs.Count -eq 0 -and $ownedApps.Count -eq 0) {
        Write-OK "You don't own any service principals or app registrations"
    }

    Write-SectionFooter
}

function Test-AzureAutomation {
    Write-SectionHeader 33 "AZURE AUTOMATION & APP SERVICES"

    if (-not $script:mgmtToken) { Write-Err "No management token"; Write-SectionFooter; return }

    foreach ($sub in $script:subscriptions) {
        $subId = $sub.subscriptionId
        if (-not $subId) { continue }

        Write-Sub "Automation Accounts ($($sub.displayName))"
        $autoAccounts = Invoke-AzMgmt "/subscriptions/$subId/providers/Microsoft.Automation/automationAccounts?api-version=2022-08-08" -allPages
        if ($autoAccounts) {
            foreach ($aa in $autoAccounts) {
                Write-DatKV "Account" $aa.name
                # Check runbooks
                $runbooks = Invoke-AzMgmt "$($aa.id)/runbooks?api-version=2022-08-08" -allPages
                if ($runbooks) {
                    foreach ($rb in $runbooks) {
                        Write-DatSub "Runbook: $($rb.name) (type: $($rb.properties.runbookType))"
                    }
                    Add-Finding "LOW" "Automation" "Automation Account '$($aa.name)' has $($runbooks.Count) runbooks"
                }
                # Check Run As accounts (managed identity)
                if ($aa.identity) {
                    Add-Finding "LOW" "AutomationMI" "Automation '$($aa.name)' has managed identity"
                }
            }
        }

        Write-Sub "App Services ($($sub.displayName))"
        $webApps = Invoke-AzMgmt "/subscriptions/$subId/providers/Microsoft.Web/sites?api-version=2022-03-01" -allPages
        if ($webApps) {
            foreach ($wa in $webApps) {
                $authEnabled = $wa.properties.siteConfig.httpLoggingEnabled
                Write-DatKV $wa.name "$($wa.properties.defaultHostName) (state: $($wa.properties.state))"
                if ($wa.identity) {
                    Add-Finding "LOW" "AppSvcMI" "App Service '$($wa.name)' has managed identity"
                }
            }
        }

        Write-Sub "Azure SQL Databases ($($sub.displayName))"
        $sqlServers = Invoke-AzMgmt "/subscriptions/$subId/providers/Microsoft.Sql/servers?api-version=2021-11-01" -allPages
        if ($sqlServers) {
            foreach ($srv in $sqlServers) {
                Write-DatKV "SQL Server" "$($srv.name).database.windows.net"
                $fwRules = Invoke-AzMgmt "$($srv.id)/firewallRules?api-version=2021-11-01" -allPages
                if ($fwRules) {
                    foreach ($fw in $fwRules) {
                        if ($fw.properties.startIpAddress -eq '0.0.0.0' -and $fw.properties.endIpAddress -eq '255.255.255.255') {
                            Add-Finding "RED" "SQLOpenFW" "SQL Server '$($srv.name)' firewall open to 0.0.0.0-255.255.255.255"
                        } elseif ($fw.name -eq 'AllowAllWindowsAzureIps') {
                            Write-DatSub "FW: AllowAllAzureIPs"
                        }
                    }
                }
            }
        }

        Write-Sub "NSG Rules ($($sub.displayName))"
        $nsgs = Invoke-AzMgmt "/subscriptions/$subId/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01" -allPages
        if ($nsgs) {
            foreach ($nsg in $nsgs) {
                $dangerousRules = $nsg.properties.securityRules | Where-Object {
                    $_.properties.direction -eq 'Inbound' -and
                    $_.properties.access -eq 'Allow' -and
                    ($_.properties.sourceAddressPrefix -eq '*' -or $_.properties.sourceAddressPrefix -eq 'Internet') -and
                    $_.properties.destinationPortRange -match '^\*$|^3389$|^22$|^445$|^1433$|^3306$'
                }
                foreach ($rule in $dangerousRules) {
                    Write-Dat "NSG '$($nsg.name)': $($rule.name) allows $($rule.properties.destinationPortRange) from $($rule.properties.sourceAddressPrefix)"
                    Add-Finding "RED" "NSGOpen" "NSG '$($nsg.name)' allows inbound $($rule.properties.destinationPortRange) from Internet"
                }
            }
        }
    }

    Write-SectionFooter
}

function Test-InstalledSoftware {
    Write-SectionHeader 34 "INSTALLED SOFTWARE - KNOWN VULNERABILITIES"

    try {
        $software = @()
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($rp in $regPaths) {
            $software += Get-ItemProperty $rp -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }
        }
        $software = $software | Sort-Object DisplayName -Unique

        # Known vulnerable patterns
        $vulnPatterns = @(
            @{ Pattern='PuTTY'; MaxVer='0.80'; CVE='CVE-2024-31497'; Desc='ECDSA nonce leak' },
            @{ Pattern='7-Zip'; MaxVer='23.99'; CVE='CVE-2024-11477'; Desc='Zstandard RCE' },
            @{ Pattern='WinRAR'; MaxVer='6.23'; CVE='CVE-2023-38831'; Desc='RCE via crafted archive' },
            @{ Pattern='FileZilla'; MaxVer='3.66.1'; CVE='CVE-2023-48795'; Desc='SSH Terrapin' },
            @{ Pattern='Adobe Acrobat'; MaxVer='24.002'; CVE='Multiple CVEs'; Desc='RCE via PDF' },
            @{ Pattern='VLC media player'; MaxVer='3.0.18'; CVE='CVE-2023-47360'; Desc='Buffer overflow' },
            @{ Pattern='Notepad\+\+'; MaxVer='8.5.7'; CVE='CVE-2023-40031'; Desc='Heap overflow' },
            @{ Pattern='KeePass'; MaxVer='2.54'; CVE='CVE-2023-32784'; Desc='Master password recovery' }
        )

        $found = @()
        foreach ($sw in $software) {
            foreach ($v in $vulnPatterns) {
                if ($sw.DisplayName -match $v.Pattern) {
                    $ver = $sw.DisplayVersion
                    if ($ver) {
                        $isVuln = $false
                        try {
                            # Normalize versions: strip non-numeric suffixes, pad segments
                            $verClean = ($ver -replace '[^0-9.]','').TrimEnd('.')
                            $maxClean = ($v.MaxVer -replace '[^0-9.]','').TrimEnd('.')
                            if ($verClean -and $maxClean) {
                                $verObj = [version]$verClean
                                $maxObj = [version]$maxClean
                                $isVuln = $verObj -lt $maxObj
                            }
                        } catch {
                            # Fallback: pad with zeros and compare segment by segment
                            try {
                                $vParts = $verClean.Split('.') | ForEach-Object { [int]$_ }
                                $mParts = $maxClean.Split('.') | ForEach-Object { [int]$_ }
                                $maxLen = [math]::Max($vParts.Count, $mParts.Count)
                                while ($vParts.Count -lt $maxLen) { $vParts += 0 }
                                while ($mParts.Count -lt $maxLen) { $mParts += 0 }
                                for ($seg = 0; $seg -lt $maxLen; $seg++) {
                                    if ($vParts[$seg] -lt $mParts[$seg]) { $isVuln = $true; break }
                                    if ($vParts[$seg] -gt $mParts[$seg]) { break }
                                }
                            } catch {}
                        }
                        if ($isVuln) {
                            $found += [PSCustomObject]@{Name=$sw.DisplayName; Version=$ver; CVE=$v.CVE; Desc=$v.Desc}
                            Write-DatKV "$($sw.DisplayName) $ver" "$($v.CVE) - $($v.Desc)"
                        }
                    }
                }
            }
        }

        if ($found.Count -gt 0) {
            Add-Finding "RED" "VulnSoftware" "$($found.Count) installed apps with known CVEs"
        } else {
            Write-OK "No known vulnerable software versions detected"
        }

        Write-Inf "Total installed software: $($software.Count)"
    } catch { Write-Err "Cannot enumerate installed software" }

    Write-SectionFooter
}

function Test-CrossTenantB2B {
    Write-SectionHeader 35 "CROSS-TENANT & B2B COLLABORATION"

    Write-Sub "Cross-Tenant Access Policies"
    try {
        $ctPolicy = Invoke-Graph "/policies/crossTenantAccessPolicy"
        if ($ctPolicy) {
            $partners = Invoke-Graph "/policies/crossTenantAccessPolicy/partners"
            if ($partners -and $partners.Count -gt 0) {
                foreach ($p in $partners) {
                    $tenantId = $p.tenantId
                    $inboundTrust = if ($p.inboundTrust) { "MFA trust: $($p.inboundTrust.isMfaAccepted)" } else { "default" }
                    Write-DatKV "Partner Tenant" "$tenantId ($inboundTrust)"
                }
                Add-Finding "INFO" "CrossTenant" "$($partners.Count) cross-tenant access partner policies"
            } else {
                Write-OK "No cross-tenant partner policies"
            }
        }
    } catch { Write-Err "Cannot read cross-tenant access policies" }

    Write-Sub "B2B Collaboration Settings"
    try {
        $extCollab = Invoke-Graph "/policies/authorizationPolicy"
        if ($extCollab) {
            $guestInvite = $extCollab.allowInvitesFrom
            Write-DatKV "Guest Invite Setting" "$guestInvite"
            if ($guestInvite -eq 'everyone') {
                Add-Finding "RED" "GuestInvite" "Anyone (including guests) can invite external users"
            } elseif ($guestInvite -eq 'adminsAndGuestInviters' -or $guestInvite -eq 'adminsGuestInvitersAndAllMembers') {
                Write-DatKV "Guest Invite" "Members can invite" -last
            }

            $guestRestrictions = $extCollab.guestUserRoleId
            $roleName = switch ($guestRestrictions) {
                "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Same as members (DANGEROUS)" }
                "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Limited (default)" }
                "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Restricted" }
                default { $guestRestrictions }
            }
            Write-DatKV "Guest Permissions" "$roleName" -last
            if ($guestRestrictions -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
                Add-Finding "RED" "GuestPerms" "Guest users have SAME permissions as members"
            }
        }
    } catch { Write-Err "Cannot read B2B settings" }

    Write-SectionFooter
}

# ============================================================================
#  LAYER 6: ADVANCED ENTRA ANALYSIS (Sections 36-38)
# ============================================================================

function Test-DynamicGroups {
    Write-SectionHeader 36 "DYNAMIC GROUPS - MEMBERSHIP RULE ABUSE"

    $groups = Invoke-Graph "/groups?`$filter=groupTypes/any(g:g eq 'DynamicMembership')&`$select=id,displayName,membershipRule,membershipRuleProcessingState,securityEnabled&`$top=999" -allPages $true
    if (-not $groups) {
        Write-Err "Cannot enumerate dynamic groups (insufficient permissions or none exist)"
        Write-SectionFooter; return
    }

    Write-Inf "Dynamic groups found: $($groups.Count)"

    # User-controllable attributes that could be modified to join a group
    $controllableAttrs = @(
        'user\.department', 'user\.jobTitle', 'user\.companyName',
        'user\.city', 'user\.state', 'user\.country', 'user\.usageLocation',
        'user\.officeLocation', 'user\.postalCode', 'user\.streetAddress',
        'user\.preferredLanguage', 'user\.employeeId', 'user\.employeeType',
        'user\.facsimileTelephoneNumber', 'user\.telephoneNumber',
        'user\.mobile', 'user\.otherMails', 'user\.proxyAddresses',
        'user\.extensionAttribute'
    )

    $abusable = @()
    foreach ($g in $groups) {
        $rule = $g.membershipRule
        if (-not $rule) { continue }

        Write-Host ""
        Write-Highlight "$($g.displayName)"
        Write-DatKV "Security Group" "$($g.securityEnabled)"
        Write-DatKV "Processing" "$($g.membershipRuleProcessingState)"
        Write-DatKV "Rule" "$rule"

        # Check if rule uses controllable attributes
        $isAbusable = $false
        $matchedAttr = ""
        foreach ($attr in $controllableAttrs) {
            if ($rule -match $attr) {
                $isAbusable = $true
                $matchedAttr = ($attr -replace '\\', '')
                break
            }
        }

        if ($isAbusable -and $g.securityEnabled) {
            $abusable += $g
            Add-Finding "RED" "DynGroup" "Dynamic security group '$($g.displayName)' uses controllable attribute ($matchedAttr)"
        }

        # Check if group has role assignments
        $roleAssignments = Invoke-Graph "/groups/$($g.id)/transitiveRoleAssignments?`$select=roleDefinitionId" 2>$null
        if (-not $roleAssignments) {
            # Alternative: check appRoleAssignments
            $appRoles = Invoke-Graph "/groups/$($g.id)/appRoleAssignments?`$select=resourceDisplayName,appRoleId"
            if ($appRoles -and $appRoles.Count -gt 0) {
                Write-DatSub "$($appRoles.Count) app role assignments"
                if ($isAbusable) {
                    Add-Finding "RED" "DynGroupRoles" "Abusable dynamic group '$($g.displayName)' has $($appRoles.Count) app role assignments"
                }
            }
        }
    }

    if ($abusable.Count -gt 0) {
        Write-Host ""
        Write-Inf "$($abusable.Count) dynamic security groups with user-controllable membership rules"
    } elseif ($groups.Count -gt 0) {
        Write-OK "No dynamic groups with easily abusable membership rules"
    }

    Write-Sub "Role-Assignable Groups"
    $roleGroups = Invoke-Graph "/groups?`$filter=isAssignableToRole eq true&`$select=id,displayName,description,membershipRule,groupTypes,securityEnabled&`$top=999" -allPages $true
    if ($roleGroups -and $roleGroups.Count -gt 0) {
        Write-Inf "Role-assignable groups: $($roleGroups.Count)"
        $meId = (Invoke-Graph "/me?`$select=id").id
        foreach ($rg in $roleGroups) {
            Write-Highlight "$($rg.displayName)"
            if ($rg.description) { Write-DatKV "Description" "$($rg.description)" }
            $isDynamic = $rg.groupTypes -contains "DynamicMembership"
            if ($isDynamic) { Write-DatKV "Type" "Dynamic (rule: $($rg.membershipRule))" }

            # Check role assignments for this group
            $groupRoles = Invoke-Graph "/groups/$($rg.id)/memberOf/microsoft.graph.directoryRole?`$select=displayName"
            if ($groupRoles -and $groupRoles.Count -gt 0) {
                foreach ($gr in $groupRoles) {
                    Write-DatKV "Has Role" "$($gr.displayName)"
                }
            }

            # Check if current user is owner
            $owners = Invoke-Graph "/groups/$($rg.id)/owners?`$select=id,displayName"
            if ($owners) {
                foreach ($o in $owners) {
                    Write-DatSub "Owner: $($o.displayName)"
                    if ($o.id -eq $meId) {
                        Add-Finding "PE" "RoleGroupOwner" "YOU are owner of role-assignable group '$($rg.displayName)' - add yourself for role PE!"
                        Add-AttackPath "Owner of '$($rg.displayName)' $iRA add yourself as member $iRA inherit directory roles"
                    }
                }
            }

            # Check if current user is member
            $isMember = Invoke-Graph "/groups/$($rg.id)/members?`$filter=id eq '$meId'&`$select=id"
            if ($isMember -and $isMember.Count -gt 0 -and $groupRoles -and $groupRoles.Count -gt 0) {
                $roleNames = ($groupRoles | ForEach-Object { $_.displayName }) -join ", "
                Add-Finding "PE" "RoleGroupMember" "YOU are member of role-assignable group '$($rg.displayName)' with roles: $roleNames"
            }

            # Dynamic role-assignable group with controllable membership = critical
            if ($isDynamic -and $rg.membershipRule) {
                foreach ($attr in $controllableAttrs) {
                    if ($rg.membershipRule -match $attr) {
                        Add-Finding "PE" "DynRoleGroup" "Role-assignable group '$($rg.displayName)' uses controllable attribute ($($attr -replace '\\','')) in dynamic rule!"
                        Add-AttackPath "Modify your $($attr -replace '\\','') $iRA auto-join '$($rg.displayName)' $iRA inherit directory roles"
                        break
                    }
                }
            }
        }
    } else {
        Write-Inf "No role-assignable groups found or insufficient permissions"
    }

    Write-SectionFooter
}

function Test-AdministrativeUnits {
    Write-SectionHeader 37 "ADMINISTRATIVE UNITS - SCOPED ADMIN ROLES"

    $aus = Invoke-Graph "/directory/administrativeUnits?`$select=id,displayName,description,membershipType,membershipRule,visibility,isMemberManagementRestricted&`$top=999" -allPages $true
    if (-not $aus) {
        Write-Err "Cannot read Administrative Units (insufficient permissions or none exist)"
        Write-SectionFooter; return
    }

    Write-Inf "Administrative Units found: $($aus.Count)"

    foreach ($au in $aus) {
        Write-Host ""
        Write-Highlight "$($au.displayName)"
        Write-DatKV "Type" "$(if ($au.membershipType) {$au.membershipType} else {'Assigned'})"
        Write-DatKV "Restricted Mgmt" "$(if ($au.isMemberManagementRestricted) {'YES'} else {'No'})"
        if ($au.membershipRule) {
            Write-DatKV "Dynamic Rule" "$($au.membershipRule)"
        }
        if ($au.description) { Write-DatKV "Description" "$($au.description)" }

        # Check scoped role assignments for this AU
        $scopedRoles = Invoke-Graph "/directory/administrativeUnits/$($au.id)/scopedRoleMembers"
        if ($scopedRoles -and $scopedRoles.Count -gt 0) {
            foreach ($sr in $scopedRoles) {
                $roleName = $sr.roleId
                # Resolve role
                $roleDef = Invoke-Graph "/directoryRoles?`$filter=roleTemplateId eq '$roleName'&`$select=displayName"
                $roleDisp = if ($roleDef -and $roleDef.Count -gt 0) { $roleDef[0].displayName } else { $roleName }
                $member = Invoke-Graph "/directoryObjects/$($sr.roleMemberInfo.id)?`$select=displayName,userPrincipalName"
                $memberName = if ($member) { "$($member.displayName) ($($member.userPrincipalName))" } else { $sr.roleMemberInfo.id }
                Write-DatKV "Scoped Role" "$memberName $iRA $roleDisp"
            }
            Add-Finding "INFO" "AU-Roles" "AU '$($au.displayName)' has $($scopedRoles.Count) scoped role assignments"
        }

        # Restricted management = protects members from tenant-level admins
        if ($au.isMemberManagementRestricted) {
            Add-Finding "INFO" "AU-Restricted" "AU '$($au.displayName)' has restricted management - members protected from some tenant admins"
        }
    }

    # Check if current user is in any AU
    $myAUs = Invoke-Graph "/me/memberOf/microsoft.graph.administrativeUnit?`$select=displayName,id"
    if ($myAUs -and $myAUs.Count -gt 0) {
        Write-Sub "Your AU Memberships"
        foreach ($myAU in $myAUs) {
            Write-Dat "Member of AU: $($myAU.displayName)"
        }
    }

    Write-SectionFooter
}

function Test-EntraConnect {
    Write-SectionHeader 38 "ENTRA CONNECT / AD SYNC ANALYSIS"

    Write-Sub "Hybrid Sync Configuration"
    $org = Invoke-Graph "/organization?`$select=displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime"
    if ($org) {
        $orgData = if ($org -is [array]) { $org[0] } else { $org }
        $syncEnabled = $orgData.onPremisesSyncEnabled
        $lastSync = $orgData.onPremisesLastSyncDateTime

        Write-DatKV "On-Prem Sync Enabled" "$(if ($syncEnabled) {'YES'} else {'No'})"
        if ($lastSync) {
            Write-DatKV "Last Sync" "$lastSync"
            $syncAge = ((Get-Date) - [datetime]$lastSync).TotalHours
            if ($syncAge -gt 24) {
                Add-Finding "LOW" "SyncStale" "Entra Connect last sync was $([math]::Round($syncAge)) hours ago"
            }
        }
    }

    if (-not $org -or -not ($org | ForEach-Object { $_.onPremisesSyncEnabled } | Where-Object { $_ -eq $true })) {
        Write-Inf "No on-premises sync detected - cloud-only tenant"
        Write-SectionFooter; return
    }

    # Find sync service accounts (DirSync / AAD Connect accounts)
    Write-Sub "Sync Service Accounts"
    $syncAccounts = Invoke-Graph "/users?`$filter=startswith(displayName,'On-Premises Directory Synchronization') or startswith(displayName,'Sync_') or startswith(userPrincipalName,'Sync_')&`$select=displayName,userPrincipalName,id,accountEnabled,onPremisesImmutableId&`$top=100"
    if (-not $syncAccounts -or $syncAccounts.Count -eq 0) {
        # Try broader search
        $syncAccounts = Invoke-Graph "/users?`$filter=startswith(displayName,'Sync_')&`$select=displayName,userPrincipalName,id,accountEnabled&`$top=100"
    }

    if ($syncAccounts -and $syncAccounts.Count -gt 0) {
        foreach ($sa in $syncAccounts) {
            Write-DatKV "Sync Account" "$($sa.displayName)"
            Write-DatKV "UPN" "$($sa.userPrincipalName)"
            Write-DatKV "Enabled" "$($sa.accountEnabled)"

            # Check roles of sync account
            $roles = Invoke-Graph "/users/$($sa.id)/memberOf?`$select=displayName"
            $roleNames = @($roles | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { $_.displayName })
            if ($roleNames.Count -gt 0) {
                Write-DatKV "Roles" "$($roleNames -join ', ')"
                if ($roleNames -match "Global Administrator|Directory Synchronization Accounts") {
                    Add-Finding "RED" "SyncAccount" "Sync account '$($sa.displayName)' has high-privilege role: $($roleNames -join ', ')"
                }
            }
        }
    } else {
        Write-Inf "No obvious sync service accounts found"
    }

    # Check on-prem synced users vs cloud-only
    Write-Sub "Sync Statistics"
    $syncedCount = 0
    $cloudCount = 0
    $allUsers = Invoke-Graph "/users?`$select=onPremisesSyncEnabled,userType&`$top=999" -allPages $true
    if ($allUsers) {
        $syncedCount = @($allUsers | Where-Object { $_.onPremisesSyncEnabled -eq $true }).Count
        $cloudCount = @($allUsers | Where-Object { $_.onPremisesSyncEnabled -ne $true -and $_.userType -eq 'Member' }).Count
        Write-DatKV "Synced from on-prem" "$syncedCount users"
        Write-DatKV "Cloud-only members" "$cloudCount users"
    }

    # Check for password writeback indicators
    Write-Sub "Password Writeback & Seamless SSO"
    # Password writeback - check via authentication methods policy
    $authMethods = Invoke-Graph "/policies/authenticationMethodsPolicy"
    if ($authMethods) {
        $sspr = Invoke-Graph "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/password"
        Write-DatKV "Auth Methods Policy" "Present"
    }

    # Check for Seamless SSO via service principals
    $seamlessSSOSP = Invoke-Graph "/servicePrincipals?`$filter=displayName eq 'Azure Active Directory Connect'&`$select=displayName,appId"
    if ($seamlessSSOSP -and $seamlessSSOSP.Count -gt 0) {
        Write-DatKV "AAD Connect SP" "Present"
        Add-Finding "INFO" "AADConnect" "Azure AD Connect service principal found - on-prem to cloud sync active"
    }

    # AZUREADSSOACC computer account = Seamless SSO
    # Can't check directly via Graph, but note it
    Write-Inf "Check on-prem AD for AZUREADSSOACC$ computer account (Seamless SSO decryption key)"
    Write-Inf "If compromised: silver ticket for any synced user"

    Write-SectionFooter
}

# ============================================================================
#  LAYER 7: MODERN PE VECTORS (Sections 39-40)
# ============================================================================

function Test-ADCS {
    Write-SectionHeader 39 "AD CERTIFICATE SERVICES (ADCS) - ESC VECTORS"

    $domain = $env:USERDNSDOMAIN
    $noEnrollSvcs = $false
    if (-not $domain) { Write-Err "Not domain-joined or USERDNSDOMAIN not set"; Write-SectionFooter; return }

    try {
        $configNC = ([adsi]"LDAP://RootDSE").configurationNamingContext
        if (-not $configNC) { Write-Err "Cannot read configurationNamingContext"; Write-SectionFooter; return }
    } catch { Write-Err "Cannot connect to LDAP"; Write-SectionFooter; return }

    Write-Sub "Enrollment Services (Certificate Authorities)"
    try {
        $enrollPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $enrollSearcher = [adsisearcher]""
        $enrollSearcher.SearchRoot = [adsi]$enrollPath
        $enrollSearcher.Filter = "(objectClass=pKIEnrollmentService)"
        $enrollSearcher.PropertiesToLoad.AddRange(@("cn","dnshostname","certificatetemplates"))
        $enrollSvcs = $enrollSearcher.FindAll()

        if (-not $enrollSvcs -or $enrollSvcs.Count -eq 0) {
            Write-OK "No ADCS enrollment services found"
            # Skip template analysis but still check ESC6/ESC7 (local CA checks)
            $noEnrollSvcs = $true
        }

        if (-not $noEnrollSvcs) {
            $allPublished = @()
            foreach ($es in $enrollSvcs) {
                $caName = "$($es.Properties['cn'][0])"
                $caHost = "$($es.Properties['dnshostname'][0])"
                $templates = @($es.Properties['certificatetemplates'])
                $allPublished += $templates
                Write-DatKV "CA Server" "$caName ($caHost)"
                Write-DatKV "Published Templates" "$($templates.Count)"

                # ESC8: Check for HTTP enrollment (no HTTPS = NTLM relay to CA)
                try {
                    $httpUrl = "http://$caHost/certsrv/"
                    $req = [System.Net.WebRequest]::Create($httpUrl)
                    $req.Timeout = 3000
                    $req.Method = "HEAD"
                    $resp = $req.GetResponse()
                    $resp.Close()
                    Add-Finding "PE" "ESC8" "CA '$caName' has HTTP enrollment at $httpUrl - NTLM relay to CA for cert!"
                } catch {
                    if ($_.Exception.InnerException.Response) {
                        # Got HTTP response (even 401/403 = endpoint exists)
                        Add-Finding "RED" "ESC8" "CA '$caName' HTTP endpoint responds at http://$caHost/certsrv/ - potential relay target"
                    }
                }
            }
            Add-Finding "INFO" "ADCS" "$($enrollSvcs.Count) Certificate Authority(ies) found"
        }
    } catch {
        Write-Err "Cannot enumerate enrollment services: $($_.Exception.Message)"
    }

    if (-not $noEnrollSvcs) {
    Write-Sub "Certificate Template Analysis (ESC1/ESC2/ESC3/ESC4)"
    try {
        $tmplPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $tmplSearcher = [adsisearcher]""
        $tmplSearcher.SearchRoot = [adsi]$tmplPath
        $tmplSearcher.Filter = "(objectClass=pKICertificateTemplate)"
        $tmplSearcher.PropertiesToLoad.AddRange(@(
            "cn","displayname","mspki-certificate-name-flag","mspki-enrollment-flag",
            "pkiextendedkeyusage","mspki-ra-signature","ntsecuritydescriptor",
            "mspki-certificate-application-policy"
        ))
        $tmplSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $templates = $tmplSearcher.FindAll()

        Write-Inf "Total certificate templates: $($templates.Count)"

        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
        # Well-known low-priv SIDs
        $lowPrivSIDs = $mySIDs + @(
            "S-1-1-0",       # Everyone
            "S-1-5-11",      # Authenticated Users
            "S-1-5-32-545"   # BUILTIN\Users
        )

        $escFindings = @()

        foreach ($tmpl in $templates) {
            $tmplName = "$($tmpl.Properties['cn'][0])"
            $displayName = "$($tmpl.Properties['displayname'][0])"
            $nameFlag = [int64]"$($tmpl.Properties['mspki-certificate-name-flag'][0])"
            $enrollFlag = [int64]"$($tmpl.Properties['mspki-enrollment-flag'][0])"
            $ekus = @($tmpl.Properties['pkiextendedkeyusage'])
            $raSignature = [int]"$($tmpl.Properties['mspki-ra-signature'][0])"

            # Parse security descriptor for enrollment rights
            $canEnroll = $false
            $canWrite = $false
            try {
                $entry = $tmpl.GetDirectoryEntry()
                $sd = $entry.ObjectSecurity
                foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    $sid = $ace.IdentityReference.Value
                    if ($lowPrivSIDs -contains $sid -and $ace.AccessControlType -eq 'Allow') {
                        $rights = "$($ace.ActiveDirectoryRights)"
                        # Enroll = ExtendedRight with specific GUID or GenericAll
                        if ($rights -match 'ExtendedRight|GenericAll|WriteDacl|WriteOwner') {
                            $canEnroll = $true
                        }
                        if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                            $canWrite = $true
                        }
                    }
                }
            } catch {}

            # ESC1: ENROLLEE_SUPPLIES_SUBJECT (0x1) + Client Auth EKU + low-priv can enroll + no manager approval
            $hasSAN = ($nameFlag -band 1) -eq 1
            $clientAuthEKUs = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0")
            $hasClientAuth = ($ekus | Where-Object { $clientAuthEKUs -contains $_ }).Count -gt 0
            $noEKU = ($ekus.Count -eq 0)
            $anyPurpose = ($ekus -contains "2.5.29.37.0")

            if ($hasSAN -and ($hasClientAuth -or $noEKU -or $anyPurpose) -and $canEnroll -and $raSignature -le 0) {
                $escFindings += [PSCustomObject]@{ESC="ESC1"; Template=$displayName; Detail="SAN + Client Auth + enrollable by low-priv"}
                Write-Host ""
                Write-Highlight "ESC1 VULNERABLE: $displayName"
                Write-DatKV "Name Flag" "ENROLLEE_SUPPLIES_SUBJECT (can specify any SAN)"
                Write-DatKV "EKU" "$(if ($hasClientAuth){'Client Auth'}elseif($noEKU){'No EKU (any purpose)'}else{'Any Purpose'})"
                Write-DatKV "Manager Approval" "Not required"
                Write-DatKV "Low-priv Enrollable" "YES"
                Add-Finding "PE" "ESC1" "Template '$displayName' - request cert as ANY user (Domain Admin!)"
            }

            # ESC2: No EKU or Any Purpose + enrollable
            if (($noEKU -or $anyPurpose) -and $canEnroll -and $raSignature -le 0 -and -not $hasSAN) {
                $escFindings += [PSCustomObject]@{ESC="ESC2"; Template=$displayName; Detail="Any Purpose/No EKU"}
                Write-Highlight "ESC2 VULNERABLE: $displayName"
                Write-DatKV "EKU" "$(if ($noEKU){'No EKU'}else{'Any Purpose'}) - usable for client auth"
                Add-Finding "RED" "ESC2" "Template '$displayName' - Any Purpose/No EKU, enrollable by low-priv"
            }

            # ESC3: Enrollment Agent template (can enroll on behalf of others)
            $enrollAgentOID = "1.3.6.1.4.1.311.20.2.1"  # Certificate Request Agent
            $isEnrollAgent = ($ekus -contains $enrollAgentOID)
            if ($isEnrollAgent -and $canEnroll -and $raSignature -le 0) {
                $escFindings += [PSCustomObject]@{ESC="ESC3"; Template=$displayName; Detail="Enrollment Agent + enrollable by low-priv"}
                Write-Highlight "ESC3 VULNERABLE: $displayName"
                Write-DatKV "EKU" "Certificate Request Agent (enroll on behalf of others)"
                Write-DatKV "Low-priv Enrollable" "YES"
                Add-Finding "PE" "ESC3" "Template '$displayName' - Enrollment Agent certificate, request certs as ANY user"
                Add-AttackPath "Enroll '$displayName' as agent $iRA use agent cert to enroll as DA on another template"
            }

            # ESC4: Low-priv can modify template
            if ($canWrite) {
                $escFindings += [PSCustomObject]@{ESC="ESC4"; Template=$displayName; Detail="Writable by low-priv"}
                Write-Highlight "ESC4 VULNERABLE: $displayName"
                Write-DatKV "Writable" "YES - low-priv user can modify template"
                Add-Finding "PE" "ESC4" "Template '$displayName' writable - modify to enable SAN + enroll as DA"
            }
        }

        if ($escFindings.Count -eq 0) {
            Write-OK "No ESC1/ESC2/ESC3/ESC4 vulnerable templates found"
        } else {
            Write-Host ""
            Write-Inf "$($escFindings.Count) vulnerable certificate templates found"
        }
    } catch {
        Write-Err "Cannot enumerate templates: $($_.Exception.Message)"
    }
    } # end if (-not $noEnrollSvcs) — template analysis requires CAs

    # ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag (allows SAN override on ANY template)
    Write-Sub "ESC6: CA SAN Override Flag"
    try {
        $caRegPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
        )
        $esc6Found = $false
        foreach ($caRegBase in $caRegPaths) {
            if (Test-Path $caRegBase -ErrorAction SilentlyContinue) {
                $caNames = Get-ChildItem $caRegBase -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
                foreach ($caName in $caNames) {
                    $policyPath = "$caRegBase\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
                    if (Test-Path $policyPath -ErrorAction SilentlyContinue) {
                        $editFlags = (Get-ItemProperty $policyPath -Name 'EditFlags' -ErrorAction SilentlyContinue).EditFlags
                        if ($editFlags) {
                            # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 = 262144
                            $sanOverride = ($editFlags -band 0x00040000) -ne 0
                            Write-DatKV "CA" $caName
                            Write-DatKV "EditFlags" "0x$($editFlags.ToString('X8'))"
                            Write-DatKV "ATTRIBUTESUBJECTALTNAME2" "$(if ($sanOverride) {'ENABLED (VULNERABLE!)'} else {'Disabled (secure)'})"
                            if ($sanOverride) {
                                $esc6Found = $true
                                Add-Finding "PE" "ESC6" "CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 - specify SAN on ANY template for impersonation!"
                                Add-AttackPath "certreq -attrib 'SAN:upn=admin@domain' $iRA enroll any template with SAN override $iRA DA cert"
                            }
                        }
                    }
                }
            }
        }
        if (-not $esc6Found) {
            # Try certutil if local registry not available (remote CA)
            $certutilOut = certutil -getreg policy\EditFlags 2>&1 | Out-String
            if ($certutilOut -match 'EDITF_ATTRIBUTESUBJECTALTNAME2\s*--\s*40000') {
                Add-Finding "PE" "ESC6" "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled - SAN override on any template!"
                Add-AttackPath "certreq -attrib 'SAN:upn=admin@domain' $iRA enroll any template $iRA DA cert"
            } elseif ($certutilOut -match 'EditFlags\s*REG_DWORD') {
                Write-OK "CA EditFlags do not include ATTRIBUTESUBJECTALTNAME2"
            } else {
                Write-DatSub "Cannot determine CA EditFlags (not local CA or access denied)"
            }
        }
    } catch { Write-Err "Cannot check ESC6: $($_.Exception.Message)" }

    # ESC7: ManageCA permission for low-priv user (can then enable ESC6 flag)
    Write-Sub "ESC7: CA Manager Permissions"
    try {
        $esc7Found = $false
        $certutilCA = certutil -ca 2>&1 | Out-String
        if ($certutilCA -and $certutilCA -notmatch 'error|denied|failed') {
            # Parse CA permissions from certutil output
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $myName = $me.Name
            $myGroups = @($me.Groups | ForEach-Object {
                try { $_.Translate([System.Security.Principal.NTAccount]).Value } catch { $_.Value }
            })
            $allIdentities = @($myName) + $myGroups

            # Check CA ACL via certutil -ca.cert or DCOM
            $caSecOut = certutil -ca.cert -config - 2>&1 | Out-String
            # Alternative: check via registry-based CA security descriptor
            $caRegBase = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
            if (Test-Path $caRegBase -ErrorAction SilentlyContinue) {
                $caNames = Get-ChildItem $caRegBase -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
                foreach ($caName in $caNames) {
                    $secPath = "$caRegBase\$caName"
                    $secData = (Get-ItemProperty $secPath -Name 'Security' -ErrorAction SilentlyContinue).Security
                    if ($secData) {
                        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($secData, 0)
                        foreach ($ace in $sd.DiscretionaryAcl) {
                            if ($ace.AceType -eq 'AccessAllowed') {
                                try {
                                    $aceSID = $ace.SecurityIdentifier
                                    $aceName = $aceSID.Translate([System.Security.Principal.NTAccount]).Value
                                    # ManageCA = 0x01 (CA admin), ManageCertificates = 0x02
                                    $hasManageCA = ($ace.AccessMask -band 1) -ne 0
                                    $hasManageCerts = ($ace.AccessMask -band 2) -ne 0
                                    if ($hasManageCA -and ($allIdentities -contains $aceName)) {
                                        $esc7Found = $true
                                        Write-Highlight "ESC7 VULNERABLE: $aceName has ManageCA on '$caName'"
                                        Add-Finding "PE" "ESC7" "$aceName has ManageCA on '$caName' - can enable ESC6 flag and issue certs as anyone!"
                                        Add-AttackPath "ManageCA $iRA certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 $iRA ESC6 $iRA DA"
                                    }
                                    if ($hasManageCerts -and ($allIdentities -contains $aceName)) {
                                        $esc7Found = $true
                                        Write-Highlight "ESC7 VULNERABLE: $aceName has ManageCertificates on '$caName'"
                                        Add-Finding "PE" "ESC7" "$aceName has ManageCertificates on '$caName' - can approve pending cert requests!"
                                    }
                                } catch {}
                            }
                        }
                    }
                }
            }
        }
        if (-not $esc7Found) {
            Write-OK "No ManageCA/ManageCertificates permissions for current user on local CA"
        }
    } catch { Write-Err "Cannot check ESC7: $($_.Exception.Message)" }

    Write-SectionFooter
}

function Test-ModernPEVectors {
    Write-SectionHeader 40 "MODERN PE VECTORS (COERCION, gMSA, DELEGATION, WSUS)"

    $domain = $env:USERDNSDOMAIN

    Write-Sub "Coercion Endpoints (PetitPotam, PrinterBug, DFSCoerce)"
    try {
        $pipes = @()
        try { $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") } catch {}
        $pipeNames = $pipes | ForEach-Object { [System.IO.Path]::GetFileName($_) }

        $coercionPipes = @(
            @{Pipe="spoolss";  Attack="PrinterBug (SpoolSample)"; Svc="Print Spooler"; Impact="Force machine auth to attacker"},
            @{Pipe="efsrpc";   Attack="PetitPotam (EFS)";         Svc="EFS";           Impact="Force machine auth without creds"},
            @{Pipe="netdfs";   Attack="DFSCoerce";                Svc="DFS";           Impact="Force machine auth via DFS"},
            @{Pipe="lsarpc";   Attack="PetitPotam (LSARPC)";      Svc="LSA";           Impact="Alternative PetitPotam vector"}
        )

        $foundCoercion = @()
        foreach ($c in $coercionPipes) {
            $exists = $pipeNames -contains $c.Pipe
            $status = if ($exists) { "AVAILABLE" } else { "Not found" }
            Write-DatKV "$($c.Attack)" "$status"
            if ($exists) { $foundCoercion += $c }
        }

        if ($foundCoercion.Count -gt 0) {
            $attacks = ($foundCoercion | ForEach-Object { $_.Attack }) -join ", "
            Add-Finding "RED" "Coercion" "$($foundCoercion.Count) coercion endpoints available: $attacks"
            if ($foundCoercion.Pipe -contains "efsrpc") {
                Add-Finding "RED" "PetitPotam" "PetitPotam (EFS) pipe available - force DC auth without credentials + relay"
            }
        } else {
            Write-OK "No coercion endpoints available"
        }
    } catch { Write-Err "Cannot enumerate named pipes" }

    Write-Sub "Named Pipe Permissions (Impersonation Targets)"
    try {
        $pipes = @()
        try { $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") } catch {}
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
        # Well-known low-priv SIDs
        $lowPrivSIDs = $mySIDs + @("S-1-1-0","S-1-5-11","S-1-5-32-545")

        # Known interesting pipes where SYSTEM/service connects as client
        $interestingPipes = @(
            @{Pattern="chromium\.";      Owner="Browser";   Risk="Token from browser process"},
            @{Pattern="mojo\.";          Owner="Browser";   Risk="Inter-process communication token"},
            @{Pattern="TSVCPIPE";        Owner="RDP";       Risk="RDP session pipe - potential SYSTEM token"},
            @{Pattern="SQLLocal\\";      Owner="SQL";       Risk="SQL Server local pipe"},
            @{Pattern="MSSQL\$";         Owner="SQL";       Risk="SQL Server instance pipe"},
            @{Pattern="gecko\.";         Owner="Firefox";   Risk="Firefox IPC pipe"},
            @{Pattern="openssh-ssh-agent";Owner="SSH";      Risk="SSH agent pipe"},
            @{Pattern="docker_engine";   Owner="Docker";    Risk="Docker engine pipe - container escape"}
        )

        $writablePipes = @()
        foreach ($pipePath in $pipes) {
            try {
                $pipeName = [System.IO.Path]::GetFileName($pipePath)
                $pipeHandle = $null

                # Check if it matches interesting patterns
                $isInteresting = $false
                $matchInfo = $null
                foreach ($ip in $interestingPipes) {
                    if ($pipeName -match $ip.Pattern) {
                        $isInteresting = $true
                        $matchInfo = $ip
                        break
                    }
                }

                if ($isInteresting) {
                    # Try to get pipe security descriptor
                    try {
                        $pipeACL = (Get-Acl "\\.\pipe\$pipeName" -ErrorAction Stop)
                        $writableACEs = $pipeACL.Access | Where-Object {
                            $_.FileSystemRights -match 'Write|FullControl|Modify|CreateFiles' -and
                            $_.AccessControlType -eq 'Allow' -and
                            ($lowPrivSIDs -contains $_.IdentityReference.Value -or
                             $_.IdentityReference.Value -match 'Everyone|Authenticated Users|BUILTIN\\Users')
                        }
                        if ($writableACEs) {
                            $writablePipes += [PSCustomObject]@{
                                Pipe=$pipeName
                                Owner=$matchInfo.Owner
                                Risk=$matchInfo.Risk
                                Identity=($writableACEs | Select-Object -First 1 -ExpandProperty IdentityReference).Value
                            }
                        }
                    } catch {}
                }
            } catch {}
        }

        if ($writablePipes.Count -gt 0) {
            foreach ($wp in $writablePipes | Select-Object -First 10) {
                Write-DatKV "$($wp.Pipe)" "WRITABLE by $($wp.Identity) [$($wp.Owner)]"
                Write-DatSub "$($wp.Risk)"
            }
            Add-Finding "RED" "WritablePipe" "$($writablePipes.Count) writable named pipes found - potential token impersonation"
        } else {
            Write-OK "No writable interesting named pipes found"
        }
    } catch { Write-Err "Cannot check named pipe permissions" }

    if ($domain) {
        Write-Sub "gMSA (Group Managed Service Accounts)"
        try {
            $gmsaSearcher = [adsisearcher]"(objectClass=msDS-GroupManagedServiceAccount)"
            $gmsaSearcher.PropertiesToLoad.AddRange(@("cn","samaccountname","serviceprincipalname","memberof","msds-managedpasswordid"))
            $gmsas = $gmsaSearcher.FindAll()

            if ($gmsas -and $gmsas.Count -gt 0) {
                $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })

                foreach ($g in $gmsas) {
                    $gName = "$($g.Properties['samaccountname'][0])"
                    $spns = @($g.Properties['serviceprincipalname'])
                    $groups = @($g.Properties['memberof'])
                    Write-DatKV "gMSA" "$gName"
                    if ($spns.Count -gt 0) { Write-DatKV "SPNs" "$($spns -join ', ')" }

                    # Check if current user can read the managed password
                    try {
                        $gEntry = $g.GetDirectoryEntry()
                        $gEntry.RefreshCache(@("msDS-ManagedPassword"))
                        $managedPwd = $gEntry.Properties["msDS-ManagedPassword"]
                        if ($managedPwd -and $managedPwd.Count -gt 0) {
                            Add-Finding "PE" "gMSA-Read" "Can read gMSA password for '$gName' - extract NT hash!"
                        }
                    } catch {
                        # Access denied = expected for non-authorized principals
                        Write-DatSub "Password: access denied (expected)"
                    }

                    # Check if gMSA is in privileged groups
                    foreach ($grp in $groups) {
                        if ($grp -match 'Domain Admins|Administrators|Enterprise Admins') {
                            Add-Finding "RED" "gMSA-Priv" "gMSA '$gName' is member of privileged group"
                        }
                    }
                }
                Add-Finding "INFO" "gMSA" "$($gmsas.Count) Group Managed Service Account(s) found"
            } else {
                Write-OK "No gMSA accounts found"
            }
        } catch { Write-Err "Cannot enumerate gMSA accounts" }

        Write-Sub "Kerberos Delegation"
        try {
            # Unconstrained delegation (exclude DCs - primaryGroupID 516)
            $unconSearcher = [adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))"
            $unconSearcher.PropertiesToLoad.AddRange(@("cn","samaccountname","dnshostname","serviceprincipalname"))
            $unconDelegation = $unconSearcher.FindAll()

            if ($unconDelegation -and $unconDelegation.Count -gt 0) {
                foreach ($u in $unconDelegation) {
                    $uName = "$($u.Properties['samaccountname'][0])"
                    $uHost = "$($u.Properties['dnshostname'][0])"
                    Write-DatKV "UNCONSTRAINED" "$uName ($uHost)"
                    Add-Finding "RED" "UnconDeleg" "Unconstrained delegation on '$uName' - captures TGTs of connecting users"
                }
            } else {
                Write-OK "No unconstrained delegation (excluding DCs)"
            }

            # Constrained delegation
            $conSearcher = [adsisearcher]"(msDS-AllowedToDelegateTo=*)"
            $conSearcher.PropertiesToLoad.AddRange(@("cn","samaccountname","msds-allowedtodelegateto"))
            $conDelegation = $conSearcher.FindAll()

            if ($conDelegation -and $conDelegation.Count -gt 0) {
                foreach ($c in $conDelegation) {
                    $cName = "$($c.Properties['samaccountname'][0])"
                    $targets = @($c.Properties['msds-allowedtodelegateto'])
                    Write-DatKV "CONSTRAINED" "$cName"
                    foreach ($t in $targets) {
                        Write-DatSub "Delegate to: $t"
                    }
                    # Check for dangerous targets
                    $dangerousTargets = $targets | Where-Object { $_ -match 'ldap/|cifs/|http/|host/' }
                    if ($dangerousTargets) {
                        Add-Finding "RED" "ConDeleg" "'$cName' can delegate to: $($dangerousTargets -join ', ')"
                    }
                }
            } else {
                Write-OK "No constrained delegation configured"
            }

            # Resource-Based Constrained Delegation (RBCD)
            $rbcdSearcher = [adsisearcher]"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
            $rbcdSearcher.PropertiesToLoad.AddRange(@("cn","samaccountname"))
            $rbcd = $rbcdSearcher.FindAll()
            if ($rbcd -and $rbcd.Count -gt 0) {
                foreach ($r in $rbcd) {
                    $rName = "$($r.Properties['samaccountname'][0])"
                    Write-DatKV "RBCD configured" "$rName"
                    Add-Finding "RED" "RBCD" "Resource-Based Constrained Delegation set on '$rName'"
                }
            }
        } catch { Write-Err "Cannot enumerate Kerberos delegation" }

        Write-Sub "Shadow Credentials (msDS-KeyCredentialLink)"
        try {
            # Check if current user can write KeyCredentialLink on any computer
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $mySIDs = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
            $lowPrivSIDs = $mySIDs + @("S-1-1-0","S-1-5-11","S-1-5-32-545")

            $compSearcher = [adsisearcher]"(&(objectCategory=computer)(!(primaryGroupID=516)))"
            $compSearcher.PropertiesToLoad.AddRange(@("cn","samaccountname","ntsecuritydescriptor"))
            $compSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $compSearcher.PageSize = 200
            $computers = $compSearcher.FindAll()

            # msDS-KeyCredentialLink GUID: 5b47d60f-6090-40b2-9f37-2a4de88f3063
            $keyCredGuid = [guid]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
            $shadowTargets = @()

            foreach ($comp in $computers) {
                try {
                    $entry = $comp.GetDirectoryEntry()
                    $sd = $entry.ObjectSecurity
                    foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                        $sid = $ace.IdentityReference.Value
                        if ($lowPrivSIDs -contains $sid -and $ace.AccessControlType -eq 'Allow') {
                            $rights = "$($ace.ActiveDirectoryRights)"
                            if ($rights -match 'GenericAll|GenericWrite|WriteProperty') {
                                # Check if WriteProperty is for KeyCredentialLink specifically or all props
                                if ($rights -match 'GenericAll|GenericWrite' -or
                                    ($ace.ObjectType -eq $keyCredGuid -or $ace.ObjectType -eq [guid]::Empty)) {
                                    $compName = "$($comp.Properties['samaccountname'][0])"
                                    $shadowTargets += $compName
                                    break
                                }
                            }
                        }
                    }
                } catch {}
                if ($shadowTargets.Count -ge 5) { break }  # limit output
            }

            if ($shadowTargets.Count -gt 0) {
                foreach ($st in $shadowTargets) {
                    Write-Dat "WRITABLE KeyCredentialLink: $st"
                }
                Add-Finding "PE" "ShadowCreds" "Can write msDS-KeyCredentialLink on $($shadowTargets.Count) computer(s) - Shadow Credentials attack!"
            } else {
                Write-OK "No writable msDS-KeyCredentialLink targets found"
            }
        } catch { Write-Err "Cannot check Shadow Credentials" }
    }

    Write-Sub "WSUS Configuration"
    try {
        $wsusServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name 'WUServer' -ErrorAction SilentlyContinue).WUServer
        $wsusStatus = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name 'UseWUServer' -ErrorAction SilentlyContinue).UseWUServer

        if ($wsusServer) {
            Write-DatKV "WSUS Server" $wsusServer
            Write-DatKV "WSUS Enabled" "$(if ($wsusStatus -eq 1) {'Yes'} else {'No'})"

            if ($wsusServer -match '^http://' -and $wsusStatus -eq 1) {
                Add-Finding "PE" "WSUS-HTTP" "WSUS uses HTTP ($wsusServer) - SharpWSUS MitM for SYSTEM execution!"
            } elseif ($wsusServer -match '^https://') {
                Write-OK "WSUS uses HTTPS (secure)"
            }
        } else {
            Write-OK "No WSUS server configured (using Windows Update directly)"
        }
    } catch { Write-Err "Cannot check WSUS config" }

    Write-Sub "noPac / sAMAccountName Spoofing (CVE-2021-42278)"
    try {
        $noPacKBs = @("KB5008380","KB5008602","KB5007206","KB5007207","KB5007205","KB5007189")
        $installedKBs = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID
        $noPacPatched = $false
        foreach ($kb in $noPacKBs) {
            if ($installedKBs -contains $kb) {
                $noPacPatched = $true
                Write-DatKV "noPac Patch" "$kb installed"
                break
            }
        }
        if (-not $noPacPatched) {
            # Check build number - fixed in builds after Nov 2021
            $build = [System.Environment]::OSVersion.Version
            # Server 2019: 17763.2300+, Server 2022: 20348.380+
            if (($build.Build -eq 17763 -and $build.Revision -ge 2300) -or
                ($build.Build -eq 20348 -and $build.Revision -ge 380) -or
                $build.Build -gt 20348) {
                Write-OK "noPac likely patched (build $($build.Build).$($build.Revision))"
            } else {
                Add-Finding "RED" "noPac" "CVE-2021-42278 patch not confirmed - sAMAccountName spoofing may be possible (PE to DA)"
            }
        } else {
            Write-OK "noPac patched"
        }
    } catch { Write-Err "Cannot check noPac patch status" }

    Write-Sub "Azure Arc Agent"
    try {
        $arcService = Get-Service himds -ErrorAction SilentlyContinue
        $arcPath = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"
        $arcInstalled = (Test-Path $arcPath -ErrorAction SilentlyContinue)

        if ($arcService -or $arcInstalled) {
            Write-DatKV "Azure Arc Agent" "INSTALLED"
            if ($arcService) { Write-DatKV "HIMDS Service" "$($arcService.Status)" }
            Add-Finding "RED" "AzureArc" "Azure Arc agent installed - hybrid identity bridge, potential lateral movement to Azure"
            # Check for Arc metadata
            try {
                $arcConfig = Get-Content "$env:ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                if ($arcConfig) {
                    Write-DatKV "Tenant" "$($arcConfig.tenantId)"
                    Write-DatKV "Subscription" "$($arcConfig.subscriptionId)"
                    Write-DatKV "Resource Group" "$($arcConfig.resourceGroup)"
                }
            } catch {}
        } else {
            Write-OK "Azure Arc agent not installed"
        }
    } catch { Write-Err "Cannot check Azure Arc" }

    Write-SectionFooter
}

# ============================================================================
#  ATTACK PATHS - VISUAL CHAIN
# ============================================================================
function Write-AttackPaths {
    Write-Host ""
    $w = $script:W
    $border = [string]::new([char]0x2550, $w)

    Write-Host "  $cTL$border$cTR" -ForegroundColor Red
    Write-Host "  $cV" -NoNewline -ForegroundColor Red
    $title = "  IDENTIFIED ATTACK PATHS"
    $pad = $w - $title.Length
    Write-Host "$title$(' ' * $pad)" -NoNewline -ForegroundColor Red
    Write-Host "$cV" -ForegroundColor Red
    Write-Host "  $cBL$border$cBR" -ForegroundColor Red
    Write-Host ""

    Log ""
    Log "=== ATTACK PATHS ==="

    if ($script:attackPaths.Count -eq 0) {
        Write-OK "No attack paths identified."
        return
    }

    $uniquePaths = $script:attackPaths | Select-Object -Unique
    $i = 1
    foreach ($path in $uniquePaths) {
        $innerW = $w - 4
        $pathLabel = " ATTACK PATH $i "
        $borderLen = $innerW - $pathLabel.Length - 2
        $topBorder = "$bH[$pathLabel]$([string]::new([char]0x2500, [math]::Max(0, $borderLen)))"

        Write-Host "  $bTL$topBorder$bTR" -ForegroundColor DarkRed
        # Word-wrap the path text
        $remaining = $path
        while ($remaining.Length -gt 0) {
            $chunk = if ($remaining.Length -gt ($innerW - 2)) { $remaining.Substring(0, $innerW - 2) } else { $remaining }
            $remaining = if ($remaining.Length -gt ($innerW - 2)) { $remaining.Substring($innerW - 2) } else { "" }
            $cPad = $innerW - $chunk.Length - 2
            Write-Host "  $bV " -NoNewline -ForegroundColor DarkRed
            Write-Host "$chunk$(' ' * [math]::Max(0, $cPad)) " -NoNewline -ForegroundColor Yellow
            Write-Host "$bV" -ForegroundColor DarkRed
        }
        Write-Host "  $bBL$([string]::new([char]0x2500, $innerW))$bBR" -ForegroundColor DarkRed

        Log "  [$i] $path"
        $i++
    }
}

# ============================================================================
#  SUMMARY DASHBOARD
# ============================================================================
function Write-Summary {
    $elapsed = (Get-Date) - $script:startTime
    $duration = if ($elapsed.TotalMinutes -ge 1) { "$([math]::Floor($elapsed.TotalMinutes))m $([math]::Round($elapsed.Seconds))s" }
                else { "$([math]::Round($elapsed.TotalSeconds))s" }

    $w = $script:W
    $border = [string]::new([char]0x2550, $w)
    $thin = [string]::new([char]0x2500, $w)

    $peCount  = @($script:findings | Where-Object { $_.Severity -eq "PE" }).Count
    $redCount = @($script:findings | Where-Object { $_.Severity -eq "RED" }).Count
    $lowCount = @($script:findings | Where-Object { $_.Severity -eq "LOW" }).Count
    $infCount = @($script:findings | Where-Object { $_.Severity -eq "INFO" }).Count
    $total    = $script:findings.Count
    $paths    = @($script:attackPaths | Select-Object -Unique).Count

    Write-Host ""
    Write-Host ""
    Write-Host "  $cTL$border$cTR" -ForegroundColor Magenta
    Write-Host "  $cV" -NoNewline -ForegroundColor Magenta
    $title = "  FENRIR v2.0 - SCAN COMPLETE"
    $pad = $w - $title.Length
    Write-Host "$title$(' ' * $pad)" -NoNewline -ForegroundColor White
    Write-Host "$cV" -ForegroundColor Magenta
    Write-Host "  $cML$border$cMR" -ForegroundColor Magenta

    # Stats bars
    $maxBar = 30
    $maxVal = [math]::Max(1, (@($peCount, $redCount, $lowCount, $infCount) | Measure-Object -Maximum).Maximum)

    $stats = @(
        @{ Label="PE!!"; Count=$peCount;  FG="Red"; BG="Yellow"; BarColor="Red" },
        @{ Label="RED";  Count=$redCount; FG="Red"; BG=$null;    BarColor="Red" },
        @{ Label="LOW";  Count=$lowCount; FG="Yellow"; BG=$null; BarColor="Yellow" },
        @{ Label="INFO"; Count=$infCount; FG="Cyan"; BG=$null;   BarColor="Cyan" }
    )

    foreach ($s in $stats) {
        $barFill = [math]::Round(($s.Count / $maxVal) * $maxBar)
        $barEmpty = $maxBar - $barFill
        $bar = "$([string]::new([char]0x2588, $barFill))$([string]::new([char]0x2591, $barEmpty))"
        $pct = if ($total -gt 0) { [math]::Round(($s.Count / $total) * 100) } else { 0 }
        $countStr = "$($s.Count)".PadLeft(4)
        $pctStr = "($pct%)".PadLeft(5)
        $labelStr = $s.Label.PadRight(6)

        Write-Host "  $cV" -NoNewline -ForegroundColor Magenta
        if ($s.BG) {
            Write-Host "  $labelStr " -NoNewline -ForegroundColor $s.FG -BackgroundColor $s.BG
        } else {
            Write-Host "  $labelStr " -NoNewline -ForegroundColor $s.FG
        }
        Write-Host " $bar" -NoNewline -ForegroundColor $s.BarColor
        Write-Host " $countStr $pctStr" -NoNewline -ForegroundColor White
        $usedLen = 2 + 6 + 1 + 1 + $maxBar + 1 + 4 + 1 + 5
        $remPad = $w - $usedLen
        Write-Host "$(' ' * [math]::Max(0, $remPad))" -NoNewline
        Write-Host "$cV" -ForegroundColor Magenta
    }

    Write-Host "  $cML$border$cMR" -ForegroundColor Magenta

    # Totals line
    $totalLine = "  Total: $total findings  |  Duration: $duration"
    $tPad = $w - $totalLine.Length
    Write-Host "  $cV" -NoNewline -ForegroundColor Magenta
    Write-Host $totalLine -NoNewline -ForegroundColor White
    Write-Host "$(' ' * [math]::Max(0, $tPad))" -NoNewline
    Write-Host "$cV" -ForegroundColor Magenta

    Write-Host "  $cBL$border$cBR" -ForegroundColor Magenta

    if ($OutputFile) {
        Write-Host ""
        Write-OK "Report saved to: $OutputFile"
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "  $iTM " -NoNewline -ForegroundColor DarkGray
    Write-Host "Completed: $ts" -ForegroundColor DarkGray
    Write-Host ""

    Log ""
    Log "=== SUMMARY ==="
    Log "  CRITICAL: $critical | HIGH: $high | MEDIUM: $medium | INFO: $info | CLEAN: $clean"
    Log "  Total: $total | Duration: $duration"
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

if ($OutputFile) {
    "FENRIR v2.0 - Report generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $OutputFile -Encoding UTF8
}

$script:startTime = Get-Date

Write-Banner
Initialize-Auth

# Layer 1: Entra ID Recon
Test-CurrentUser
Test-DirectoryRoles
Test-MFAStatus
Test-ConditionalAccess
Test-AppRegistrations
Test-ServicePrincipals
Test-DangerousPermissions
Test-GuestUsers
Test-PasswordPolicy
Test-StaleAccounts
Test-OnPremFlags
Test-PIM

# Layer 2: Azure Resources
Test-AzureRBAC
Test-AzureVMs
Test-KeyVault
Test-StorageAccounts
Test-Intune
Test-MailPermissions

# Layer 3: Cloud -> Local Pivoting
Test-VMRunCommand
Test-IMDSToken
Test-HybridJoinPRT
Test-CloudLAPS
Test-SecurityDefaults
Test-ADACLAbuse
Test-LocalPrivesc

# Layer 4: Deep Local Enumeration
Test-LocalServices
Test-ScheduledTasks
Test-StoredCredentials
Test-AlwaysInstallElevated
Test-AutorunsStartup
Test-NetworkSecurity

# Layer 5: Extended Cloud Checks
Test-AppRedirectURIs
Test-AzureAutomation
Test-InstalledSoftware
Test-CrossTenantB2B

# Layer 6: Advanced Entra Analysis
Test-DynamicGroups
Test-AdministrativeUnits
Test-EntraConnect

# Layer 7: Modern PE Vectors
Test-ADCS
Test-ModernPEVectors

# Summary
Write-Summary
