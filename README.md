# vcdSnapshotManager

PowerShell module for managing VMware vCloud Director snapshots. Provides functions to create, retrieve, and remove snapshots for vApps and VMs, as well as query vApps using the vCD API.

## Overview

vcdSnapshotManager is a comprehensive PowerShell module designed to simplify snapshot management operations in VMware vCloud Director environments. It supports both the Legacy API (XML) and Cloud API (JSON) endpoints, providing flexibility for different vCD versions and configurations.

## Features

- **Flexible Authentication**: Connect using username/password or API Key (Bearer token)
- **Snapshot Management**: Create, retrieve, and remove snapshots for VMs and vApps
- **Pipeline Support**: All functions support PowerShell pipeline for efficient batch operations
- **Dual API Support**: Works with both Legacy API (/api) and Cloud API (/cloudapi)
- **Safety Features**: Built-in confirmation prompts for destructive operations
- **PowerShell Compatibility**: Works with PowerShell 5.1 and PowerShell Core 6+

## Requirements

- PowerShell 5.1 or later (compatible with PowerShell Core)
- Network access to vCloud Director API endpoints
- Valid vCloud Director credentials or API key
- Appropriate permissions in vCloud Director to manage VMs/vApps and snapshots

## Installation

### Manual Installation

1. Download or clone this repository
2. Copy the module folder to one of your PowerShell module paths:
   - `$env:USERPROFILE\Documents\WindowsPowerShell\Modules\vcdSnapshotManager` (Windows PowerShell)
   - `$env:USERPROFILE\Documents\PowerShell\Modules\vcdSnapshotManager` (PowerShell Core)

3. Import the module:
```powershell
Import-Module vcdSnapshotManager
```

### Verify Installation

```powershell
Get-Module -Name vcdSnapshotManager -ListAvailable
Get-Command -Module vcdSnapshotManager
```

## Functions

### Connection and Authentication

#### Connect-vCloudDirector

Connects to VMware vCloud Director and establishes an authenticated REST API session.

**Parameters:**
- `Server` - The vCloud Director server IP or FQDN (required)
- `Port` - The port for vCloud Director API (default: 443)
- `Credential` - PSCredential object containing username@organization and password
- `ApiKey` - API Key/Bearer token for authentication (alternative to Credential)
- `Organization` - The vCloud Director organization name
- `ApiVersion` - The vCloud Director API version to use (default: 39.1)
- `UseCloudApi` - Use the Cloud API (/cloudapi) instead of legacy API (/api)
- `IgnoreSSLErrors` - Ignore SSL certificate errors

**Examples:**

```powershell
# Connect using username and password
$cred = Get-Credential -Message "Enter vCD credentials (username@organization)"
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred

# Connect using API Key with organization
Connect-vCloudDirector -Server "vcd.example.com" -ApiKey "your-refresh-token" -Organization "MyOrg" -UseCloudApi

# Connect with custom API version and ignore SSL errors
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred -ApiVersion "37.0" -IgnoreSSLErrors
```

#### Invoke-vcdRestMethod

Wrapper function for making REST API calls to vCloud Director. This is a low-level function used by other module functions but can also be used directly for custom API calls.

**Parameters:**
- `Endpoint` - The API endpoint path (relative to base URL)
- `Method` - HTTP method (Get, Post, Put, Delete, Patch)
- `Body` - Request body for Post/Put/Patch operations
- `ContentType` - Override the default Content-Type header
- `ApiVersion` - Override the API version for this specific call
- `SkipCertificateCheck` - Skip SSL certificate validation
- `OutFile` - Path to save response content to file
- `TimeoutSec` - Request timeout in seconds (default: 100)

**Examples:**

```powershell
# Get current session information
$session = Invoke-vcdRestMethod -Endpoint "1.0.0/sessions/current" -Method Get

# Get all VDCs
$vdcs = Invoke-vcdRestMethod -Endpoint "1.0.0/vdcs" -Method Get

# Custom API call with body
$body = @{ name = "Test"; description = "Test entity" }
$result = Invoke-vcdRestMethod -Endpoint "1.0.0/entities" -Method Post -Body $body
```

### vApp Management

#### Get-vcdVApp

Retrieves vCloud Director vApp information by name using the query service.

**Parameters:**
- `Name` - The name(s) of the vApp(s) to retrieve (supports wildcards)
- `ExactMatch` - Only return vApps with exact name matches

**Examples:**

```powershell
# Get a specific vApp by name
Get-vcdVApp -Name "MyApp"

# Get multiple vApps
Get-vcdVApp -Name "App1", "App2", "App3"

# Get all vApps
Get-vcdVApp

# Get vApps using pipeline
"WebApp", "DatabaseApp" | Get-vcdVApp

# Get vApps with exact name match
Get-vcdVApp -Name "Production-App" -ExactMatch

# Get vApps using wildcard pattern
Get-vcdVApp -Name "Prod*"
```

### Snapshot Management

#### New-vcdSnapshot

Creates a snapshot for one or more vCloud Director virtual machines or vApps.

**Parameters:**
- `VMorVApp` - The VM or vApp object(s) to snapshot (required)
- `SnapshotName` - The name for the snapshot (default: "Snapshot_TIMESTAMP")
- `Description` - Optional description for the snapshot
- `SnapshotMemory` - Include the VM's memory in the snapshot
- `Quiesce` - Quiesce the guest OS before taking the snapshot (requires VMware Tools)

**Examples:**

```powershell
# Create a simple snapshot for a single vApp
$vapp = Get-vcdVApp -Name "MyApp"
$vapp | New-vcdSnapshot -SnapshotName "Before Upgrade"

# Create a snapshot with memory for multiple VMs
$vms | New-vcdSnapshot -SnapshotName "Backup" -SnapshotMemory

# Create a quiesced snapshot
New-vcdSnapshot -VMorVApp $vm -SnapshotName "PrePatch" -Quiesce

# Create snapshots with memory and quiesce
Get-vcdVApp -Name "Prod*" | New-vcdSnapshot -SnapshotName "Maintenance" -SnapshotMemory -Quiesce

# Create snapshot with custom description
$vapp | New-vcdSnapshot -SnapshotName "Backup" -Description "Weekly backup before maintenance"
```

#### Get-vcdSnapshot

Retrieves snapshot information for vCloud Director virtual machines or vApps.

**Parameters:**
- `VMorVApp` - The VM or vApp object(s) to retrieve snapshots for (required)

**Output Properties:**
- `VMorVAppId` - The ID of the VM or vApp
- `VMorVAppName` - The name of the VM or vApp
- `SnapshotName` - Name of the snapshot
- `Created` - When the snapshot was created
- `Size` - Size of the snapshot
- `PoweredOn` - Whether the VM was powered on when snapshot was taken
- `Memory` - Whether memory was included in the snapshot
- `Quiesced` - Whether the guest OS was quiesced

**Examples:**

```powershell
# Get snapshots for a single vApp
$vapp = Get-vcdVApp -Name "MyApp"
$vapp | Get-vcdSnapshot

# Get snapshots for multiple VMs
$vms | Get-vcdSnapshot

# Get snapshots and display specific properties
Get-vcdVApp -Name "Prod*" | Get-vcdSnapshot | Select-Object VMorVAppName, SnapshotName, Created, Size

# Get snapshots for all vApps
Get-vcdVApp | Get-vcdSnapshot | Format-Table -AutoSize
```

#### Remove-vcdSnapshot

Removes (consolidates) snapshots from vCloud Director virtual machines or vApps.

**IMPORTANT**: This operation removes ALL snapshots for the VM/vApp. vCloud Director does not support removing individual snapshots - the consolidate action removes the entire snapshot chain.

**Parameters:**
- `VMorVApp` - The VM or vApp object(s) to remove snapshots from (required)
- `AllSnapshots` - Use removeAllSnapshots endpoint instead of consolidate
- `Confirm` - Prompts for confirmation (enabled by default)
- `WhatIf` - Shows what would happen without executing

**Examples:**

```powershell
# Remove snapshots for a single vApp (with confirmation)
$vapp = Get-vcdVApp -Name "MyApp"
$vapp | Remove-vcdSnapshot

# Remove snapshots for multiple VMs without confirmation
$vms | Remove-vcdSnapshot -Confirm:$false

# Show what would happen without actually removing
$vapp | Remove-vcdSnapshot -WhatIf

# Remove all snapshots using removeAllSnapshots endpoint
$vapp | Remove-vcdSnapshot -AllSnapshots

# Remove snapshots from all vApps in a VDC
Get-vcdVApp | Where-Object { $_.vdcName -eq "Production-VDC" } | Remove-vcdSnapshot -Confirm:$false
```

## Complete Workflow Examples

### Example 1: Create Maintenance Snapshots

```powershell
# Connect to vCloud Director
$cred = Get-Credential
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred

# Get production vApps
$prodApps = Get-vcdVApp -Name "Prod*"

# Create snapshots with memory and quiesce
$prodApps | New-vcdSnapshot -SnapshotName "Pre-Maintenance" -SnapshotMemory -Quiesce -Description "Snapshot before monthly maintenance"

# Verify snapshots were created
$prodApps | Get-vcdSnapshot | Format-Table -AutoSize
```

### Example 2: Snapshot Management for Upgrades

```powershell
# Connect
Connect-vCloudDirector -Server "vcd.example.com" -ApiKey $apiKey -Organization "MyOrg" -UseCloudApi

# Get the app to upgrade
$app = Get-vcdVApp -Name "DatabaseApp" -ExactMatch

# Check existing snapshots
$app | Get-vcdSnapshot

# Create pre-upgrade snapshot
$app | New-vcdSnapshot -SnapshotName "Before Upgrade to v2.0" -Quiesce

# Perform upgrade...
# (upgrade steps here)

# If upgrade successful, remove snapshot
$app | Remove-vcdSnapshot -Confirm:$false

# If upgrade failed, you can revert to snapshot in vCD UI
```

### Example 3: Bulk Snapshot Cleanup

```powershell
# Connect
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred

# Find all vApps with snapshots
$allVApps = Get-vcdVApp
$vAppsWithSnapshots = $allVApps | Get-vcdSnapshot | Where-Object { $_.SnapshotName } | Select-Object -Unique VMorVAppName

# Review snapshots older than 7 days
$oldSnapshots = $allVApps | Get-vcdSnapshot | Where-Object {
    $_.Created -and $_.Created -lt (Get-Date).AddDays(-7)
}

$oldSnapshots | Format-Table -AutoSize

# Remove old snapshots
$oldSnapshots | ForEach-Object {
    $vapp = Get-vcdVApp -Name $_.VMorVAppName -ExactMatch
    $vapp | Remove-vcdSnapshot -Confirm:$false
}
```

### Example 4: Generate Snapshot Report

```powershell
# Connect
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred

# Get all snapshots and create a report
$snapshotReport = Get-vcdVApp | Get-vcdSnapshot | Where-Object { $_.SnapshotName } | Select-Object `
    VMorVAppName,
    SnapshotName,
    Created,
    @{Name='AgeDays';Expression={((Get-Date) - $_.Created).Days}},
    @{Name='SizeGB';Expression={[math]::Round($_.Size / 1GB, 2)}},
    PoweredOn,
    Memory,
    Quiesced

# Display report
$snapshotReport | Format-Table -AutoSize

# Export to CSV
$snapshotReport | Export-Csv -Path "vCD-Snapshots-Report.csv" -NoTypeInformation

# Show summary statistics
$snapshotReport | Group-Object VMorVAppName | Select-Object Name, Count, @{
    Name='TotalSizeGB';
    Expression={($_.Group | Measure-Object SizeGB -Sum).Sum}
}
```

## Best Practices

1. **Always use descriptive snapshot names** to identify their purpose
2. **Use the -Quiesce parameter** when possible to ensure application-consistent snapshots (requires VMware Tools)
3. **Remove snapshots** as soon as they're no longer needed to reclaim storage
4. **Test snapshot operations** in a non-production environment first
5. **Use -WhatIf** with Remove-vcdSnapshot to preview changes before execution
6. **Monitor snapshot age and size** to prevent storage issues
7. **Document your snapshot strategy** and retention policies

## Troubleshooting

### Connection Issues

If you encounter SSL certificate errors:
```powershell
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred -IgnoreSSLErrors
```

### API Version Compatibility

If you get API version errors, try specifying a different version:
```powershell
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred -ApiVersion "37.0"
```

### Session Expiration

If your session expires during long-running operations, the module includes automatic token refresh for API Key authentication. For username/password authentication, reconnect:
```powershell
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred
```

### Verbose Logging

Enable verbose output for troubleshooting:
```powershell
$VerbosePreference = "Continue"
Connect-vCloudDirector -Server "vcd.example.com" -Credential $cred -Verbose
$VerbosePreference = "SilentlyContinue"
```

## Session Information

After connecting with Connect-vCloudDirector, a global session variable `$Global:vcdSession` is created and used by all module functions. This contains:
- Authentication headers
- API endpoint information
- API version
- Organization details
- API type (Legacy or Cloud)

## Security Notes

- API keys and credentials are stored in memory only during the session
- Use PowerShell SecureString and PSCredential objects for password handling
- The module supports SSL certificate validation (can be disabled if needed)
- Session tokens are automatically managed and refreshed when possible

## Version History

### Version 1.0.0
- Initial release of vcdSnapshotManager module
- Connect-vCloudDirector: Authenticate to vCloud Director using credentials or API key
- Invoke-vcdRestMethod: Generic REST API wrapper for vCD operations
- Get-vcdVApp: Query and retrieve vApps by name
- New-vcdSnapshot: Create snapshots for VMs/vApps with memory and quiesce options
- Get-vcdSnapshot: Retrieve snapshot information for VMs/vApps
- Remove-vcdSnapshot: Remove/consolidate snapshots with safety confirmations
- Full pipeline support across all functions
- Support for both Legacy API (XML) and Cloud API (JSON)

## Author

**Andrew Ramsay**
Logicalis Australia

## Copyright

(c) 2025. All rights reserved.

## Support

For issues, questions, or contributions, please contact the module maintainer or refer to your organization's internal documentation
