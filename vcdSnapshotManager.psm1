#region Connect-vCloudDirector
function Connect-vCloudDirector {
    <#
    .SYNOPSIS
        Connects to VMware vCloud Director and establishes an authenticated REST API session
    .DESCRIPTION
        This private function connects to VMware vCloud Director using either:
        - Basic authentication (username/password)
        - API Key (Bearer token) authentication
        Both methods establish a session for subsequent API calls.

        This is a private helper function for AsBuiltReport.VMware.CloudDirector module.
    .PARAMETER Server
        The vCloud Director server IP or FQDN
    .PARAMETER Port
        The port for vCloud Director API (default: 443)
    .PARAMETER Credential
        PSCredential object containing username@organization and password (required for basic auth)
    .PARAMETER ApiKey
        API Key/Bearer token for authentication (alternative to Credential)
    .PARAMETER Organization
        The vCloud Director organization name (can also be included in username as username@organization)
    .PARAMETER ApiVersion
        The vCloud Director API version to use (default: 37.0)
    .PARAMETER UseCloudApi
        Use the Cloud API (/cloudapi) instead of legacy API (/api). Recommended when using ApiKey authentication.
    .PARAMETER IgnoreSSLErrors
        Switch to ignore SSL certificate errors
    .OUTPUTS
        Hashtable - Returns session information including headers and connection details
    .NOTES
        This is a private function adapted for AsBuiltReport module use.
    #>
    [CmdletBinding(DefaultParameterSetName = 'BasicAuth')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ApiKey')]
        [string]$Server,

        [Parameter(Mandatory = $false, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ApiKey')]
        [int]$Port = 443,

        [Parameter(Mandatory = $true, ParameterSetName = 'BasicAuth')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'ApiKey')]
        [string]$ApiKey,

        [Parameter(Mandatory = $false, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ApiKey')]
        [string]$Organization,

        [Parameter(Mandatory = $false, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ApiKey')]
        [string]$ApiVersion = "39.1",

        [Parameter(Mandatory = $false, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ApiKey')]
        [switch]$UseCloudApi,

        [Parameter(Mandatory = $false, ParameterSetName = 'BasicAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ApiKey')]
        [switch]$IgnoreSSLErrors
    )

    # SSL Certificate handling
    if ($IgnoreSSLErrors) {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # PowerShell 5.1 - Use .NET ServicePointManager
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                Add-Type @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(
                            ServicePoint srvPoint, X509Certificate certificate,
                            WebRequest request, int certificateProblem) {
                            return true;
                        }
                    }
"@
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    }

    # Determine base URL based on API type
    if ($UseCloudApi) {
        $baseUrl = "https://$Server`:$Port/cloudapi/"
        $apiType = "cloudapi"
    } else {
        $baseUrl = "https://$Server`:$Port/api/"
        $apiType = "legacy"
    }

    try {
        # API Key Authentication
        if ($PSCmdlet.ParameterSetName -eq 'ApiKey') {
            Write-Verbose "Using API Key authentication (Refresh Token)"

            # Validate that Organization is provided for tenant authentication
            if ([string]::IsNullOrEmpty($Organization)) {
                throw "Organization parameter is required when using API Key authentication for tenant access"
            }

            # Exchange refresh token for access token via OAuth endpoint
            $oauthUri = "https://$Server`:$Port/oauth/tenant/$Organization/token?grant_type=refresh_token&refresh_token=$ApiKey"

            $oauthHeaders = @{
                'Accept' = 'application/json'
            }

            $oauthParams = @{
                Uri     = $oauthUri
                Headers = $oauthHeaders
                Method  = 'Post'
            }

            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $oauthParams['SkipCertificateCheck'] = $true
            }

            Write-Verbose "Exchanging refresh token for access token at: https://$Server/oauth/tenant/$Organization/token"

            try {
                $tokenResponse = Invoke-RestMethod @oauthParams
                $accessToken = $tokenResponse.access_token

                if ([string]::IsNullOrEmpty($accessToken)) {
                    throw "Failed to obtain access token from OAuth endpoint"
                }

                Write-Verbose "Successfully obtained access token"
            }
            catch {
                throw "Failed to exchange refresh token for access token: $($_.Exception.Message)"
            }

            if ($UseCloudApi) {
                # Cloud API authentication with access token
                $headers = @{
                    'Authorization' = "Bearer $accessToken"
                    'Accept'        = "application/json;version=$ApiVersion"
                    'Content-Type'  = 'application/json'
                }

                # Verify the token by getting current session info
                $sessionUri = $baseUrl + "1.0.0/sessions/current"

                $invokeParams = @{
                    Uri     = $sessionUri
                    Headers = $headers
                    Method  = 'Get'
                }

                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $invokeParams['SkipCertificateCheck'] = $true
                }

                Write-Verbose "Validating access token at: $sessionUri"
                $sessionResponse = Invoke-RestMethod @invokeParams

                # Store session information
                $sessionInfo = @{
                    Headers      = @{
                        'Authorization' = "Bearer $accessToken"
                        'Accept'        = "application/json;version=$ApiVersion"
                        'Content-Type'  = 'application/json'
                    }
                    Server       = $Server
                    Port         = $Port
                    Organization = $Organization
                    ApiVersion   = $ApiVersion
                    BaseUrl      = $baseUrl
                    ApiType      = $apiType
                    AuthType     = 'ApiKey'
                }

                if ($sessionResponse.org) {
                    Write-Verbose "Authenticated to organization: $($sessionResponse.org.name)"
                    $sessionInfo['OrgName'] = $sessionResponse.org.name
                }

                if ($sessionResponse.user) {
                    Write-Verbose "Logged in as user: $($sessionResponse.user)"
                    $sessionInfo['User'] = $sessionResponse.user
                }

                Write-Verbose "Successfully connected to vCloud Director at $Server using Cloud API"
                Write-Verbose "Using API version: $ApiVersion"

                # Store session in global variable
                $Global:vcdSession = $sessionInfo

                return $sessionInfo

            } else {
                # Legacy API with access token
                $headers = @{
                    'Authorization' = "Bearer $accessToken"
                    'Accept'        = "application/*+xml;version=$ApiVersion"
                }

                # Verify the token by calling the session endpoint
                $sessionUri = $baseUrl + "session"

                $invokeParams = @{
                    Uri     = $sessionUri
                    Headers = $headers
                    Method  = 'Get'
                }

                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $invokeParams['SkipCertificateCheck'] = $true
                }

                Write-Verbose "Validating access token at: $sessionUri"
                $response = Invoke-RestMethod @invokeParams

                # Store session information
                $sessionInfo = @{
                    Headers      = @{
                        'Authorization' = "Bearer $accessToken"
                        'Accept'        = "application/*+xml;version=$ApiVersion"
                        'Content-Type'  = 'application/*+xml'
                    }
                    Server       = $Server
                    Port         = $Port
                    Organization = $Organization
                    ApiVersion   = $ApiVersion
                    BaseUrl      = $baseUrl
                    ApiType      = $apiType
                    AuthType     = 'ApiKey'
                }

                Write-Verbose "Successfully connected to vCloud Director at $Server using Legacy API"
                Write-Verbose "Using API version: $ApiVersion"

                # Store session in global variable
                $Global:vcdSession = $sessionInfo

                return $sessionInfo
            }
        }

        # Basic Authentication (username/password)
        else {
            Write-Verbose "Using Basic authentication (username/password)"

            # Determine username and organization
            $username = $Credential.UserName
            $password = $Credential.GetNetworkCredential().Password

            # If username contains @, split it
            if ($username -contains '@') {
                $parts = $username -split '@'
                $username = $parts[0]
                if ([string]::IsNullOrEmpty($Organization)) {
                    $Organization = $parts[1]
                }
            }

            # Construct the full username with organization
            if (-not [string]::IsNullOrEmpty($Organization)) {
                $fullUsername = "$username@$Organization"
            } else {
                $fullUsername = $username
            }

            # Create authorization header
            $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$fullUsername`:$password"))

            if ($UseCloudApi) {
                # Cloud API with Basic auth
                $headers = @{
                    'Authorization' = "Basic $base64Auth"
                    'Accept'        = "application/json;version=$ApiVersion"
                    'Content-Type'  = 'application/json'
                }

                $sessionUri = $baseUrl + "1.0.0/sessions"

                $invokeParams = @{
                    Uri     = $sessionUri
                    Headers = $headers
                    Method  = 'Post'
                }

                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $invokeParams['SkipCertificateCheck'] = $true
                }

                $response = Invoke-RestMethod @invokeParams

                # Extract Bearer token from response
                if ($response.accessToken) {
                    $bearerToken = $response.accessToken
                } else {
                    throw "Failed to obtain access token from vCloud Director Cloud API"
                }

                # Store session information
                $sessionInfo = @{
                    Headers      = @{
                        'Authorization' = "Bearer $bearerToken"
                        'Accept'        = "application/json;version=$ApiVersion"
                        'Content-Type'  = 'application/json'
                    }
                    Server       = $Server
                    Port         = $Port
                    Organization = $Organization
                    ApiVersion   = $ApiVersion
                    BaseUrl      = $baseUrl
                    ApiType      = $apiType
                    AuthType     = 'Basic'
                    User         = $fullUsername
                }

                Write-Verbose "Successfully connected to vCloud Director at $Server using Cloud API"
                Write-Verbose "Using API version: $ApiVersion"

                # Store session in global variable
                $Global:vcdSession = $sessionInfo

                return $sessionInfo

            } else {
                # Legacy API with Basic auth
                $headers = @{
                    'Authorization' = "Basic $base64Auth"
                    'Accept'        = "application/*+xml;version=$ApiVersion"
                }

                # Authenticate and get session token
                $sessionUri = $baseUrl + "sessions"

                # Handle SSL certificate checking based on PowerShell version
                $invokeParams = @{
                    Uri     = $sessionUri
                    Headers = $headers
                    Method  = 'Post'
                }

                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $invokeParams['SkipCertificateCheck'] = $true
                }

                $response = Invoke-WebRequest @invokeParams

                # Extract the x-vcloud-authorization token from response headers
                $authToken = $response.Headers['x-vcloud-authorization']

                if ([string]::IsNullOrEmpty($authToken)) {
                    throw "Failed to obtain authentication token from vCloud Director"
                }

                # Store session information
                $sessionInfo = @{
                    Headers      = @{
                        'x-vcloud-authorization' = $authToken
                        'Accept'                 = "application/*+xml;version=$ApiVersion"
                        'Content-Type'           = 'application/*+xml'
                    }
                    Server       = $Server
                    Port         = $Port
                    Organization = $Organization
                    ApiVersion   = $ApiVersion
                    BaseUrl      = $baseUrl
                    ApiType      = $apiType
                    AuthType     = 'Basic'
                    User         = $fullUsername
                }

                Write-Verbose "Successfully connected to vCloud Director at $Server"
                Write-Verbose "Using API version: $ApiVersion"

                # Store session in global variable
                $Global:vcdSession = $sessionInfo

                return $sessionInfo
            }
        }
    }
    catch {
        Write-Error "Failed to connect to vCloud Director: $($_.Exception.Message)"
        throw
    }
}
#end region

#region Invoke-vcdRestMethod
function Invoke-vcdRestMethod {
    <#
    .SYNOPSIS
        Wrapper function for making REST API calls to vCloud Director

    .DESCRIPTION
        This private function provides a standardized way to make REST API calls to vCloud Director.
        It handles:
        - Header compliance with API version requirements
        - Automatic token refresh when approaching expiration
        - Support for both Legacy API (/api) and Cloud API (/cloudapi)
        - Consistent error handling
        - SSL certificate validation options

    .PARAMETER Endpoint
        The API endpoint path (relative to base URL). Do not include the base URL or leading slash.
        Examples: "sessions/current", "1.0.0/vdcs", "org/{id}/users"

    .PARAMETER Method
        HTTP method to use (Get, Post, Put, Delete, Patch). Default is 'Get'

    .PARAMETER Body
        Request body for Post/Put/Patch operations. Can be a hashtable (auto-converted to JSON) or string

    .PARAMETER ContentType
        Override the default Content-Type header. If not specified, uses session default

    .PARAMETER ApiVersion
        Override the API version for this specific call. If not specified, uses session default

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation (PowerShell 6+)

    .PARAMETER OutFile
        Path to save response content to file

    .PARAMETER TimeoutSec
        Request timeout in seconds. Default is 100 seconds

    .EXAMPLE
        # Get current session information (uses $Global:vcdSession automatically)
        $result = Invoke-vcdRestMethod -Endpoint "1.0.0/sessions/current" -Method Get

    .EXAMPLE
        # Get all VDCs
        $vdcs = Invoke-vcdRestMethod -Endpoint "1.0.0/vdcs" -Method Get

    .EXAMPLE
        # Create a new entity with body
        $body = @{
            name = "Test"
            description = "Test entity"
        }
        $result = Invoke-vcdRestMethod -Endpoint "1.0.0/entities" -Method Post -Body $body

    .OUTPUTS
        PSObject - Parsed response from the API call

    .NOTES
        This is a private helper function for AsBuiltReport.VMware.CloudDirector module.
        Uses $Global:vcdSession for session information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch')]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,

        [Parameter(Mandatory = $false)]
        [string]$OutFile,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 100
    )

    begin {
        # Validate global session object
        if (-not $Global:vcdSession -or -not $Global:vcdSession.Headers -or -not $Global:vcdSession.BaseUrl) {
            throw "No valid vCloud Director session found. Please connect using Connect-vCloudDirector first. Global session must contain Headers and BaseUrl properties."
        }

        # Check if token needs refresh (if expiration tracking is available)
        if ($Global:vcdSession.TokenExpiration) {
            $timeUntilExpiration = ($Global:vcdSession.TokenExpiration - (Get-Date)).TotalMinutes

            if ($timeUntilExpiration -lt 5) {
                Write-Verbose "Token expires in $([math]::Round($timeUntilExpiration, 2)) minutes. Refreshing token..."

                # Attempt to refresh the token
                try {
                    if ($Global:vcdSession.RefreshToken) {
                        # Use refresh token to get new access token
                        $refreshParams = @{
                            Server       = $Global:vcdSession.Server
                            Port         = $Global:vcdSession.Port
                            ApiKey       = $Global:vcdSession.RefreshToken
                            Organization = $Global:vcdSession.Organization
                            ApiVersion   = $Global:vcdSession.ApiVersion
                            UseCloudApi  = ($Global:vcdSession.ApiType -eq 'cloudapi')
                        }

                        if ($SkipCertificateCheck) {
                            $refreshParams['IgnoreSSLErrors'] = $true
                        }

                        $newSession = Connect-vCloudDirector @refreshParams

                        # Update the global session with new token
                        $Global:vcdSession.Headers = $newSession.Headers
                        $Global:vcdSession.TokenExpiration = $newSession.TokenExpiration

                        Write-Verbose "Token successfully refreshed and global session updated"
                    } else {
                        Write-Warning "Token is expiring soon but no refresh token available"
                    }
                } catch {
                    Write-Warning "Failed to refresh token: $_"
                }
            }
        }
    }

    process {
        try {
            # Build headers from global session
            $headers = $Global:vcdSession.Headers.Clone()

            # Override API version if specified
            if ($ApiVersion) {
                if ($Global:vcdSession.ApiType -eq 'cloudapi') {
                    $headers['Accept'] = "application/json;version=$ApiVersion"
                } else {
                    $headers['Accept'] = "application/*+xml;version=$ApiVersion"
                }
            }

            # Override Content-Type if specified
            if ($ContentType) {
                $headers['Content-Type'] = $ContentType
            }

            # Construct full URI
            # Remove leading slash from endpoint if present
            $cleanEndpoint = $Endpoint.TrimStart('/')
            $uri = "$($Global:vcdSession.BaseUrl)$cleanEndpoint"

            Write-Verbose "[$Method] $uri"

            # Build Invoke-RestMethod parameters
            $invokeParams = @{
                Uri         = $uri
                Method      = $Method
                Headers     = $headers
                TimeoutSec  = $TimeoutSec
            }

            # Add body if provided
            if ($Body) {
                if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
                    # Convert to JSON for Cloud API or if Content-Type is JSON
                    if ($Global:vcdSession.ApiType -eq 'cloudapi' -or $headers['Content-Type'] -like '*json*') {
                        $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 10)
                        Write-Verbose "Request Body (JSON): $($invokeParams['Body'])"
                    } else {
                        # For legacy API, assume XML string or convert
                        $invokeParams['Body'] = $Body
                        Write-Verbose "Request Body: $($invokeParams['Body'])"
                    }
                } else {
                    # Body is already a string (JSON or XML)
                    $invokeParams['Body'] = $Body
                    Write-Verbose "Request Body: $($invokeParams['Body'])"
                }
            }

            # Add OutFile if specified
            if ($OutFile) {
                $invokeParams['OutFile'] = $OutFile
            }

            # Handle SSL certificate validation based on PowerShell version
            if ($SkipCertificateCheck) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $invokeParams['SkipCertificateCheck'] = $true
                } else {
                    # For PowerShell 5.1, certificate policy should already be set by Connect-vCloudDirector
                    Write-Verbose "SSL certificate validation handled by session configuration"
                }
            }

            # Make the API call
            Write-Verbose "Invoking REST method..."
            $response = Invoke-RestMethod @invokeParams

            # Handle pagination for Cloud API list responses
            if ($Global:vcdSession.ApiType -eq 'cloudapi' -and $response.values) {
                $allResults = @($response.values)

                # Check if there are more pages
                while ($response.resultTotal -gt $allResults.Count) {
                    Write-Verbose "Fetching next page of results ($($allResults.Count) / $($response.resultTotal))"

                    # Build next page URI
                    $pageNum = [math]::Ceiling($allResults.Count / $response.pageSize) + 1
                    $pageUri = if ($uri -match '\?') {
                        "$uri&page=$pageNum"
                    } else {
                        "$uri?page=$pageNum"
                    }

                    $invokeParams['Uri'] = $pageUri
                    $response = Invoke-RestMethod @invokeParams

                    if ($response.values) {
                        $allResults += $response.values
                    } else {
                        break
                    }
                }

                # Return all results with metadata
                return @{
                    values      = $allResults
                    resultTotal = $response.resultTotal
                    pageSize    = $response.pageSize
                }
            }

            # For Legacy API or non-paginated responses, return as-is
            return $response

        } catch {
            # Enhanced error handling
            $statusCode = $_.Exception.Response.StatusCode.value__
            $statusDescription = $_.Exception.Response.StatusDescription

            Write-Verbose "API Error: $statusCode - $statusDescription"

            # Try to get error details from response
            if ($_.ErrorDetails.Message) {
                Write-Verbose "Error Details: $($_.ErrorDetails.Message)"
            }

            # Construct detailed error message
            $errorMessage = "vCloud Director API Error"
            if ($statusCode) {
                $errorMessage += " [$statusCode]"
            }
            $errorMessage += ": $($_.Exception.Message)"

            # Add endpoint information
            $errorMessage += "`nEndpoint: $Method $uri"

            # Add response details if available
            if ($_.ErrorDetails.Message) {
                try {
                    $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($errorDetail.message) {
                        $errorMessage += "`nDetails: $($errorDetail.message)"
                    }
                } catch {
                    $errorMessage += "`nDetails: $($_.ErrorDetails.Message)"
                }
            }

            throw $errorMessage
        }
    }

    end {
        Write-Verbose "REST method invocation completed"
    }
}
#end region

#region New-vcdSnapshot
function New-vcdSnapshot {
    <#
    .SYNOPSIS
        Creates a snapshot for one or more vCloud Director virtual machines or vApps

    .DESCRIPTION
        This function creates snapshots for vCloud Director VMs or vApps using the POST /vApp/{id}/action/createSnapshot endpoint.
        It supports creating snapshots with memory, quiescing the guest OS, and custom snapshot names.

        The function can process single or multiple VMs/vApps and accepts pipeline input.

    .PARAMETER VMorVApp
        The VM or vApp object(s) to snapshot. Can be a single object or an array.
        Accepts objects with an 'id' or 'href' property containing the vApp/VM identifier.

    .PARAMETER SnapshotName
        The name for the snapshot. If not specified, a default name with timestamp will be used.

    .PARAMETER Description
        Optional description for the snapshot. If not specified, a default description will be used.

    .PARAMETER SnapshotMemory
        Switch to include the VM's memory in the snapshot. Default is $false.
        When enabled, the snapshot will capture the memory state of the VM.

    .PARAMETER Quiesce
        Switch to quiesce the guest OS before taking the snapshot. Default is $false.
        Requires VMware Tools to be installed and running in the guest OS.

    .EXAMPLE
        # Create a simple snapshot for a single vApp
        $vapp | New-vcdSnapshot -SnapshotName "Before Upgrade"

    .EXAMPLE
        # Create a snapshot with memory for multiple VMs
        $vms | New-vcdSnapshot -SnapshotName "Backup" -SnapshotMemory

    .EXAMPLE
        # Create a quiesced snapshot for a VM
        New-vcdSnapshot -VMorVApp $vm -SnapshotName "PrePatch" -Quiesce

    .EXAMPLE
        # Create snapshots with memory and quiesce for multiple vApps
        Get-vApps | New-vcdSnapshot -SnapshotName "Maintenance" -SnapshotMemory -Quiesce

    .OUTPUTS
        PSObject - Returns the task object(s) for the snapshot creation operation(s)

    .NOTES
        Requires an active vCloud Director session via Connect-vCloudDirector.
        Uses the legacy API endpoint: POST /vApp/{id}/action/createSnapshot
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('VM', 'vApp', 'Id')]
        [object[]]$VMorVApp,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotName,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [switch]$SnapshotMemory,

        [Parameter(Mandatory = $false)]
        [switch]$Quiesce
    )

    begin {
        # Validate that we have an active session
        if (-not $Global:vcdSession -or -not $Global:vcdSession.Headers -or -not $Global:vcdSession.BaseUrl) {
            throw "No valid vCloud Director session found. Please connect using Connect-vCloudDirector first."
        }

        Write-Verbose "Starting snapshot creation process"

        # If no snapshot name provided, create a default one with timestamp
        if ([string]::IsNullOrEmpty($SnapshotName)) {
            $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $SnapshotName = "Snapshot_$timestamp"
            Write-Verbose "No snapshot name provided, using default: $SnapshotName"
        }

        # If no description provided, create a default one
        if ([string]::IsNullOrEmpty($Description)) {
            $Description = "Snapshot created by vcdSnapshotManager"
        }
    }

    process {
        foreach ($item in $VMorVApp) {
            try {
                # Extract the vApp/VM ID from the object
                $vAppId = $null

                if ($item -is [string]) {
                    # If it's a string, assume it's the ID
                    $vAppId = $item
                }
                elseif ($item.id) {
                    $vAppId = $item.id
                }
                elseif ($item.href) {
                    # Extract ID from href (e.g., "https://vcd.example.com/api/vApp/vapp-12345")
                    if ($item.href -match '(vapp-[a-f0-9\-]+|vm-[a-f0-9\-]+)') {
                        $vAppId = $matches[1]
                    }
                }

                if ([string]::IsNullOrEmpty($vAppId)) {
                    Write-Warning "Could not extract vApp/VM ID from object. Skipping..."
                    continue
                }

                # Clean up the ID if it contains URN format
                if ($vAppId -match 'urn:vcloud:(?:vapp|vm):([a-f0-9\-]+)') {
                    $cleanId = $matches[1]
                    $vAppId = if ($vAppId -match ':vm:') { "vm-$cleanId" } else { "vapp-$cleanId" }
                }
                elseif ($vAppId -notmatch '^(vapp-|vm-)') {
                    # If it doesn't start with vapp- or vm-, try to add vapp- prefix
                    Write-Verbose "ID doesn't have expected prefix, adding 'vapp-' prefix"
                    $vAppId = "vapp-$vAppId"
                }

                Write-Verbose "Processing snapshot for vApp/VM ID: $vAppId"

                # Build the XML body for the snapshot request
                # Note: memory, name, and quiesce are attributes, Description is a child element
                $snapshotXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<vcloud:CreateSnapshotParams xmlns:vcloud="http://www.vmware.com/vcloud/v1.5" memory="$($SnapshotMemory.IsPresent.ToString().ToLower())" name="$([System.Security.SecurityElement]::Escape($SnapshotName))" quiesce="$($Quiesce.IsPresent.ToString().ToLower())">
    <vcloud:Description>$([System.Security.SecurityElement]::Escape($Description))</vcloud:Description>
</vcloud:CreateSnapshotParams>
"@

                Write-Verbose "Snapshot XML Request:`n$snapshotXml"

                # Construct the endpoint
                $endpoint = "vApp/$vAppId/action/createSnapshot"

                # Make the API call
                Write-Verbose "Creating snapshot '$SnapshotName' for $vAppId"
                Write-Verbose "Memory: $($SnapshotMemory.IsPresent), Quiesce: $($Quiesce.IsPresent)"

                $response = Invoke-vcdRestMethod -Endpoint $endpoint -Method Post -Body $snapshotXml -ContentType 'application/vnd.vmware.vcloud.createSnapshotParams+xml'

                # Return the response (typically a Task object)
                Write-Verbose "Snapshot creation initiated successfully for $vAppId"
                $response

            }
            catch {
                Write-Error "Failed to create snapshot for $($item.id ?? $item): $($_.Exception.Message)"
                # Continue processing other items even if one fails
                continue
            }
        }
    }

    end {
        Write-Verbose "Snapshot creation process completed"
    }
}
#end region

#region Get-vcdSnapshot
function Get-vcdSnapshot {
    <#
    .SYNOPSIS
        Retrieves snapshot information for vCloud Director virtual machines or vApps

    .DESCRIPTION
        This function retrieves the list of snapshots for vCloud Director VMs or vApps using the GET /vApp/{id}/snapshotSection endpoint.
        It returns detailed information about all snapshots including creation time, size, and whether memory/quiesce was used.

        The function can process single or multiple VMs/vApps and accepts pipeline input.

    .PARAMETER VMorVApp
        The VM or vApp object(s) to retrieve snapshots for. Can be a single object or an array.
        Accepts objects with an 'id' or 'href' property containing the vApp/VM identifier.

    .EXAMPLE
        # Get snapshots for a single vApp
        $vapp | Get-vcdSnapshot

    .EXAMPLE
        # Get snapshots for multiple VMs
        $vms | Get-vcdSnapshot

    .EXAMPLE
        # Get snapshots for a specific VM by ID
        Get-vcdSnapshot -VMorVApp "vapp-12345678-1234-1234-1234-123456789abc"

    .EXAMPLE
        # Get all snapshots and display specific properties
        Get-vApps | Get-vcdSnapshot | Select-Object VMName, SnapshotName, Created, Size

    .OUTPUTS
        PSCustomObject - Returns snapshot information including:
        - VMorVAppId: The ID of the VM or vApp
        - VMorVAppName: The name of the VM or vApp (if available)
        - SnapshotName: Name of the snapshot
        - Created: When the snapshot was created
        - Size: Size of the snapshot
        - PoweredOn: Whether the VM was powered on when snapshot was taken
        - Memory: Whether memory was included in the snapshot
        - Quiesced: Whether the guest OS was quiesced

    .NOTES
        Requires an active vCloud Director session via Connect-vCloudDirector.
        Uses the legacy API endpoint: GET /vApp/{id}/snapshotSection
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('VM', 'vApp', 'Id')]
        [object[]]$VMorVApp
    )

    begin {
        # Validate that we have an active session
        if (-not $Global:vcdSession -or -not $Global:vcdSession.Headers -or -not $Global:vcdSession.BaseUrl) {
            throw "No valid vCloud Director session found. Please connect using Connect-vCloudDirector first."
        }

        Write-Verbose "Starting snapshot retrieval process"
    }

    process {
        foreach ($item in $VMorVApp) {
            try {
                # Extract the vApp/VM ID from the object
                $vAppId = $null
                $vAppName = $null

                if ($item -is [string]) {
                    # If it's a string, assume it's the ID
                    $vAppId = $item
                }
                else {
                    # Try to get the name if available
                    if ($item.name) {
                        $vAppName = $item.name
                    }

                    if ($item.id) {
                        $vAppId = $item.id
                    }
                    elseif ($item.href) {
                        # Extract ID from href (e.g., "https://vcd.example.com/api/vApp/vapp-12345")
                        if ($item.href -match '(vapp-[a-f0-9\-]+|vm-[a-f0-9\-]+)') {
                            $vAppId = $matches[1]
                        }
                    }
                }

                if ([string]::IsNullOrEmpty($vAppId)) {
                    Write-Warning "Could not extract vApp/VM ID from object. Skipping..."
                    continue
                }

                # Clean up the ID if it contains URN format
                if ($vAppId -match 'urn:vcloud:(?:vapp|vm):([a-f0-9\-]+)') {
                    $cleanId = $matches[1]
                    $vAppId = if ($vAppId -match ':vm:') { "vm-$cleanId" } else { "vapp-$cleanId" }
                }
                elseif ($vAppId -notmatch '^(vapp-|vm-)') {
                    # If it doesn't start with vapp- or vm-, try to add vapp- prefix
                    Write-Verbose "ID doesn't have expected prefix, adding 'vapp-' prefix"
                    $vAppId = "vapp-$vAppId"
                }

                Write-Verbose "Retrieving snapshots for vApp/VM ID: $vAppId"

                # Construct the endpoint
                $endpoint = "vApp/$vAppId/snapshotSection"

                # Make the API call
                $response = Invoke-vcdRestMethod -Endpoint $endpoint -Method Get

                # Parse the XML response
                if ($response) {
                    # Check if there are any snapshots
                    if ($response.SnapshotSection) {
                        $snapshotSection = $response.SnapshotSection

                        # Check if snapshots exist
                        if ($snapshotSection.Snapshot) {
                            $snapshots = $snapshotSection.Snapshot

                            # Ensure it's an array even if there's only one snapshot
                            if ($snapshots -isnot [array]) {
                                $snapshots = @($snapshots)
                            }

                            foreach ($snapshot in $snapshots) {
                                # Create a custom object with snapshot details
                                [PSCustomObject]@{
                                    VMorVAppId   = $vAppId
                                    VMorVAppName = $vAppName
                                    SnapshotName = $snapshot.name
                                    Created      = if ($snapshot.created) { [DateTime]$snapshot.created } else { $null }
                                    Size         = $snapshot.size
                                    PoweredOn    = if ($snapshot.poweredOn) { [bool]::Parse($snapshot.poweredOn) } else { $false }
                                    Memory       = if ($snapshot.memory) { [bool]::Parse($snapshot.memory) } else { $false }
                                    Quiesced     = if ($snapshot.quiesced) { [bool]::Parse($snapshot.quiesced) } else { $false }
                                    RawSnapshot  = $snapshot
                                }
                            }
                        }
                        else {
                            Write-Verbose "No snapshots found for $vAppId"
                            # Optionally return an object indicating no snapshots
                            [PSCustomObject]@{
                                VMorVAppId   = $vAppId
                                VMorVAppName = $vAppName
                                SnapshotName = $null
                                Created      = $null
                                Size         = $null
                                PoweredOn    = $null
                                Memory       = $null
                                Quiesced     = $null
                                RawSnapshot  = $null
                            }
                        }
                    }
                    else {
                        Write-Verbose "No snapshot section found for $vAppId"
                    }
                }

            }
            catch {
                Write-Error "Failed to retrieve snapshots for $($item.id ?? $item): $($_.Exception.Message)"
                # Continue processing other items even if one fails
                continue
            }
        }
    }

    end {
        Write-Verbose "Snapshot retrieval process completed"
    }
}
#end region

#region Remove-vcdSnapshot
function Remove-vcdSnapshot {
    <#
    .SYNOPSIS
        Removes (consolidates) snapshots from vCloud Director virtual machines or vApps

    .DESCRIPTION
        This function removes snapshots from vCloud Director VMs or vApps using the POST /vApp/{id}/action/consolidate endpoint.
        The consolidate operation merges the snapshot disk chain, effectively removing all snapshots and committing
        the changes back to the base disk.

        IMPORTANT: This operation removes ALL snapshots for the VM/vApp. vCloud Director does not support
        removing individual snapshots - the consolidate action removes the entire snapshot chain.

        The function can process single or multiple VMs/vApps and accepts pipeline input.

    .PARAMETER VMorVApp
        The VM or vApp object(s) to remove snapshots from. Can be a single object or an array.
        Accepts objects with an 'id' or 'href' property containing the vApp/VM identifier.

    .PARAMETER AllSnapshots
        When specified, uses the removeAllSnapshots endpoint instead of consolidate.
        The removeAllSnapshots action removes all snapshots without consolidation.

    .PARAMETER Confirm
        Prompts for confirmation before removing snapshots. This is enabled by default due to the
        destructive nature of the operation.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs without actually executing the operation.

    .EXAMPLE
        # Remove snapshots for a single vApp (with confirmation)
        $vapp | Remove-vcdSnapshot

    .EXAMPLE
        # Remove snapshots for multiple VMs without confirmation
        $vms | Remove-vcdSnapshot -Confirm:$false

    .EXAMPLE
        # Remove snapshots for a specific VM by ID
        Remove-vcdSnapshot -VMorVApp "vapp-12345678-1234-1234-1234-123456789abc"

    .EXAMPLE
        # Show what would happen without actually removing snapshots
        $vapp | Remove-vcdSnapshot -WhatIf

    .EXAMPLE
        # Remove snapshots from all VMs in a vApp
        Get-vApp | Remove-vcdSnapshot -Confirm:$false

    .EXAMPLE
        # Remove all snapshots without consolidation
        $vapp | Remove-vcdSnapshot -AllSnapshots

    .OUTPUTS
        PSObject - Returns the task object for the consolidate or removeAllSnapshots operation

    .NOTES
        Requires an active vCloud Director session via Connect-vCloudDirector.
        Uses the legacy API endpoints:
        - POST /vApp/{id}/action/consolidate (default)
        - POST /vApp/{id}/action/removeAllSnapshots (when -AllSnapshots is specified)

        WARNING: This operation removes ALL snapshots for the VM/vApp. Make sure you have
        verified the snapshots before removal as this operation cannot be undone.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('VM', 'vApp', 'Id')]
        [object[]]$VMorVApp,

        [Parameter(Mandatory = $false)]
        [switch]$AllSnapshots
    )

    begin {
        # Validate that we have an active session
        if (-not $Global:vcdSession -or -not $Global:vcdSession.Headers -or -not $Global:vcdSession.BaseUrl) {
            throw "No valid vCloud Director session found. Please connect using Connect-vCloudDirector first."
        }

        Write-Verbose "Starting snapshot removal process"
    }

    process {
        foreach ($item in $VMorVApp) {
            try {
                # Extract the vApp/VM ID from the object
                $vAppId = $null
                $vAppName = $null

                if ($item -is [string]) {
                    # If it's a string, assume it's the ID
                    $vAppId = $item
                }
                else {
                    # Try to get the name if available
                    if ($item.name) {
                        $vAppName = $item.name
                    }

                    if ($item.id) {
                        $vAppId = $item.id
                    }
                    elseif ($item.href) {
                        # Extract ID from href (e.g., "https://vcd.example.com/api/vApp/vapp-12345")
                        if ($item.href -match '(vapp-[a-f0-9\-]+|vm-[a-f0-9\-]+)') {
                            $vAppId = $matches[1]
                        }
                    }
                }

                if ([string]::IsNullOrEmpty($vAppId)) {
                    Write-Warning "Could not extract vApp/VM ID from object. Skipping..."
                    continue
                }

                # Clean up the ID if it contains URN format
                if ($vAppId -match 'urn:vcloud:(?:vapp|vm):([a-f0-9\-]+)') {
                    $cleanId = $matches[1]
                    $vAppId = if ($vAppId -match ':vm:') { "vm-$cleanId" } else { "vapp-$cleanId" }
                }
                elseif ($vAppId -notmatch '^(vapp-|vm-)') {
                    # If it doesn't start with vapp- or vm-, try to add vapp- prefix
                    Write-Verbose "ID doesn't have expected prefix, adding 'vapp-' prefix"
                    $vAppId = "vapp-$vAppId"
                }

                # Create target description for ShouldProcess
                $targetDescription = if ($vAppName) {
                    "$vAppName ($vAppId)"
                } else {
                    $vAppId
                }

                # Determine the action and endpoint based on AllSnapshots parameter
                $action = if ($AllSnapshots) {
                    "removeAllSnapshots"
                } else {
                    "consolidate"
                }
                $actionDescription = if ($AllSnapshots) {
                    "Remove all snapshots"
                } else {
                    "Remove all snapshots (consolidate)"
                }

                # Check if we should process this item
                if ($PSCmdlet.ShouldProcess($targetDescription, $actionDescription)) {
                    Write-Verbose "Processing snapshot removal for vApp/VM ID: $vAppId using action: $action"

                    # Construct the endpoint
                    $endpoint = "vApp/$vAppId/action/$action"

                    Write-Verbose "Removing snapshots for $vAppId using endpoint: $endpoint"

                    # Make the API call - both actions don't require a body
                    $response = Invoke-vcdRestMethod -Endpoint $endpoint -Method Post -ContentType 'application/vnd.vmware.vcloud.task+xml'

                    # Return the response (typically a Task object)
                    Write-Verbose "Snapshot consolidation initiated successfully for $vAppId"

                    # Add custom properties to the response for better tracking
                    if ($response) {
                        $response | Add-Member -NotePropertyName 'VMorVAppId' -NotePropertyValue $vAppId -Force -PassThru
                        if ($vAppName) {
                            $response | Add-Member -NotePropertyName 'VMorVAppName' -NotePropertyValue $vAppName -Force
                        }
                        $response
                    } else {
                        $response
                    }
                }
                else {
                    Write-Verbose "Skipped snapshot removal for $vAppId (user declined)"
                }

            }
            catch {
                Write-Error "Failed to remove snapshots for $($item.id ?? $item): $($_.Exception.Message)"
                # Continue processing other items even if one fails
                continue
            }
        }
    }

    end {
        Write-Verbose "Snapshot removal process completed"
    }
}
#end region

#region Get-vcdVApp
function Get-vcdVApp {
    <#
    .SYNOPSIS
        Retrieves vCloud Director vApp information by name using the query service

    .DESCRIPTION
        This function retrieves vApp details from vCloud Director using the query service API.
        It can search for single or multiple vApps by name and supports pipeline input.

        The function uses the vCloud Director query service endpoint which provides efficient
        searching and filtering capabilities across the vCloud Director environment.

    .PARAMETER Name
        The name(s) of the vApp(s) to retrieve. Can be a single name or an array of names.
        Supports wildcard matching using '*' character.
        If not specified, returns all vApps accessible to the user.

    .PARAMETER ExactMatch
        When specified, only returns vApps with exact name matches. By default, the function
        performs a 'contains' search (case-insensitive).

    .EXAMPLE
        # Get a specific vApp by name
        Get-vcdVApp -Name "MyApp"

    .EXAMPLE
        # Get multiple vApps by name
        Get-vcdVApp -Name "App1", "App2", "App3"

    .EXAMPLE
        # Get vApps using pipeline input
        "WebApp", "DatabaseApp" | Get-vcdVApp

    .EXAMPLE
        # Get all vApps
        Get-vcdVApp

    .EXAMPLE
        # Get vApps with exact name match
        Get-vcdVApp -Name "Production-App" -ExactMatch

    .EXAMPLE
        # Get vApps using wildcard pattern
        Get-vcdVApp -Name "Prod*"

    .OUTPUTS
        PSCustomObject - Returns vApp information including:
        - name: The vApp name
        - id: The vApp ID (urn format)
        - href: The API href for the vApp
        - status: The vApp status
        - isDeployed: Whether the vApp is deployed
        - isEnabled: Whether the vApp is enabled
        - ownerName: The owner of the vApp
        - vdc: The VDC containing the vApp
        - vdcName: The VDC name
        - numberOfVMs: Number of VMs in the vApp
        - And other available properties from the query response

    .NOTES
        Requires an active vCloud Director session via Connect-vCloudDirector.
        Uses the query service API endpoint: GET /query?type=vApp
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('vAppName', 'vApp')]
        [string[]]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$ExactMatch
    )

    begin {
        # Validate that we have an active session
        if (-not $Global:vcdSession -or -not $Global:vcdSession.Headers -or -not $Global:vcdSession.BaseUrl) {
            throw "No valid vCloud Director session found. Please connect using Connect-vCloudDirector first."
        }

        Write-Verbose "Starting vApp retrieval process"

        # Collection to store all results
        $allVApps = @()
    }

    process {
        # If no names provided, get all vApps (only once in the first process iteration)
        if (-not $Name -and $allVApps.Count -eq 0) {
            try {
                Write-Verbose "No vApp name specified, retrieving all vApps"

                # Construct the query endpoint
                $endpoint = "query?type=vApp&pageSize=128"

                Write-Verbose "Querying vApps: $endpoint"

                # Make the API call
                $response = Invoke-vcdRestMethod -Endpoint $endpoint -Method Get

                # Handle the response based on API type
                if ($Global:vcdSession.ApiType -eq 'cloudapi') {
                    # Cloud API response format
                    if ($response.values) {
                        $allVApps = $response.values
                    }
                }
                else {
                    # Legacy API response format
                    if ($response.QueryResultRecords.VAppRecord) {
                        $vAppRecords = $response.QueryResultRecords.VAppRecord

                        # Ensure it's an array
                        if ($vAppRecords -isnot [array]) {
                            $vAppRecords = @($vAppRecords)
                        }

                        $allVApps = $vAppRecords
                    }
                }

                Write-Verbose "Retrieved $($allVApps.Count) vApp(s)"

                # Return all vApps
                foreach ($vApp in $allVApps) {
                    $vApp
                }
            }
            catch {
                Write-Error "Failed to retrieve vApps: $($_.Exception.Message)"
            }
        }
        else {
            # Process each vApp name
            foreach ($vAppName in $Name) {
                try {
                    Write-Verbose "Searching for vApp: $vAppName"

                    # Build filter based on ExactMatch parameter
                    $filter = if ($ExactMatch) {
                        "name==$vAppName"
                    }
                    else {
                        # Use contains filter for partial matching
                        "name==*$vAppName*"
                    }

                    # Construct the query endpoint with filter
                    $endpoint = "query?type=vApp&filter=$([System.Web.HttpUtility]::UrlEncode($filter))&pageSize=128"

                    Write-Verbose "Query filter: $filter"
                    Write-Verbose "Query endpoint: $endpoint"

                    # Make the API call
                    $response = Invoke-vcdRestMethod -Endpoint $endpoint -Method Get

                    # Handle the response based on API type
                    $vAppRecords = @()

                    if ($Global:vcdSession.ApiType -eq 'cloudapi') {
                        # Cloud API response format
                        if ($response.values) {
                            $vAppRecords = $response.values
                        }
                    }
                    else {
                        # Legacy API response format
                        if ($response.QueryResultRecords.VAppRecord) {
                            $vAppRecords = $response.QueryResultRecords.VAppRecord

                            # Ensure it's an array
                            if ($vAppRecords -isnot [array]) {
                                $vAppRecords = @($vAppRecords)
                            }
                        }
                    }

                    if ($vAppRecords.Count -eq 0) {
                        Write-Warning "No vApp found with name: $vAppName"
                    }
                    else {
                        Write-Verbose "Found $($vAppRecords.Count) vApp(s) matching '$vAppName'"

                        # Return each matching vApp
                        foreach ($vApp in $vAppRecords) {
                            $vApp
                        }
                    }
                }
                catch {
                    Write-Error "Failed to retrieve vApp '$vAppName': $($_.Exception.Message)"
                    continue
                }
            }
        }
    }

    end {
        Write-Verbose "vApp retrieval process completed"
    }
}
#end region

