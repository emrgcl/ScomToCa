[CmdletBinding()]
Param(

    [Parameter(Mandatory = $true)]
    [string]$WebConsole,
    [ValidateSet('New','Closed','All')]
    $ResolutionState,
    [pscredential]$Credential,
    [switch]$UseTls12,
    [string]$CconfigPath = '.\Config.psd1'

Function Get-SCOMHeaders {
    [Cmdletbinding()]
    Param(

        [string]$WebConsole
    )

    $SCOMHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $SCOMHeaders.Add('Content-Type', 'application/json; charset=utf-8')
    $BodyRaw = "Windows"
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($BodyRaw)
    $EncodedText = [Convert]::ToBase64String($Bytes)
    $JSONBody = $EncodedText | ConvertTo-Json
    
    # The SCOM REST API authentication URL
    $URIBase = "http://$WebConsole/OperationsManager/authenticate"
    Write-Verbose "Authentication URL = $URIBase"
    
    $AuthenticationParams = @{

        Method = 'Post'
        Uri = $URIBase
        Headers = $SCOMHeaders
        Body = $JSONBody
        SessionVariable = 'WebSession'
        ErrorAction = 'Stop'

    }

    if ($Credential -and $Credential -is [pscredential]) {

        $AuthenticationParams.Add('Credential',$Credential)
        Write-Verbose 'Credentials used adding.'

    } else {

        $AuthenticationParams.Add('UseDefaultCredentials',$true)
        Write-Verbose 'Credentials not used, using defaults.'    
    }

    try {

        # Authentication
        $Authentication = Invoke-RestMethod @AuthenticationParams
        # Initiate the Cross-Site Request Forgery (CSRF) token, this is to prevent CSRF attacks
        $CSRFtoken = $WebSession.Cookies.GetCookies($URIBase) | Where-Object { $_.Name -eq 'SCOM-CSRF-TOKEN' }
        Write-Verbose "Token from the webssion = $($CSRFtoken.Value)"
        $TokenLifeTimeHours = [Math]::Round((([datetime]::Parse( $Authentication.expiryTime))  - (Get-Date)).TotalHours,2)
        Write-Verbose "Current authentication will last for $TokenLifeTimeHours hours."
        $SCOMHeaders.Add('SCOM-CSRF-TOKEN', [System.Web.HttpUtility]::UrlDecode($CSRFtoken.Value))
        $SCOMHeaders

    }
    Catch {

        throw "Could not authenticate, Exiting. Error: $($_.Exception.Message)"

    }
    # The query which contains the criteria for our alerts
}

Function Get-ScomRestAlert {
     [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true)]
        [string]$WebConsole,
        [ValidateSet('New','Closed','All')]
        $ResolutionState,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $ScomHeaders,
        [switch]$UseTls12

    )

   
    # Set the Header and the Body

    switch ($ResolutionState)
    {
        'New' {$Criteria = "(ResolutionState = '0')"}
        'Closed' {$Criteria = "(ResolutionState = '255')"}
        'All' {$Criteria = "(ResolutionState = '0') or (ResolutionState = '255')"}
        Default {$Criteria = "(ResolutionState = '0') or (ResolutionState = '255')"}
    }
    $Query = @(@{         
            
            'classId' = ''
            # Get all alerts with severity '2' (critical) and resolutionstate '0' (new)
            'criteria' = $Criteria
            'displayColumns' ='severity','monitoringobjectdisplayname','monitoringobjectpath','name','age','description','owner','timeadded','repeatcount','netbioscomputername','netbiosdomainname','ismonitoralert','resolutionstate','MonitoringClassId','MonitoringRuleId'
    })
    
    # Convert our query to JSON format
    $JSONQuery = $Query | ConvertTo-Json

    if ($UseTls12.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/alert" -Method Post -Body $JSONQuery -ContentType "application/json" -Headers $SCOMHeaders -WebSession $WebSession
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/alert" -Method Post -Body $JSONQuery -ContentType "application/json" -Headers $SCOMHeaders -WebSession $WebSession
    }


    # Print out the alert results
    $Alerts = $Response.Rows
    $Alerts
    $ScriptDurationSeconds = [Math]::Round(((Get-Date) - $Starttime).TotalSeconds)
    Write-Verbose "$($Alerts.Count) number of alerts returned."

}
#region Main
$Starttime = Get-Date
 
 try {
# Import Config
$config = Import-PowerShellDataFile -ErrorAction Stop -Path $CconfigPath

# Get Auth Header
$ScomHeaders = Get-ScomHeaders -WebConsole $WebConsole -ErrorAction Stop
$Log = "[$(Get-Date -Format G)] Successfully intialized config and got authentication token."
 }
 Catch {
    $Log = "[$(Get-Date -Format G)] Could not imitialize config or could not get authenticcation token. Eror: $($error[0].Exception.Message)"
 }
 finally {
    Write-Verbose $Log
 }
 

# get all new alerts
$Alerts = get-ScomRestAlert -WebConsole $WebConsole -resolutionstate 'New' -ScomHeaders $ScomHeaders -UseTls12

$Alerts
<#
    Filter Alersts based on
    1) MoitoringRuleId
    2) MonitoringClassID
    3) State = Kayit_ac

#>


# Create new CA Incident
# Set Kayit acabiladiğin alertlerin resolution states to Kayit_acildi



Write-Verbose "Script ended. Duration $ScriptDurationSeconds seconds."
#endregion