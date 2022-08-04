[CmdletBinding()]
Param(
 
    [Parameter(Mandatory = $true)]
    [string]$WebConsole,
    [ValidateSet('New','Closed','All')]
    $ResolutionState,
    [ValidateSet('Warning','Information','Error','All')]
    $Severity,
    [pscredential]$Credential,
    [switch]$UseTls12,
    [string]$ConfigPath = '.\Config.psd1'
)
Function Get-ScomRestClass  {
    [CmdletBinding()]
   Param(

        [Parameter(Mandatory = $true)]
        [string]$WebConsole,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $SCOMHeaderObject,
        [switch]$UseTls12,
        [string]$ObjectID

    )

    
    if ($UseTls12.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/classesForObject/$ObjectID"  -Method GET -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/classesForObject/$ObjectID" -Method GET -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    }

 
    
    $Response.Rows
            
}

Function Get-ScomRestClasses  {
    [CmdletBinding()]
   Param(

        [Parameter(Mandatory = $true)]
        [string]$WebConsole,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $SCOMHeaderObject,
        [switch]$UseTls12,
        [string]$ClassID

    )
$JSonBody = @"
"Name LIKE '%'"
"@ | ConvertTo-Json
    
    if ($UseTls12.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/scomClasses"  -Method POST -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false -Body $JSonBody
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/scomClasses/" -Method Post -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false -Body $JSonBody
    }

 
    
    $Response.ScopeDatas
            
}

Function Write-Log {

    [CmdletBinding()]
    Param(
    
    
    [Parameter(Mandatory = $True)]
    [string]$Message,
    [string]$LogFilePath = "$($env:TEMP)\log_$((New-Guid).Guid).txt",
    [Switch]$DoNotRotateDaily
    )
    
    if ($DoNotRotateDaily) {

        
        $LogFilePath = if ($Script:LogFilePath) {$Script:LogFilePath} else {$LogFilePath}
            
    } else {
        if ($Script:LogFilePath) {

        $LogFilePath = $Script:LogFilePath
        $DayStamp = (Get-Date -Format 'yMMdd').Tostring()
        $Extension = ($LogFilePath -split '\.')[-1]
        $LogFilePath -match "(?<Main>.+)\.$extension`$" | Out-Null
        $LogFilePath = "$($Matches.Main)_$DayStamp.$Extension"
        
    } else {$LogFilePath}
    }
    $Log = "[$(Get-Date -Format G)][$((Get-PSCallStack)[1].Command)] $Message"
    
    Write-Verbose $Log
    $Log | Out-File -FilePath $LogFilePath -Append -Force
    
}
Function Get-ScomAlertObjects {
    [CmdletBinding()]
    Param($Alerts)
    Foreach ($Alert in $alerts) {
 
        $AlertDetail = Get-ScomRestAlertDetails -WebConsole $WebConsole -SCOMHeaderObject $SCOMHeaderObject -UseTls12 -AlertId $Alert.Id
         
         
        [PSCustomObject]@{
         
        NetBiosComputerName = $Alert.NetBiosComputerName
        Source = $AlertDetail.Source
        AlertDescription = $Alert.description
        Severity = $Alert.Severity
        TimeModified = Get-ScomRestAlertLastModified -AlertID $Alert.Id -SCOMHeaderObject $SCOMHeaderObject -UseTls12 -WebConsole $WebConsole
        ResolutionState = $Alert.ResolutionState
        AlertID = $Alert.ID
        MonitoringObjectDisplayName = $alert.MonitoringObjectDisplayName 
        MonitoringObjectPath = $Alert.monitoringobjectpath
        WorkflowName = Get-SCOMWorkflowName -AlertDetail $AlertDetail
        ClassNames = @((Get-ScomRestClass -SCOMHeaderObject $ScomHeaderOBject -WebConsole $webconsole -UseTls12 -Verbose -ObjectID $AlertDetail.sourceID).DisplayName)
        }
         
        }    
}
Function Get-DurationString {
    Param(
        [Parameter(Mandatory = $true)]
        [DateTime]$Starttime,
        [Parameter(Mandatory = $true)]
        [string]$Section,
        [Parameter(Mandatory = $true)]
        [ValidateSet('TotalHours','TotalDays','TotalMinutes','TotalSeconds','TotalMilliSeconds')]
        [String]$TimeSelector,
        [Switch]$IncludeTime
    )
        switch($TimeSelector)
        {
            'TotalHours' {$TimeSelected = 'Hours'}
            'TotalDays' {$TimeSelected = 'Days'}
            'TotalMinutes' {$TimeSelected = 'Minutes'}
            'TotalSeconds' {$TimeSelected = 'Seconds'}
            'TotalMilliSeconds' {$TimeSelected = 'MilliSeconds'}
        }        
    $Duration = [Math]::Round(((Get-Date) - $Starttime).$timeSelector)
    if($IncludeTime.IsPresent) {
    "[$(Get-Date -Format G)][$Section] Completed in  $Duration $TimeSelected."
    } else {
        "[$Section] Completed in $Duration $TimeSelected."
    }
}
Function  Get-SCOMWorkflowName {
    [CmdletBinding()]
    Param($AlertDetail)
 
    if($AlertDetail.ismonitoralert) {
        $AlertDetail.monitorName
    } else {
        $AlertDetail.ruleName
    }
 
 
}
Function Get-ScomRestAlertLastModified  {
    [CmdletBinding()]
   Param(
 
        [Parameter(Mandatory = $true)]
        [string]$WebConsole,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $SCOMHeaderObject,
        [switch]$UseTls12,
        [string]$AlertID
 
    )
 
 
    if ($UseTls12.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/alertInformation/$AlertID"  -Method Get -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/alertInformation/$AlertID" -Method Get -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    }
 
 
    
    ($Response.alertHistoryResponses.TimeModified | ForEach-Object { [datetime]$_} | Sort-Object -Descending)[0]
            
}
 Function Get-ScomRestAlertDetails {
    [CmdletBinding()]
    Param(
 
        [Parameter(Mandatory = $true)]
        [string]$WebConsole,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $SCOMHeaderObject,
        [switch]$UseTls12,
        [string]$AlertID
 
    )
 
    if ($UseTls12.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/alertDetails/$AlertID"  -Method GET -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$False
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/alertDetails/$AlertID" -Method GET -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$False
    }
 
 
    
    $Response
 
    
 
    <#
    GET http://<Servername>/OperationsManager/data/alertDetails/{alertId}
    #>
}
Function Get-SCOMHeaderObject {
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
    $URIBase = "https://$WebConsole/OperationsManager/authenticate"
    Write-Log "Authentication URL = $URIBase"
    
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
        Write-Log 'Credentials used adding.'
 
    } else {
 
        $AuthenticationParams.Add('UseDefaultCredentials',$true)
        Write-Log 'Credentials not used, using defaults.'    
    }
 
    try {
 
        # Authentication
        $Authentication = Invoke-RestMethod @AuthenticationParams 
        # Initiate the Cross-Site Request Forgery (CSRF) token, this is to prevent CSRF attacks
        $CSRFtoken = $WebSession.Cookies.GetCookies($URIBase) | Where-Object { $_.Name -eq 'SCOM-CSRF-TOKEN' }
        if ([string]::IsNullOrEmpty($CSRFtoken.value)){
         Write-Log "Could not get token or token is invalid."     
        } 
        else {
            Write-Log "Successfully got token. TokenLength : $(($CSRFtoken.value).length) characters."
        }
        Write-Log "Tokenlength from the webssion = $(($CSRFtoken.value).length)"
        $TokenLifeTimeHours = [Math]::Round((([datetime]::Parse( $Authentication.expiryTime))  - (Get-Date)).TotalHours,2)
        Write-Log "Current authentication will last for $TokenLifeTimeHours hours."
        $SCOMHeaders.Add('SCOM-CSRF-TOKEN', [System.Web.HttpUtility]::UrlDecode($CSRFtoken.Value))
        [PSCustomObject]@{
            Headers = $SCOMHeaders
            Session = $WebSession
            }
 
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
        [ValidateSet('Warning','Information','Error','All')]
        $Severity,
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        $SCOMHeaderObject,
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
    Switch ($severity)
    {
        'Error' {$Criteria = "$Criteria and (Severity = '2')"}
        'Warning' {$Criteria = "$Criteria and (Severity = '1')"} 
        'Information' {$Criteria = "$Criteria and (Severity = '0')"}
        'All' {$Criteria = $Criteria}  
        default {$Criteria = $Criteria}
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
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/alert" -Method Post -Body $JSONQuery -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    } else {
        $Response = Invoke-RestMethod -Uri "http://$WebConsole/OperationsManager/data/alert" -Method Post -Body $JSONQuery -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session -Verbose:$false
    }
 
 
    # Print out the alert results
    $Alerts = $Response.Rows
    $Alerts
    
    Write-Log "$($Alerts.Count) number of alerts returned."
 
}
#region Main
$Starttime = Get-Date
 try {
# Import Config
$config = Import-PowerShellDataFile -ErrorAction Stop -Path $ConfigPath
$LogFilePath = $config.LogFilePath
# Get Auth Header
$SCOMHeaderObject = get-SCOMHeaderObject -WebConsole $WebConsole -ErrorAction Stop
$Log = "Successfully intialized config and got authentication token."
}
Catch {
    $Log = "Could not imitialize config or could not get authenticcation token. Eror: $($error[0].Exception.Message)"
    throw $Log
}
finally {
    Write-Log $Log
    $DurationMessage = Get-DurationString -Starttime $Starttime -Section 'Script Initialization' -TimeSelector TotalSeconds
    Write-Log $DurationMessage
}
 
# get all new alerts
$AlertsStart = Get-Date
$Alerts = get-ScomRestAlert -WebConsole $WebConsole -resolutionstate $ResolutionState -SCOMHeaderObject $SCOMHeaderObject -UseTls12 -Severity $Severity
$Log = Get-DurationString -Starttime $AlertsStart -Section 'Get All Alerts' -TimeSelector TotalSeconds
Write-Log $Log
# Consolidate Alerts
$AlertDetatilStart = Get-date
$AlertObjects = Get-ScomAlertObjects -Alerts $Alerts 
$AlertObjects | Export-Clixml -Path ".\AlertObjects_$((new-guid).Guid).xml"
$Log = Get-DurationString -Starttime $AlertDetatilStart -Section 'Get Alert Details' -TimeSelector TotalSeconds
Write-Log $Log

# Get classes 
$ClassStart = Get-Date
$Classes=Get-ScomRestClasses -SCOMHeaderObject $ScomHeaderOBject -WebConsole $webconsole -UseTls12 -Verbose -ClassID '0a188da7-0273-3b4d-dde4-7bf278cbc68d'
$Log = Get-DurationString -Starttime $ClassStart -Section 'Get All Classes' -TimeSelector TotalSeconds
Write-Log $Log
# Get Alert Monitor/rule information
 
# create an alert objecct with required parameters. 
<#
    Filter Alersts based on
    1) MoitoringRuleId
    2) MonitoringClassID
    3) State = Kayit_ac
 
#>
 
 
#region Create new CA Incident
 
 
<#
$content_Desc = @â€
    "source" = $source
    "resource_name" = 
    "description" = $description
    "severity" = $($severity_map[$severity])
    "modified" = $localTime
    "type" = $resolution
    "class" = $category
    "manager" = $alertName
â€œ@
 
$Proxy = New-WebServiceProxy -Uri http://cmtest.yapikredi.com.tr/wsCozumMerkezi/CmService.asmx?wsdl
$Proxy.Timeout = 60000
 
$Values = '' | Select-Object @{n = "Value" ;e={$resource_name}},@{n= "Key" ; e={"affected_resource"}}
 
write-host  $content_Desc
"`n" + $content_Desc | Out-File "c:\temp\output.txt" -Append
$ret = $Proxy.CreateRequest("430980","scom",$content_Desc,"","test","DisMusteriHizmetKesintisiYaratmaz","BazÄ±IcMusterilerDisMusteriler","Scom",$Values)
echo $ret
$ret | Out-File "c:\temp\output.txt" -Append
#>
 
#endregion
# Set Kayit acabiladiÄŸin alertlerin resolution states to Kayit_acildi. Bunun iÃ§in AlertIds diye bir fieldda alertidleri gÃ¶ndermen yeterli. 
 
<#
POST http://<Servername>/OperationsManager/data/alertResolutionStates
 
{
  "alertIds": [
    "667736a8-d59a-407b-b142-80fd74ba4041"
  ],
  "resolutionState": 249,
  "comment": "Acko"
}
#>
 
 
 
$Log = Get-DurationString -Starttime $Starttime -Section 'Script main' -TimeSelector TotalSeconds
Write-Log $Log
#endregion 
 
