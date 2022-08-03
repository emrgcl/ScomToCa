[Ccmdletbinding()]
Param($webConsole,$AlertID)
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
$ScomHEaSCOMHeaderObjectderObject = Get-SCOMHeaderObject -webConsole $webConsole
#http://<Servername>/OperationsManager/data/alertInformation/{alertId}
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    $Response = Invoke-RestMethod -Uri "https://$WebConsole/OperationsManager/data/alertInformation/$AlertID" -Method Post -ContentType "application/json" -Headers $SCOMHeaderObject.Headers -WebSession $SCOMHeaderObject.Session
    

    # Print out the alert results
    $Response.Rows
    