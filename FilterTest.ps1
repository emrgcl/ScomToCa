Function Test-ClassName{
    [CmdletBinding()]
    Param(
        $ClassNames,
        $Config
    )

    $Result = $ClassNames | Where-Object {$_ -in $COnfig.ClassNames}
    -not [string]::IsNullOrEmpty($Result)
}

$Config = Import-PowerShellDataFile -Path .\Config.psd1
$AlertObjects = Import-Clixml -Path C:\temp\AlertObjects_9f78ae5d-e955-42b6-878b-ce95877178ac.xml
$Result = $AlertObjects | Where-Object { (Test-ClassName -ClassNames $_.ClassNames -Config $Config) -or ($_.WorkflowName -in $Config.WorkflowNames) }
,
[PsCustomObject]@{
    TotalCount = $AlertObjects.Count
    FilteredCount = $Result.Count

}