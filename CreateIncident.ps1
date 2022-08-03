Param ([String]$AlertSource,
        [ String ]$AlertName,
        [ String ] $AlertDescription,
        [ String ] $Severity,
        [ String ] $Category,
        [ String ] $LastModifiedLocal,
        [ String ] $ResolutionStateName,
        [ String ] $AlertId,
        [ String ] $ManagedEntityPath,
        [ String ] $ManagedEntityDisplayName)

$alertName = "$AlertName"
$source ="$AlertSource"
$description = "$AlertDescription"
$severity = "$Severity"
$category = "$Category"
$localTime = "$LastModifiedLocal"
$resolution = "$ResolutionStateName"
$alertid = "$AlertId"
$alertpath = "$ManagedEntityPath"
$managedEntitiyDisplayName = "$ManagedEntityDisplayName"


$severity_map = @{
        "0" = "clear"
        "1" = "major"
        "2" = "critical"
        "5" = "critical"
    }

function manipulate_path_source
{
    Param(
        $alertpath_source,
        $split_word
        )

    $splitUp = "$alertpath_source"
    $splitUp = $splitUp.ToLower().Substring(0,$splitUp.ToLower().IndexOf($split_word))
    $splitUp = $splitUp -split " " -split "\[" -split "\]" -split ";" -split "\(" -split "\)"| where {$_}
    $hostname = $splitUp | Select-Object -Last 1 
    return $hostname
}

if($alertpath.ToLower().Contains(".kfs.local")){

   $resource_name = manipulate_path_source -alertpath_source $alertpath -split_word ".kfs.local"

}elseif($alertpath.ToLower().Contains(".coda.com")){

    $resource_name = manipulate_path_source -alertpath_source $alertpath -split_word ".coda.com"

}elseif($alertpath.ToLower().Contains(".ykbdmz.com")){

    $resource_name = manipulate_path_source -alertpath_source $alertpath -split_word ".ykbdmz.com"

}elseif($alertpath.ToLower().Contains(".kfssub.local")){

    $resource_name = manipulate_path_source -alertpath_source $alertpath -split_word ".kfssub.local"


}elseif($alertpath.ToLower().Contains(".kfsnl.local")){

    $resource_name = ""

}else{

    if($managedEntitiyDisplayName.ToLower().Contains(".kfs.local")){

        $resource_name = manipulate_path_source -alertpath_source $managedEntitiyDisplayName -split_word ".kfs.local"

    }elseif($managedEntitiyDisplayName.ToLower().Contains(".coda.com")){

        $resource_name = manipulate_path_source -alertpath_source $managedEntitiyDisplayName -split_word ".coda.com"

    }elseif($managedEntitiyDisplayName.ToLower().Contains(".ykbdmz.com")){

        $resource_name = manipulate_path_source -alertpath_source $managedEntitiyDisplayName -split_word ".ykbdmz.com"

    }elseif($alertpath.ToLower().Contains(".kfssub.local")){

        $resource_name = manipulate_path_source -alertpath_source $managedEntitiyDisplayName -split_word ".kfssub.local"

    }elseif($managedEntitiyDisplayName.ToLower().Contains(".kfsnl.local")){

        $resource_name = ""

    }else{

         $resource_name = ""

    }

}

$content_Desc = @”
    "source" = $source
    "resource_name" = $resource_name
    "description" = $description
    "severity" = $($severity_map[$severity])
    "modified" = $localTime
    "type" = $resolution
    "class" = $category
    "manager" = $alertName
“@

$Proxy = New-WebServiceProxy -Uri http://cmtest.yapikredi.com.tr/wsCozumMerkezi/CmService.asmx?wsdl
$Proxy.Timeout = 60000

$Values = '' | Select-Object @{n = "Value" ;e={$resource_name}},@{n= "Key" ; e={"affected_resource"}}

write-host  $content_Desc
"`n" + $content_Desc | Out-File "c:\temp\output.txt" -Append
$ret = $Proxy.CreateRequest("430980","scom",$content_Desc,"","test","DisMusteriHizmetKesintisiYaratmaz","BazıIcMusterilerDisMusteriler","Scom",$Values)
echo $ret
$ret | Out-File "c:\temp\output.txt" -Append

# Load the OpsMgr Provider
Import-Module OperationsManager
New-SCOMManagementGroupConnection

# Locate the Specific Alert
$alert = Get-SCOMAlert -Id $alertid
$alert   | Out-File "c:\temp\output.txt" -Append
$alertid | Out-File "c:\temp\output.txt" -Append


if($ret.IsSuccess -eq 2){

    $($ret.KayitNo) + " Numaralı kayıt açılmıştır." | Out-File "c:\temp\output.txt" -Append


        $alert | Set-SCOMAlert -TicketId "$($ret.KayitNo)"
        $alert | Set-SCOMAlert -ResolutionState 236
        "Kayıt çözüm merkezinde açılmıştır.`n" | Out-File "c:\temp\output.txt" -Append


}else {
    $alert | Set-SCOMAlert -ResolutionState 0
    "Kayıt çözüm merkezinde açılamamıştır, statusu new'e çekilmiştir.`n"| Out-File "c:\temp\output.txt" -Append
}