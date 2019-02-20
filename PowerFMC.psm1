function New-FMCAuthToken           {
<#
 .SYNOPSIS
Obtains Domain UUID and X-auth-access-token
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API, authenticate, and provide an X-auth-access-token and
Domain UUID for use in other functions
 .EXAMPLE
New-FMCAuthToken -fmcHost 'https://fmcrestapisandbox.cisco.com' -username 'davdecke' -password 'YDgQ7CBR'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost=$env:FMCHost,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Username,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            $Password=(Get-Credential -UserName $Username -Message "Enter Credentials for $FMCHost").GetNetworkCredential().password

    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
     }
Process {
$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$uri = "$FMCHost/api/fmc_platform/v1/auth/generatetoken"
$headers = @{ Authorization = "Basic $encodedCredentials" }
$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post
$Domain =  $AuthResponse.Headers.Item('DOMAIN_UUID')
$AuthToken = $AuthResponse.Headers.Item('X-auth-access-token')
        }
End {
$output = New-Object -TypeName psobject
$output | Add-Member -MemberType NoteProperty -Name fmcHost            -Value $FMCHost
$output | Add-Member -MemberType NoteProperty -Name Domain             -Value $Domain
$output | Add-Member -MemberType NoteProperty -Name AuthAccessToken    -Value $AuthToken
$env:FMCHost      = $output.FMCHost
$env:FMCDomain    = $output.Domain
$env:FMCAuthToken = $output.AuthAccessToken
$output
    }
}
function New-FMCObject              {
<#
 .SYNOPSIS
Post a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API containing custom data
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
New-FMCObject -uri $uri -object ($body | ConvertTo-Json) -AuthToken 637a1b3f-787b-4179-be40-e19ee2aa9e60
 .PARAMETER uri
Resource location
 .PARAMETER object
JSON data
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$object,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken"
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $object
        }
End     {
$response
        }
}
function New-FMCNetworkObject       {
<#
 .SYNOPSIS
Create network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and add items under /object/networks
 .EXAMPLE
New-FMCNetworkObject -name 'PowerFMC_Net' -Network '172.21.33.0/24' -description 'Test Network for PowerFMC'

New-FMCNetworkObject -name 'PowerFMC_Host' -Network '172.21.33.7' -description 'Test Host for PowerFMC'

New-FMCNetworkObject -name 'PowerFMC_Range' -Network '172.21.33.100-172.21.33.200' -description 'Test Range for PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network, host, or range dotted-decimal IP and CIDR notation for mask
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [alias("value")]
            [string]$Network,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
if ($network -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$')                                 {
    $uri  = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networks"
    $type = 'network'
    }
if ($network -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/32$') {
    $uri  = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/hosts" 
    $type = 'host'
    }
if ($network -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')      {
    $uri  = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/ranges"
    $type = 'range'
    }

$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name        -Value $Name
$body | Add-Member -MemberType NoteProperty -name value       -Value "$Network"
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name type        -Value $type
if ($JSON) {$uri ; $body | ConvertTo-Json} else {
Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
       }
      }
End {}
}
function New-FMCNetworkGroup        {
<#
 .SYNOPSIS
Create network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Network Groups
 .EXAMPLE
New-FMCNetworkGroup -Members 'PowerFMC_Host,PowerFMC_Net,PowerFMC_Range' -Name 'PowerFMC_Group1' -Description 'Group containing objects'

New-FMCNetworkGroup -Members '10.10.10.0/24,20.20.20.20,30.30.30.100-30.30.30.200' -Name 'PowerFMC_Group2' -Description 'Group containing literals'

New-FMCNetworkGroup -Members '1.1.1.1,PowerFMC_Host' -Name 'PowerFMC_Group2' -Description 'Group containing objects and literals'

New-FMCNetworkGroup -Name Objects -Members (((Get-FMCNetworkObject Net0*).name) -join ',') -Description 'Group containin objects that begin with "Net0"'

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Members
Member objects or literal networks/hosts/ranges
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('true','false')] 
            [string]$Overridable='false',
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$literals = @()
$objects  = @()
$range    = @()

$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'

$MemberArray = $Members -split ','
$MemberArray | foreach {
             if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
              if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$') {$literals += $_}
              if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')            {$range += $_}
              } else {$objects += $_}
               
             }
if ($objects) {
 $NetworkObjects = Get-FMCNetworkObject -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain -Terse
 $Debug = $objects
 $NetObj = @()
    $objects | foreach {
    $id = $NetworkObjects | Where-Object -Property name -EQ $_
    $id = $id.id
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name id -Value $id
    $NetObj += $obj
    }
}

if ($range) {
$range | foreach {
 [Net.IPAddress]$beginIP = $range.Split('-')[0]
 [Net.IPAddress]$finshIP = $range.Split('-')[1]

 $beginBytes = $beginIP.GetAddressBytes()
 [int64]$beginInt = ([int64]$beginBytes[0]*16777216)+([int64]$beginBytes[1]*65536)+([int64]$beginBytes[2]*256)+([int64]$beginBytes[3])

 $finshBytes = $finshIP.GetAddressBytes()
 [int64]$finishInt = ([int64]$finshBytes[0]*16777216)+([int64]$finshBytes[1]*65536)+([int64]$finshBytes[2]*256)+([int64]$finshBytes[3])

 for ($int = $beginInt; $int -le $finishInt; $int++) {
  $IPAddress = @()
  $oct1 = ([math]::truncate($int/16777216)).tostring()
  $oct2 = ([math]::truncate(($int%16777216)/65536)).tostring()
  $oct3 = ([math]::truncate(($int%65536)/256)).tostring()
  $oct4 = ([math]::truncate($int%256)).tostring()
  $IPAddress = $oct1+'.'+$oct2+'.'+$oct3+'.'+$oct4
  $literals += $IPAddress
     }
    }
   }
if ($literals) {
 $NetLit = @()
    $literals | foreach {
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name value -Value $_
    $NetLit += $obj
    }
}

 }
End {
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "NetworkGroup"
if ($objects)  {$body | Add-Member -MemberType NoteProperty -name objects  -Value $NetObj}
if ($literals) {$body | Add-Member -MemberType NoteProperty -name literals -Value $NetLit}
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value $Description
$body | Add-Member -MemberType NoteProperty -name name        -Value $Name
if ($JSON) {($body | ConvertTo-Json)} else {
Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json) }

 }
}
function New-FMCPortObject          {
<#
 .SYNOPSIS
Create Port objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and add items under /object/protocolportobjects
 .EXAMPLE
New-FMCPortObject -Name PowerFMC_Test123 -protocol TCP -port 123
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Protocol
Protocol name; e.g. TCP, UDP
 .PARAMETER Port
Port number
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Protocol,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Port,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$Name    = $Name -replace '(\\|\/|\s)','_'
if ($Port -match '^\d+\-\d+$') {
 if  ($port.Split('-')[0] -eq $port.Split('-')[1]) { $Port = $port.Split('-')[0] } 
  }
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name        -Value "$Name"
$body | Add-Member -MemberType NoteProperty -name protocol    -Value "$protocol"
$body | Add-Member -MemberType NoteProperty -name port        -Value "$port"
$body | Add-Member -MemberType NoteProperty -name type        -Value "ProtocolPortObject"
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
if ($JSON) {$body | ConvertTo-Json} else {
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
                     }
$response
        }
End     {}
}
function New-FMCPortGroup           {
<#
 .SYNOPSIS
Create port groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Port Groups
 .EXAMPLE
New-FMCPortGroup -Name PowerFMC_PortGroup -Members 'PowerFMC_Test123,PowerFMC_Test567' -Description 'Group with two objects'

New-FMCPortGroup -Name PowerFMC_PortGroup -Members 'tcp/55,udp/100-110,PowerFMC_Test567' -Description 'Mixed objects/literals'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$Name = $Name -replace '(\\|\/|\s)','_'

$PortObjects  = Get-FMCPortObject -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain -Terse
$PortObjects += Get-FMCPortGroup  -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain
$objects = @()
$Members.Split(',') | foreach {
   $member = $_ -replace '\\|\/|\s','_'
   $PortObject = @()
   $PortObject = $PortObjects | Where-Object -Property name -EQ $member
   if (!$PortObject.id) {Write-Host "Object $member does not exist" -ForegroundColor Yellow} else {
    if ($PortObject.type -like "*Group*") { 
     $PortObject.objects | foreach {
      $id   = $_.id
      $type = $_.type
      $object = New-Object psobject
      $object | Add-Member -MemberType NoteProperty -Name type -Value $type
      $object | Add-Member -MemberType NoteProperty -Name id   -Value $id
      $objects += $object
      }
     } else {
    $id   = $PortObject.id
    $type = $PortObject.type
    $object = New-Object psobject
    $object | Add-Member -MemberType NoteProperty -Name type -Value $type
    $object | Add-Member -MemberType NoteProperty -Name id   -Value $id
    $objects += $object}
    }
  }
 
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "PortObjectGroup"
$body | Add-Member -MemberType NoteProperty -name objects     -Value $objects
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name name        -Value "$Name"
if ($JSON) {($body | ConvertTo-Json)} else {
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
 }
$response
        }
End {}
}
function New-FMCAccessPolicy        {
    <#
 .SYNOPSIS
Creates a new acccess policy
 .DESCRIPTION
Invokes a REST post method to create a new access policy
 .EXAMPLE
New-FMCAccessPolicy -Name PowerFMC_AccessPolicy -Description 'Access Policy Created with PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of access policy
 .PARAMETER ParentPolicy
Parent policy to inherit from
 .PARAMETER IntrusionPolicy
Name of default intrusion policy
/#>
    
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$ParentPolicy,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IntrusionPolicy="No Rules Active",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$LogBegin="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$LogEnd="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SendEventsToFMC="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain"
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$IPID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$IP = New-Object -TypeName psobject
$IP | Add-Member -MemberType NoteProperty -name id -Value $IPID.id
$DefAct = New-Object -TypeName psobject
$DefAct | Add-Member -MemberType NoteProperty -name intrusionPolicy -Value $IP
$DefAct | Add-Member -MemberType NoteProperty -name type            -Value AccessPolicyDefaultAction
$DefAct | Add-Member -MemberType NoteProperty -name logBegin        -Value $LogBegin
$DefAct | Add-Member -MemberType NoteProperty -name logEnd          -Value $LogEnd
$DefAct | Add-Member -MemberType NoteProperty -name sendEventsToFMC -Value $SendEventsToFMC

$body = New-Object -TypeName psobject
if ($ParentPolicy) {
    $Parent = Get-FMCAccessPolicy -Name $ParentPolicy -AuthToken $AuthToken -Domain $Domain -FMCHost $FMCHost -Terse
    $ParentID = New-Object psobject
    $ParentID | Add-Member -MemberType NoteProperty -Name type -Value AccessPolicy
    $ParentID | Add-Member -MemberType NoteProperty -Name name -Value $Parent.name
    $ParentID | Add-Member -MemberType NoteProperty -Name id   -Value $Parent.id
    $metadata = New-Object psobject
    $metadata | Add-Member -MemberType NoteProperty -Name inherit      -Value $true
    $metadata | Add-Member -MemberType NoteProperty -Name parentPolicy -Value $ParentID
    $body     | Add-Member -MemberType NoteProperty -name metadata     -Value $metadata
    $type = 'AccessPolicy'
                   } else {$type = 'AccessPolicyDefaultAction'}
$body | Add-Member -MemberType NoteProperty -name type           -Value $type
$body | Add-Member -MemberType NoteProperty -name name           -Value "$Name"
$body | Add-Member -MemberType NoteProperty -name description    -Value "$Description"
$body | Add-Member -MemberType NoteProperty -name defaultAction  -Value $DefAct

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
        }
End     {}
}
function New-FMCAccessPolicyRule    {
        <#
 .SYNOPSIS
Creates a new acccess policy rule
 .DESCRIPTION
Invokes a REST post method to post new rules into an access policy.
Allow for bulk rule import via pipeline. 
 .EXAMPLE
$csv = Import-Csv .\Book1.csv
$csv[1]

AccessPolicy        : TST1111
Name                : BulkTest2
Action              : BLOCK_RESET
Enabled             : True
SourceZones         : MC-INSIDE
DestinationZones    : MC-OUTSIDE
SourceNetworks      : 100.1.1.2
DestinationNetworks : 200.1.1.2
DestinationPorts    : tcp/112,udp/1002

$csv | New-FMCAccessPolicyRule
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Rule Name
 .PARAMETER AccessPolicy
Access policy rule will belong to
 .PARAMETER Action
Action rule will take (e.g. Allow or Block)
 .PARAMETER SourceZones
Source zone. Multiple items must be separated by commas
 .PARAMETER DestinationZones
Destination zone. Multiple items must be separated by commas
 .PARAMETER SourceNetworks
Source network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER DestinationNetworks
Destination network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER SourcePorts
Source port(s). Multiple items must be separated by commas
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER DestinationPorts
Destination port(s). Multiple items must be separated by commas.
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER Enabled
Sets enable parameter to true or false (true by default)
 .PARAMETER IntrusionPolicy
Selects the IPS policy for the rule
/#>

    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$RuleName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AccessPolicy,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("ALLOW","TRUST","MONITOR","BLOCK","BLOCK_RESET","BLOCK_INTERACTIVE","BLOCK_RESET_INTERACTIVE")] 
            [string]$Action,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourceZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourceNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$SourcePorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DestinationPorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("True","False")] 
            [string]$Enabled='True',

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IntrusionPolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("True","False")] 
           [string]$LogBegin='False',

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("True","False")] 
            [string]$LogEnd='False',

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("True","False")] 
            [string]$SendEventsToFMC='False',

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Syslog,

       # [Parameter(ParameterSetName="SectionOnly",    Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="SectionBefore",  Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="BeforeOnly", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Mandatory","Default")]
            [string]$section,

       # [Parameter(ParameterSetName="CategoryOnly",   Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="CategoryBefore", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="BeforeOnly", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$category,

       # [Parameter(ParameterSetName="SectionAfter",   Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="CategoryAfter",  Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="BeforeOnly", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
               [int]$insertAfter,

       # [Parameter(ParameterSetName="SectionBefore",  Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="CategoryBefore", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
       # [Parameter(ParameterSetName="BeforeOnly", Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
               [int]$insertBefore,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$comment,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
    
        [Parameter(DontShow)]
            [switch]$JSON

    )
Begin   {
$FMCErrors = @()
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$AllZones        = Get-FMCZone -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$AllNetObjects   = @()
$AllNetObjects   = Get-FMCNetworkObject -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$AllNetObjects  += Get-FMCNetworkGroup  -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$AllPortObjects  = @()
$AllPortObjects  = Get-FMCPortObject -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$AllPortObjects += Get-FMCPortGroup  -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$SyslogAlerts    = Get-FMCObject -uri "$env:FMCHost/api/fmc_config/v1/domain/$env:FMCDomain/policy/syslogalerts" -AuthToken $env:FMCAuthToken
         }
Process {
$policyUUID = (Get-FMCAccessPolicy -Name $AccessPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse).id

if ($category -and $insertBefore -and !$qParams)  { $qParams = "?category=$category&insertBefore=$insertBefore" } 
if ($section  -and $insertBefore -and !$qParams)  { $qParams = "?section=$section&insertBefore=$insertBefore" } 
if ($category -and $insertAfter  -and !$qParams)  { $qParams = "?category=$category&insertAfter=$insertAfter" } 
if ($section  -and $insertAfter  -and !$qParams)  { $qParams = "?section=$section&insertAfter=$insertAfter" }  
if ($category -and !$qParams)                     { $qParams = "?category=$category" } 
if ($section  -and !$qParams)                     { $qParams = "?section=$section" }  
if ($insertAfter  -and !$qParams)                 { $qParams = "?insertAfter=$insertAfter" } 
if ($insertBefore -and !$qParams)                 { $qParams = "?insertBefore=$insertBefore" } 

$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$policyUUID/accessrules$qParams"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
## Parsing Source or destination Security Zones

if ($SourceZones -or $DestinationZones) {
 if ($SourceZones)      {
 $SourceZones_split = $SourceZones -split ',|,\n|\n'
 $sZ = @()
 $SourceZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $sZ += $Zone
               }
$sZones = New-Object psobject
$sZones | Add-Member -MemberType NoteProperty -Name objects -Value $sZ
 }
 if ($DestinationZones) {
$DestinationZones_split = $DestinationZones -split ',|,\n|\n'
$dZ = @()
$DestinationZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $dZ += $Zone
               }
$dZones = New-Object psobject
$dZones | Add-Member -MemberType NoteProperty -Name objects -Value $dZ
 }
}
## /Parsing Source or destination Security Zones

## Parsing Source or destination networks
if ($SourceNetworks -or $DestinationNetworks) {
 if ($SourceNetworks)      {
$literals     = @()
$objects      = @()
$SourceNetObj = @()
$SourceNetLit = @()
$SourceNetworks = $SourceNetworks.TrimStart(' ')
$SourceNetworks = $SourceNetworks.TrimEnd(' ')
$SourceNetworks_split = (($SourceNetworks -split ',|,\n|\n').TrimStart(' ')).TrimEnd(' ')
$SourceNetworks_split | foreach {
                     if ($_ -match '(^(\d{1,3}\.){3}\d{1,3}$|^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^(\d{1,3}\.){3}\d{1,3}\-(\d{1,3}\.){3}\d{1,3})') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourceNetObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type  -Value ""
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $SourceNetLit += $Obj
                              }

                }
 $sNets = New-Object psobject 
 if ($SourceNetObj) { $sNets | Add-Member -MemberType NoteProperty -Name objects  -Value $SourceNetObj }
 if ($SourceNetLit) { $sNets | Add-Member -MemberType NoteProperty -Name literals -Value $SourceNetLit }
 }
 if ($DestinationNetworks) {
$literals     = @()
$objects      = @()
$DestinationNetObj = @()
$DestinationNetLit = @()
$DestinationNetworks = $DestinationNetworks.TrimStart(' ')
$DestinationNetworks = $DestinationNetworks.TrimEnd(' ')
$DestinationNetworks_split = (($DestinationNetworks -split ',|,\n|\n').TrimStart(' ')).TrimEnd(' ')
$DestinationNetworks_split | foreach {
                     if ($_ -match '(^(\d{1,3}\.){3}\d{1,3}$|^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^(\d{1,3}\.){3}\d{1,3}\-(\d{1,3}\.){3}\d{1,3})') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationNetObj += $Obj
            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type  -Value ""
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $DestinationNetLit += $Obj
                              }

                }
 $dNets = New-Object psobject 
 if ($DestinationNetObj) { $dNets | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationNetObj }
 if ($DestinationNetLit) { $dNets | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationNetLit }
 }

}
## /Parsing Source or destination networks

## Parsing Source or destination ports
if ($SourcePorts -or $DestinationPorts) {
 if ($SourcePorts) {
$literals     = @()
$objects      = @()
$SourcePortObj = @()
$SourcePortLit = @()
$SourcePorts = $SourcePorts.TrimStart(' ')
$SourcePorts = $SourcePorts.TrimEnd(' ')
$SourcePorts_split = $SourcePorts -split ',|,\n|\n'
$SourcePorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            if ($MasterProtocolListByName[$_]) { $literals += $_} else {
            $i = $AllPortObjects | Where-Object -Property name -EQ ($_ -replace '\s|\\|\/','_')
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourcePortObj += $Obj}
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $MasterProtocolListByName[$i[0]]
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $SourcePortLit += $Obj
                              }
 $sPorts = New-Object psobject 
 if ($SourcePortObj) { $sPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $SourcePortObj }
 if ($SourcePortLit) { $sPorts | Add-Member -MemberType NoteProperty -Name literals -Value $SourcePortLit }
                }
 }
 if ($DestinationPorts) {
$literals     = @()
$objects      = @()
$DestinationPortObj = @()
$DestinationPortLit = @()
$DestinationPorts = $DestinationPorts.TrimStart(' ')
$DestinationPorts = $DestinationPorts.TrimEnd(' ')
$DestinationPorts_split = $DestinationPorts -split ',|,\n|\n'
$DestinationPorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            if ($MasterProtocolListByName[$_]) { $literals += $_} else {
            $i = $AllPortObjects | Where-Object -Property name -EQ ($_ -replace '\s|\\|\/','_')
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationPortObj += $Obj}
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $MasterProtocolListByName[$i[0]]
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $DestinationPortLit += $Obj
                              }

                }
 $dPorts = New-Object psobject 
 if ($DestinationPortObj) { $dPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationPortObj }
 if ($DestinationPortLit) { $dPorts | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationPortLit }
 }


}
## /Parsing Source or destination ports

if ($Syslog) {
 $SyslogItem = New-Object psobject
 $SyslogItem | Add-Member -MemberType NoteProperty -Name name -Value ($SyslogAlerts.items | where {$_.name -eq $Syslog}).name
 $SyslogItem | Add-Member -MemberType NoteProperty -Name id   -Value ($SyslogAlerts.items | where {$_.name -eq $Syslog}).id
 $SyslogItem | Add-Member -MemberType NoteProperty -Name type -Value ($SyslogAlerts.items | where {$_.name -eq $Syslog}).type
 }
if ($IntrusionPolicy) {
$ipsPolicyID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$ipsPolicy = New-Object -TypeName psobject
$ipsPolicy | Add-Member -MemberType NoteProperty -name name -Value $ipsPolicyID.name
$ipsPolicy | Add-Member -MemberType NoteProperty -name id   -Value $ipsPolicyID.id
$ipsPolicy | Add-Member -MemberType NoteProperty -name type -Value $ipsPolicyID.type
}

if ($comment) {$comments = New-Object -TypeName psobject @{newComments = $comment}}
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type            -Value 'AccessRule'
$body | Add-Member -MemberType NoteProperty -name enabled         -Value (Get-Culture).TextInfo.ToTitleCase($Enabled.tolower())
$body | Add-Member -MemberType NoteProperty -name name            -Value $RuleName
$body | Add-Member -MemberType NoteProperty -name action          -Value $Action
if ($ipsPolicy) { $body | Add-Member -MemberType NoteProperty -name ipsPolicy            -Value $ipsPolicy }
if ($sZones)    { $body | Add-Member -MemberType NoteProperty -name sourceZones          -Value $sZones }
if ($dZones)    { $body | Add-Member -MemberType NoteProperty -name destinationZones     -Value $dZones }
if ($sNets)     { $body | Add-Member -MemberType NoteProperty -name sourceNetworks       -Value $sNets }
if ($dNets)     { $body | Add-Member -MemberType NoteProperty -name destinationNetworks  -Value $dNets }
if ($sPorts)    { $body | Add-Member -MemberType NoteProperty -name sourcePorts          -Value $sPorts }
if ($dPorts)    { $body | Add-Member -MemberType NoteProperty -name destinationPorts     -Value $dPorts }
if ($Syslog)    { $body | Add-Member -MemberType NoteProperty -name syslogConfig         -Value $SyslogItem }
$body | Add-Member -MemberType NoteProperty -name logBegin        -Value (Get-Culture).TextInfo.ToTitleCase($logBegin.tolower())
$body | Add-Member -MemberType NoteProperty -name logEnd          -Value (Get-Culture).TextInfo.ToTitleCase($logEnd.tolower())
$body | Add-Member -MemberType NoteProperty -name sendEventsToFMC -Value (Get-Culture).TextInfo.ToTitleCase($SendEventsToFMC.tolower())
if ($comment) {$body | Add-Member -MemberType NoteProperty -name newComments -Value $comments.Values}
if ($JSON) {$uri ; ($body | ConvertTo-Json -Depth 5)} else {
try {
 Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
    } catch {
       Write-Host "$RuleName could not be created:" -ForegroundColor DarkRed -BackgroundColor White
       Write-Host $_.Exception.Message -ForegroundColor DarkRed -BackgroundColor White
       $e = New-Object psobject
       $e | Add-Member -MemberType NoteProperty -Name Rule -Value $RuleName
       $e | Add-Member -MemberType NoteProperty -Name URI  -Value $uri
       $e | Add-Member -MemberType NoteProperty -Name JSON -Value ($body | ConvertTo-Json -Depth 5)
       $FMCErrors += $e
            }
                                                           } 
        }
End     {
if ($FMCErrors) {
 
 }

}
}
function Get-FMCObject              {
    <#
 .SYNOPSIS
Post a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST get against the FMC API path
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
Get-FMCObject -uri $uri
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken"
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        }
End     {
$response
        }
}
function Get-FMCNetworkObject       {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
Get-FMCNetworkObject

Get-FMCNetworkObject -Name NetworkObject1

Get-FMCNetworkObject -Name NetworkObject*

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkaddresses?offset=0&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkaddresses?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }

$NetObjects      = $items | Where-Object {$_.name -like $Name}
$NetObjects 
        }
End {}
}
function Get-FMCNetworkGroup        {
<#
 .SYNOPSIS
Displays network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networkgroups
 .EXAMPLE
# Get-FMCNetworkObject
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Terse
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=0&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
 $NetObjects      = $items | Where-Object {$_.name -like $Name}
        }
End {
$NetObjects 
    }
}
function Get-FMCPortObject          {
    <#
 .SYNOPSIS
Displays port objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve port objects
 .EXAMPLE
Get-FMCPortObject -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'YDgQ7CBR' -Name PowerFMC*
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of port object(s). Wildcards accepted
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
        }
Process {
$offset = 0
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects?offset=$offset&limit=25&expanded=$Expanded"
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/protocolportobjects?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = @()
$offset = 0
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects?offset=$offset&limit=25&expanded=$Expanded"
$response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response_icmp.paging.pages
$items += $response_icmp.items
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/icmpv4objects?offset=$offset&limit=25&expanded=$Expanded"
    $response_icmp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response_icmp = @()
$PortObj = $items | Where-Object {$_.name -like $Name}
        }
End {
$PortObj 
    }
}
function Get-FMCPortGroup           {
    <#
 .SYNOPSIS
Displays port group objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve port group objects
 .EXAMPLE
Get-FMCPortObject -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'YDgQ7CBR' -Name PowerFMC*
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of port group object(s). Wildcards accepted
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Terse
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
      }
Process {
 [int]$offset = 0
 $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups?offset=$offset&limit=25&expanded=$Expanded"
 $headers     = @{ "X-auth-access-token" = "$AuthToken" }
 $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
 [int]$pages  = $response.paging.pages
 [int]$offset = 0
 $items       = $response.items
 while ($pages -gt 1) {
    [int]$offset = $offset+25
    $uri         = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/portobjectgroups?offset=$offset&limit=25&expanded=$Expanded"
    $response    = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items      += $response.items
    $pages--
                      }
 $NetObjects     = $items | Where-Object {$_.name -like $Name}
        }
End {
$NetObjects 
    }
}
function Get-FMCAccessPolicy        {
    <#
 .SYNOPSIS
Displays access policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve access policies
 .EXAMPLE
 $a | Get-FMCAccessPolicy -Name PowerFMC_Policy
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of access policy. Wildcards accepted
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like $Name
        }
End     {
$response
        }
}
function Get-FMCIntrusionPolicy     {
    <#
 .SYNOPSIS
Displays intrusion policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve intrusion policies
 .EXAMPLE
 Get-FMCIntrusionPolicy -AuthToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of intrusion policy. Wildcards accepted
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/intrusionpolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/intrusionpolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
        }
End     {
$response
        }
}
function Get-FMCFilePolicy          {
    <#
 .SYNOPSIS
Displays file policies in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve file policies
 .EXAMPLE
 Get-FMCFilePolicy -AuthToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of file policy. Wildcards accepted
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/filepolicies?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/filepolicies?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
        }
End     {
$response
        }
}
function Get-FMCAccessPolicyRule    {
    <#
 .SYNOPSIS
Displays rules in an access policy
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve access policy rules
 .EXAMPLE
$a | Get-FMCAccessPolicyRule -AccessPolicy PowerFMC_AccessPolicy
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER AccessPolicy
Name of the access policy to query
 .PARAMETER RuleName
Name of the rule(s). Wildcards accepted
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AccessPolicy,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$RuleName="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
               [int]$RuleIndex,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$OutFile,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$ContainerUUID = Get-FMCAccessPolicy -Name $AccessPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$ContainerUUID = $ContainerUUID.id
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$ContainerUUID/accessrules?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$ContainerUUID/accessrules?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
if ($RuleIndex) {
 $response = $items | Where-Object {$_.metadata.ruleIndex -EQ $RuleIndex}} else {
 $response = $items | Where-Object {$_.name -Like $RuleName}
 }
        }
End     {
if ($OutFile) {
$fileObject = @()
$response | foreach {
$i = New-Object psobject
$i | Add-Member -MemberType NoteProperty -Name AccessPolicy -Value $_.metadata.accessPolicy.name
$i | Add-Member -MemberType NoteProperty -Name RuleIndex    -Value $_.metadata.ruleIndex
$i | Add-Member -MemberType NoteProperty -Name Section      -Value $_.metadata.section
$i | Add-Member -MemberType NoteProperty -Name Category     -Value $_.metadata.category
$i | Add-Member -MemberType NoteProperty -Name RuleName     -Value $_.name
$i | Add-Member -MemberType NoteProperty -Name Action       -Value $_.action

$srcZone=@()
if ($_.sourceZones.objects) {foreach ($obj in $_.sourceZones.objects) {$srcZone+=[string]$obj.name}}
$i | Add-Member -MemberType NoteProperty -Name SourceZones    -Value ($srcZone -join ",`n")

$dstZone=@()
if ($_.destinationZones.objects) {foreach ($obj in $_.destinationZones.objects) {$dstZone+=[string]$obj.name}}
$i | Add-Member -MemberType NoteProperty -Name DestinationZones    -Value ($dstZone -join ",`n")
 
$vlan=@()
if ($_.vlanTags.objects)  {foreach ($vlanObject  in $_.vlanTags.objects)  {$vlan+=[string]$vlanObject.name}}
if ($_.vlanTags.literals) {foreach ($vlanLiteral in $_.vlanTags.literals) {
    if ($vlanLiteral.startTag -eq $vlanLiteral.endTag) {$vlan+=[string]$vlanLiteral.endTag} else {
    $vlan+=[string]$vlanLiteral.startTag+'-'+[string]$vlanLiteral.endTag} }}
$i | Add-Member -MemberType NoteProperty -Name VLANTags       -Value ($vlan -join ",`n")

$srcNet=@()
if ($_.sourceNetworks.objects)  {foreach ($obj in $_.sourceNetworks.objects)  {$srcNet+=[string]$obj.name}}
if ($_.sourceNetworks.literals) {foreach ($lit in $_.sourceNetworks.literals) {$srcNet+=[string]$lit.value}}
$i | Add-Member -MemberType NoteProperty -Name SourceNetworks     -Value ($srcNet -join ",`n")

$srcPort=@()
if ($_.sourcePorts.objects)  {foreach ($obj in $_.sourcePorts.objects)  {$srcPort+=[string]$obj.name}}
if ($_.sourcePorts.literals) {foreach ($lit in $_.sourcePorts.literals) {if (!$lit.port) {
    $srcPort+=[string]$MasterProtocolList[[int]$lit.protocol]} else {
    $srcPort+=[string]$MasterProtocolList[[int]$lit.protocol]+'/'+[string]$lit.port}}}
$i | Add-Member -MemberType NoteProperty -Name SourcePorts -Value ($srcPort -join ",`n")

$dstNet=@()
if ($_.destinationNetworks.objects)  {foreach ($obj in $_.destinationNetworks.objects)  {$dstNet+=[string]$obj.name}}
if ($_.destinationNetworks.literals) {foreach ($lit in $_.destinationNetworks.literals) {$dstNet+=[string]$lit.value}}
$i | Add-Member -MemberType NoteProperty -Name DestinationNetworks -Value ($dstNet -join ",`n")

$dstPort=@()
if ($_.destinationPorts.objects)  {foreach ($obj in $_.destinationPorts.objects)  {$dstPort+=[string]$obj.name}}
if ($_.destinationPorts.literals) {foreach ($lit in $_.destinationPorts.literals) {if (!$lit.port) {
    $dstPort+=[string]$MasterProtocolList[[int]$lit.protocol]} else {    
    $dstPort+=[string]$MasterProtocolList[[int]$lit.protocol]+'/'+[string]$lit.port}}}
$i | Add-Member -MemberType NoteProperty -Name DestinationPorts -Value ($dstPort -join ",`n")

$url=@()
if ($_.urls.objects)                     {foreach ($obj in $_.urls.objects) {$url+=[string]$obj.name}}
if ($_.urls.urlCategoriesWithReputation) {foreach ($cat in $_.urls.urlCategoriesWithReputation) {$url+=[string]$cat.category.name+';'+[string]$cat.reputation}}
$i | Add-Member -MemberType NoteProperty -Name URLs -Value ($url -join ",`n")

$apps=@()
if ($_.applications) {foreach ($app in $_.applications.applications) {$apps+=[string]$app.name}}
$i | Add-Member -MemberType NoteProperty -Name Applications    -Value ($apps -join ",`n")

$i | Add-Member -MemberType NoteProperty -Name SGT             -Value $_.sourceSGT.objects.name
$i | Add-Member -MemberType NoteProperty -Name IntrusionPolicy -Value $_.ipsPolicy.name
$i | Add-Member -MemberType NoteProperty -Name FilePolicy      -Value $_.filePolicy.name
$i | Add-Member -MemberType NoteProperty -Name Enabled         -Value $_.enabled
$i | Add-Member -MemberType NoteProperty -Name LogBegin        -Value $_.logBegin
$i | Add-Member -MemberType NoteProperty -Name LogEnd          -Value $_.logEnd
$i | Add-Member -MemberType NoteProperty -Name LogFiles        -Value $_.logFiles
$i | Add-Member -MemberType NoteProperty -Name SendEventsToFMC -Value $_.sendEventsToFMC
$i | Add-Member -MemberType NoteProperty -Name SyslogConfig    -Value $_.syslogConfig.name
$i | Add-Member -MemberType NoteProperty -Name SNMPConfig      -Value $_.snmpConfig.name

$comments=@()
if ($_.commentHistoryList) {foreach ($com in $_.commentHistoryList) {$comments+=[string]$com.comment}}
$i | Add-Member -MemberType NoteProperty -Name Comment -Value ($comments -join ",`n")

$fileObject += $i
 }
$fileObject | Export-Csv -Path $OutFile -NoClobber -NoTypeInformation
 } else {
$response }

        }
}
function Get-FMCZone                {
        <#
 .SYNOPSIS
Displays zones defined in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and display zones
 .EXAMPLE
Get-FMCZone -Name *INSIDE* -AuthToken 77df501f-d85a-44c6-9ec4-29007a29dbd7 -Domain e276abec-e0f2-11e3-8169-6d9ed49b625f -FMCHost https://fmcrestapisandbox.cisco.com
  .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Name
Name of the zone(s). Wildcards accepted
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Terse
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if ($Terse) {$Expanded='false'} else {$Expanded='true'}
         }
Process {
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/securityzones?offset=0&limit=25&expanded=$Expanded"
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$pages = $response.paging.pages
$items = $response.items
$offset = 0
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/securityzones?offset=$offset&limit=25&expanded=$Expanded"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $items   += $response.items
                     }
$response = $items | Where-Object -Property name -Like "$Name"
        }
End     {
$response
        }
}
function Get-FMCDeployment          {
<#
.SYNOPSIS
Displays devices with pending deployments
.DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under deployment/deployabledevice
.EXAMPLE
Get-FMCDeployment
name            id
----            ----
Site1-FW-1      80372a5e-1277-11e9-8139-8420ae49820f
Site1-FW-2      80372a5e-1277-11e9-8139-31d10e1340da
Site2-FW-1      80372a5e-1277-11e9-8139-134b14c1940d
Site2-FW-2      80372a5e-1277-11e9-8139-85786c610a95


Get-FMCDeployment -Name Site1-FW-1

name            id
----            ----
Site1-FW-1      80372a5e-1277-11e9-8139-8420ae49820f

Get-FMCDeployment -Name Site1-FW-*

name            id
----            ----
Site1-FW-1      80372a5e-1277-11e9-8139-8420ae49820f
Site1-FW-2      80372a5e-1277-11e9-8139-31d10e1340da

.PARAMETER Name
Name of device. Wildcards allowed
.PARAMETER fmcHost
Base URL of FMC
.PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain"
    )
Begin {$out = @()}
Process {
$offset   = 0
$uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/deployment/deployabledevices?offset=$offset&limit=25&expanded=true"
$response = Get-FMCObject -uri $uri -AuthToken $env:FMCAuthToken
$pages    = $response.paging.pages
$DepDevs  = $response.items
while ($pages -gt 1) {
    $offset   = $offset+25
    $pages--
    $uri      = "$FMCHost/api/fmc_config/v1/domain/$Domain/deployment/deployabledevices?offset=$offset&limit=25&expanded=true"
    $response = Get-FMCObject -uri $uri -AuthToken $env:FMCAuthToken
    $DepDevs += $response.items
                      }

$DepDevs = $DepDevs | where {$_.name -like $Name}
                     

 foreach ($dd in $DepDevs) {
  $i = New-Object psobject
  $i | Add-Member -MemberType NoteProperty -Name Name     -Value $dd.name
  $i | Add-Member -MemberType NoteProperty -Name id       -Value $dd.device.id
  $i | Add-Member -MemberType NoteProperty -Name version  -Value $dd.version
  $i | Add-Member -MemberType NoteProperty -Name Interupt -Value $dd.trafficInterruption
  $i | Add-Member -MemberType NoteProperty -Name Status   -Value ($dd.policyStatusList | where {$_.upToDate -ne 'True'})
  $out += $i
 }
        }
End {$out}
}
function Remove-FMCObject           {
        <#
 .SYNOPSIS
Removes an object via the REST API
 .DESCRIPTION
This cmdlet will invoke a REST delete method against a URI
 .EXAMPLE
$uri = https://fmcrestapisandbox.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
Remove-FMCObject -uri $uri -AuthToken 637a1b3f-787b-4179-be40-e19ee2aa9e60
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            $Object
    )
Begin   {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
         }
Process {
if ($Object) { $uri = $Object.links.self }
$headers = @{ "X-auth-access-token" = "$AuthToken" }
$response = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers
$response
        }
End {}
}
function Update-FMCAccessPolicyRule {
        <#
 .SYNOPSIS
Updates existing acccess policy rules
 .DESCRIPTION
Invokes a REST put method to update new rules in access policies
 .EXAMPLE
$x = $a | Get-FMCAccessPolicyRule -AccessPolicy TST1111 -RuleName BulkTest* 
$x | Update-FMCAccessPolicyRule -AuthToken $a.AuthAccessToken -Domain $a.Domain -FMCHost $a.fmcHost -IntrusionPolicy IntPO2 -FilePolicy Malware-Detect
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER Action
Action rule will take (e.g. Allow or Block)
 .PARAMETER SourceZones
Source zone. Multiple items must be separated by commas
 .PARAMETER DestinationZones
Destination zone. Multiple items must be separated by commas
 .PARAMETER SourceNetworks
Source network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER DestinationNetworks
Destination network. Multiple items must be separated by commas
Will accept either a network object/group, or a literal host/network/range value: e.g. 10.10.10.0/24
 .PARAMETER SourcePorts
Source port(s). Multiple items must be separated by commas
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER DestinationPorts
Destination port(s). Multiple items must be separated by commas.
Will accept either a port object/group, or a literal port value: e.g. tcp/890
 .PARAMETER Enabled
Sets enable parameter to true or false (true by default)
 .PARAMETER IntrusionPolicy
Selects the IPS policy for the rule
/#>

    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("True","False")] 
            [string]$Enabled,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("ALLOW","TRUST","MONITOR","BLOCK","BLOCK_RESET","BLOCK_INTERACTIVE","BLOCK_RESET_INTERACTIVE")] 
            [string]$Action,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourceZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationZones,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourceNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationNetworks,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$SourcePorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$DestinationPorts,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$IntrusionPolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$FilePolicy,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("True","False")] 
           [string]$LogBegin,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("True","False")] 
            [string]$LogEnd,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("True","False")] 
            [string]$SendEventsToFMC,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Syslog,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [string]$Comment,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
           [string]$Domain="$env:FMCDomain",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
           [switch]$Replace,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            $InputObject,

        [Parameter(DontShow)]
           [switch]$JSON

    )
Begin   {
$BeginTime = Get-Date
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'

if ($SourceZones -or $DestinationZones) {$AllZones = Get-FMCZone -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse}
if ($IntrusionPolicy)                   {$AllIPSPolicies  = Get-FMCIntrusionPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse}
if ($FilePolicy)                        {$AllFilePolicies = Get-FMCIntrusionPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse}
if ($SourceNetworks -or $DestinationNetworks) {
       $AllNetObjects   = @()
       $AllNetObjects   = Get-FMCNetworkObject -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
       $AllNetObjects  += Get-FMCNetworkGroup  -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
       }
if ($SourcePorts    -or $DestinationPorts)    {
       $AllPortObjects  = @()
       $AllPortObjects  = Get-FMCPortObject -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
       $AllPortObjects += Get-FMCPortGroup  -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
       }
if ($Syslog)                            {$SyslogAlerts = Get-FMCObject -uri "$env:FMCHost/api/fmc_config/v1/domain/$env:FMCDomain/policy/syslogalerts" -AuthToken $env:FMCAuthToken}
         }
Process {
$ruleUUID   = $InputObject.id
$policyUUID = $InputObject.metadata.accessPolicy.id
$uri     = "$FMCHost/api/fmc_config/v1/domain/$Domain/policy/accesspolicies/$policyUUID/accessrules/$ruleUUID"
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }

if (!$Enabled)         {$rule_Enabled         = $InputObject.enabled}         else {$rule_Enabled         = $Enabled        }
if (!$Action)          {$rule_Action          = $InputObject.action}          else {$rule_Action          = $Action         }
if (!$urls)            {$rule_urls            = $InputObject.urls}            else {$rule_urls            = $urls           }
if (!$vlanTags)        {$rule_vlanTags        = $InputObject.vlanTags}        else {$rule_vlanTags        = $vlanTags       }
if (!$logBegin)        {$rule_logBegin        = $InputObject.logBegin}        else {$rule_logBegin        = $logBegin       }
if (!$logEnd)          {$rule_logEnd          = $InputObject.logEnd}          else {$rule_logEnd          = $logEnd         }
if (!$snmpConfig)      {$rule_snmpConfig      = $InputObject.snmpConfig}      else {$rule_snmpConfig      = $snmpConfig     }
if (!$variableSet)     {$rule_variableSet     = $InputObject.variableSet}     else {$rule_variableSet     = $variableSet    }
if (!$logFiles)        {$rule_logFiles        = $InputObject.logFiles}        else {$rule_logFiles        = $logFiles       }
if (!$Syslog)          {$SyslogItem           = $InputObject.syslogConfig}    else {$rule_Syslog          = $Syslog         }
if (!$applications)    {$rule_applications    = $InputObject.applications}    else {$rule_applications    = $applications   }
if (!$sourceSGT)       {$rule_sourceSGT       = $InputObject.sourceSGT}       else {$rule_sourceSGT       = $sourceSGT      }
if (!$sendEventsToFMC) {$rule_sendEventsToFMC = $InputObject.sendEventsToFMC} else {$rule_sendEventsToFMC = $sendEventsToFMC}

## Parsing Source or destination Security Zones
 if ($SourceZones)         {
 $SourceZones_split = $SourceZones -split ','
 $sZ = @()
 $SourceZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $sZ += $Zone
               }
if ($InputObject.sourceZones.objects -and (!$Replace)){$sZ += $InputObject.sourceZones.objects}
$sZones = New-Object psobject
$sZones | Add-Member -MemberType NoteProperty -Name objects -Value $sZ
 } else {$sZones = $InputObject.sourceZones}
 if ($DestinationZones)    {
 $DestinationZones_split = $DestinationZones -split ','
 $dZ = @()
 $DestinationZones_split | foreach {
               $i = @()
               $i = $AllZones | Where-Object -Property name -EQ $_
               $Zone = New-Object psobject
               $Zone | Add-Member -MemberType NoteProperty -Name name -Value $i.name
               $Zone | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
               $Zone | Add-Member -MemberType NoteProperty -Name type -Value $i.type
               $dZ += $Zone
               }
if ($InputObject.destinationZones.objects -and (!$Replace)){$dZ += $InputObject.destinationZones.objects}
$dZones = New-Object psobject
$dZones | Add-Member -MemberType NoteProperty -Name objects -Value $dZ
 } else {$dZones = $InputObject.destinationZones}
## /Parsing Source or destination Security Zones

## Parsing Source or destination networks
 if ($SourceNetworks)      {
$literals     = @()
$objects      = @()
$SourceNetObj = @()
$SourceNetLit = @()
$SourceNetworks = $SourceNetworks.TrimStart(' ')
$SourceNetworks = $SourceNetworks.TrimEnd(' ')
$SourceNetworks_split = $SourceNetworks -split ',\n|,'
$SourceNetworks_split | foreach {
                     if ($_ -match '(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourceNetObj += $Obj
            if ($InputObject.sourceNetworks.objects -and (!$Replace)){$SourceNetObj += $InputObject.sourceNetworks.objects}

            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $SourceNetLit += $Obj
            if ($InputObject.sourceNetworks.literals -and (!$Replace)){$SourceNetLit += $InputObject.sourceNetworks.literals}
                              }
                }
 $sNets = New-Object psobject 
 if ($SourceNetObj) { $sNets | Add-Member -MemberType NoteProperty -Name objects  -Value $SourceNetObj }
 if ($SourceNetLit) { $sNets | Add-Member -MemberType NoteProperty -Name literals -Value $SourceNetLit }
 } else {$sNets = $InputObject.SourceNetworks}
 if ($DestinationNetworks) {
$literals     = @()
$objects      = @()
$DestinationNetObj = @()
$DestinationNetLit = @()
$DestinationNetworks = $DestinationNetworks.TrimStart(' ')
$DestinationNetworks = $DestinationNetworks.TrimEnd(' ')
$DestinationNetworks_split = $DestinationNetworks -split ',\n|,'
$DestinationNetworks_split | foreach {
                     if ($_ -match '(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllNetObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationNetObj += $Obj
            if ($InputObject.destinationNetworks.objects -and (!$Replace)){$DestinationNetObj += $InputObject.destinationNetworks.objects}
            }}
 if ($literals) { $literals | foreach {
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name value -Value "$_"
            $DestinationNetLit += $Obj
            if ($InputObject.destinationNetworks.literals -and (!$Replace)){$DestinationNetLit += $InputObject.destinationNetworks.literals}
                              }

                }
 $dNets = New-Object psobject 
 if ($DestinationNetObj) { $dNets | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationNetObj }
 if ($DestinationNetLit) { $dNets | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationNetLit }
 } else {$dNets = $InputObject.DestinationNetworks}
## /Parsing Source or destination networks

## Parsing Source or destination ports
 if ($SourcePorts)         {
$literals     = @()
$objects      = @()
$SourcePortObj = @()
$SourcePortLit = @()
$SourcePorts = $SourcePorts.TrimStart(' ')
$SourcePorts = $SourcePorts.TrimEnd(' ')
$SourcePorts_split = $SourcePorts -split ',\n|,'
$SourcePorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllPortObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $SourcePortObj += $Obj
            if ($InputObject.sourcePorts.objects -and (!$Replace)){$SourcePortObj += $InputObject.sourcePorts.objects}
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $MasterProtocolListByName[$i[0]]
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $SourcePortLit += $Obj
            if ($InputObject.sourcePorts.literals -and (!$Replace)){$SourcePortLit += $InputObject.sourcePorts.literals}
                              }
 $sPorts = New-Object psobject 
 if ($SourcePortObj) { $sPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $SourcePortObj }
 if ($SourcePortLit) { $sPorts | Add-Member -MemberType NoteProperty -Name literals -Value $SourcePortLit }
                }
 } else {$sPorts = $InputObject.SourcePorts}
 if ($DestinationPorts)    {
$literals     = @()
$objects      = @()
$DestinationPortObj = @()
$DestinationPortLit = @()
$DestinationPorts = $DestinationPorts.TrimStart(' ')
$DestinationPorts = $DestinationPorts.TrimEnd(' ')
$DestinationPorts_split = $DestinationPorts -split ',\n|,'
$DestinationPorts_split | foreach {
                     if ($_ -match '(^\w+?\/\d+$|^\w+?\/\d+\-\d+$)') {
                        $literals += $_} else {$objects += $_}}
 if ($objects) { $objects | foreach {
            $i = $AllPortObjects | Where-Object -Property name -EQ $_
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type -Value $i.type
            $Obj | Add-Member -MemberType NoteProperty -Name name -Value $i.name
            $Obj | Add-Member -MemberType NoteProperty -Name id   -Value $i.id
            $DestinationPortObj += $Obj
            if ($InputObject.destinationPorts.objects -and (!$Replace)){$DestinationPortObj += $InputObject.destinationPorts.objects}
            }}
 if ($literals) { $literals | foreach {
            $i = $_ -split '\/'
            $i[0] = $MasterProtocolListByName[$i[0]]
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name type     -Value PortLiteral
            $Obj | Add-Member -MemberType NoteProperty -Name port     -Value $i[1]
            $Obj | Add-Member -MemberType NoteProperty -Name protocol -Value $i[0]
            $DestinationPortLit += $Obj
            if ($InputObject.destinationPorts.literals -and (!$Replace)){$DestinationPortLit += $InputObject.destinationPorts.literals}
                              }

                }
 $dPorts = New-Object psobject 
 if ($DestinationPortObj) { $dPorts | Add-Member -MemberType NoteProperty -Name objects  -Value $DestinationPortObj }
 if ($DestinationPortLit) { $dPorts | Add-Member -MemberType NoteProperty -Name literals -Value $DestinationPortLit }
 } else {$dPorts = $InputObject.DestinationPorts}
## /Parsing Source or destination ports

if ($IntrusionPolicy) {
$ipsPolicyID = Get-FMCIntrusionPolicy -Name $IntrusionPolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$ipsPolicy   = New-Object -TypeName psobject
$ipsPolicy   | Add-Member -MemberType NoteProperty -name name -Value $ipsPolicyID.name
$ipsPolicy   | Add-Member -MemberType NoteProperty -name id   -Value $ipsPolicyID.id
$ipsPolicy   | Add-Member -MemberType NoteProperty -name type -Value $ipsPolicyID.type
} else { $ipsPolicy = $InputObject.ipsPolicy}

if ($FilePolicy) {
$fPolicyID = Get-FMCFilePolicy -Name $FilePolicy -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
$fPolicy   = New-Object -TypeName psobject
$fPolicy   | Add-Member -MemberType NoteProperty -name name -Value $fPolicyID.name
$fPolicy   | Add-Member -MemberType NoteProperty -name id   -Value $fPolicyID.id
$fPolicy   | Add-Member -MemberType NoteProperty -name type -Value $fPolicyID.type
} else { $fPolicy = $InputObject.filePolicy}

if ($rule_Syslog) {
 $SyslogItem = New-Object psobject
 $SyslogItem | Add-Member -MemberType NoteProperty -Name name -Value ($SyslogAlerts.items | where {$_.name -eq $rule_Syslog}).name
 $SyslogItem | Add-Member -MemberType NoteProperty -Name id   -Value ($SyslogAlerts.items | where {$_.name -eq $rule_Syslog}).id
 $SyslogItem | Add-Member -MemberType NoteProperty -Name type -Value ($SyslogAlerts.items | where {$_.name -eq $rule_Syslog}).type
 }

if ($Comment) {
 $Comments = @()
 $Comments += $Comment
 } 
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name -Value $InputObject.Name
if ($rule_Enabled)            {$body | Add-Member -MemberType NoteProperty -name enabled             -Value $rule_Enabled}
if ($ruleUUID)                {$body | Add-Member -MemberType NoteProperty -name id                  -Value $ruleUUID}
if ($rule_Action)             {$body | Add-Member -MemberType NoteProperty -name action              -Value $rule_Action}
if ($rule_urls)               {$body | Add-Member -MemberType NoteProperty -name urls                -Value $rule_urls}
if ($rule_vlanTags)           {$body | Add-Member -MemberType NoteProperty -name vlanTags            -Value $rule_vlanTags}
if ($ipsPolicy)               {$body | Add-Member -MemberType NoteProperty -name ipsPolicy           -Value $ipsPolicy }
if ($fPolicy)                 {$body | Add-Member -MemberType NoteProperty -name filePolicy          -Value $fPolicy }
if ($sZones)                  {$body | Add-Member -MemberType NoteProperty -name sourceZones         -Value $sZones }
if ($dZones)                  {$body | Add-Member -MemberType NoteProperty -name destinationZones    -Value $dZones }
if ($sNets)                   {$body | Add-Member -MemberType NoteProperty -name sourceNetworks      -Value $sNets }
if ($dNets)                   {$body | Add-Member -MemberType NoteProperty -name destinationNetworks -Value $dNets }
if ($sPorts)                  {$body | Add-Member -MemberType NoteProperty -name sourcePorts         -Value $sPorts }
if ($dPorts)                  {$body | Add-Member -MemberType NoteProperty -name destinationPorts    -Value $dPorts }
if ($Comments)                {$body | Add-Member -MemberType NoteProperty -name newComments         -Value $Comments }
if ($rule_logBegin)           {$body | Add-Member -MemberType NoteProperty -name logBegin            -Value $rule_logBegin }
if ($rule_logEnd)             {$body | Add-Member -MemberType NoteProperty -name logEnd              -Value $rule_logEnd }
if ($SyslogItem)              {$body | Add-Member -MemberType NoteProperty -name syslogConfig        -Value $SyslogItem}
if ($rule_snmpConfig)         {$body | Add-Member -MemberType NoteProperty -name snmpConfig          -Value $rule_snmpConfig}
if ($variableSet)             {$body | Add-Member -MemberType NoteProperty -name variableSet         -Value $rule_variableSet}
if ($rule_logFiles)           {$body | Add-Member -MemberType NoteProperty -name logFiles            -Value $rule_logFiles}
if ($rule_applications)       {$body | Add-Member -MemberType NoteProperty -name applications        -Value $rule_applications}
if ($rule_sourceSGT)          {$body | Add-Member -MemberType NoteProperty -name sourceSGT           -Value $rule_sourceSGT }
if ($rule_sendEventsToFMC)    {$body | Add-Member -MemberType NoteProperty -name sendEventsToFMC     -Value $rule_sendEventsToFMC }
if ($JSON) {$uri ; ($body | ConvertTo-Json -Depth 5)} else {
Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
     }
    }
End     {}
}
function Update-FMCNetworkGroup     {
<#
 .SYNOPSIS
Create network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Network Groups
 .EXAMPLE
$a | New-FMCNetworkGroup -Members 'PowerFMC_Host,PowerFMC_Net,PowerFMC_Range' -Name 'PowerFMC_Group' -Description 'Group made with PowerFMC'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Members
Member objects or literal networks/hosts/ranges
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$Members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Replace,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$inputGroup = Get-FMCNetworkGroup -Name $Name -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain
$GroupID    = $inputGroup.id
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/object/networkgroups/$GroupID"
$NetObj = @()
$NetLit = @()
        }
Process {

$literals = @()
$objects  = @()
if ($Members) {
$MemberArray = $Members -split ','
$MemberArray | foreach {
             if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
              if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$') {$literals += $_}
              if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')            {$range += $_}
              } else {$objects += $_}
             }
if ($objects) {
$NetworkObjects = Get-FMCNetworkObject -AuthToken $env:FMCAuthToken -FMCHost $env:FMCHost -Domain $env:FMCDomain -Terse
    $objects | foreach {
    $id = $NetworkObjects | Where-Object -Property name -EQ $_
    $id = $id.id
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name id -Value $id
    $NetObj += $obj
    }
}
if ($literals) {
    $literals | foreach {
    $obj = New-Object psobject
    $obj | Add-Member -MemberType NoteProperty -Name type  -Value 'Range'
    $obj | Add-Member -MemberType NoteProperty -Name value -Value $_
    $NetLit += $obj
    }
}
  }
 }
End {
if (!$Replace) {
 if ($inputGroup.objects)  { $NetObj += $inputGroup.objects }
 if ($inputGroup.literals) { $NetLit += $inputGroup.literals }
 if (!$Description) { if ($inputGroup.description) {$Description = $inputGroup.description}}
 if (!$Overridable) { if ($inputGroup.overridable) {$Overridable = $inputGroup.overridable}}
 }
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type         -Value "NetworkGroup"
if ($NetObj)      {$body | Add-Member -MemberType NoteProperty -name objects     -Value $NetObj}
if ($NetLit)      {$body | Add-Member -MemberType NoteProperty -name literals    -Value $NetLit}
if ($Overridable) {$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable}
if ($Description) {$body | Add-Member -MemberType NoteProperty -name description -Value $Description}
$body | Add-Member -MemberType NoteProperty -name id           -Value $GroupID
$body | Add-Member -MemberType NoteProperty -name name         -Value $Name
if ($JSON) {($body | ConvertTo-Json)} else {
Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
  }
 }
}
function Update-FMCPortGroup        {
<#
 .SYNOPSIS
Create port groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and update a Port Group
 .EXAMPLE
$FMCHost = 'https://fmcrestapisandbox.cisco.com'

New-FMCPortGroup -Name PowerFMC_PortGroup -Members 'PowerFMC_Test123,PowerFMC_Test567' -Description 'Group with two objects'

New-FMCPortGroup -Name PowerFMC_PortGroup -Members 'tcp/55,udp/100-110,PowerFMC_Test567' -Description 'Mixed objects/literals'
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Overridable="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Replace,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken",
        [Parameter(DontShow)]
            [switch]$JSON
    )
Begin {
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$PortGroup = Get-FMCPortGroup -name $Name -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain
$uri = $PortGroup.links.self
$headers = @{ "X-auth-access-token" = "$AuthToken" ;'Content-Type' = 'application/json' }
$PortObjects  = Get-FMCPortObject -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain -Terse
$PortObjects += Get-FMCPortGroup  -fmcHost $FMCHost -AuthToken $AuthToken -Domain $Domain
        }
Process {
$objects = @()
$Members.Split(',') | foreach {
   $member = $_ -replace '\\|\/|\s','_'
   $PortObject = @()
   $PortObject = $PortObjects | Where-Object -Property name -EQ $member
   if (!$PortObject.id) {Write-Host "Object $member does not exist" -ForegroundColor Yellow} else {
    if ($PortObject.type -like "*Group*") { 
     $PortObject.objects | foreach {
      $id   = $_.id
      $type = $_.type
      $object = New-Object psobject
      $object | Add-Member -MemberType NoteProperty -Name type -Value $type
      $object | Add-Member -MemberType NoteProperty -Name id   -Value $id
      $objects += $object
      }
     } else {
    $id   = $PortObject.id
    $type = $PortObject.type
    $object = New-Object psobject
    $object | Add-Member -MemberType NoteProperty -Name type -Value $type
    $object | Add-Member -MemberType NoteProperty -Name id   -Value $id
    $objects += $object}
    }
  }
 if (!$Replace) {
  $objects += $PortGroup.objects
  if (!$Description) {$Description = $PortGroup.description}
  }
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name id          -Value $PortGroup.id
$body | Add-Member -MemberType NoteProperty -name name        -Value $PortGroup.name
$body | Add-Member -MemberType NoteProperty -name type        -Value "PortObjectGroup"
$body | Add-Member -MemberType NoteProperty -name objects     -Value $objects
$body | Add-Member -MemberType NoteProperty -name overridable -Value $Overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$Description"
if ($JSON) {$uri ; ($body | ConvertTo-Json)} else {
$response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
 }
$response
        }
End {}
}
function Invoke-FMCDeployment       {
<#
 .SYNOPSIS
Initiates a deployment to FMC managed devices
 .DESCRIPTION
This cmdlet will invoke a REST Post against the deployment requests API uri and trigger a deployment
 .EXAMPLE
Get-FMCDeployment | Invoke-FMCDeployment
 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$Force,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [switch]$NoWarn,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$id,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$version,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$FMCHost="$env:FMCHost",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain="$env:FMCDomain",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:FMCAuthToken"
    )
Begin {
 if ($Force) {[string]$FD = 'True'} else {[string]$FD = 'False'}
 if ($NoWarn){[string]$NW = 'True'} else {[string]$NW = 'False'}
 $IDs = @()
 }
Process {
 $ver  = $version
 $IDs += $id
        }
End {
 $body = New-Object -TypeName psobject
 $body | Add-Member -MemberType NoteProperty -name type          -Value "DeploymentRequest"
 $body | Add-Member -MemberType NoteProperty -name forceDeploy   -Value $FD
 $body | Add-Member -MemberType NoteProperty -name ignoreWarning -Value $NW
 $body | Add-Member -MemberType NoteProperty -name version       -Value $ver
 $body | Add-Member -MemberType NoteProperty -name deviceList    -Value $IDs

$uri = "$FMCHost/api/fmc_config/v1/domain/$Domain/deployment/deploymentrequests"
New-FMCObject -uri $uri -AuthToken $env:FMCAuthToken -object ($body | ConvertTo-Json)
    }
}


$MasterProtocolList       = [ordered]@{
 0 = 'HOPOPT'
 1 = 'ICMP'
 2 = 'IGMP'
 3 = 'GGP'
 4 = 'IPv4'
 5 = 'ST'
 6 = 'TCP'
 7 = 'CBT'
 8 = 'EGP'
 9 = 'IGP'
 10 = 'BBN-RCC-MON'
 11 = 'NVP-II'
 12 = 'PUP'
 13 = 'ARGUS'
 14 = 'EMCON'
 15 = 'XNET'
 16 = 'CHAOS'
 17 = 'UDP'
 18 = 'MUX'
 19 = 'DCN-MEAS'
 20 = 'HMP'
 21 = 'PRM'
 22 = 'XNS-IDP'
 23 = 'TRUNK-1'
 24 = 'TRUNK-2'
 25 = 'LEAF-1'
 26 = 'LEAF-2'
 27 = 'RDP'
 28 = 'IRTP'
 29 = 'ISO-TP4'
 30 = 'NETBLT'
 31 = 'MFE-NSP'
 32 = 'MERIT-INP'
 33 = 'DCCP'
 34 = '3PC'
 35 = 'IDPR'
 36 = 'XTP'
 37 = 'DDP'
 38 = 'IDPR-CMTP'
 39 = 'TP++'
 40 = 'IL'
 41 = 'IPv6'
 42 = 'SDRP'
 43 = 'IPv6-Route'
 44 = 'IPv6-Frag'
 45 = 'IDRP'
 46 = 'RSVP'
 47 = 'GRE'
 48 = 'DSR'
 49 = 'BNA'
 50 = 'ESP'
 51 = 'AH'
 52 = 'I-NLSP'
 53 = 'SWIPE'
 54 = 'NARP'
 55 = 'MOBILE'
 56 = 'TLSP'
 57 = 'SKIP'
 58 = 'IPv6-ICMP'
 59 = 'IPv6-NoNxt'
 60 = 'IPv6-Opts'
 62 = 'CFTP'
 64 = 'SAT-EXPAK'
 65 = 'KRYPTOLAN'
 66 = 'RVD'
 67 = 'IPPC'
 69 = 'SAT-MON'
 70 = 'VISA'
 71 = 'IPCV'
 72 = 'CPNX'
 73 = 'CPHB'
 74 = 'WSN'
 75 = 'PVP'
 76 = 'BR-SAT-MON'
 77 = 'SUN-ND'
 78 = 'WB-MON'
 79 = 'WB-EXPAK'
 80 = 'ISO-IP'
 81 = 'VMTP'
 82 = 'SECURE-VMTP'
 83 = 'VINES'
 84 = 'TTP'
 85 = 'NSFNET-IGP'
 86 = 'DGP'
 87 = 'TCF'
 88 = 'EIGRP'
 89 = 'OSPFIGP'
 90 = 'Sprite-RPC'
 91 = 'LARP'
 92 = 'MTP'
 93 = 'AX.25'
 94 = 'IPIP'
 95 = 'MICP'
 96 = 'SCC-SP'
 97 = 'ETHERIP'
 98 = 'ENCAP'
 100 = 'GMTP'
 101 = 'IFMP'
 102 = 'PNNI'
 103 = 'PIM'
 104 = 'ARIS'
 105 = 'SCPS'
 106 = 'QNX'
 107 = 'A/N'
 108 = 'IPComp'
 109 = 'SNP'
 110 = 'Compaq-Peer'
 111 = 'IPX-in-IP'
 112 = 'VRRP'
 113 = 'PGM'
 115 = 'L2TP'
 116 = 'DDX'
 117 = 'IATP'
 118 = 'STP'
 119 = 'SRP'
 120 = 'UTI'
 121 = 'SMP'
 122 = 'SM'
 123 = 'PTP'
 124 = 'ISIS over IPv4'
 125 = 'FIRE'
 126 = 'CRTP'
 127 = 'CRUDP'
 128 = 'SSCOPMCE'
 129 = 'IPLT'
 130 = 'SPS'
 131 = 'PIPE'
 132 = 'SCTP'
 133 = 'FC'
 134 = 'RSVP-E2E-IGNORE'
 135 = 'Mobility Header'
 136 = 'UDPLite'
 137 = 'MPLS-in-IP'
 138 = 'manet'
 139 = 'HIP'
 140 = 'Shim6'
 141 = 'WESP'
 142 = 'ROHC'
 255 = 'Reserved'
 }
$MasterProtocolListByName = [ordered]@{
 'HOPOPT'          = 0
 'ICMP'            = 1
 'IGMP'            = 2
 'GGP'             = 3
 'IPv4'            = 4
 'ST'              = 5
 'TCP'             = 6
 'CBT'             = 7
 'EGP'             = 8
 'IGP'             = 9
 'BBN-RCC-MON'     = 10
 'NVP-II'          = 11
 'PUP'             = 12
 'ARGUS'           = 13
 'EMCON'           = 14
 'XNET'            = 15
 'CHAOS'           = 16
 'UDP'             = 17
 'MUX'             = 18
 'DCN-MEAS'        = 19
 'HMP'             = 20
 'PRM'             = 21
 'XNS-IDP'         = 22
 'TRUNK-1'         = 23
 'TRUNK-2'         = 24
 'LEAF-1'          = 25
 'LEAF-2'          = 26
 'RDP'             = 27
 'IRTP'            = 28
 'ISO-TP4'         = 29
 'NETBLT'          = 30
 'MFE-NSP'         = 31
 'MERIT-INP'       = 32
 'DCCP'            = 33
 '3PC'             = 34
 'IDPR'            = 35
 'XTP'             = 36
 'DDP'             = 37
 'IDPR-CMTP'       = 38
 'TP++'            = 39
 'IL'              = 40
 'IPv6'            = 41
 'SDRP'            = 42
 'IPv6-ROute'      = 43
 'IPv6-FRag'       = 44
 'IDRP'            = 45
 'RSVP'            = 46
 'GRE'             = 47
 'DSR'             = 48
 'BNA'             = 49
 'ESP'             = 50
 'AH'              = 51
 'I-NLSP'          = 52
 'SWIPE'           = 53
 'NARP'            = 54
 'MOBILE'          = 55
 'TLSP'            = 56
 'SKIP'            = 57
 'IPv6-ICmP'       = 58
 'IPv6-NOnxt'      = 59
 'IPv6-OPts'       = 60
 'CFTP'            = 62
 'SAT-EXPAK'       = 64
 'KRYPTOLAN'       = 65
 'RVD'             = 66
 'IPPC'            = 67
 'SAT-MON'         = 69
 'VISA'            = 70
 'IPCV'            = 71
 'CPNX'            = 72
 'CPHB'            = 73
 'WSN'             = 74
 'PVP'             = 75
 'BR-SAT-MON'      = 76
 'SUN-ND'          = 77
 'WB-MON'          = 78
 'WB-EXPAK'        = 79
 'ISO-IP'          = 80
 'VMTP'            = 81
 'SECURE-VMTP'     = 82
 'VINES'           = 83
 'TTP'             = 84
 'NSFNET-IGP'      = 85
 'DGP'             = 86
 'TCF'             = 87
 'EIGRP'           = 88
 'OSPFIGP'         = 89
 'SpritE-rpc'      = 90
 'LARP'            = 91
 'MTP'             = 92
 'AX.25'           = 93
 'IPIP'            = 94
 'MICP'            = 95
 'SCC-SP'          = 96
 'ETHERIP'         = 97
 'ENCAP'           = 98
 'GMTP'            = 100
 'IFMP'            = 101
 'PNNI'            = 102
 'PIM'             = 103
 'ARIS'            = 104
 'SCPS'            = 105
 'QNX'             = 106
 'A/N'             = 107
 'IPComp'          = 108
 'SNP'             = 109
 'Compaq-peer'     = 110
 'IPX-in-IP'       = 111
 'VRRP'            = 112
 'PGM'             = 113
 'L2TP'            = 115
 'DDX'             = 116
 'IATP'            = 117
 'STP'             = 118
 'SRP'             = 119
 'UTI'             = 120
 'SMP'             = 121
 'SM'              = 122
 'PTP'             = 123
 'ISIS oVER Ipv4'  = 124
 'FIRE'            = 125
 'CRTP'            = 126
 'CRUDP'           = 127
 'SSCOPMCE'        = 128
 'IPLT'            = 129
 'SPS'             = 130
 'PIPE'            = 131
 'SCTP'            = 132
 'FC'              = 133
 'RSVP-E2E-IGNORE' = 134
 'MobiliTy header' = 135
 'UDPLitE'         = 136
 'MPLS-iN-IP'      = 137
 'manet'           = 138
 'HIP'             = 139
 'Shim6'           = 140
 'WESP'            = 141
 'ROHC'            = 142
 'ReservEd'        = 255
 }
