<#
    .NOTES
        Author: Mark McGill, VMware
        Last Edit: 7/11/2022
        Version 1.0.0.0
    .SYNOPSIS
        Retrieves license information from VMware products
    .DESCRIPTION

#>
function Get-VMwareLicenses
{
    #Requires -Version 5.0
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)][ValidateSet("vCenter","Horizon","LogInsight","NSX","vRA","vROps")]$type,
        [Parameter(Mandatory=$true)]$server,
        [Parameter(Mandatory=$true)]$user,
        [Parameter(Mandatory=$true)]$password
    )

    $na = "N/A"
    $columns = "Server", "Type", "Product Name", "License Key", "Quantity", "Used", "Unit of Measure", "Information", "ExpirationDate"
    $date = Get-Date -format "MM-dd-yyyy"
    Function Convert-FromUnixDate ($unixDate) 
    {
        $ErrorActionPreference = "Stop"
        Try
        {
            $date = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliSeconds($unixDate))
            $ErrorActionPreference = "Continue"
            Return $date
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "Error converting Unix Date/Time. Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
     

    Function Get-vCenterLicensing($fqdn,$userName,$password)
    {
        try 
        {   
            $ErrorActionPreference  = "Stop"
            $connect = Connect-VIServer -server $fqdn -user $userName -Password $password
            #Get the license info from vCenter
            $serviceInstance = Get-View ServiceInstance
            $licenses = (Get-View $serviceInstance.Content.LicenseManager).Licenses

            $licenseDetails = @()
            Foreach ($license in $licenses)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "vCenter"
                $details."Product Name" = $license.Name
                $details."License Key" = $license.LicenseKey
                $details.Quantity = $license.Total
                $details.Used = $license.Used
                $details."Unit of Measure" = $license.CostUnit
                If ($license.Name -match "NSX for vSPhere")
                {
                    $details.Information = $nsxManFqdn
                }
                Else
                {
                    $details.Information = $license.Labels | Select -expand Value
                }
                $expirationDate = $license.Properties | Where { $_.Key -eq "expirationDate" } | Select -Expand Value
                If ($expirationDate.Count -gt 0)
                {
                    $details.ExpirationDate = $expirationDate
                }
                Else
                {
                    $details.ExpirationDate = "Never"
                }
                $licenseDetails += $details
                $ErrorActionPreference = "Continue"
                Return $licenseDetails
            }
        }
        catch 
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving vCenter licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
      
    Function Get-vROPsLicensing($fqdn,$userName,$password)
    {
        Try
        {
            $ErrorActionPreference = "Stop"
            #call rest api to get authentication token
            $authUri = "https://$fqdn/suite-api/api/auth/token/acquire"
            $licenseUri = "https://$fqdn/suite-api/api/deployment/licenses"
            $authHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $authHeaders.Add("Content-Type", "application/json")
            $authHeaders.Add("Accept", "application/json") 
            $authBody = @{
                        "username" = $userName;
                        "password" = $password
            } | ConvertTo-Json

            $token = (Invoke-RestMethod -uri $authUri -Headers $authHeaders -Body $authBody -Method Post -SkipCertificateCheck).Token
            
            #call rest api to get vROPs licensing
            $licenseHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $licenseHeaders.Add("Content-Type", "application/json")
            $licenseHeaders.Add("Authorization", "vRealizeOpsToken $token")
            $licenseHeaders.Add("Accept", "application/json")
            $licenses = (Invoke-RestMethod -uri $licenseUri -Headers $licenseHeaders -Method GET -SkipCertificateCheck).solutionLicenses
            $licenseDetails = @()
            foreach($license in $licenses)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "vROPs"
                $details."Product Name" = "vROPs"
                $details."License Key" = $license.licenseKey
                $capacity = ($license.capacity).Split(" ")
                $details.Quantity = $capacity[0]
                $used = ($license.usage).Split(" ")
                $details.Used = $used[0]
                $details."Unit of Measure" = ($license.capacity -replace ($capacity[0])).Trim()
                $details.ExpirationDate = Convert-FromUnixDate $license.expirationDate
                $licenseDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $licenseDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving vROPs licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
      
    Function Get-LogInsightLicensing($fqdn,$username,$password)
    {
        $ErrorActionPreference = "Stop"
        Try
        {
            $baseUri = "https://$fqdn/api/v1"
            $sessionUri = "$baseUri/sessions"
            $licenseUri = "$baseUri/licenses"
            $sessionBody = @{
                username = $username ;
                password = $password 
            } | ConvertTo-Json
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Accept","application/json")
            $headers.Add("Content-Type","application/json")
            $sessionId = (Invoke-RestMethod $sessionUri -Headers $headers -Body $sessionBody -Method Post -SkipCertificateCheck).sessionId
            
            $headers.Add("Authorization","Bearer $sessionId")
            $licenses = (Invoke-RestMethod -uri $licenseUri -Headers $headers -Method Get -SkipCertificateCheck).Licenses 

            $licenseDetails = @()
            
            foreach($license in $licenses)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "LogInsight"
                $details."Product Name" = "LogInsight"
                $details."License Key" = $license.licenseKey
                $details.Quantity = $license.count
                $details.Used = $na
                $details."Unit of Measure" = $license.typeEnum
                $details.Information = $info.status
                $details.ExpirationDate = Convert-FromUnixDate $info.expiration
                $licenseDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $licenseDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving LogInsight licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
      
    Function Get-vRALicensing($fqdn,$username,$password)
    {
        $ErrorActionPreference = "Stop"
        #uses plink to ssh to vRA server since it no longer can retrieve license info via API
        Try
        {
            #$command = "plink -batch -no-antispoof $username@$fqdn -pw $password $vraCli"
            $vraResponse = plink -load $username@$fqdn -no-antispoof "vracli license"
            $headerLengths = $vraResponse[1].split("  ")
            $n = 0
            $headers = @()
            $headerRow = $vraResponse[0]
            foreach($headerLength in $headerLengths)
            {
                If($n -eq 0)
                {
                    $start = 0
                    $end = $headerLengths[0].Length  
                }
                else
                {
                    $start = $start + $headerLengths[$n-1].Length + 2
                    $end = $end + $headerLengths[$n].Length + 2
                }
                
                $header = ($headerRow[$start..$end] -join '').Trim()
                $headers += $header
                $n++
            }
            
            $licenses = @()
            for($i = 2 ; $i -lt $vraResponse.Count; $i++)
            {
                $vraLicense = "" | Select $headers
                $n=0
                foreach ($headerLength in $headerLengths)
                {
                    If($n -eq 0)
                    {
                        $start = 0
                        $end = $headerLengths[0].Length
                    }
                    else
                    {
                        $start = $start + $headerLengths[$n-1].Length + 2
                        $end = $end + $headerLengths[$n].Length + 2
                    }
                    $licenseValue = ($vraResponse[$i][$start..$end] -join '').Trim()
                    $vraLicense.($headers[$n]) = $licenseValue
                    $n++
                }
                $licenses += $vraLicense
            }
    
            $licenseDetails = @()
                    
            foreach($license in $licenses)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "vRealize Automation"
                $details."Product Name" = $license.Product
                $details."License Key" = $license.key
                $details.Quantity = $na
                $details.Used = $na
                $details."Unit of Measure" = $na
                $details.Information = "Valid: $($license.Valid),Error:$($license.Error)"
                $details.ExpirationDate = $license.Expiration
                $licenseDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $licenseDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving vRA licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
    
      
    Function Get-NSXLicensing($fqdn,$userName,$password)
    {
        #nsx-t api explorer: https://<nsx-server>/policy/api.html
        Try
        {
            $licenseUri = "https://$fqdn/api/v1/licenses"
            $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($userName,$secPassword)
            $licenseUri = "https://$fqdn/api/v1/licenses"
            $response = Invoke-RestMethod -uri $licenseUri -Authentication Basic -SkipCertificateCheck -Credential $creds -Method GET
            $licenses = $response.results
            $licenseDetails = @()
            foreach ($license in $licenses)
            {
                $details = "" | Select $columns       
                $details.Server = $fqdn
                $details.Type = "NSX"
                $details."Product Name" = $license.Description
                $details."License Key" = $license.license_key
                $details.Quantity = $license.quantity
                $details.Used = $na
                $details."Unit of Measure" = $license.capacityType
                $details.Information = "Expired: $($license.is_expired) Is_Eval: $($license.is_eval)"
                $details.ExpirationDate = (([datetime]$license.expiry).AddSeconds([int](1672444800000 / 1000)))
                $licenseDetails += $details
            }
            Write_Log "Successfully retrieved NSX licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
        Catch
        {
            Write_Log "ERROR retrieving NSX licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
        Return $licenseDetails
    }
      
    Function Get-HorizonLicenses($fqdn,$userName,$password)
    {
        #userName should be in the format "user@domain.com"
        $ErrorActionPreference = "Stop"
        Try
        {
            If ($PsVersionTable.PSVersion.Major -gt 5)
            {
                Powershell -version 5.1
            }
            $hvServer = Connect-HVServer -Server $fqdn -User $userName -Password $password
            $viewApi = $hvServer.ExtensionData
            $licenses = $viewApi.license.license_get()

            $licenseDetails = @()
            foreach($license in $licenses)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "Horizon"
                $details."Product Name" = $license.LicenseEdition
                $details."License Key" = $license.LicenseKey
                $details.Quantity = $na
                $details.Used = $na
                $details."Unit of Measure" = $license.UsageModel
                $details.Information = "LicenseMode: $($license.LicenseMode)"
                $details.ExpirationDate = $license.ExpirationTime
                $licenseDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $licenseDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving Horizon licenses from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
        
    }
      
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    #///////////////////////////////CODE BODY ////////////////////////////////
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    #call the appropriate action based on product type
    switch ($type)
    {
        "vCenter" 
        {
            $results = Get-vCenterLicensing $server $user $pw
        }
        "vROps" 
        {
            $results = Get-vROPsLicensing $server $user $pw
        }
        "LogInsight" 
        {
            $results = Get-LogInsightLicensing $server $user $pw
        }
        "NSX" 
        {
            $results = Get-NSXLicensing $server $user $pw
        }
        "vRA" 
        {
            $results = Get-vRALicensing $server $user $pw
        }
        "Horizon"
        {
            $results = Get-HorizonLicensing $server $user $pw
        }
    }
    Return $results
}
