<#
 ==========[DISCLAIMER]===========================================================================================================
  This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
  INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
  code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software 
  product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the 
  Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or 
  lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
 =================================================================================================================================
 
 Original Script by Dmitriy Plokhih at http://aka.ms/exrtfm
 Updated Script by Marco Estrada at http://aka.ms/ExRESScoping
 Version 2018.06.20
#>

$Header = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
"@

function Create-ZipFile
{
param
( [string]$dir, #directory of collected xml files
  [string]$mask="ExRESScoping*.*l",
  [string]$zipFileName="ExRESScoping.zip"

)
$zipFile = Join-Path -Path $dir -ChildPath $zipFilename
$searchStr = Join-Path -Path $dir -ChildPath $mask

#Prepare zip file
#if(-not (test-path($zipFile))) {
    set-content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
    (dir $zipFile).IsReadOnly = $false  
#}

$shellApplication = new-object -com shell.application
$zipPackage = $shellApplication.NameSpace($zipFile)
$files = Get-ChildItem -Path $searchStr | where{! $_.PSIsContainer}

foreach($file in $files) { 
    $zipPackage.CopyHere($file.FullName)
#using this method, sometimes files can be 'skipped'
#this 'while' loop checks each file is added before moving to the next
    while($zipPackage.Items().Item($file.name) -eq $null){
        Start-sleep -seconds 1
    }
}
}

function Invoke-RunspaceJob
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]
        $InputObject,

        [Parameter(Mandatory=$true, 
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Int32]
        $ThrottleLimit = 32,

        [Parameter(Position=3)]
        [Int32]
        $Timeout,

        [Parameter(Position=5)]
        [switch]
        $ShowProgress,

        [Parameter(Position=4)]
        [ValidateScript({$_ | ForEach-Object -Process {Get-Variable -Name $_}})]
        [string[]]
        $SharedVariables
    )

    Begin
    {
        #region Creating initial variables
        $runspacetimers = [HashTable]::Synchronized(@{})
        $SharedVariables += 'runspacetimers'
        $runspaces = New-Object -TypeName System.Collections.ArrayList
        $bgRunspaceCounter = 0
        #endregion Creating initial variables

        #region Creating initial session state and runspace pool
        Write-Verbose -Message "Creating initial session state"
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($ExternalVariable in $SharedVariables)
        {
            Write-Verbose -Message ('Adding variable ${0} to initial session state' -f $ExternalVariable)
            $iss.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $ExternalVariable, (Get-Variable -Name $ExternalVariable -ValueOnly), ''))
        }
        Write-Verbose "Creating runspace pool with Throttle Limit $ThrottleLimit"
        $rp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
        $rp.Open()
        #endregion Creating initial session state and runspace pool

        #region Append timeout tracking code at the begining of scriptblock
        $ScriptStart = {
            [CmdletBinding()]
            Param
            (
                [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
                $_,

                [Parameter(Position=1)]
                [ValidateNotNullOrEmpty()]
                [int]
                $bgRunspaceID
            )
            $runspacetimers.$bgRunspaceID = Get-Date
        }

        $ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($ScriptStart.ToString() + $ScriptBlock.ToString())
        #endregion Append timeout tracking code at the begining of scriptblock

        #region Runspace status tracking and result retrieval function
        function Get-Result
        {
            [CmdletBinding()]
            Param
            (
                [switch]$Wait
            )
            do
            {
                $More = $false
                foreach ($runspace in $runspaces)
                {
                    $StartTime = $runspacetimers.($runspace.ID)
                    if ($runspace.Handle.isCompleted)
                    {
                        Write-Verbose -Message ('Thread done for {0}' -f $runspace.IObject)
                        $runspace.PowerShell.EndInvoke($runspace.Handle)
                        $runspace.PowerShell.Dispose()
                        $runspace.PowerShell = $null
                        $runspace.Handle = $null
                    }
                    elseif ($runspace.Handle -ne $null)
                    {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime)
                    {
                        if ((New-TimeSpan -Start $StartTime).TotalMinutes -ge $Timeout)
                        {
                            Write-Warning -Message ('Timeout {0}' -f $runspace.IObject)
                            $runspace.PowerShell.Dispose()
                            $runspace.PowerShell = $null
                            $runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($threat in $runspaces.Clone())
                {
                    if ( -not $threat.handle)
                    {
                        Write-Verbose -Message ('Removing {0}' -f $threat.IObject)
                        $runspaces.Remove($threat)
                    }
                }
                if ($ShowProgress)
                {
                    $ProgressSplatting = @{
                        Activity = 'Working'
                        Status = 'Proccesing threads'
                        CurrentOperation = '{0} of {1} total threads done' -f ($bgRunspaceCounter - $runspaces.Count), $bgRunspaceCounter
                        PercentComplete = ($bgRunspaceCounter - $runspaces.Count) / $bgRunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        }
        #endregion Runspace status tracking and result retrieval function
    }
    Process
    {
        foreach ($Object in $InputObject)
        {
            $bgRunspaceCounter++
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameter('bgRunspaceID',$bgRunspaceCounter).AddArgument($Object)
            $psCMD.RunspacePool = $rp
            
            Write-Verbose -Message ('Starting {0}' -f $Object)
            [void]$runspaces.Add(@{
                Handle = $psCMD.BeginInvoke()
                PowerShell = $psCMD
                IObject = $Object
                ID = $bgRunspaceCounter
           })
            Get-Result
        }
    }
    End
    {
        Get-Result -Wait
        if ($ShowProgress)
        {
            Write-Progress -Activity 'Working' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Closing runspace pool"
        $rp.Close()
        $rp.Dispose()
    }
}
function Get-DomainNetBIOSName
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Identity
    )

    Process
    {
        foreach ($Domain in $Identity)
        {
                $RootDSE = [ADSI]"LDAP://RootDSE"
                $ConfigNC = $RootDSE.Get("configurationNamingContext")
                $ADSearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Partitions," + $ConfigNC)
                $SearchString="(&(objectclass=Crossref)(dnsRoot="+$Domain+")(netBIOSName=*))"
                $Search = New-Object System.DirectoryServices.DirectorySearcher($ADSearchRoot,$SearchString)
                $NetBIOSName = ($Search.FindOne()).Properties["netbiosname"]
                Write-Output $NetBIOSName
        }
    }
}

function Get-ForestInfo
{
    [CmdletBinding()]
    Param
    (
    )
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}

if (!(Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue))
{
	if (Test-Path "$($env:ExchangeInstallPath)bin\RemoteExchange.ps1")
	{
		. "$($env:ExchangeInstallPath)bin\RemoteExchange.ps1"
		Connect-ExchangeServer -auto
	} else {
		throw "Exchange Management Shell cannot be loaded"
	}
}
$xmlData = @()
Set-ADServerSettings -ViewEntireForest:$true
$MyDocsPath = [Environment]::GetFolderPath("MyDocuments")
$HTMLOutPath = Join-Path -Path $MyDocsPath -ChildPath "ExRESScoping.html"
$XMLOutPath = Join-Path -Path $MyDocsPath -ChildPath "ExRESScoping.xml"

try
{
    $Forest = Get-ForestInfo -ErrorAction Stop    
    $ForestHTML = $Forest | ConvertTo-Html -Property Name, ForestMode -Fragment -As List -PreContent "<h2>Forest:</h2>" | Out-String

}
catch
{
    throw "Failed to get AD Data: $($_.Exception.Message)"
}

$DomainData = $Forest.Domains | ForEach-Object -Process {
    try
    {
        New-Object -TypeName PSObject -Property @{
            DomainName = $_.Name
            ParentDomain = $_.Parent
            ChildDomains = ($_.Children | ForEach-Object {$_.Name}) -join ', '
            DomainMode = $_.DomainMode
            DN = $_.GetDirectoryEntry().distinguishedName[0]
            NetBIOSName = Get-DomainNetBIOSName $_.Name -ErrorAction Stop
            PDC = $_.PdcRoleOwner
        }
    }
    catch
    {
        Write-Warning -Message ("Error retrieving domain data {0}: {1}" -f $_.Name, $_.Exception.Message)
    }
}
$DomainHTML = $DomainData | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Domains:</h2>" | Out-String
$DomainData | %{$xmlData += [PSCustomObject]@{Type="AD";DomainName=$_.DomainName;PDC=$_.PDC;NetBIOSName=$_.NetBIOSName}}

$SitesHTML = Get-ADSite | ConvertTo-Html -Fragment -As Table -Property Name, HubSiteEnabled -PreContent "<h2>Sites:</h2>" | Out-String
$SitesLinkHTML = Get-ADSiteLink | ConvertTo-Html -Fragment -As Table -Property Name, Cost, ADCost, ExchangeCost, @{L='Sites';E={($_.Sites | foreach {$_.Rdn.EscapedName}) -join ', ' }} -PreContent "<h2>Site links:</h2>" | Out-String

$OrgConfigData = Get-OrganizationConfig
$xmlData += [PSCustomObject]@{Type="Org";Name=$OrgConfigData.Name}
$OrgConfigHTML = $OrgConfigData | ConvertTo-Html -Fragment -As List -Property Name, AdminDisplayName -PreContent "<h2>Organization Info:</h2>" | Out-String

#Resolve Build number to CU friendly name (reused from original HealthChecker.ps1 :))
function Get-ExchangeUpdateName($build)
{
	switch($build)
	{
		#Exchange 2016
		{$build -like "Version 15.1 (Build 225.16)"} {"Exchange 2016 RTM"}
		{$build -like "Version 15.1 (Build 396.30)"} {"Exchange 2016 CU1"}
		{$build -like "Version 15.1 (Build 466.34)"} {"Exchange 2016 CU2"}
		{$build -like "Version 15.1 (Build 544.27)"} {"Exchange 2016 CU3"}
		{$build -like "Version 15.1 (Build 669.32)"} {"Exchange 2016 CU4"}
		{$build -like "Version 15.1 (Build 845.34)"} {"Exchange 2016 CU5"}
		{$build -like "Version 15.1 (Build 1034.26)"} {"Exchange 2016 CU6"}
		{$build -like "Version 15.1 (Build 1261.35)"} {"Exchange 2016 CU7"}
		{$build -like "Version 15.1 (Build 1415.2)"} {"Exchange 2016 CU8"}
		{$build -like "Version 15.1 (Build 1466.3)"} {"Exchange 2016 CU9"}
		{$build -like "Version 15.1 (Build 1531.3)"} {"Exchange 2016 CU10"}
		#Exchange 2013
		{$build -like "Version 15.0 (Build 516.32)"} {"Exchange 2013 RTM"}
		{$build -like "Version 15.0 (Build 620.29)"} {"Exchange 2013 CU1"}
		{$build -like "Version 15.0 (Build 712.24)"} {"Exchange 2013 CU2"}
		{$build -like "Version 15.0 (Build 775.38)"} {"Exchange 2013 CU3"}
		{$build -like "Version 15.0 (Build 847.32)"} {"Exchange 2013 CU4"}
		{$build -like "Version 15.0 (Build 913.22)"} {"Exchange 2013 CU5"}
		{$build -like "Version 15.0 (Build 995.29)"} {"Exchange 2013 CU6"}
		{$build -like "Version 15.0 (Build 1044.25)"} {"Exchange 2013 CU7"}
		{$build -like "Version 15.0 (Build 1076.9)"} {"Exchange 2013 CU8"}
		{$build -like "Version 15.0 (Build 1104.5)"} {"Exchange 2013 CU9"}
		{$build -like "Version 15.0 (Build 1130.7)"} {"Exchange 2013 CU10"}
		{$build -like "Version 15.0 (Build 1156.6)"} {"Exchange 2013 CU11"}
		{$build -like "Version 15.0 (Build 1178.4)"} {"Exchange 2013 CU12"}
		{$build -like "Version 15.0 (Build 1210.3)"} {"Exchange 2013 CU13"}
		{$build -like "Version 15.0 (Build 1236.3)"} {"Exchange 2013 CU14"}
		{$build -like "Version 15.0 (Build 1263.5)"} {"Exchange 2013 CU15"}
		{$build -like "Version 15.0 (Build 1293.2)"} {"Exchange 2013 CU16"}
		{$build -like "Version 15.0 (Build 1320.4)"} {"Exchange 2013 CU17"}
		{$build -like "Version 15.0 (Build 1347.2)"} {"Exchange 2013 CU18"}
		{$build -like "Version 15.0 (Build 1365.1)"} {"Exchange 2013 CU19"}
		{$build -like "Version 15.0 (Build 1367.3)"} {"Exchange 2013 CU20"}
		{$build -like "Version 15.0 (Build 1395.4)"} {"Exchange 2013 CU21"}
		#Exchange 2010
		{$build -like "Version 14.3 (Build 123.4)"} {"Exchange 2010 SP3"}
		default {"Exchange 20??"}
	}
}

$DAGData = Get-DatabaseAvailabilityGroup | Sort-Object WhenCreatedUTC -Descending | Select-Object -First 1
$DAGData | %{$xmlData += [PSCustomObject]@{Type="DAG";Name=$_.Name;Servers=$_.Servers.Name}}

$DAGsHTML = $DAGData | ConvertTo-Html -Property Name, @{'L'='Servers';'E'={$_.Servers.Name -join ' '}}, WitnessServer, DatacenterActivationMode, @{l='IPv4 Addressess';e={($_.DatabaseAvailabilityGroupIpv4Addresses | Select-Object -ExpandProperty IPAddressToString) -Join ','}}, ThirdpartyReplication, AllowCrossSiteRpcClientAccess -Fragment -As Table -PreContent "<h2>Database Availability Groups:</h2>" | Out-String

$DAGNetworksHTML = Get-DatabaseAvailabilityGroupNetwork -Identity $DAGData.Name | ConvertTo-Html -Property Name, @{l='Subnets';e={$_.Subnets | % {$_.SubnetId.IPRange.Expression}}}, MapiAccessEnabled,ReplicationEnabled,IgnoreNetwork -Fragment -As Table -PreContent "<h2>DAG Networks:</h2>" | Out-String

$DAGServers = $DAGData.Servers | Sort-Object
$ExchangeSrvs = ForEach ($DAGSrv in $DAGServers){Get-ExchangeServer -Status $DAGSrv.Name}

$WhichExVer = $ExchangeSrvs[0].AdminDisplayVersion
$WhichExSite = $ExchangeSrvs[0].Site

$ExchangeServers = $ExchangeSrvs | ForEach-Object {
    New-Object -TypeName PSObject -Property @{
        ServerName = $_.Name
        Domain = $_.Domain
        Site = $_.Site
        ServerRoles = $_.ServerRole
        GC = $_.CurrentGlobalCatalogs -join ', '
        Edition = $_.Edition
        FQDN = $_.Fqdn
        OSVersion = ''
        OSSPVersion = ''
        Disks = ''
        ExVersion = Get-ExchangeUpdateName($_.AdminDisplayVersion)
        'IPv4 Addresses' = ''
        'Subnet Mask' = ''
        'Default Gateway' = ''
        'DNS Servers' = ''
    }
}
$ExchangeData = $ExchangeServers | where {$_.ServerRoles -notlike "*edge*"} | Invoke-RunspaceJob -ThrottleLimit 50 -Timeout 2 -ScriptBlock {
    $ResultObject = $_
    $OS = Get-WmiObject -Class Win32_OperatingSystem -Property Caption, CSDVersion -ComputerName  $ResultObject.Fqdn -ErrorAction Stop
    $Disks = (Get-WmiObject -Class Win32_Volume -Property Name, Capacity, FreeSpace, BlockSize -Filter "DriveType = 3" -ComputerName $ResultObject.Fqdn -ErrorAction Stop | ForEach-Object -Process {
        "Path={0}; Capacity={1:N2} GB; Free={2:N2} GB; Cluster={3} KB" -f $_.Name, ($_.Capacity / 1gb), ($_.FreeSpace / 1gb), ($_.BlockSize / 1kb)
    }) -join "---------"
    $IPConfig  = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName  $ResultObject.Fqdn -ErrorAction Stop | ? {$_.DefaultIPGateway -ne $Null} | 
                    Select-Object @{l='IPv4 Addresses';e={$_.IPAddress -match '(\d{1,3}\.){3}\d{1,3}'}}, `
                                  @{l='Subnet Mask';e={@($_.IPSubnet)[0]}}, `
                                  @{l='Default Gateway';e={$_.DefaultIPGateway}}, `
                                  @{l='DNS Servers';e={$_.DNSServerSearchOrder}}
    if ($OS)
    {
        $ResultObject.OSVersion = $OS.Caption
        $ResultObject.OSSPVersion = $OS.CSDVersion
    }
    if ($Disks)
    {
        $ResultObject.Disks = $Disks
    }
    if ($IPConfig) {
        $ResultObject.'IPv4 Addresses' = $IPConfig.'IPv4 Addresses' -join ','
        $ResultObject.'Subnet Mask' = $IPConfig.'Subnet Mask'
        $ResultObject.'Default Gateway' = $IPConfig.'Default Gateway'
        $ResultObject.'DNS Servers' = $IPConfig.'DNS Servers' -join ','
    }
    Write-Output $ResultObject
}

$exchangeData | %{$xmlData += [PSCustomObject]@{Type="Server";Name=$_.ServerName;ServerRoles=$_.ServerRoles;FQDN=$_.FQDN;Site=$_.Site;Domain=$_.Domain;GC=$_.GC;Disks=$_.Disks;ExVersion=$_.ExVersion}}
$ExchangeServersHTML = $ExchangeData | sort Site,ServerRoles,ServerName | ConvertTo-Html -Property ServerName,ServerRoles,FQDN,GC,Site,OSVersion,Disks,OSSPVersion,ExVersion,Edition,Domain -Fragment -As Table -PreContent "<h2>Servers:</h2>" | Out-String

$TCPIPHTML = $ExchangeData | ConvertTo-Html -Property ServerName, 'IPv4 Addresses', 'Subnet Mask', 'Default Gateway', 'DNS Servers' -Fragment -As Table -PreContent "<h2>TCP/IP Config:</h2>" | Out-String

$MailboxDBs = ForEach ($DAGSrv in $DAGServers){Get-MailboxDatabase -Server $DAGSrv.Name}
$MailboxDBs =  $MailboxDBs | select -uniq

$MailboxData = $MailboxDBs | Sort-Object Name | Select-Object Name, Server, EdbFilePath, LogFolderPath, MasterServerOrAvailabilityGroup, MasterType, Recovery, @{L='Copies';E={($_.DatabaseCopies | Select-Object -ExpandProperty HostServerName) -join ' '}}
$MailboxData | %{$xmlData += [PSCustomObject]@{Type="DB";Name=$_.Name;EdbFilePath=$_.EdbFilePath;LogFolderPath=$_.LogFolderPath;DAG=$_.MasterServerOrAvailabilityGroup;MasterType=$_.MasterType;Recovery=$_.Recovery;Copies=$_.Copies}}

$MailboxDBHTML = $MailboxData | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Mailbox Databases:</h2>" | Out-String

$EdgeSubscription = Get-EdgeSubscription
if ($EdgeSubscription -ne $null) {
    $EdgeHTML = $EdgeSubscription | ConvertTo-Html -Fragment -As Table -Property Name, Site, Domain -PreContent "<h2>Edge:</h2>" | Out-String
}

$AcceptedDomainsData = Get-AcceptedDomain
$AcceptedDomainsData | ?{$_.Default -eq "True"} | %{$xmlData += [PSCustomObject]@{Type="AcceptedDomains";Name=$_.Name;DomainName=$_.DomainName}}

$AcceptedDomainsHTML = $AcceptedDomainsData | ConvertTo-Html -Property Name, DomainName, DomainType, Default -Fragment -As Table -PreContent "<h2>Accepted Domains:</h2>" | Out-String

$EmailAddressPoliciesHTML = Get-EmailAddressPolicy | ConvertTo-Html Name, Priority, EnabledPrimarySMTPAddressTemplate, IncludedRecipients -Fragment -As Table -PreContent "<h2>Email Address Policies:</h2>" | Out-String

Switch ($WhichExVer)
	{
		{$WhichExVer -like "*14.*"} {
			$CASServers = Get-ExchangeServer | ? {$_.Site -eq $WhichExSite -and $_.ServerRole -like "*ClientAccess*" -and $_.AdminDisplayVersion -like "*14.*"}
			$CASConfig = ForEach ($CASSrv in $CASServers){Get-ClientAccessServer -IncludeAlternateServiceAccountCredentialStatus -Identity $CASSrv.Name | Select-Object Name, AutoDiscoverServiceInternalUri, AlternateServiceAccountConfiguration}
		}
		{$WhichExVer -like "*15.0*"} {
			$CASServers = Get-ExchangeServer | ? {$_.Site -eq $WhichExSite -and $_.ServerRole -like "*ClientAccess*" -and $_.AdminDisplayVersion -like "*15.0*"}
			$CASConfig = ForEach ($CASSrv in $CASServers){Get-ClientAccessServer -IncludeAlternateServiceAccountCredentialStatus -Identity $CASSrv.Name | Select-Object Name, AutoDiscoverServiceInternalUri, AlternateServiceAccountConfiguration}
		}
		{$WhichExVer -like "*15.1*"} {
			$CASServers = $DAGServers
			$CASConfig = ForEach ($CASSrv in $CASServers){Get-ClientAccessService -IncludeAlternateServiceAccountCredentialStatus -Identity $CASSrv.Name | Select-Object Name, AutoDiscoverServiceInternalUri, AlternateServiceAccountConfiguration}
		}
	}
$CASConfigHTML = $CASConfig | ConvertTo-Html -Fragment -As Table -PreContent "<h2>CAS Config:</h2>" | Out-String

$URLConfig = @()
$URLConfig += ForEach ($CASSrv in $CASServers){Get-OutlookAnywhere -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, @{L='InternalUrl';E={$_.InternalHostName}}, @{L='ExternalUrl';E={$_.ExternalHostName}}, @{L='InternalAuthenticationMethods';E={$_.InternalClientAuthenticationMethod}}, @{L='ExternalAuthenticationMethods';E={$_.ExternalClientAuthenticationMethod}}, @{L='IISAuthenticationMethods';E={($_.IISAuthenticationMethods) -join ' '}}}
If ($WhichExVer -like "*15.*") {$URLConfig += ForEach ($CASSrv in $CASServers){Get-MAPIVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}, @{L='IISAuthenticationMethods';E={($_.IISAuthenticationMethods) -join ' '}}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-OABVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-WebServicesVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-OwaVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-EcpVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-ActiveSyncVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfig += ForEach ($CASSrv in $CASServers){Get-AutodiscoverVirtualDirectory -Server $CASSrv.Name -ADPropertiesOnly | Select-Object Identity, InternalUrl, ExternalUrl, @{L='InternalAuthenticationMethods';E={($_.InternalAuthenticationMethods) -join ' '}}, @{L='ExternalAuthenticationMethods';E={($_.ExternalAuthenticationMethods) -join ' '}}}
$URLConfigHTML = $URLConfig | ConvertTo-Html -Fragment -As Table -PreContent "<h2>CAS URLs and Authentication:</h2>" | Out-String

$Header + "<h1>Exchange Recovery Execution Service (ExRES) Scoping Tool</h1>" + $ForestHTML + $OrgConfigHTML + $DomainHTML + $SitesHTML + $SitesLinkHTML + $DAGsHTML + $ExchangeServersHTML + $EdgeHTML + $TCPIPHTML + $DAGNetworksHTML + $MailboxDBHTML + $AcceptedDomainsHTML + $EmailAddressPoliciesHTML + $CASConfigHTML + $URLConfigHTML | Out-File $HTMLOutPath -Force
$xmlData | Export-Clixml -Path $XMLOutPath
Create-ZipFile -dir $MyDocsPath
$zipPath = Join-Path -Path $MyDocsPath -ChildPath "ExRESScoping.zip"
Invoke-Expression "explorer.exe '/select,$zipPath'"
Write-Host "Please upload the $zipPath file to the secure UDE Workspace provided by the MS Engineer."
