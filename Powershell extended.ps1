#Region Miscellaneous
<#
Think plan learning -ne code from internet

.psm1 module
.psd1 data file/manifest
.ps1xml 
.pscc session configuration
.psrc role capabilities

$Array = @()
(1..200).ForEach({ (1..$_).ForEach({ $array += "x" }) })

$array = New-Object System.Collections.ArrayList
(1..200).ForEach({ (1..$_).ForEach({ $null = $array.add("x") }) })

Function Help (optional)
Function Name
#[Cmdletbinding()] (optional)
parameters (optional)
function logic (optional begin process end)
return (optional)

getProperties()
[DateTime] | Get-Member -Static
$obj | Add-Memeber -NotePropertyMembers @{LineCount = 0 }
([math].DeclaredMethods | Select-Object Name -Unique ).Name -join ", "

With hashtable, you need getEnumerator() for going through foreach.
You can't use Write-Verbose etc unless you are using cmdletbinding. cmdletbinding can provide whatif option if SupportsShouldProcess enabled and begin, process, end blocks there
Default values do not work with mandatory parameters

[appdomain]::CurrentDomain.GetAssemblies().Where({-not($_.IsDynamic)}).ForEach({$_.GetExportedTypes().Where({$_.IsPublic -AND $_.IsEnum})}) | Sort-Object Name
[appdomain]::CurrentDomain.GetAssemblies().Where({-not($_.IsDynamic)}).ForEach({$_.GetExportedTypes().Where({$_.IsPublic -AND $_.IsEnum})}) | Sort-Object Name  | Select-Object name, fullname, @{l="Values";e={($_.declaredmembers | ?{$_.Name -ne "value__"}).Name -join ","}}
[system.enum]::GetValues([system.dayOfweek])


[psobject].assembly.gettype("System.Management.Automation.TypeAccelerators")::Get

# paste your pattern here:
$pattern = '^((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
do
{
	$ip = Read-Host 'Enter IPv4'
} while ($ip -notmatch $pattern)

"Entered and validated IPv4: $ip"
[ipaddress]

function test-alias { 
	switch($MyInvocation.InvocationName) {
		Alias1 {Write-host "Command used was $($MyInvocation.InvocationName)"}
		Alias2 {Write-host "Command used is $($MyInvocation.InvocationName)"}
	} 
}

dont always use *return*

Get-MgUser -UserId manish.kumar@atos.net -ExpandProperty manager | Select displayName, @{Name = 'Manager'; Expression = {$_.Manager.AdditionalProperties.displayName}}
Get-MgGroupMember -GroupId 2cef9a5b-cbe1-4d0e-a464-0ab5e598379f -Property * | select * -ExpandProperty additionalProperties | Select-Object @{l="UserPrincipalName";e={$_.AdditionalProperties["userPrincipalName"]}}, @{l="DisplayName";e={$_.AdditionalProperties["displayName"]}}, @{l="mobilephone";e={$_.AdditionalProperties["mobilePhone"]}}, @{l="mailnickname";e={$_.AdditionalProperties["mailNickname"]}}, @{l="accountEnabled";e={$_.AdditionalProperties["accountEnabled"]}}, @{l="WhenCreated";e={$_.AdditionalProperties["createdDateTime"]}}, @{l="OnPremDomain";e={$_.AdditionalProperties["onPremisesDomainName"]}}

(Get-MgUser -UserId nitish.kumar@atos.net ).psobject.properties | ?{$_.Value -AND $_.Value -notlike "Microsoft*"} | ft Name, Value
(Get-azureadUser -SearchString nitish.kumar@atos.net ).psobject.properties | ?{$_.Value -AND $_.Value -notlike "Microsoft*"} | ft Name, Value

((get-mguser -userId dd143ebf-5bb1-43da-b01f-cb581d321039) | Get-Member | ?{$_.MemberType -eq 'Property'}).Name -join ", "

get-MgUserMailFolderMessageRule -UserId nitish.kumar@atos.net -MailFolderId Inbox
Get-MgUserMailFolder -UserId nitish.kumar@atos.net | Select-Object DisplayName, IsHidden, TotalItemCount, UnreadItemCount, @{l="SizeInMb";e={$_.AdditionalProperties.("sizeInBytes")/1Mb}} | ft

(Get-MgContext).scopes
find-MgGraphCommand -Command Get-MgUserLicenseDetail

#>
#Endregion

#Region HELP

Get-command Get-ChildItem | Select-Object Name, Commandtype, @{l = "Description"; e = { (Get-Help $_.name).Synopsis } }, HelpUri | format-list

#EndRegion

#Region PING

$pingObj = new-object System.Net.NetworkInformation.ping
$PingAnswer = $pingObj.Send("Google.com")
$PingAnswer.status

#EndRegion

#Region SIGNING

$params = @{
	Subject           = 'CN=PowerShell Code Signing Cert'
	Type              = 'CodeSigning'
	CertStoreLocation = 'Cert:\CurrentUser\My'
	HashAlgorithm     = 'sha256'
}
$cert = New-SelfSignedCertificate @params

Set-AuthenticodeSignature add-signature.ps1 $cert

#EndRegion

#Region Credential

If ([System.IO.File]::Exists("C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml")) {
	$UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
}
Else {
	$Answer = Read-host "Want to create credentials file to re-use (Y/N)"
	If ($Answer.ToUpper() -eq "Y") {
		Get-Credential  -Message "Provide O365 admin credentials" | Export-CliXml -Path "C:\temp\myCred_$($env:USERNAME)_$($env:COMPUTERNAME).xml"
		Write-Output "`nCredentials file created."  -Foregroundcolor GREEN -Backgroundcolor White
	}
	Else {
		Write-Output "`nThese credentials would not be saved for later run." -Foregroundcolor RED -Backgroundcolor YELLOW
		$UserCredential = Get-Credential	
	}
}

new-StoredCredential -Target O1365 -Credentials (Get-Credential) -Persist LocalMachine
Get-StoredCredential -target O365
#EndRegion

#Region Editing file access time

$it = get-item C:\temp\caconfig.ps1
$it.CreationTime = (Get-Date).AddYears(-100)

#EndRegion

#Region Regular Expression
[regex]::Escape()

\s whitespace, \w word charater. \d any digit, [] character group [a-c1-3], \b boundary
if CAPS then opposite effect, ^ in group means opposite
* 0 or more times, + 1 or more time, { 2 } 2 times, { 2, 5 } min 2 time and max 5 times
$ means end of line

ipconfig | Select-String -Pattern "IPv4 Address[.\s]*:\s*([\d.]+)\s*$" | ForEach-Object { $_.Matches.Groups[1].Value }


#endRegion

#Region Array
[System.Collections.ArrayList]::new()
[System.Collections.ArrayList]@()
$MyList = New-Object -TypeName System.Collections.ArrayList

#EndRegion

#region speech

Add-Type -AssemblyName System.Speech
$ATAVoiceEngine = New-Object System.Speech.Synthesis.SpeechSynthesizer
$mytext = "Hello Students! Welcome to the powershell class. How are you doing today?"
$ATAVoiceEngine.SelectVoice("Microsoft Zira Desktop")
$ATAVoiceEngine.Speak($mytext)

#endRegion