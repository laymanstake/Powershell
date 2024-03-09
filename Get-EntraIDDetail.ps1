<#
.SYNOPSIS
	Script to get important details of Entra ID
.DESCRIPTION
	Script to get important details of Entra ID
.NOTES
	This would need a number of permissions, which would involve the Global admin permissions for the first time but all these permissions are READ permissions and would not make change in curnt configuration
.LINK
	https://nitishkumar.net
.EXAMPLE
	Test-MyTestFunction -Verbose
	
#>

# Output formating options
$logopath = "https://camo.githubusercontent.com/239d9de795c471d44ad89783ec7dc03a76f5c0d60d00e457c181b6e95c6950b6/68747470733a2f2f6e69746973686b756d61722e66696c65732e776f726470726573732e636f6d2f323032322f31302f63726f707065642d696d675f32303232303732335f3039343534372d72656d6f766562672d707265766965772e706e67"
$ReportPath = "$env:USERPROFILE\desktop\EntraIDReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
$CopyRightInfo = " @Copyright Nitish Kumar <a href='https://github.com/laymanstake'>Visit nitishkumar.net</a>"

# CSS codes to format the report
$header = @"
<style>
    body { background-color: #b9d7f7; }
    h1 { font-family: Arial, Helvetica, sans-serif; color: #e68a00; font-size: 28px; }    
    h2 { font-family: Arial, Helvetica, sans-serif; color: #000099; font-size: 16px; }    
    table { font-size: 12px; border: 1px;  font-family: Arial, Helvetica, sans-serif; } 	
    td { padding: 4px; margin: 0px; border: 1; }	
    th { background: #395870; background: linear-gradient(#49708f, #293f50); color: #fff; font-size: 11px; text-transform: uppercase; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    CreationDate { font-family: Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
</style>
"@

If ($logopath) {
	$header = $header + "<img src=$logopath alt='Company logo' width='150' height='150' align='right'>"
}


if (Get-MgContext) {	
	# Disconnect current connection before starting
	Disconnect-MGGraph
	Connect-MGGraph -NoWelcome -scopes Directory.Read.All, IdentityProvider.Read.All, OnPremDirectorySynchronization.Read.All, SecurityEvents.Read.All
}
else {
	# Connect with tenant if no existing connection
	Connect-MGGraph -NoWelcome -scopes Directory.Read.All, IdentityProvider.Read.All, OnPremDirectorySynchronization.Read.All, SecurityEvents.Read.All
}

$ConnectionDetail = Get-MgContext | Select-Object Account, TenantId, Environment, @{l = "Scopes"; e = { $_.Scopes -join "," } }

$ServicePlans = (Get-MgSubscribedSku | Where-Object { $_.ServicePlans.ProvisioningStatus -eq "Success" }).ServicePlans.ServicePlanName

If ($ServicePlans -contains "AAD_Premium_P2") {
	$EntraLicense = "Entra ID P2"
}
elseif ($ServicePlans -contains "AAD_Premium") {
	$EntraLicense = "Entra ID P1"
}
else {
	$EntraLicense = "Entra ID Free"
}

$TenantBasicDetail = Get-MgOrganization | Select-Object DisplayName, CreatedDateTime, CountryLetterCode, @{l = "TenantID"; e = { $_.Id } }, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, TenantType, @{l = "EntraID"; e = { $EntraLicense } }, @{l = "Domain"; e = { (($_.VerifiedDomains | Where-Object { $_.Name -notlike "*.Onmicrosoft.com" }) | ForEach-Object { "$($_.Type):$($_.Name)" } ) -join "``n" } }

$EnabledAuthMethods = (Get-MgPolicyAuthenticationMethodPolicy ).AuthenticationMethodConfigurations | Select-Object @{label = "AuthMethodType"; expression = { $_.Id } }, State

$EnabledAuthSummary = ($EnabledAuthMethods | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Auth Methods Summary</h2>")

$TenantSummary = ($TenantBasicDetail | ConvertTo-Html -As List -Property DisplayName, CreatedDateTime, CountryLetterCode, Id, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, TenantType, EntraID, Domain -Fragment -PreContent "<h2>Entra Summary: $forest</h2>") -replace "`n", "<br>"

$ReportRaw = ConvertTo-HTML -Body "$TenantSummary $EnabledAuthSummary" -Head $header -Title "Report on Entra ID: $($TenantBasicDetail.Displayname)" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
$ReportRaw | Out-File $ReportPath
Invoke-item $ReportPath