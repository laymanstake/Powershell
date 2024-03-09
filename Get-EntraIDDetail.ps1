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


if(Get-MgContext) {	
	# Disconnect current connection before starting
	Disconnect-MGGraph
	Connect-MGGraph -NoWelcome -scopes Directory.Read.All, IdentityProvider.Read.All, OnPremDirectorySynchronization.Read.All, SecurityEvents.Read.All
} else {
	# Connect with tenant if no existing connection
	Connect-MGGraph -NoWelcome -scopes Directory.Read.All, IdentityProvider.Read.All, OnPremDirectorySynchronization.Read.All, SecurityEvents.Read.All
}

$ConnectionDetail = Get-MgContext | Select-Object Account, TenantId, Environment, @{l="Scopes";e={$_.Scopes -join ","}}

$TenantBasicDetail = Get-MgOrganization | Select-Object DisplayName, CreatedDateTime, CountryLetterCode, Id, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, TenantType, @{l="Domain";e={($_.VerifiedDomains | Where-Object{$_.Name -notlike "*.Onmicrosoft.com"}) | ForEach-Object{"$($_.Type):$($_.Name)"}}}

$ServicePlans = (Get-MgSubscribedSku | Where-Object{$_.ServicePlans.ProvisioningStatus -eq "Success"}).ServicePlans.ServicePlanName

If($ServicePlans -contains "AAD_Premium_P2"){
	$EntraLicense = "Entra ID P2"
} elseif ($ServicePlans -contains "AAD_Premium") {
	$EntraLicense = "Entra ID P1"
} else {
	$EntraLicense = "Entra ID Free"
}