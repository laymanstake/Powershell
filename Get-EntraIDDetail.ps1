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
$logopath = "https://raw.githubusercontent.com/laymanstake/laymanstake/master/images/logo.png"
$ReportPath = "c:\temp\EntraIDReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
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

$TenantBasicDetail = Get-MgOrganization | Select-Object DisplayName, CreatedDateTime, CountryLetterCode, @{l = "TenantID"; e = { $_.Id } }, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, TenantType, @{l = "EntraID"; e = { $EntraLicense } }, @{l = "Domain"; e = { (($_.VerifiedDomains | Where-Object { $_.Name -notlike "*.Onmicrosoft.com" }) | ForEach-Object { "$($_.Type):$($_.Name)" } ) -join "``n" } }, @{l = "SecurityDefaults"; e = { (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy")["isEnabled"] } }

$EnabledAuthMethods = (Get-MgPolicyAuthenticationMethodPolicy ).AuthenticationMethodConfigurations | Select-Object @{label = "AuthMethodType"; expression = { $_.Id } }, State

$MonitoredPriviledgedRoles = ("Global Administrator", "Global Reader", "Security Administrator", "Privileged Authentication Administrator", "User Administrator")
$ActivatedRoles = Get-MgDirectoryRole | Select-Object Id, Displayname

$RoleDetail = ForEach ($privilegedRole in $MonitoredPriviledgedRoles) {	
	$RoleID = ($ActivatedRoles | Where-Object { $_.DisplayName -eq $privilegedRole }).Id	
	If ($privilegedRole -in $ActivatedRoles.DisplayName) {
		$name = $privilegedRole
		$Count = Get-MgDirectoryRoleMemberCount -DirectoryRoleId $RoleID -ConsistencyLevel eventual
	}
	else {
		$name = $privilegedRole
		$count = "Role not activated"
	}

	[PSCustomObject]@{		
		Name  = $Name
		Count = $Count
	}
}

# License summary 

$LicenseDetail = Get-MgSubscribedSku -all | Select-Object SkuPartNumber, SkuId, @{Name = "ActiveUnits"; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits, @{Name = "AvailableUnits"; Expression = { ($_.PrepaidUnits).Enabled - $_.ConsumedUnits } }
$CASPolicyDetail = Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime

# Create HTML table elements
$EnabledAuthSummary = ($EnabledAuthMethods | Sort-Object State -Descending | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Auth Methods Summary : $($TenantBasicDetail.DisplayName)</h2>")
$RoleSummary = ($RoleDetail | Sort-Object Count | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Priviledged Entra Role Summary: $($TenantBasicDetail.DisplayName)</h2>")
$TenantSummary = ($TenantBasicDetail | ConvertTo-Html -As List -Property DisplayName, CreatedDateTime, CountryLetterCode, Id, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime, TenantType, EntraID, Domain, SecurityDefaults -Fragment -PreContent "<h2>Entra Summary: $forest</h2>") -replace "`n", "<br>"
$LicenseSummary = $LicenseDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>License Summary: $($TenantBasicDetail.DisplayName)</h2>"
$CASSummary = $CASPolicyDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Conditional Access Policy Summary: $($TenantBasicDetail.DisplayName)</h2>"

$ReportRaw = ConvertTo-HTML -Body "$TenantSummary $LicenseSummary $RoleSummary $EnabledAuthSummary $CASSummary" -Head $header -Title "Report on Entra ID: $($TenantBasicDetail.Displayname)" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
$ReportRaw | Out-File $ReportPath
Invoke-item $ReportPath