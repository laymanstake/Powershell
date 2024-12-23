function Get-GPOSettingReport {
    <#
        .SYNOPSIS
        This function provides all users and computer settings for a given GPO or a set of GPOs
        .DESCRIPTION
        As of now, its limited to list only the settings which are visible under all settings sections
        .PARAMETER GPO
        Specify one GPO name or list of multiple GPOs name
        .PARAMETER outputPath
        Specify filename (CSV) for the output
        .INPUTS
        None. It doesn't support input via pipeline
        .OUTPUTS
        System.String, System.object
        .EXAMPLE
        PS> Get-GPOSettingReport -GPO "Default Domain Policy"
        .EXAMPLE
        PS> Get-GPOSettingReport -GPO "Default Domain Policy","WSUS"
        .EXAMPLE
        PS> Get-GPOSettingReport -GPO "Default Domain Policy","WSUS" -outputPath c:\temp\GPOSettingReport.csv
        .LINK
        https://nitishkumar.net
	#>

    param (
        [Parameter(Mandatory = $true)][validatescript({ $_.count -ge 1 })][string[]]$GPO,
        [Parameter(Mandatory = $false)][validatescript({ Test-Path -Path $_ -IsValid })][string]$outputPath
    )
    
    $Results = @()

    ForEach ($GPOName in $GPO) {
        $GPOxml = [xml](Get-GPOReport -Name $GPOName -ReportType Xml)        

        $GPOInfo = $GPOxml.GPO

        #Write-Host "Processing $($GPOInfo.Name).."

        ForEach ($extension in $GPOxml.GPO.Computer.ExtensionData.Extension) {
            If ($extension.Policy.Name) {
                ForEach ($policy in $extension.Policy) {
                    $dropdownlist = ""
                    $Checkbox = ""

                    $dropdownlist += ForEach ($dd in $policy.dropdownlist) {
                        if ($dd) {
                            "$($dd.Name) $($dd.State): $( $dd.value.name)"
                        }
                    } 

                    $dropdownlist = $dropdownlist -join "`n"
                    

                    $Checkbox += ForEach ($cb in $policy.checkbox) {
                        if ($cb) {
                            "$($cb.Name) $($cb.State): $( $cb.value.name)"
                        }
                    }  

                    $Checkbox = $Checkbox -join "`n" 
                    
                    $results += [PSCustomObject]@{
                        GPOName     = $GPOInfo.Name
                        Type        = "Computer settings"
                        SettingName = $Policy.Name
                        State       = $Policy.state
                        Settings    = $dropdownlist + "`n" + $Checkbox
                        Explanation = $policy.explain
                        Category    = $Policy.category
                    }
                }
            }
        }

        ForEach ($extension in $GPOxml.GPO.User.ExtensionData.Extension) {
            If ($extension.Policy.Name) {
                ForEach ($policy in $extension.Policy) {
                    $dropdownlist = ""
                    $Checkbox = ""
                    $dropdownlist += ForEach ($dd in $policy.dropdownlist) {
                        if ($dd) {
                            "$($dd.Name) $($dd.State): $( $dd.value.name)"
                        }
                    } 

                    $dropdownlist = $dropdownlist -join "`n"
                    

                    $Checkbox += ForEach ($cb in $policy.checkbox) {
                        if ($cb) {
                            "$($cb.Name) $($cb.State): $( $cb.value.name)"
                        }
                    }  

                    $Checkbox = $Checkbox -join "`n" 

                    $results += [PSCustomObject]@{
                        GPOName     = $GPOInfo.Name
                        Type        = "User settings"
                        SettingName = $Policy.Name
                        State       = $Policy.state                        
                        Settings    = $dropdownlist + "`n" + $Checkbox
                        Explanation = $policy.explain
                        Category    = $Policy.category
                    }
                }
            }
        }
    }

    If ($outputPath) {
        $results | Export-csv -NoTypeInformation $outputPath
    }
    else {
        return $results
    }
}

$GPOs = (Get-GPO -All ).DisplayName

Get-GPOSettingReport -GPO $GPOs -outputPath "c:\temp\AllGPOSettings.csv"