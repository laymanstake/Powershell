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
        [Parameter(Mandatory = $false)][validatescript({
                $parentPath = Split-Path -Parent $_
                if (-not (Test-Path -Path $parentPath)) {
                    New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
                }
                $true
            })][string]$outputPath
    )
    
    $Results = @()

    ForEach ($GPOName in $GPO) {        
        # capture the GPO settings in XML format
        $GPOxml = [xml](Get-GPOReport -Name $GPOName -ReportType Xml)        

        # capture the GPO basic information
        $GPOInfo = $GPOxml.GPO

        # capture the computer settings
        ForEach ($extension in $GPOxml.GPO.Computer.ExtensionData.Extension) {
            # Looking for startup and shutdown scripts configured
            If ( $extension.type -like "*Scripts" ) {
                ForEach ($scr in $extension.Script) {
                    If ($scr.command) {
                        $results += [PSCustomObject]@{
                            GPOName     = $GPOInfo.Name
                            Type        = "Computer settings"
                            SettingName = "Scripts (Startup/ Shutdown)"
                            State       = "Enabled"
                            Settings    = "$($scr.command) : $($scr.Type) : $($scr.Order) : $($scr.RunOrder)" 
                            Explanation = ""
                            Category    = "Windows Settings/Scripts"
                        }
                    }
                }
            }

            # Looking for registry entries configured
            If ( $extension.type -like "*SecuritySettings" ) {
                ForEach ($reg in $extension.Registry) {
                    If ($reg.Path) {
                        $results += [PSCustomObject]@{
                            GPOName     = $GPOInfo.Name
                            Type        = "Computer settings"
                            SettingName = "Security Settings/Registry"
                            State       = ""
                            Settings    = "$($reg.Path) | $($reg.Mode)" 
                            Explanation = ""
                            Category    = "Windows Settings/Security Settings/Registry"
                        }
                    }
                }

                # Looking for system services configured
                ForEach ($sService in $extension.SystemServices) {
                    If ($sService.Name) {
                        $results += [PSCustomObject]@{
                            GPOName     = $GPOInfo.Name
                            Type        = "Computer settings"
                            SettingName = "Security Settings/SystemServices"
                            State       = ""
                            Settings    = "$($sService.Name):$($sService.StartupMode)" 
                            Explanation = ""
                            Category    = "Windows Settings/Security Settings/SystemServices"
                        }
                    }
                }

                # Looking for restricted groups configured
                ForEach ($rGroup in $extension.RestrictedGroups) {
                    If ($rgroup.groupname.name.'#Text') {
                        $results += [PSCustomObject]@{
                            GPOName     = $GPOInfo.Name
                            Type        = "Computer settings"
                            SettingName = "Security Settings/RestrictedGroups"
                            State       = ""
                            Settings    = "GroupName:: $($rgroup.groupname.name.'#Text') : Member:: $($rgroup.member.name.'#Text') : MemberOf:: $($rgroup.memberOf.name.'#Text')" 
                            Explanation = ""
                            Category    = "Windows Settings/Security Settings/RestrictedGroups"
                        }
                    }
                }

                # Looking for security options configured
                ForEach ($secoption in $extension.SecurityOptions) {
                    If ($secoption.display.Name) {
                        $results += [PSCustomObject]@{
                            GPOName     = $GPOInfo.Name
                            Type        = "Computer settings"
                            SettingName = "Security Settings/SecurityOptions"
                            State       = ""
                            Settings    = "$($secoption.display.Name)::$($secoption.display.displayString)$($secoption.display.displayBoolean)$(($secoption.display.displayFields.field | ForEach-Object {"$($_.Name) $($_.value)"}) -join "`n")"
                            Explanation = ""
                            Category    = "Windows Settings/Security Settings/SecurityOptions"
                        }
                    }
                }
            }

            # Looking for all settings configured
            If ($extension.Policy.Name) {
                ForEach ($policy in $extension.Policy) {
                    $dropdownlist = ""
                    $Checkbox = ""

                    $dropdownlist += ForEach ($dd in $policy.dropdownlist) {                        
                        "$($dd.Name) $($dd.State): $( $dd.value.name)"                        
                    } 

                    # Convert the dropdownlist array to string
                    $dropdownlist = $dropdownlist -join "`n"                    

                    $Checkbox += ForEach ($cb in $policy.checkbox) {                        
                        "$($cb.Name) $($cb.State): $( $cb.value.name)"                        
                    }  

                    # Conver the checkbox array to string
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

        # capture the user settings
        ForEach ($extension in $GPOxml.GPO.User.ExtensionData.Extension) {
            If ($extension.Policy.Name) {
                ForEach ($policy in $extension.Policy) {
                    $dropdownlist = ""
                    $Checkbox = ""
                    
                    $dropdownlist += ForEach ($dd in $policy.dropdownlist) {                    
                        "$($dd.Name) $($dd.State): $( $dd.value.name)"                        
                    } 

                    $dropdownlist = $dropdownlist -join "`n"
                    
                    $Checkbox += ForEach ($cb in $policy.checkbox) {                    
                        "$($cb.Name) $($cb.State): $( $cb.value.name)"                        
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