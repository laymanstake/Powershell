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
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Scripts (Startup/ Shutdown)"
                            State        = "Enabled"
                            Settings     = "$($scr.command) : $($scr.Type) : $($scr.Order) : $($scr.RunOrder)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Scripts"
                        }
                    }
                }
            }

            # Looking for registry entries configured
            If ( $extension.type -like "*SecuritySettings" ) {
                ForEach ($reg in $extension.Registry) {
                    If ($reg.Path) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Registry"
                            State        = "N/A"
                            Settings     = "$($reg.Path) | $($reg.Mode)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Registry"
                        }
                    }
                }

                # Looking for system services configured
                ForEach ($sService in $extension.SystemServices) {
                    If ($sService.Name) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/SystemServices"
                            State        = "N/A"
                            Settings     = "$($sService.Name):$($sService.StartupMode)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/SystemServices"
                        }
                    }
                }

                # Looking for restricted groups configured
                ForEach ($rGroup in $extension.RestrictedGroups) {
                    If ($rgroup.groupname.name.'#Text') {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/RestrictedGroups"
                            State        = "N/A"
                            Settings     = "GroupName:: $($rgroup.groupname.name.'#Text') : Member:: $($rgroup.member.name.'#Text') : MemberOf:: $($rgroup.memberOf.name.'#Text')" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/RestrictedGroups"
                        }
                    }
                }

                # Looking for security options configured
                ForEach ($secoption in $extension.SecurityOptions) {
                    If ($secoption.display.Name) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/SecurityOptions"
                            State        = "N/A"
                            Settings     = "$($secoption.display.Name)::$($secoption.display.displayString)$($secoption.display.displayBoolean)$(($secoption.display.displayFields.field | ForEach-Object {"$($_.Name) $($_.value)"}) -join "`n")"
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/SecurityOptions"
                        }
                    }
                }

                # Looking for user rights assignments
                ForEach ($rasgnmnt in $extension.UserRightsAssignment) {
                    If ($rasgnmnt.member.name."#text") {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Local Policies/User Rights Assignment"
                            State        = "N/A"
                            Settings     = "Assignment type: $($rasgnmnt.name) | Assignment value: $($rasgnmnt.member.name."#text")" 
                            Explanation  = "N/A"
                            Category     = "Local Policies/User Rights Assignment"
                        }
                    }
                }
            }

            # Looking for registry entries configured
            If ( $extension.type -like "*RegistrySettings" ) {
                ForEach ($reg in $extension.registrysetting) {
                    If ($reg.value) {
                        $regdetails = $reg | Where-Object { $_.value } | select-Object @{l = "keypath"; e = { $_.keypath + "\" + $_.value.Name } }, @{l = "value"; e = { "$($_.value.string)$($_.value.number)" } }

                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Administrative Templates/Extra Registry Settings"
                            State        = "N/A"
                            Settings     = "$($regdetails.keypath) | $($regdetails.value)" 
                            Explanation  = "N/A"
                            Category     = "Administrative Templates/Extra Registry Settings"
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
                        GPOName      = $GPOInfo.Name
                        WhenCreated  = $GPOInfo.CreatedTime
                        LastModified = $GPOInfo.ModifiedTime
                        Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                        Type         = "Computer settings"
                        SettingName  = $Policy.Name
                        State        = $Policy.state
                        Settings     = $dropdownlist + "`n" + $Checkbox
                        Explanation  = $policy.explain
                        Category     = $Policy.category
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
                        GPOName      = $GPOInfo.Name
                        WhenCreated  = $GPOInfo.CreatedTime
                        LastModified = $GPOInfo.ModifiedTime
                        Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                        Type         = "User settings"
                        SettingName  = $Policy.Name
                        State        = $Policy.state                        
                        Settings     = $dropdownlist + "`n" + $Checkbox
                        Explanation  = $policy.explain
                        Category     = $Policy.category
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