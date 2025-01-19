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
            # Looking for Public key policies
            If ( $extension.type -like "*PublicKeySettings" ) {
                
                # Root Certification Authorities
                ForEach ($rootcert in $extension.RootCertificate) {
                    If ($rootcert) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Public Key Policies/Trusted Root Certification Authorities"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($rootcert.IssuedTo) | IssuedBy: $($rootcert.IssuedBy) | ExpirationDate: $($rootcert.ExpirationDate)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Trusted Root Certification Authorities"
                        }
                    }
                }

                # Intermediate Certification Authorities
                ForEach ($Intermediaterootcert in $extension.IntermediateCACertificate) {
                    If ($Intermediaterootcert) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Public Key Policies/Intermediate Certification Authorities"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($Intermediaterootcert.IssuedTo) | IssuedBy: $($Intermediaterootcert.IssuedBy) | ExpirationDate: $($Intermediaterootcert.ExpirationDate)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Intermediate Certification Authorities"
                        }
                    }
                }

                # Client - Auto-Enrollment Settings
                ForEach ($AutoEnrollmentSettings in $extension.AutoEnrollmentSettings) {
                    If ($AutoEnrollmentSettings) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Public Key Policies/Certificate Services Client - Auto-Enrollment Settings"
                            State        = "Enabled"
                            Settings     = "EnrollCertificatesAutomatically: $($AutoEnrollmentSettings.EnrollCertificatesAutomatically) | ExpiryNotification: $($AutoEnrollmentSettings.ExpiryNotification) | NotifyPercent: $($AutoEnrollmentSettings.NotifyPercent.value)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Certificate Services Client - Auto-Enrollment Settings"
                        }
                    }
                }

                # Encrypting file system
                ForEach ($efs in $extension.EFSRecoveryAgent) {
                    If ($efs) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Public Key Policies/Encrypting file system"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($efs.IssuedTo) | IssuedBy: $($efs.IssuedBy) | ExpirationDate: $($efs.ExpirationDate) | CertificatePurpose: $($efs.CertificatePurpose.purpose)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Encrypting file system"
                        }
                    }
                }
            }

            # Looking for software installation configured
            If ( $extension.type -like "*SoftwareInstallationSettings" ) {
                ForEach ($app in $extension.MsiApplication) {
                    If ($app) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer Settings/Policies/Software Settings"
                            SettingName  = "Assigned Applications"
                            State        = "N/A"
                            Settings     = "Name: $($app.Name) | Path: $($app.path) | version: $($app.MajorVersion).$($app.MinorVersion) | DeploymentType: $($app.DeploymentType) | AutoInstall: $($app.AutoInstall)" 
                            Explanation  = "N/A"
                            Category     = "Policies/Assigned Applications"
                        }
                    }
                }
            }

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

            # Looking for Advanced Audit Policy Configuration settings
            If ( $extension.type -like "*AuditSettings" ) {
                # Looking for audit policies settings configured
                ForEach ($auditsetting in $extension.auditsetting) {
                    if ($auditsetting) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Advanced Audit Policy Configuration"
                            State        = "Enabled"
                            Settings     = "$($auditsetting.SubcategoryName): $($auditsetting.SettingValue)"
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Advanced Audit Policy Configuration"
                        }
                    }
                }
            }

            # Looking for Windows Firewall Configuration settings
            If ( $extension.type -like "*WindowsFirewallSettings" ) {
                # Looking for Inbound firewall rules configured
                ForEach ($InboundFirewallRule in $extension.InboundFirewallRules) {
                    if ($InboundFirewallRule) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Windows Defender Firewall with Advanced Security/Inbound Rules"
                            State        = $InboundFirewallRule.Active
                            Settings     = "Name: $($InboundFirewallRule.Name) - Profile: $($InboundFirewallRule.Profile -join ' ') - LocalPort: $($InboundFirewallRule.Lport -join ' ') - RemotePort: $($InboundFirewallRule.Rport -join ' ') - App: $($InboundFirewallRule.app) - Protocol: $($InboundFirewallRule.protocol) - Action: $($InboundFirewallRule.Action)"
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Windows Defender Firewall with Advanced Security/Inbound Rules"
                        }
                    }
                }

                # Looking for Outbound firewall rules configured
                ForEach ($OutboundFirewallRule in $extension.OutboundFirewallRules) {
                    if ($OutboundFirewallRule) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Windows Defender Firewall with Advanced Security/Outbound Rules"
                            State        = $OutboundFirewallRule.Active
                            Settings     = "Name: $($OutboundFirewallRule.Name) - Profile: $($OutboundFirewallRule.Profile -join ' ') - LocalPort: $($OutboundFirewallRule.Lport -join ' ') - RemotePort: $($OutboundFirewallRule.Rport -join ' ') - App: $($OutboundFirewallRule.app) - Protocol: $($OutboundFirewallRule.protocol) - Action: $($OutboundFirewallRule.Action)"
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Windows Defender Firewall with Advanced Security/Outbound Rules"
                        }
                    }
                }
            }

            # Looking for registry entries configured
            If ( $extension.type -like "*SecuritySettings" ) {
                # Looking for account policies settings configured
                ForEach ($account in $extension.Account) {
                    If ($account) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Account Policies"
                            State        = "Enabled"
                            Settings     = "$($account.type) policy - $($account.Name): $($account.SettingBoolean)$($account.SettingNumber)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Account Policies"
                        }
                    }
                }

                # Looking for event log settings configured
                ForEach ($eventlog in $extension.eventlog) {
                    If ($eventlog) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Event log"
                            State        = "Enabled"
                            Settings     = "$($eventlog.log) $($eventlog.name): $($eventlog.SettingNumber)$($eventlog.SettingBoolean)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Event log"
                        }
                    }
                }

                # Looking for Audit policy settings configured
                ForEach ($audit in $extension.audit) {
                    If ($audit) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Security Settings/Audit Policy"
                            State        = "Enabled"
                            Settings     = "$($audit.Name) - SuccessAttempts:$($audit.SuccessAttempts) | FailureAttempts:$($audit.FailureAttempts)"
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings/Audit Policy"
                        }
                    }
                }

                # Looking for registry settings configured
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
                    $text = $policy.edittext.value

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
                        Settings     = $text + "`n" + $dropdownlist + "`n" + $Checkbox
                        Explanation  = $policy.explain
                        Category     = $Policy.category
                    }
                }
            }

            # Looking for Wireless Network (802.11) Policies configured
            If ( $extension.type -like "*WLanSvcSettings" ) {
                ForEach ($WLanSvcSetting in $extension.WLanSvcSetting) {
                    If ($WLanSvcSetting) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Computer settings"
                            SettingName  = "Windows Settings/Security Settings/Wireless Network (802.11) Policies"
                            State        = "N/A"
                            Settings     = "Policy Name: $($WLanSvcSetting.WLanPolicies.name)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Security Settings"
                        }
                    }
                }
            }
        }

        # capture the user settings
        ForEach ($extension in $GPOxml.GPO.User.ExtensionData.Extension) {
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

            # Looking for public key settings
            If ( $extension.type -like "*PublicKeySettings" ) {
                
                # Root Certification Authorities
                ForEach ($rootcert in $extension.RootCertificate) {
                    If ($rootcert) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "User settings"
                            SettingName  = "Public Key Policies/Trusted Root Certification Authorities"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($rootcert.IssuedTo) | IssuedBy: $($rootcert.IssuedBy) | ExpirationDate: $($rootcert.ExpirationDate)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Trusted Root Certification Authorities"
                        }
                    }
                }

                # Intermediate Certification Authorities
                ForEach ($Intermediaterootcert in $extension.IntermediateCACertificate) {
                    If ($Intermediaterootcert) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "User settings"
                            SettingName  = "Public Key Policies/Intermediate Certification Authorities"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($Intermediaterootcert.IssuedTo) | IssuedBy: $($Intermediaterootcert.IssuedBy) | ExpirationDate: $($Intermediaterootcert.ExpirationDate)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Intermediate Certification Authorities"
                        }
                    }
                }

                # Trusted People Certificate
                ForEach ($TrustedPeopleCertificate in $extension.TrustedPeopleCertificate) {
                    If ($TrustedPeopleCertificate) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "User settings"
                            SettingName  = "Public Key Policies/Trusted People Certificates"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($TrustedPeopleCertificate.IssuedTo) | IssuedBy: $($TrustedPeopleCertificate.IssuedBy) | ExpirationDate: $($TrustedPeopleCertificate.ExpirationDate)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Trusted People Certificates"
                        }
                    }
                }

                # Client - Auto-Enrollment Settings
                ForEach ($AutoEnrollmentSettings in $extension.AutoEnrollmentSettings) {
                    If ($AutoEnrollmentSettings) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "User settings"
                            SettingName  = "Public Key Policies/Certificate Services Client - Auto-Enrollment Settings"
                            State        = "Enabled"
                            Settings     = "EnrollCertificatesAutomatically: $($AutoEnrollmentSettings.EnrollCertificatesAutomatically) | ExpiryNotification: $($AutoEnrollmentSettings.ExpiryNotification) | NotifyPercent: $($AutoEnrollmentSettings.NotifyPercent.value)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Certificate Services Client - Auto-Enrollment Settings"
                        }
                    }
                }

                # Encrypting file system
                ForEach ($efs in $extension.EFSRecoveryAgent) {
                    If ($efs) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "User settings"
                            SettingName  = "Public Key Policies/Encrypting file system"
                            State        = "Enabled"
                            Settings     = "IssuedTo: $($efs.IssuedTo) | IssuedBy: $($efs.IssuedBy) | ExpirationDate: $($efs.ExpirationDate) | CertificatePurpose: $($efs.CertificatePurpose.purpose)" 
                            Explanation  = "N/A"
                            Category     = "Windows Settings/Public Key Policies/Encrypting file system"
                        }
                    }
                }
            }

            # Looking for policy settings
            If ($extension.Policy) {
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

            # Looking for drive map settings configured
            If ( $extension.type -like "*DriveMapSettings" ) {
                ForEach ($drivesettings in $extension.DriveMapSettings) {
                    If ($drivesettings) {
                        ForEach ($drive in $drivesettings.drive) {
                            $filter = $drive.filters.filterldap.searchfilter
                            $binding = $drive.filters.filterldap.binding

                            $results += [PSCustomObject]@{
                                GPOName      = $GPOInfo.Name
                                WhenCreated  = $GPOInfo.CreatedTime
                                LastModified = $GPOInfo.ModifiedTime
                                Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                                Type         = "Preferences/Windows Settings"
                                SettingName  = "Preferences/Windows Settings/Drive Maps"
                                State        = If ($filter -OR $binding) { "Filter: $filter | Binding: $binding" } else { "" }
                                Settings     = "Order: $($drive.GPOSettingOrder) | Drive letter: $($drive.Name) | Path: $($drive.Properties.path)"
                                Explanation  = "N/A"
                                Category     = "Preferences/Windows Settings"
                            }
                        }
                    }
                }
            }

            # Looking for login/logoff scripts
            If ( $extension.type -like "*Scripts" ) {
                ForEach ($script in $extension.script) {
                    If ($script) {
                        $results += [PSCustomObject]@{
                            GPOName      = $GPOInfo.Name
                            WhenCreated  = $GPOInfo.CreatedTime
                            LastModified = $GPOInfo.ModifiedTime
                            Links        = $GPOInfo.linksTo.SOMPath -join "`n"
                            Type         = "Preferences/Windows Settings"
                            SettingName  = "Preferences/Windows Settings/Scripts"
                            State        = "N/A"
                            Settings     = "Type: $($script.type)| Order: $($script.Order)| Command: $($script.command) $($script.parameters)"
                            Explanation  = "N/A"
                            Category     = "Preferences/Windows Settings"
                        }                        
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

#Get-GPOSettingReport -GPO "NPS Cert" -outputPath "c:\temp\AllGPOSettings2.csv"

Get-GPOSettingReport -GPO $GPOs -outputPath "c:\temp\AllGPOSettings.csv"