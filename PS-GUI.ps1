Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$GreetingLabel = New-Object Windows.Forms.Label
$GreetingLabel.Text = "Hyper-V VM Creation Utility"
$GreetingLabel.Font = New-Object Drawing.Font("Arial", 24, [Drawing.FontStyle]::Bold)
$GreetingLabel.AutoSize = $true
$GreetingLabel.Location = New-Object Drawing.Point(10, 10)
$GreetingLabel.ForeColor = [System.Drawing.Color]::Black

$VMNameBox = New-Object System.Windows.Forms.textbox
$VMNameBox.Text = "NewVM"
$VMNameBox.Multiline = $False
$VMNameBox.Size = New-Object System.Drawing.Size(100, 100)
$VMNameBox.Location = new-object System.Drawing.Size(10, 150)

$VMNameLabel = New-Object Windows.Forms.Label
$VMNameLabel.Text = "Virtual Machine Name"
$VMNameLabel.AutoSize = $true
$VMNameLabel.Location = New-Object Drawing.Point(10, 180)
$VMNameLabel.ForeColor = [System.Drawing.Color]::Black

$MemoryComboBox = New-Object system.Windows.Forms.ComboBox
$MemoryComboBox.text = ""
$MemoryComboBox.width = 100
$MemoryComboBox.autosize = $true
$MemoryComboBox.location = New-Object System.Drawing.Point(200, 170)
# Add the items in the dropdown list
@(2, 4, 6, 8, 10, 12, 14, 16) | ForEach-Object { [void] $MemoryComboBox.Items.Add($_) }
# Select the default value
$MemoryComboBox.SelectedIndex = 0

$MemoryLabel = New-Object Windows.Forms.Label
$MemoryLabel.Text = "Memory (GB)"
$MemoryLabel.AutoSize = $true
$MemoryLabel.Location = New-Object Drawing.Point(200, 150)
$MemoryLabel.ForeColor = [System.Drawing.Color]::Black

$VHDSizeBox = New-Object System.Windows.Forms.textbox
$VHDSizeBox.Text = 40
$VHDSizeBox.Multiline = $False
$VHDSizeBox.Size = New-Object System.Drawing.Size(100, 100)
$VHDSizeBox.Location = new-object System.Drawing.Size(10, 220)

$VHDSizeLabel = New-Object Windows.Forms.Label
$VHDSizeLabel.Text = "Virtual Hard Disk Size (GB)"
$VHDSizeLabel.AutoSize = $true
$VHDSizeLabel.Location = New-Object Drawing.Point(10, 250)
$VHDSizeLabel.ForeColor = [System.Drawing.Color]::Black

$CreateButton = New-Object System.Windows.Forms.Button
$CreateButton.Location = New-Object System.Drawing.Size (200, 220)
$CreateButton.Size = New-Object System.Drawing.Size(160, 30)
$CreateButton.Font = New-Object System.Drawing.Font("Lucida Console", 18, [System.Drawing.FontStyle]::Regular)
$CreateButton.BackColor = "LightGray"
$CreateButton.Text = "Submit"
$CreateButton.Add_Click({

        #Get VM Name
        $VMName = $VMNameBox.Text
        $VMNameBox.Text = ""


        #Get VM Memory
        $Index = $MemoryComboBox.SelectedIndex
        [String]$VMMem = $MemoryComboBox.Items[$Index]
        $VMMem = $VMMem + "GB"
        $Index = $MemoryComboBox.SelectedIndex = 0

        #Get Virtual Hard Disk Size
        [String]$VHDX = $VHDSizeBox.Text
        $VHDX = $VHDX + "GB"
        $VHDSizeBox.Text = ""

        #Create VHD Path
        $VHDPath = "C:\temp\" + $VMName + ".VHDX"

        #Form VM Creation Command
        #[String]$NewVMCommand = "New-VM -Name $VMName -MemoryStartupBytes $VMMem -NewVHDPath $VHDPath -NewVHDSizeBytes $VHDX"

        #Create Virtual Machine
        Invoke-Expression $NewVMCommand
    })

$Form = New-Object Windows.Forms.Form
$Form.Text = "VM Creation Tool"
$Form.Width = 550
$Form.Height = 350
$Form.BackColor = "LightBlue"

$Form.Controls.add($GreetingLabel)
$Form.Controls.add($VMNameBox)
$Form.Controls.add($VMNameLabel)
$Form.Controls.add($VHDSizeBox)
$Form.Controls.add($VHDSizeLabel)
$Form.Controls.add($MemoryComboBox)
$Form.Controls.add($MemoryLabel)
$Form.Controls.add($CreateButton)
$Form.Add_Shown({ $Form.Activate() })
$Form.ShowDialog()