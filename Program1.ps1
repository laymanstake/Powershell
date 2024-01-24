Function Get-RPS {
    $RPSChoice = Get-Random -Minimum 1 -Maximum 9

    Write-Verbose "Random number selected is $RPSChoice"

    switch ($RPSChoice) {
        { $_ -gt 1 -AND $_ -lt 3 } { Write-Output "Rock" }
        { $_ -gt 3 -AND $_ -lt 6 } { Write-Output "Paper" }
        { $_ -gt 6 -AND $_ -lt 9 } { Write-Output "Scissors" }
    }
}

function Start-RPSGame {
    param ($NoOfRounds)

    $Round = 1
    while ($Round -le $NoOfRounds) {
        for ($RPSCounterDisp = 1; $RPSCounterDisp -lt 3; $RPSCounterDisp++) {
            switch ($RPSCounterDisp) {
                1 { Write-Host "******Rock******" }
                2 { Write-Host "******Paper******" }
                3 { Write-Host "******Scissors******" }
            }
            Start-Sleep -Milliseconds 500
        }

        Get-RPS

        $Round++
        Write-Output "`n`n"
        Start-Sleep -Seconds 2
    }
}

Start-RPSGame(3)