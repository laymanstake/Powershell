param (
    [parameter (mandatory=$false)][Object]$webhookData,
    [parameter (mandatory=$false)][string]$recipients = "Nitish.Kumar@atos.net"
)

function Get-QueryResults {
    param (
        [parameter (mandatory=$false)][string]$query,
        [parameter (mandatory=$false)][pscredential]$cred,
)
}

$tenantID = "73393259-5f29-40e2-8a8b-6b5a9b570f56"    
$MYcredetial = "GA"
$cred = Get-AutomationPSCredential -Name $MYcredetial
$clientID = $cred.UserName
$clientSecret = $Cred.GetNetworkCredential().Password


if($Webhookdata -ne $null){
    $essentials = $Webhookdata.RequestBody | ConvertFrom-JSON

    $AlertRule = $essentials.data.essentials.alertRule
    $severity = $essentials.data.essentials.severity
    $signalType = $essentials.data.essentials.signalType
    $firedDateTime = $essentials.data.essentials.firedDateTime
    $conditionType = $essentials.data.alertContext.conditionType
    $condition = $essentials.data.alertContext.condition.allOf[0].searchQuery
    $threshold = $essentials.data.alertContext.condition.AllOf[0].threshold
    $Count = $essentials.data.alertContext.condition.AllOf[0].metricValue
    $resultsUrl = $essentials.data.alertContext.condition.AllOf[0].linkToFilteredSearchResultsAPI
    
    $windowStartTime = $essentials.data.alertContext.condition.windowStartTime
    $windowEndTime = $essentials.data.alertContext.condition.windowEndTime

    $WebhookName = $Webhookdata.WebhookName
    $WebhookBody = ConvertFrom-JSON -InputObject $WebhookData.RequestBody
    $Subject = "$AlertRule - $severity - $signalType - $firedDateTime"

    $style = "BODY{font-family: Arial; font-size: 10pt;}"
    $style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
    $style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
    $style = $style + "TD{border: 1px solid black; padding: 5px; }"
    $style = $style + ""
    #$mailbody = "Alert rule named $AlertRule fired since below $conditionType condition met $count times while threshold is $threshold <br><br> $condition <br><br> <a href=$resultsUrl>Link to query results</a>"
}

$mailSender = "odl_user_1376770@otuwamsb100951.onmicrosoft.com"
$mailRecipient = $recipients

#Connect to Graph API
$tokenBody = @{
    Grant_Type = "client_credentials"
    Scope = "https://graph.microsoft.com/.default"
    Client_Id = $clientID
    Client_Secret = $clientSecret
}

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type" = "application/json"
}

# Get query results
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $tenantID 

$token = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io").Token
$logQueryHeaders = @{
        Authorization  = "Bearer $token"        
}

$resultsTable = invoke-RestMethod -Method Get "$resultsUrl" -Headers $logQueryHeaders

$count = 0
foreach ($table in $resultsTable.Tables) {
    $count += $table.Rows.Count
}

$results = New-Object object[] $count

$i = 0;

foreach ($table in $resultsTable.Tables) {
    foreach ($row in $table.Rows) {
        $properties = @{}
        for ($columnNum=0; $columnNum -lt $table.Columns.Count; $columnNum++) {
            $properties[$table.Columns[$columnNum].name] = $row[$columnNum]
        }      
        $results[$i] = (New-Object PSObject -Property $properties)
        $null = $i++
    }
}

$resultsOutput = @"
$(($results | Select-Object TimeGenerated, Computer, Account, AccountType, LogonType | ConvertTo-Html -As Table -fragment) -replace "\\", "&#47;")
"@

$mailbody = "Alert rule named $AlertRule fired since below $conditionType condition met $count times while threshold is $threshold <br><br> $condition <br><br> $resultsOutput <a href=$resultsUrl>Link to query results</a>"



#Send email
$URLsend = "https://graph.microsoft.com/v1.0/users/$mailSender/sendMail"
$BodyJsonsend = @"
{
    "message": {
        "subject": "$Subject",
        "body": {
            "contentType": "HTML",
            "content": "$($mailbody)"
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "$recipients"
                }
            }
        ]
    },
    "saveToSentItems": "false"
}
"@

Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend
