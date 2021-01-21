# This script was originally designed to run as part of an automation runbook in azure to alert system admins by email when a
# Firewall rule had been changed or updated

# Add applicationId TenantId and Certificate Thumbrint of your automation account

Connect-AZAccount -TenantId "xxx" -ApplicationId "xxx" -CertificateThumbprint "xxx"

## The script requires that you create a credential object in Azure automation in which the SMTP server credentials are stored
$Credential = Get-AutomationPSCredential -Name "xxx"
write-host $Credential
$SmtpServer = "smtp.office365.com"; 

$To = @("user2@userdomain.com", "user2@userdomain.com");
$From = "security@userdomain.com"; 
$WorkspaceName = 'MyLogAnalyticsWorkspace' ## The name of the Log analytics workspace where your Active Log alerts are being sent to
$ResourceGroupName = 'MyLogAnalyticsResourceGroup' ## The name of the Log analytics workspaces reosurce group
$Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$QueryResults = Invoke-AzOperationalInsightsQuery -Workspace $Workspace -Query 'AzureActivity | where TimeGenerated > ago(24h) | where ResourceGroup == "VNETResourceGroup" ## This needs to be the resource group where you are looking for firewall change events that contains the VNET'
foreach ($x in $QueryResults.Results) {
	$jsonobj = $x.Properties | ConvertFrom-Json
	$action = $x.OperationNameValue.split("/")[3]
	if ($action -eq "WRITE") { 
		$action = "CREATE" 
        }
    if (($action -eq "CREATE") -or ($action -eq "DELETE"))
    {
        $user = $jsonobj.caller
	$rule = $jsonobj.resource
	$date = $jsonobj.eventSubmissionTimestamp

	$body += $date + " --- " + $user + " issued the action " + $action + " on " + $rule + '<br>'
    }
}
If ($body) { Send-MailMessage -UseSSL -Port 587 -Credential $Credential -SmtpServer $SmtpServer -To $To -From $From -Subject "Firewall Change Alerts" -Body $body -BodyAsHTML }
