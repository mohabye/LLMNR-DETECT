# LLMNR-DETECT
this PowerShell script that uses Sysmon to detect any malicious SMB connections to untrusted IP addresses on the network
Using Event Id 3 
the code : 
The $trustedIPs variable contains a list of trusted IP addresses. Add all your trusted IP addresses to this list.
The script retrieves events from the Microsoft-Windows-Sysmon/Operational log with an event ID of 3 using the Get-WinEvent cmdlet. The -MaxEvents parameter restricts the number of events retrieved to 1000 (you can adjust this value as needed).
The script loops through each event and extracts the destination IP address from the event properties.
If the destination IP address is not found in the $trustedIPs list, the script considers it a potentially malicious SMB connection and constructs an alert message.
The alert message is then displayed using Write-Host. You can customize this part to trigger other actions, such as sending an email or triggering an alert mechanism specific to your environment.
