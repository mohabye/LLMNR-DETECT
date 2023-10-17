$trustedIPs = @("10.100.10.100", "192.168.1.10", "172.16.0.50") # List of trusted IP addresses

$events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3} -MaxEvents 1000

foreach ($event in $events) {
    $eventData = $event.Properties
    
    $destinationIP = $eventData[7].Value

    if ($trustedIPs -notcontains $destinationIP) {
        $alertMessage = "Malicious SMB connection detected:`n"
        $alertMessage += "Destination IP: $destinationIP`n"
        $alertMessage += "Event Time: $($event.TimeCreated)"

        Write-Host $alertMessage
        # You can customize the action here, such as sending an email or triggering an alert mechanism
    }
}
