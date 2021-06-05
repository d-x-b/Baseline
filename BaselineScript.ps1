$targets = Get-Content -Path C:\Targets.txt

Foreach($targ in $targets) {Invoke-Command -ComputerName $targ {

#Variables to collect information
$Computername        =  Get-WmiObject -Class Win32_ComputerSystem
$IP                  =  Get-NetIPConfiguration
$NetworkAdapterinfo  =  Get-NetAdapter -Name *
$Listofusers         =  Get-ChildItem C:\Users\* | Format-Table -Property Name
$Date                =  Get-Date -UFormat %Y-%m-%d
$Services            =  Get-Service | Format-Table -Property Name,Status
$Process             =  Get-Process
$Physical            =  Get-WmiObject -class Win32_Physicalmedia
$AV                  =  Get-WmiObject -Class AntiVirusProduct -Namespace root\SecurityCenter2 | Select-Object -Property displayname, productstate
$Connections         =  Get-NetTCPConnection
$Localusr            =  Get-LocalUser | Format-Table -Property Name, Enabled

#Exporting data to .csv
$Output = New-Object -TypeName psobject
$Output | Add-Member -MemberType NoteProperty -Name 'Date' -Value $Date
$Output | Add-Member -MemberType NoteProperty -Name 'Computer Name' -Value $Computername.PSComputerName
$Output | Add-Member -MemberType NoteProperty -Name 'IP' -Value $IP.IPv4Address.IPaddress
$Output | Add-Member -MemberType NoteProperty -Name 'Network Adapter' -Value $NetworkAdapterinfo
$Output | Add-Member -MemberType NoteProperty -Name 'Users' -Value $Listofusers
$Output | Add-Member -MemberType NoteProperty -Name 'Services' -Value $Services = Get-Service | Format-Table -Property Name,Status
$Output | Add-Member -MemberType NoteProperty -Name 'Processes' -Value $Process
$Output | Add-Member -MemberType NoteProperty -Name 'Physical' -Value $Physical
$Output | Add-Member -MemberType NoteProperty -Name 'AV' -Value $AV
$Output | Add-Member -MemberType NoteProperty -Name 'Connections' -Value $Connections
$Output | Add-Member -MemberType NoteProperty -Name 'Local Users' -Value $Localusr
$Output | ConvertTo-Csv -NoTypeInformation | Export-Csv C:\Users\Public\Baseline.csv -Append
}
}
