# Define the main menu
function Show-Menu {
    Write-Host "User and Computer Management"
    Write-Host "--------------------------------"
    Write-Host "1. List User information" -ForegroundColor Green
    Write-Host "2. List Computer information, may not show in Powershell ISE" -ForegroundColor Green
    Write-Host "3. Domain Scan" -ForegroundColor Green
    Write-Host "4. Add Computer to DRA" -ForegroundColor Green
    Write-Host "5. Add User to Groups, notepad method (Req. {DODID}a & Group CN Names)" -ForegroundColor Green
    Write-Host "6. Remove Computer" -ForegroundColor Green
    Write-Host "7. Add User to Group (Req. {DODID}a & Group CN Name)" -ForegroundColor Green
    Write-Host "8. Remove User from Group (Req. {DODID}a & Group CN Name)" -ForegroundColor Green
    Write-Host "9. Install RSAT & DRA Extensions files" -ForegroundColor Magenta
    Write-Host "10. Retrieve DRA Powershell Manual" -ForegroundColor Magenta
    Write-Host "11. Enable/Unlock User Account (Req. {DODID}a)" -ForegroundColor Green
    Write-Host "12. Disable User Account" -ForegroundColor Green
    Write-Host "13. Restore Computer Account" -ForegroundColor Green
    Write-Host "14. CST Continuity locations" -ForegroundColor Magenta
    Write-Host "15. Exit" -ForegroundColor Yellow
    Write-Host "16. View User Groups (Req. {DODID}a, get CN Name and CN Group Here)" -ForegroundColor Green
    Write-Host "17. Printer Script" -ForegroundColor Green
    Write-Host "18. Admin script" -ForegroundColor Green
    Write-Host "19. Printer Subnet Ping Sweep" -ForegroundColor Green
    Write-Host "20. Check logged in users, Unstable in ISE" -ForegroundColor Green
    Write-host "21. Quick check Active Directory User, Unstable in ISE" -ForegroundColor Green
    Write-Host "22. Restart Computer" -ForegroundColor Green
}

function Add-ComputerWithPermissions {
    $computerLocation = "*"
    $organization = "23 CS"
    $base = "Moody AFB"
    $canJoinToDomain = "CN=XXXXXXXX,OU=XXXXX XXXX,OU=XXXXXXX XXXX,OU=XXXXXX,DC=XXXX,DC=XXXXXXX,DC=XXXX,DC=XXX"
    $computerNames = @()
    while ($true) {
        $computerName = Read-Host "Please enter a computer name (or press Enter to execute)"
        if ($computerName -ne "") {
            $computerNames += $computerName
        } else {
            break
        }
    }
    
    foreach ($ComputerName in $computerNames) {
        $distName = "CN=$($ComputerName),"CN=XXXXXXXX,OU=XXXXX XXXX,OU=XXXXXXX XXXX,OU=XXXXXX,DC=XXXX,DC=XXXXXXX,DC=XXXX,DC=XXX"
        Add-DRAcomputer -Domain "XXXX.XXXX.XXXX.XXXX" -Properties @{DistinguishedName=$distName;Location=$computerLocation;IsDisabled=$false;o=$organization;l=$base;AccountThatCanAddComputerToDomain=$canJoinToDomain} -DRARestPort '8755' -DRAHostServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -DRAHostPort '11192' -DRARestServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -Timeout -1
    }
}


# Loop through the menu options
while ($true) {
    Show-Menu
    $input = Read-Host "Please enter your choice (1-22)"

    switch ($input) {
        "1" {
            # List users
            $f = read-host "Enter {DODID}a for user"
            $uzr = get-aduser $f | select-object -ExpandProperty DistinguishedName
            Get-DRAUser -identifier $uzr -domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Read-Host "Press enter to return to the main menu..."
        }
        "2" {
            # List computers
            $computerNamez = @()
    while ($true) {
        $computerName = Read-Host "Please enter a computer name (or press Enter to execute)"
        if ($computerName -ne "") {
            $computerNamez += $computerName
        } else {
            break
        }
    }
    
    foreach ($ComputerName in $computerNamez) {
            $lol = get-adcomputer $ComputerName | Select-Object -ExpandProperty DistinguishedName
            Get-DRAComputer -identifier $lol -domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Read-Host "Press enter to return to the main menu..."
        }
    }
        "3" {Read-Host "This script scans all Objects in Active Directory, can be helpful when locating last known user logged into PC, press enter to continue, or Control+C to Cancel"
        write-host "Setting variable arrays" -ForegroundColor DarkYellow
$ouSearch = @()
$servers = @()
$accounts = @()
$computers = @()
$collection = @()
$serverCollection = @()
$accountCollection = @()
$today = get-date -f ("yyyyMMdd")
write-host "Variable arrays created" -ForegroundColor Yellow

write-host "Searching active directory for all server OU's named Moody AFB" -ForegroundColor DarkYellow
$ouSearch = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Servers,DC=Area52,DC=AFNOAPPS,DC=USAF,DC=MIL" | Select-Object Name, DistinguishedName | where {$_.name -like "Moody AFB"}
write-host "Search Complete and stored in variable" -ForegroundColor Yellow

write-host "Configuring array to store server names" -ForegroundColor DarkYellow
foreach ($ou in $ouSearch){
    $distinguishedName = $ou.DistinguishedName
    $serverGroup = get-adcomputer -filter * -searchbase "$distinguishedName" | select-object DistinguishedName, Enabled, IPv4Address, LastLogonDate, Name, ObjectClass, OperatingSystem, OperatingSystemVersion
    foreach($server in $serverGroup){
        $serverName = $server.name
        $servers += $serverName

        $serverObject = New-Object PSObject	
	    Add-Member -inputObject $serverObject -memberType NoteProperty -name "distinguishedName" -value $server.DistinguishedName
        Add-Member -InputObject $serverObject -MemberType NoteProperty -Name "enabled" -Value $server.enabled
        Add-Member -InputObject $serverObject -MemberType NoteProperty -Name "name" -Value $server.name
	    $serverCollection += $serverObject
	    write-host "Added $serverName to collection array" -foregroundcolor Yellow
    }       
}
Write-Host "Array created with all server info" -ForegroundColor Yellow

write-host "Searching Active Directory for all computers in Moody AFB Computers OU" -ForegroundColor DarkYellow

$computerSearch = get-adcomputer -filter * -properties * -searchbase "OU=Moody AFB Computers, OU=Moody AFB,OU=AFCONUSEAST,OU=Bases,DC=Area52,DC=AFNOAPPS,DC=USAF,DC=MIL" | select-object DistinguishedName, Enabled, IPv4Address,LastLogonDate, Location, Name, o, OperatingSystem, OperatingSystemVersion
write-host "Active Directory search complete" -ForegroundColor Yellow

write-host "Configuring array to store computer names" -ForegroundColor DarkYellow
foreach ($computer in $computerSearch){
    $computerName = $computer.name
    $computers += $computerName

    $computerObject = New-Object PSObject	
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "name" -Value $computer.name	
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "ipv4Address" -Value $computer.ipv4Address
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "owner" -Value ($computer.o).Value
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "enabled" -Value $computer.enabled
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "lastLogonDate" -Value $computer.lastLogonDate
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "location" -Value $computer.location
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "operatingSystem" -Value $computer.operatingSystem
    Add-Member -InputObject $computerObject -MemberType NoteProperty -Name "operatingSystemVersion" -Value $computer.operatingSystemVersion
    Add-Member -inputObject $computerObject -memberType NoteProperty -name "distinguishedName" -value $computer.DistinguishedName
	$collection += $computerObject
	write-host "Added $computerName to collection array" -foregroundcolor Yellow
}
Write-Host "Array created with all computer info" -ForegroundColor Yellow

write-host "Searching active directory for all OU's named Moody AFB" -ForegroundColor DarkYellow
$ouAllSearch = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Administration,DC=Area52,DC=AFNOAPPS,DC=USAF,DC=MIL" | Select-Object Name, DistinguishedName, lastlogondate, enabled
write-host "Search Complete and stored in variable" -ForegroundColor Yellow

write-host "Configuring array to store account names" -ForegroundColor DarkYellow
foreach ($ou in $ouAllSearch){
    $distinguishedName = $ou.DistinguishedName
    $accountGroup = get-aduser -filter * -searchbase "$distinguishedName" | select-object DistinguishedName, Enabled, LastLogonDate, Name | where {$_.name -like "*qseu*"}
    foreach($account in $accountGroup){
        $accountName = $account.name
        $accounts += $accountName

        $accountObject = New-Object PSObject	
	    Add-Member -inputObject $accountObject -memberType NoteProperty -name "distinguishedName" -value $account.DistinguishedName
        Add-Member -InputObject $accountObject -MemberType NoteProperty -Name "enabled" -Value $account.enabled
        Add-Member -InputObject $accountObject -MemberType NoteProperty -Name "lastLogonDate" -Value $account.lastLogonDate
        Add-Member -InputObject $accountObject -MemberType NoteProperty -Name "name" -Value $account.name
	    $accountCollection += $accountObject
	    write-host "Added $accountName to collection array" -foregroundcolor Yellow
    }       
}
Write-Host "Array created with all account info" -ForegroundColor Yellow

write-host "Exporting information from the server and computer arrays to csv" -ForegroundColor DarkGreen
$collection | export-csv -path ~\Desktop\$today.csv -NoTypeInformation -NoClobber
$serverCollection | export-csv -path ~\Desktop\$today.csv -NoTypeInformation -NoClobber
$accountCollection | export-csv -path ~\Desktop\$today.csv -NoTypeInformation -NoClobber
write-host "Information exported to ~\Desktop\$today.csv" -foregroundcolor Green}
        "4" {
            # Add computer with permissions
            Add-ComputerWithPermissions
            Write-Host "Computers added successfully."
            Read-Host "Press enter to return to the main menu..."
        }
        "5" {  # Add user to group
    try {
        # Ask the user to enter the username
        $Username = Read-Host -Prompt "Enter the {DODID}a of the user you want to check"

        # Get the user
        Write-Host "Retrieving current list of groups user is added to..." -ForegroundColor Green
        $User = Get-ADUser -Identity $Username -Properties MemberOf

        if (!$User) {
            throw "User $Username not found"
        }

        # Get the groups the user is a member of
        $Groups = $User.MemberOf | Get-ADGroup

        # Display the list of groups, use user distinguished name for command
        $UserDN = (Get-ADUser -Identity $Username).DistinguishedName 
        $Groups | Format-Table -Property Name, DistinguishedName

        # Provide instruction for group assignment
        Write-Host "Please find group CN names from option 16 to add to current user. Note: This is the notepad/mirror method."

        # Read group CN names from a file
        if (Test-Path -Path ~/Desktop) {
            Write-Host "Desktop Path Exists, placing file on Desktop"
            $FilePath = "~/Desktop/GroupMemberAdd.txt"
            cd ~/Desktop/
        } else {
            Write-Host "Path does not exist. One Drive possibly being utilized, placing file in Documents instead"
            $FilePath = "~/Documents/GroupMemberAdd.txt"
            cd ~/Documents/
        }

        notepad GroupMemberAdd.txt
        Read-Host 'Press Enter when groups have been added to text file'
        
        $GroupNames = Get-Content -Path $FilePath

        foreach($GroupName in $GroupNames){
        try {
            Write-Host "Adding user to group $GroupName..."
            Add-DRAGroupMembers -Identifier $GroupName -Domain XXXX.XXXX.XXXX.XXXX -Users $UserDN -Domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Write-Host "User added to group $GroupName successfully. Please wait 5-10 minutes for group to populate"
        } catch [System.UnauthorizedAccessException] {
                Write-Host "Error: Failed to add user to group $GroupName, insufficient privileges." -ForegroundColor Red
            } catch {
                Write-Host "Error: Failed to add user to group $GroupName. Error message: $_" -ForegroundColor Red
            }}
        
        Read-Host "Press enter to return to the main menu..."
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}



        "6" {
            do {
                # Remove computer
                $computerName = Read-Host "Enter the computer name to remove"
                remove-dracomputer -Identity $computerName -Domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
                Write-Host "Computer removed successfully."

                $continue = Read-Host "Would you like to remove another computer? (yes/no)"
            } while ($continue -eq "yes")
            
            Read-Host "Press enter to return to the main menu..."
        }
        "7" {
            # Add user to group
            # Ask the user to enter the username
            $Username = Read-Host -Prompt "Enter the username of the user you want to check"
            # Get the user
            $User = Get-ADUser -Identity $Username -Properties MemberOf
            # Get the groups the user is a member of
            $Groups = $User.MemberOf | Get-ADGroup
            # Display the list of groups, use user distinguished name for command
            $UserDN = (Get-ADUser -Identity $Username).DistinguishedName
            $Groups | Format-Table -Property Name, DistinguishedName
            # Remove user from group
            Write-Host "Please find group CN name from option 16 to add user"
            get-aduser $username | select-object DistinguishedName
            $groupname = Read-host "Enter Group CN name given from option 16"
            Add-DRAGroupMembers -Identifier $groupname -Domain XXXX.XXXX.XXXX.XXXX -Users $UserDN -Domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Write-Host "User added to group successfully. Please wait 5-10 minutes for group to populate"
            Read-Host "Press enter to return to the main menu..."
        }
        "8" {
            # Ask the user to enter the username
            $Username = Read-Host -Prompt "Enter the username of the user you want to check"
            # Get the user
            $User = Get-ADUser -Identity $Username -Properties MemberOf
            # Get the groups the user is a member of
            $Groups = $User.MemberOf | Get-ADGroup
            # Display the list of groups, use user distinguished name for command
            $UserDN = (Get-ADUser -Identity $Username).DistinguishedName
            $Groups | Format-Table -Property Name, DistinguishedName
            # Remove user from group
            Write-Host "Please find group CN name from option 16 to remove user"
            get-aduser $username | select-object DistinguishedName
            $groupname = Read-host "Enter Group CN name given from option 16"
            Remove-DRAGroupMembers -Identifier $groupname -Domain XXXX.XXXX.XXXX.XXXX -Users $UserDN
            Write-Host "User removed from group successfully."
            Read-Host "Press enter to return to the main menu..."
        }
        "9" {Function Check-RunAsAdministrator()
{
  # Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  # Check if the user running the script is a member of the Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       # Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       # Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       # Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       # Exit from the current, unelevated, process
       Exit
    }
}

Check-RunAsAdministrator
Write-Host "Please select the DRAExtensions.exe installer located within .ZIP folder"
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
$FileBrowser.Filter = "EXE files (*.exe)|*.exe|All files (*.*)|*.*"
$FileBrowser.ShowDialog() | Out-Null
$install = $FileBrowser.FileName
Start-Process -FilePath $install -Wait -NoNewWindow
Import-Module “C:\Program Files (x86)\NetIQ\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions”
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
Write-Host -ForegroundColor green  "Install Complete, Close Powershell and Reopen to have your DRA Powershell module imported successfully"
        default {
            Write-Host "Invalid selection. Please try again."
            Start-Sleep -Seconds 2
            }
        }
        "10" {
        cd "\\132.40.16.11\Moody_MSG\CS\SCO\SCOS\CST\5_Continuity\Scripts\DRA tools"
        .\DRA_PowerShell_Help.docx
        cd ~
        }
        "15" {
            # Exit
            break
        }
        "11" {
    $domain = "XXXX.XXXX.XXXX.XXXX"
    $usernames = @()
    while ($true) {
        $username = Read-Host "Please enter a username (or press Enter to execute)"
        if ($username -ne "") {
            $usernames += $username
        } else {
            break
        }
    }
    foreach ($username in $usernames) {
        try {
            $getdodid = (Get-ADUser -Identity $username).DistinguishedName
            Unlock-DRAUser -Domain $domain -Identifier $getdodid -ErrorAction Stop -DRARestPort '8755' -DRAHostServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -DRAHostPort '11192' -DRARestServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -Timeout -1
            Write-Host "Successfully unlocked user ${username}" -ForegroundColor Green
        } catch {
            Write-Host "Failed to unlock user ${username}: $_" -ForegroundColor Red
            continue
        }
        try {
            $getdodid = (Get-ADUser -Identity $username).DistinguishedName
            Enable-DRAUser -Domain $domain -Identifier $getdodid -ErrorAction Stop -DRARestPort '8755' -DRAHostServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -DRAHostPort '11192' -DRARestServer XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX -Timeout -1
            Write-Host "Successfully enabled user ${username}" -ForegroundColor Green
        } catch {
            Write-Host "Failed to enable user ${username}: $_" -ForegroundColor Red
        }
    }
}

        "12" {
            # Disable user account
            $username = Read-Host "Enter the username to disable"
            Disable-DRAUser $username -domain "'XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Write-Host "User account disabled successfully."
            Read-Host "Press enter to return to the main menu..."
        }
        "13" {
            # Enable computer account
            $computerName = Read-Host "Enter the computer name to enable"
            Restore-DRAComputer -identifier $computerName -domain "XXXX.XXXX.XXXX.XXXX" -DRAHostServer "XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX" -DRAHostPort '11192' -DRARestServer 'XXXX-XXXX-XXXX.XXXX.XXXX.XXXX.XXX' -DRARestPort '8755'
            Write-Host "Computer account enabled successfully."
            Read-Host "Press enter to return to the main menu..."
         }
        "14" {
            Write-Host "
            Copy and Paste these locations in File Explorer on demand, add more if needed
            ------------------------------------------------------------------------------
            CST Continuity Notebook
            \\132.40.16.11\Moody_MSG\CS\SCO\SCOS\CST\CST Continuity

            CST How-To Guides
            \\132.40.16.11\Moody_MSG\CS\SCO\SCOS\CST\5_Continuity\SOPs
            
            Printer SOPs and IP Listings
            \\132.40.16.11\Moody_MSG\CS\SCO\SCOS\CST\Projects\1_Printers

            CST Software
            \\132.40.16.12\Moody_GROUPS\Community\Community (2020)\CST\Software
            \\132.40.16.12\Moody_GROUPS\Community\Software

            CST Drivers
            \\132.40.16.12\Moody_GROUPS\Community\Community (2020)\CST\Drivers

            CST Scripts
            \\132.40.16.11\Moody_MSG\CS\SCO\SCOS\CST\5_Continuity\Scripts
            "
            Read-host "Press Enter to continue..."
        }
        "16" {# Ask the user to enter the username
            $Username = Read-Host -Prompt "Enter the username of the user you want to check"
            # Get the user
            $User = Get-ADUser -Identity $Username -Properties MemberOf
            # Get the groups the user is a member of
            $Groups = $User.MemberOf | Get-ADGroup
            # Display the list of groups
            get-aduser $User | select-object DistinguishedName
            $Groups | Format-Table -Property Name, DistinguishedName

        }
        "17" {
$count = 0
$good = 0    
$bad = 0
if (Test-Path -Path ~/Desktop) {
    "Desktop Path Exists, placing file on Desktop"
    cd ~/Desktop
} else {
    "Path does not exist. One Drive possibly being utilized, placing file in Documents instead"
    cd ~/Documents
}
notepad GIVECOMPUTERNAMES.txt
read-host -Prompt "Press enter to continue..."   # prompts to input text document

function addShortcut {   
    Write-Host $PCName -ForegroundColor Green   #outputs connectable cpmpurters names
    reg add "\\$PCname\HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f
    msg /server:$PCname /time:9000 /V * 'You have been allowed access to map to Printers via Print Server, please see if you can map to the printer created for you in the Print Server'
} 
$computerNames = @(Get-Content -Path '~/Desktop/GIVECOMPUTERNAMES.txt')   #gets contents of the text document
do {
   
    $PCName = $computerNames[$count]
    if ($PCName -ne "")   #this is to skip blank spaces in computer list
    {
    
        if (Test-Connection -ComputerName $PCName -Count 1 -Quiet)   #test to see if a connection is able to be made
        {     
                $good ++
                $count ++
                addShortcut        
        }
        else {
            $bad ++
            $count ++
            Write-Host $PCName -ForegroundColor Red    #outputs computer names that cant be connected
        }    
    }
    else {
        $count ++
    }
} until($count -eq $computerNames.Count)   #shows number of good and bad connects
Write-Host "    ALL DONE"
Write-Host $good -ForegroundColor green  " workstations added the shortcut" 
Write-Host $bad -ForegroundColor Red  " workstations couldn't connect"
Write-Host "Printer script ran successfully."
            Read-Host "Press enter to return to the main menu..."

        }
        "18" {
$count = 0
$good = 0
$computerNames = @()

Write-Host "Please enter the computer names. Press enter without input to finish."

do {
    $inputName = Read-Host -Prompt "Enter a computer name"
    if ($inputName -ne "") {
        $computerNames += $inputName
    }
} until ($inputName -eq "")

function addShortcut {   
    Write-Host $PCName -ForegroundColor Green
    reg add "\\$PCName\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    msg /server:$PCName /time:1200 /V * "Admin/User logon enabled for this PC"
} 

do {
    $PCName = $computerNames[$count]
    if ($PCName -ne "") {
        if (Test-Connection -ComputerName $PCName -Count 1 -Quiet) {
            $good ++
            $count ++
            addShortcut        
        } else {
            $bad ++
            $count ++
            Write-Host $PCName -ForegroundColor Red
            Write-Host -ForegroundColor Red 'Could not connect to the PC, possibly turned off, offline, or blocking ping requests'
        }    
    } else {
        $count ++
    }
} until($count -eq $computerNames.Count)

Write-Host -ForegroundColor Magenta "Complete"
Write-Host $good -ForegroundColor green  " workstations added the shortcut" 
Write-Host $bad -ForegroundColor Red  " workstations couldn't connect"
Write-Host "Admin Script ran successfully"
            Read-Host "Press enter to return to the main menu..."
}
        "19" {Write-Host "This script will ping the Subnet we use for printers and export them into a document in your documents folder, in a newly created 'PrintScan' director"
        cd ~/Documents
if (Test-Path -Path ~/Documents/PrinterScan) {
    cd PrinterScan
} else {
mkdir PrinterScan
cd PrinterScan}
if (Test-Path -Path ~/Documents/PrinterScan/targets.txt) {
    'Targets file exists, removing...'
    rm ~/Documents/PrinterScan/targets.txt
}
for ($i=1; $i -lt 255; $i++) {
    Write-Output 132.40.72.$i >> ~/Documents/PrinterScan/targets.txt
    }
for ($i=1; $i -lt 255; $i++) {
    Write-Output 132.40.73.$i >> ~/Documents/PrinterScan/targets.txt
    }
for ($i=1; $i -lt 255; $i++) {
    Write-Output 132.40.74.$i >> ~/Documents/PrinterScan/targets.txt
    }
for ($i=1; $i -lt 255; $i++) {
    Write-Output 132.40.75.$i >> ~/Documents/PrinterScan/targets.txt
    }
$targetlist = Get-Content '~/Documents/PrinterScan/targets.txt'
echo $targetlist
$ErrorActionPreference = "SilentlyContinue"
$targetfailures = @()
$targetsuccess = @()
foreach($target in $targetlist)
    {
    if (Test-Connection $target -Quiet -Count 1){
    Write-Host "IP Not available" -ForegroundColor Red
    $targetsuccess += $target 
    }
    Else{
    Write-Host "IP available" -ForegroundColor Green
    $targetfailures += $target 
    }
}
$targetsuccess > ~/Documents/Success_$((Get-date).ToString('MM-dd-yyyy')).txt
Get-Content ~/Documents/Success_$((Get-date).ToString('MM-dd-yyyy')).txt|ForEach-Object {$_ + " IP Nonavailable"} >> ~/Documents/PrinterScan/nonavailable.txt
$targetfailures > ~/Documents/Failure_$((Get-date).ToString('MM-dd-yyyy')).txt
Get-Content ~/Documents/Failure_$((Get-date).ToString('MM-dd-yyyy')).txt|ForEach-Object {$_ + " IP available"} >> ~/Documents/PrinterScan/available.txt
Get-Content ~/Documents/PrinterScan/available.txt, ~/Documents/PrinterScan/nonavailable.txt | Set-Content PrinterIPRange$((Get-date).ToString('MM-dd-yyyy')).txt
echo 'Removing files...'
rm ~/Documents/PrinterScan/nonavailable.txt,~/Documents/PrinterScan/available.txt, ~/Documents/PrinterScan/targets.txt
Write-Host 'Please see PrinterIPRange text document within your Documents/PrinterScan Directory' -ForegroundColor Green
Write-Host "Ping Sweep Script ran successfully."
            Read-Host "Press enter to return to the main menu..."}
        "20" {
              while ($true) {
        $frp = Read-Host -Prompt "Please enter a computer name to enumerate usernames"
        if ($frp -ne "") {
            $top += $frp
        } else {
            break
        }
    }
    
    foreach ($frp in $top){
    quser /server:$frp
    Write-Host "If script says RPC Server unavailable or denies you to query users, open an elevated Powershell and type [quser /server:COMPUTERNAME] "
        }
       }
        "21" {
            $grr = Read-Host -Prompt "Enter {DODID}a for user to lookup"
            Get-ADuser $grr
            Read-Host "Press enter to return to the main menu..."
        }
        "22"{
            $rpc = Read-host -Prompt "Enter computer name to restart"
            Restart-Computer $rpc -Force
        }
    }
}
