# Active Directory Admin Management

This PowerShell script provides a menu-driven interface for managing users and computers in an Active Directory environment. It includes functionalities for listing user and computer information, performing domain scans, managing group memberships, and more.

## Features

- **List User Information**: Retrieves and displays information about a specified user.
- **List Computer Information**: Retrieves and displays information about specified computers. (Note: May not show in PowerShell ISE)
- **Domain Scan**: Scans all objects in Active Directory to locate the last known user logged into a computer.
- **Add Computer to DRA**: Adds a computer to the Directory and Resource Administrator (DRA) with specified permissions.
- **Add User to Groups (Notepad Method)**: Adds a user to multiple groups using a notepad method for group CN names.
- **Remove Computer**: Removes a specified computer from the domain.
- **Add User to Group**: Adds a user to a specified group.
- **Remove User from Group**: Removes a user from a specified group.
- **Install RSAT & DRA Extensions Files**: Installs Remote Server Administration Tools (RSAT) and DRA Extensions.
- **Retrieve DRA PowerShell Manual**: Opens the DRA PowerShell manual document.
- **Enable/Unlock User Account**: Enables and unlocks a specified user account.
- **Disable User Account**: Disables a specified user account.
- **Restore Computer Account**: Restores a specified computer account.
- **CST Continuity Locations**: Provides quick access to CST continuity locations.
- **Exit**: Exits the script.
- **View User Groups**: Displays the groups a specified user is a member of.
- **Printer Script**: Runs a script to map printers to specified computers.
- **Admin Script**: Enables admin/user logon for specified computers.
- **Printer Subnet Ping Sweep**: Performs a ping sweep on printer subnets and logs the results.
- **Check Logged-In Users**: Checks for logged-in users on specified computers.
- **Quick Check Active Directory User**: Quickly checks information for a specified user in Active Directory.
- **Restart Computer**: Restarts a specified computer.

## Usage

1. **Clone or download the script** to your local machine.
2. **Open PowerShell with administrative privileges**.
3. **Navigate to the directory** containing the script.
4. **Run the script** using the following command:
    ```powershell
    .\<script-name>.ps1
    ```
5. The main menu will be displayed. **Enter the number** corresponding to the desired action and follow the prompts.

## Prerequisites

- Ensure you have the necessary permissions to perform administrative tasks in the Active Directory environment.
- Install Remote Server Administration Tools (RSAT) if not already installed.

## Example

To list user information, follow these steps:

1. Run the script.
2. Enter `1` at the main menu.
3. Enter the `{DODID}a` of the user when prompted.

The script will retrieve and display the user's information.

## Notes

- Some functionalities may not work in PowerShell ISE. It is recommended to run the script in the standard PowerShell console.
- The script includes safety checks and error handling to ensure smooth operation. However, it is advisable to test the script in a controlled environment before deploying it in a production setting.

## Contributions

Feel free to contribute to the script by submitting pull requests or opening issues on the GitHub repository.
