[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/eckdd/PowerFMC)

# PowerFMC
PowerShell REST client for Cisco Firepower Management Center (FMC)

USE AT YOUR OWN RISK! 
This module is still under development and any feature may or may not work as intended.
Please only use in lab/development environments unless you have a strong understanding of PowerShell and the REST API.
I am not responsible for any damages or downtime caused by the use of these modules. Review issues and features at: https://app.gitkraken.com/glo/board/W-BgOWfwqwAOfuwg

The functions in this module invoke REST calls to the FMC API enabling the bulk creation and management of objects and policies.

# Requirements
This module was developed in PowerShell version 5.1 on Windows 10.
Firepower Mangement Center 6.2.3

# Setup

1. Create a folder called 'PowerFMC' in one of the PowerShell module paths listed in the $env:PSModulePath variable (e.g. C:\Program Files\WindowsPowerShell\Modules).

2. Copy the contents of this repository into the PowerFMC folder.

3. Load the module by running 'Import-Module PowerFMC' in PowerShell

4. View available functions by running 'Get-Command -Module PowerFMC'

# Usage 

Begin by generating  an Auth Access Token with the New-FMCAuthToken function. This will prompt for the FMC host URL and credentials with API access. Once ran, a token valid for 30 minutes will be stored in the current PowerShell session environment and all other functions can be used without specifying the token, domain, or FMC host.
