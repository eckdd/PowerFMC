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

# Setup/Update

Paste the following in PowerShell:
#
md ($env:PSModulePath -split ';')[0] -ErrorAction Ignore

cd ($env:PSModulePath -split ';')[0]

Start-BitsTransfer -Source https://github.com/eckdd/PowerFMC/archive/master.zip -Destination .

Expand-Archive -Path .\master.zip

md .\PowerFMC -ErrorAction Ignore

copy ".\master\PowerFMC-master\\*" -Container PowerFMC -Force

del .\master\ -Force -Recurse

del .\master.zip
#

# Usage 

Begin by generating  an Auth Access Token with the New-FMCAuthToken function. This will prompt for the FMC host URL and credentials with API access. Once ran, a token valid for 30 minutes will be stored in the current PowerShell session environment and all other functions can be used without specifying the token, domain, or FMC host.

To see a list of all functions, run Get-Command -Module PowerFMC
To see help with examples for any specific functions, run Get-Help the-name-of-the-function -Examples; e.g. Get-Help New-FMCNetworkObject -Examples
You can also add a -? at the end of a function to see the possible parameters avaialble for it; e.g. New-FMCAuthToken -?
