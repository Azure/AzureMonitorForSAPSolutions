# Introduction
This section is for files relating to enabling SapMonitors where the source system VNet blocks outbound internet connections.

## create-install-files.sh (For Developers)
This script is for creating the installation files needed to get the Collector VM running the payload without internet connectivity.
With every release, there should be a corresponding `no-internet-install-<VERSION>.tar` which is created using this script.

## setup.sh (For Users)
When a customer attempts to create a SapMonitor, if the source system VNet is blocking outbound internet connections, they may get the following error:
```
Failed Monitor Deployment: Status 4; Error \\nW: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/dists/xenial/InRelease  Could not connect to azure.archive.ubuntu.com:80 (51.132.212.186), connection timed out\\nW: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/dists/xenial-updates/InRelease  Unable to connect to azure.archive.ubuntu.com:http:\\nW: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/dists/xenial-backports/InRelease  Unable to connect to azure.archive.ubuntu.com:http:\\nW: Failed to fetch http://security.ubuntu.com/ubuntu/dists/xenial-security/InRelease  Cannot initiate the connection to security.ubuntu.com:80 (2001:67c:1562::15). - connect (101: Network is unreachable) [IP: 2001:67c:1562::15 80]\\nW: Some index files failed to download. They have been ignored, or old ones used instead.\\n\\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\\n\\nE: Unable to locate package containerd\\nE: Unable to locate package docker.io\\nE: Couldn't find any package by glob 'docker.io'\\nE: Couldn't find any package by regex 'docker.io'\\n\\\"\\r\\n\\r\\nMore information on troubleshooting is available at https://aka.ms/VMExtensionCSELinuxTroubleshoot \"
```
Or the creation may timeout altogether:
```
cli.azure.cli.core.util : Deployment failed. Correlation ID: cc2f0f53-d610-4581-816e-de360f3e015a. Failed Monitor Deployment: step timed out
Deployment failed. Correlation ID: cc2f0f53-d610-4581-816e-de360f3e015a. Failed Monitor Deployment: step timed out
```
These error messages imply that the user's subscription has some network restrictions that do not allow outbound internet connections. To work-around these restrictions, the user can follow below steps :  

1. Open [cloud shell](https://docs.microsoft.com/en-us/azure/cloud-shell/overview) on Azure Portal in Bash mode.
2. Authenticate to your Azure Account and set the context to the subscription you provisioned your AMS resource in. 
```
az login
az account set --subscription <YOUR_SUBSCRIPTION_ID>
```
3. Download the required scripts to re-configure your AMS resource.
```
wget https://raw.githubusercontent.com/Azure/AzureMonitorForSAPSolutions/master/no-internet/setup.sh
```
4. Execute the script with relevant parameters :
```
bash setup.sh <SAPMONITOR_RESOURCE_GROUP> <SAPMONITOR_RESOURCE_NAME>
```

## Troubleshooting Guide
1. You may see access errors when you try to run the script with "AuthorizationFailed" messages, you need to make sure the user who you authenticated with has relevant access to perform the re-configuraion required. 
