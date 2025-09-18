## Explanation

When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when the same entity fails to log into the same VM a given number of times within a certain time period. (i.e. 10 failed logons or more per 5 hours).

## Creation of Alert Rule

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 50 times or more within the last 5 hours. Also adding a description and then classifying the type of MITRE ATT&CK. 

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 50
| order by NumberOfFailures desc 

```
<img width="466" height="664" alt="image" src="https://github.com/user-attachments/assets/26448df5-280f-456b-b99f-cc7f894c3d9c" />

## NIST 800-61: Incident Response Lifecycle

### Preparation
Document roles, responsibilities, and procedures.
Ensure tools, systems, and training are in place.

### Detection and Analysis
Identify and validate the incident.
  Observed the incident and assign it to myself, set the status to Active
  Investigate the Incident by Actions → Investigate
Gather relevant evidence and assess impact.
  Observe the different entity mappings and take notes:
    The Brute Force Detection - Tom incident was triggered from different 3 IP addresses against 4 different hosts. <164.92.128.27, 92.63.197.9, 161.35.85.83>

<img width="1263" height="188" alt="image" src="https://github.com/user-attachments/assets/0eb2c8c2-757f-4f49-9ffb-e3d02d39e9b8" />



Checked to make sure none of the IP addresses attempting to brute force the machine actually logged in.

  ```kql
DeviceLogonEvents
| where RemoteIP in ("164.92.128.27", "92.63.197.9", "161.35.85.83", "92.63.197.9")
| where ActionType != "LogonFailed"

```
Resulted in outputs which means there were no successful attempts

## Containment, Eradication, and Recovery

Isolate affected systems to prevent further damage.
In real life if this was a serious threat, we would isolate the machine with Defender for Endpoint and
conduct an AV scan
<img width="1199" height="493" alt="image" src="https://github.com/user-attachments/assets/e276451b-23e8-4fa6-8b18-b214f64ba0a2" />

For the lab, we can create or update the Network Security Group (NSG) attached to the Virtual Machine to prevent any traffic except the local PC from reaching the VM, and record in your notes:
NSG was locked down to prevent RDP attempts from the public internet.
<img width="1045" height="468" alt="image" src="https://github.com/user-attachments/assets/b732e97e-d598-4e80-b13a-a5d3341d19d4" />

Corporate policy was proposed to require this for all VMs going forward. (this can be done with Azure Policy)
Remove the threat and restore systems to normal.
Brute force was not successful, so no threats related to this incident.

## Post-Incident Activities

Document findings and lessons learned.
  Record your notes within the incident.
  
Update policies and tools to prevent recurrence.
  In real life, we would probably make a company policy for hardening the VMs to not allow completely wide open NSGs. This can be done with Azure Policy, but we won’t do anything for now. Just acknowledge it

## Closure

Review and confirm incident resolution.
  Review/observe your notes for the incident.
Finalize reporting and close the case.
  Close out the Incident within Sentinel as a “True Positive”

<img width="447" height="662" alt="image" src="https://github.com/user-attachments/assets/91ca5d80-222c-4f0e-bafd-a4bc2c66d139" />





