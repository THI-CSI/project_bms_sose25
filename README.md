# Decentralized IAM for Battery Data

## Structure

| Team                                   | Description |
|----------------------------------------| - |
| Requirements Management                | Extraction and prioritization of project requirements from documentation, with structured issue creation.  |
| Infrastructure                         | Management and configuration of technical and organizational infrastructure, including GitHub settings and coordination. |
| [IAM-Blockchain](blockchain/README.md) | Development of a blockchain core through data storage design, block and transaction structuring, and definition of consensus and networking approaches. |
| [BMS](bms/README.md)                   | Secure battery data capture, encryption, and communication between the Battery Management System and the blockchain, including hardware simulation. |
| [Cloud](cloud/README.md)               | API and database design for battery data ingestion and decryption, with the creation of a Battery Pass interface and integration of BMS and cloud services. |

## Contributions
All implementations and changes should be documented as issues, tracked in the Kanban board and assigned to sprint. 
The actual work must be done in an own branch and once an issue has been resolved, a pull request to the main branch for approval needs to be submitted. 

Detailed information about issues, pull requests and our contribution guidelines can be found here:
- [Issue Templates](https://github.com/THI-CSI/decentralized_iam_battery_data/tree/main/.github/ISSUE_TEMPLATE)
- [Pull Request Template](https://github.com/THI-CSI/decentralized_iam_battery_data/blob/main/.github/PULL_REQUEST_TEMPLATE.md)
- [Contribution Guidelines](https://github.com/THI-CSI/decentralized_iam_battery_data/blob/main/CONTRIBUTING.md) 

## Notes
Documentation is done here in GitHub, but quick notes can be found in [our HedgeDoc](https://md.s0ck.de/Project2025). The main page of our HedgeDoc can be found [here](https://md.s0ck.de/Project2025) and should include links to all other Docs created by us.

## Sequence Diagrams

- [BMS DID Creation](organizational/report/assets/bms_did_creation.svg)
- [ORG DID Creation](organizational/report/assets/org_did_creation.svg)
- [VC Creation](organizational/report/assets/vc_creation.svg)
- [Service Access](organizational/report/assets/service_access.svg)
- [DID Revocation](organizational/report/assets/did_revocation.svg)

## Communication Protocol

We are using **HTTP** as communication protocol.


## BatteryPass Schemas

`decentralized_iam_battery_data/cloud/BatteryPassDataModel` contains JSON Schemas from the [BatteryPass Data Model](https://github.com/batterypass/BatteryPassDataModel).

**License:** Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)  
**Source:** https://github.com/batterypass/BatteryPassDataModel

These schemas are used for non-commercial validation purposes in this project.


