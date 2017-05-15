# wannapry-smb1
A PowerShell script to disable and remove SMB 1.0 from an entire domain.

**Please** don't rely on this to protect your systems from the EternalBlue/WannaCry exploit.  Install the official Microsoft security patches.  Use this as an extra line of defense.

## How to run
1. Log onto a computer, as a user who has administrative rights to all computers on the domain.
2. Install the Active Directory PowerShell module.
3. Adjust your execution policy as needed with `Set-ExecutionPolicy`.
4. Run this script:  `.\Remove-SMB1FromDomain.ps1`
