# wannapry-smb1
A PowerShell script to disable and remove SMB 1.0 from an entire domain.  If you don't rely on this protocol, [Microsoft's bloggers recommend you remove it](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/) (though it's still enabled by default).

**Please** don't rely on this to protect your systems from the EternalBlue/WannaCry exploit.  Install [the official Microsoft security patches](https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/).  Use this script only as an extra line of defense.

## How to run
1. Log onto a computer, as a user who has administrative rights to all computers on the domain.
2. Install the Active Directory PowerShell module.
3. Adjust your execution policy as needed with `Set-ExecutionPolicy`.
4. Run this script:  `.\Remove-SMB1FromDomain.ps1`
