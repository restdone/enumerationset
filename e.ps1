. C:\AD\Tools\EnumerationSet\PowerView.ps1

echo "========================================="
echo "==========Basic Enumeration=============="
echo "========================================="
# Domain,SID,User,Computer,Group
Get-Domain
Get-DomainSID
echo "========================================="
echo "==========List users, built rdp=========="
echo "========================================="
Get-DomainUser -Properties samaccountname,logonCount
Get-DomainUser -LDAPFilter "Description=*built*"| Select name, Description
Get-DomainUser -LDAPFilter "Description=*RDP*"| Select name, Description
echo "========================================="
echo "==========List machines=================="
echo "========================================="
Get-DomainComputer | select -ExpandProperty dnshostname
echo "========================================="
echo "==========List Groups and users under it="
echo "========================================="
Get-DomainGroup | ForEach-Object { Write-Host "Group: $($_.Name)"; $_.Member; Write-Host }
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroup -Identity "Enterprise Admins"
Get-DomainGroupMember -Identity "Enterprise Admin"
Get-DomainGroup *admin*

echo "========================================="
echo "============Find Forest Domain==========="
echo "========================================="
# Forrest
Get-ForestDomain -Verbose
echo "========================================="
echo "============Find Domain Trust============"
echo "========================================="
# Use the trust to attempt dcsync after obtaining krbtgt -> Attack path 16
Get-DomainTrust
echo "========================================="
echo "============Find Domain User or EA======="
echo "========================================="
Get-ForestDomain |select -ExpandProperty Name | foreach-Object {echo "$_ , DA and EA of $_" ;Get-DomainController -Domain $_ ;Get-DomainGroupMember -Identity "Domain Admins" -Domain $_;Get-DomainGroupMember -Identity "Enterprise Admins" -Domain $_}
# Find External Trust
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
Get-ForestDomain |select -ExpandProperty Name | foreach-object{Get-ForestDomain -Forest $_ }| %{Get-DomainTrust -Domain $_.Name}


# OU
echo "========================================="
echo "============Find OU======================"
echo "========================================="
Get-DomainOU
# All Computer under the same OU
#(Get-DomainOU -Identity ouname).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

# GPO
echo "========================================="
echo "============Find GPO====================="
echo "========================================="
Get-DomainOU|select -ExpandProperty name|foreach-object {Get-DomainGPO -Identity (Get-DomainOU -Identity $_).gplink.substring(11,(Get-DomainOU -Identity $_).gplink.length-72)}

#Get-DomainGPO -Identity '{7478F170-6A0C-490C-B355-9E4618BC785D}'
#Get-DomainGPO -Identity (Get-DomainOU -Identity StudentMachines).gplink.substring(11,(Get-DomainOU -Identity StudentMachines).gplink.length-72)
#Get-DomainGPO -Identity (Get-DomainOU -Identity Servers).gplink.substring(11,(Get-DomainOU -Identity Servers).gplink.length-72)
#Get-DomainGPO -Identity (Get-DomainOU -Identity Applocked).gplink.substring(11,(Get-DomainOU -Identity Applocked).gplink.length-72)



# Attack Path 8
# Kerberoast, get ticket, use it or decrypt
echo "========================================="
echo "============Check Path 8================="
echo "========================================="
Get-DomainUser -SPN

# Attack Path 9
# Find TRUSTED_TO_AUTH_FOR_DELEGATION
echo "========================================="
echo "============Check Path 9================="
echo "========================================="
Get-DomainUser -TrustedToAuth

# Attack Path 10
# msds-allowedtodelegateto listed what target's TGS can be obtained by which machine
echo "========================================="
echo "============Check Path 10================"
echo "========================================="
Get-DomainComputer -TrustedtoAuth

# Attack Path 2
#  If executable, prove the current user has admin access to those non-dc machines
echo "========================================="
echo "============Check Path 2================="
echo "========================================="
#Get-NetLocalGroup -ComputerName ${Get-DomainComputer | select -ExpandProperty dnshostname}
Get-DomainComputer | select -ExpandProperty dnshostname | Foreach-Object {echo "----- List of $_ -----";Get-NetLocalGroup -ComputerName $_}
#Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
#Get-NetLoggedon -ComputerName dcorp-adminsrv

# Attack Path 4,5
# Listed which server should be compromised
# to get current dc or dc of other domain's ticket
echo "========================================="
echo "============Check Path 4/5==============="
echo "========================================="
Get-DomainComputer -Unconstrained

# If executable, prove the current user has remote reg on that machine
#Get-LoggedonLocal -ComputerName dcorp-adminsrv

# If executable, prove the current user has localadmin + remote reg on that machine
#Get-LastLoggedOn -ComputerName dcorp-adminsrv







#Check Vuln Service Powerup -> Attack Path 1
# Check local machine vuln to PE
#. C:\AD\Tools\PowerUp.ps1
#Invoke-AllChecks

# Check database link to find the path to get cmd execution -> Attack path 17
echo "========================================="
echo "============Check Path 17================"
echo "========================================="
Import-Module C:\AD\Tools\EnumerationSet\PowerUpSQL-master\PowerUpSQL.psd1
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose |select -ExpandProperty instance|foreach-object {Get-SQLServerLinkCrawl -Instance $_ -Verbose}
#Get-SQLServerLink -Instance dcorp-mssql -Verbose
#Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose


# Bloodhound
#ACL GenericWrite to computer, Attack Path 12

# ADCS Attack path 13
# if ENROLLEE_SUPPLIES_SUBJECT, then try to get enrollment rights to do esc1
echo "========================================="
echo "============Check Path 13================"
echo "========================================="
C:\AD\Tools\EnumerationSet\Certify.exe find /enrolleeSuppliesSubject


# ADCS Attack path 14
# show the vulnerable template
# or with Certificate Request Agent at pkiextendedkeyusage to do esc3
echo "========================================="
echo "============Check Path 14================"
echo "========================================="
C:\AD\Tools\EnumerationSet\Certify.exe find /vulnerable

# ADCS Attack path 18 (ESC6)
# [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
# all enrollees can specify SAN
echo "========================================="
echo "============Check Path 18==============="
echo "========================================="
C:\AD\Tools\EnumerationSet\Certify.exe cas


# Check Accessible sharedrive use file explorer
# Attack path 15, to get find share drive of other domains
#\\xxxxx.local

#ACL
echo "========================================="
echo "=========Find ACL of DA ================="
echo "========================================="
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
$ACL_Domain_Users = Get-DomainUser -Properties samaccountname
foreach ($user_to_check_acl in $ACL_Domain_Users.samaccountname) {echo "checking interesting ACL of $user_to_check_acl"; Find-InterestingDomainACL | ?{$_.identityreferencename -match $user_to_check_acl}}
#Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceDN -like "*RDP*"}