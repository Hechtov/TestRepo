#Requires -Version 5.1
<#

####################################################################################################
#                                                                                                  #
#   AzureStealth - Discover the most privileged users in Azure and escalate privileges with them   #
#                                                                                                  #
####################################################################################################
#                                                                                                  #
#                                                                                                  #
#                                Written by: Asaf Hecht (@Hechtov)                                 #
#                                                                                                  #
#                                                                                                  #
####################################################################################################


Versions Notes:

Version 0.1 - 03.03.19

#>

$AzureStealthVersion = "v0.1"

$AzureStealth = @"

----------------------------------------------------------------------------------

                                      _____ _             _ _   _     
           /\                        / ____| |           | | | | |    
          /  \    _____   _ _ __ ___| (___ | |_ ___  __ _| | |_| |__  
         / /\ \  |_  / | | | `'__/ _ \\___ \| __/ _ \/ _`` | | __| `'_ \ 
        / ____ \  / /| |_| | | |  __/____) | ||  __/ (_| | | |_| | | |
       /_/    \_\/___|\__,_|_|  \___|_____/ \__\___|\__,_|_|\__|_| |_|
                                                                
"@                                   

$Author = @"
----------------------------------------------------------------------------------

                        Author: Asaf Hecht - @Hechtov
                                CyberArk Labs
                         Future updates via Twitter

----------------------------------------------------------------------------------

"@


Write-Output $AzureStealth
Write-Output "`n                  ***   Welcome to AzureStealth $AzureStealthVersion   ***`n"
Write-Output " Discover the most privileged users in Azure and escalate privileges with them :)`n"
Write-Output $Author



# Guide for installing Azure AZ PowerShell Module:
#     https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-1.4.0
# If local admin:
#     Install-Module -Name Az -AllowClobber
# Else:
#     Install-Module -Name Az -AllowClobber -Scope CurrentUser

function Check-AzureModule {
    # Try loading the AZ PowerShell Module
    try {
        $azModule = Get-InstalledModule -Name Az
    }
    Catch {
        Write-Host "Couldn't find the Azure PowerShell Module" -ForegroundColor Yellow
        Write-Host "The tool will prompt you and install it using the `"Install-Module -Name Az`" command" -ForegroundColor Yellow
        if ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
            Install-Module -Name Az -AllowClobber
        }
        else {
            Install-Module -Name Az -AllowClobber -Scope CurrentUser
        }
    }
    try {
        $azModule = Get-InstalledModule -Name Az
        if ($azModule){
            Write-Host "`n  [+] Great, Azure PowerShell Module exists`n"   
        }
    }
    catch {
        Write-Host "Encountered an error - couldn't find the Azure PowerShell Module" -BackgroundColor Red
        Write-Host "Please install Azure Az PowerShell Module (requires PowerShell version 5.1+)" -BackgroundColor Red
        Write-Host "Installation guideline:" -BackgroundColor Red
        Write-Host "https://docs.microsoft.com/en-us/powershell/azure/install-az-ps" -BackgroundColor Red
        Return $false
    }

    Return $true
}

function Connect-AzureEnvironment {
    
    try {
        $answer = "n"
        $AzContext = Get-AzContext  | Where-Object {($_.Tenant) -or ($_.TenantId)}
        if ($AzContext.Account) {
            Write-Host "The current Azure account context is set for:"
            Write-Host ($AzContext | select  Name, Account, Environment | Format-List | Out-String)  -NoNewline
            $answer = Read-Host "Do you want to use this Azure Account context? Press (y/Y or n/N)"
        }
        if ($answer.ToLower() -notmatch "y") {
            Write-Host "The follwoing Azure user/s are available through the cache:`n"
            $AzCachedContext = Get-AzContext -ListAvailable | Where-Object {($_.Tenant) -or ($_.TenantId)}
            $counter = 0
            $AzCachedContext | foreach {
                $counter++
                $context = $_.Account.id | Out-String
                Write-Host $counter") "$context -NoNewline
            }
            $contextAnswer = Read-Host "`nDo you want to use one of the above cached users? Press the user's number" 
            $contextNum = [int]$contextAnswer
            if ($contextNum -le $counter) {
                $contextNum--
                Set-AzContext -Context $AzCachedContext[$contextNum] -ErrorAction Stop  > $null
            }
            else {
                Write-Host "Please connect to your desired Azure environment"
                Write-Host "These are the available Azure environments:"
                $AzEnvironment = Get-AzEnvironment | select Name, ResourceManagerUrl
                Write-Host ($AzEnvironment | Format-Table | Out-String)  -NoNewline
                $answer = read-host "Do you use the US-based `"AzureCloud`" environment? Press (y/Y or n/N)"
                if ($answer.ToLower() -match "y") {
                    Connect-AzAccount -ErrorAction Stop > $null
                }
                else {
                    $AzEnvironment = Read-Host "Ok, please write your Azure environment Name from the list above.`nAzure environment Name"
                    Connect-AzAccount -Environment $AzEnvironment -ErrorAction Stop > $null
                }
            }
        }
    }
    catch {
        Write-Host "Encountered an error - check again the inserted Azure Credentials" -BackgroundColor red
        Write-Host "There was a problem when trying to access the target Azure Tanent\Subscription" -BackgroundColor Red
        Write-Host "Please try again... and use a valid Azure user" 
        Write-Host "You can also try different Azure user credentials or test the scan on a different environment"
        return $false
    }
    Write-Host "`n  [+] Got valid Azure credentials"
    return $true
}

function Connect-AzureActiveDirectory {
    [CmdletBinding()]
    param(
    $AzContext
    )
    try {
        $tenantId = $AzContext.Tenant.Id
        $accountId = $AzContext.Account.Id
        $AzAD = Connect-AzureAD -TenantId $tenantId -AccountId $accountId -ErrorAction Stop
        $directoryName = $AzAD.TenantDomain
        Write-Host "`n  [+] Connected to the Azure Active Directory: "$directoryName
    }
    catch {
         Write-Host "`nCoudn't connect to the Azure Active Directory using the chosen user" -BackgroundColor red
         Write-Host "Please try again... and use a valid Azure AD user" -BackgroundColor red
         Write-Host "The tool will continue but it won't scan the Tenant Directory level (only subscriptions will be scanned)" -BackgroundColor red
         Write-Host "You can also try different Azure user credentials or test the scan on a different environment"
         return $false
    }   
    
    return $true
}

<#
function Add-PrivilegeAzEntityLine {
    [CmdletBinding()]
    param(
    $AzEntityObject,
    [string]
    $EntityType,
    [string]
    $PrivilegeReason
    )   
    
    
    $EntityDisplayName 
    $EntityUserName 
    $EntityType 
    $PrivilegeType	
    $RBACRole	
    $IsCustomRole	
    $ClassicSubscriptionAdminRole	
    $DirectoryRole	
    $SubscriptionName     #Important: AssignableScopes in the role definition might have multiple subscriptions	
    $SubscriptionID #(might be multiple)	
    $SubscriptionStatus #?	
    $DirectoryTenantName	
    $DirectoryTenantID	
    $HasMFA	
    $EntityLastActivityTimeAgo(Days)	
    $EntityCredentialsAge(Days)	
    $IsthereADenyRoleOnThisEntity #?	
    $AzureUserType	
    $HasEmail	
    $HasPhoto
    $RBACRoleDefinition #(might be multiple)	
    $RBACRoleDescription	
    $DirectoryRoleDefinition	
    $DirectoryRoleDescription	
    $UserObjectID	
    $RBACRoleId
  

    If ($EntityType -eq "user") {
        $EntityDisplayName = $AzEntityObject.DisplayName
        $EntityUserName = $AzEntityObject.UserPrincipalName
        #$EntityType = $EntityType
        #$PrivilegeType = $PrivilegeType
    
    
    }






    $entityInfoLine = [PSCustomObject][ordered] @{
        EntityName        = [string]$EntityName
        EntityType        = [string]$entityType
    }

    $privilegedAzEntitiesOutput += $entityInfoLine

}
#>


function Add-PrivilegeAzureEntity {
    [CmdletBinding()]
    param(
    #$AzEntityObject,
    [string]
    #$EntityType,
    [string]
    #$PrivilegeReason,
    #$TenantInfo,
    [string]
    $entityId,
    [string]
    $DirectoryTenantID,
    [string]
    $SubscriptionID,
    [string]
    $RoleId,
    [string]
    $PrivilegeReason,
    [string]
    $ClassicSubscriptionAdminRole,
    [string]
    $scope,
    [switch]
    $ClassicAdmin
    )

    <#
    $EntityDisplayName - GLOBAL	 
    $EntityUserName - GLOBAL	 
    $EntityType - GLOBAL	 
    $PrivilegeType	
    $RBACRole	
    $IsCustomRole	
    $ClassicSubscriptionAdminRole	
    $DirectoryRole	
    $SubscriptionName    - GLOBAL	  #Important: AssignableScopes in the role definition might have multiple subscriptions	
    $SubscriptionID  - GLOBALkey	#(might be multiple)	
    $SubscriptionStatus - GLOBAL	 #?	
    $DirectoryTenantName - GLOBAL		
    $DirectoryTenantID - GLOBALkey		
    $HasMFA - GLOBAL	
    $EntityLastActivityTimeAgo(Days) - GLOBAL		
    $EntityCredentialsAge(Days) - GLOBAL		
    $AzureUserType - GLOBAL	
    $HasEmail - GLOBAL		
    $HasPhoto - GLOBAL	
    $RBACRoleDefinition  - GLOBAL	 #(might be multiple)	
    $RBACRoleDescription - GLOBAL		
    $DirectoryRoleDefinition - GLOBAL		
    $DirectoryRoleDescription - GLOBAL		
    $UserObjectID - GLOBALkey
    $RBACRoleId - GLOBALkey	

    @entityDict:
        $entityId - GLOBALkey
        $EntityDisplayName - GLOBAL	 
        $EntityUserName - GLOBAL	 
        $EntityType - GLOBAL
        $EntityGroupMemberships -GLOBAL
        $HasMFA - GLOBAL	
        $EntityLastActivityTimeAgo(Days) - GLOBAL		
        $EntityCredentialsAge(Days) - GLOBAL		
        $AzureUserType - GLOBAL	
        $HasEmail - GLOBAL		
        $HasPhoto - GLOBAL
    @tenantDict:
    	$DirectoryTenantID - GLOBALkey
        $DirectoryTenantName - GLOBAL
    @subscriptionDict:
        $SubscriptionID  - GLOBALkey	#(might be multiple)	
        $SubscriptionName    - GLOBAL	  #Important: AssignableScopes in the role definition might have multiple subscriptions	
        $SubscriptionStatus - GLOBAL	 #?	
    @roleDict:
        $RoleId - GLOBALkey
        $RBACRoleId - GLOBAL
        $RoleType - GLOBAL
        $RBACRoleDefinition  - GLOBAL	 #(might be multiple)	
        $RBACRoleDescription - GLOBAL		
        $DirectoryRoleDefinition - GLOBAL		
        $DirectoryRoleDescription - GLOBAL
        $RBACRole - GLOBAL
        $IsCustomRole - GLOBAL
        $DirectoryRole - GLOBAL  
    $PrivilegeType		
    $ClassicSubscriptionAdminRole	

    $privilegedAzEntitiesOutput = @()
    $privilegedAzEntitiesDict = @{}
    $entityDict = @{}
    $tenantDict = @{}
    $subscriptionDict = @{}
    $roleDict = @{}

    #>
    #$PrivilegeType = $PrivilegeReason
    $directoryAdmin = @("Application Administrator", "Authentication Administrator",`
        "Cloud Application Administrator", "Helpdesk Administrator", "Privileged Role Administrator", "User Account Administrator")

    $subscriptionAdmin =  @("Owner","Contributor", "User Access Administrator")
    
    if ($ClassicAdmin) {
        $ClassicAdministrator = $PrivilegeReason
        $PrivilegeType = "Full Subscription Admin"
        $RoleId = "Classic Subscription Admin"
    }
    else {
        if ($PrivilegeReason -eq "Company Administrator") {
            $roleDict[$RoleId].DisplayName = "Global Administrator"
            $PrivilegeType = "Full Azure Directory Admin"
        }
        elseif ($directoryAdmin -contains $PrivilegeReason) {
            $PrivilegeType = "Full Azure Directory Shadow Admin"
        }
        if ($subscriptionAdmin -contains $PrivilegeReason) {
            $PrivilegeType = "Full Subscription Admin"
        }
    }
    
    if ($entityDict[$entityId].ExtensionProperty.createdDateTime) {
        $EntityCreationDate = Get-Date ($entityDict[$entityId].ExtensionProperty.createdDateTime) -Format "yyyMMdd"
    }

    if ($roleDict[$RoleId].IsCustom) {
        $customRole = $True
    }

    $entityLine = [PSCustomObject][ordered] @{
        EntityDisplayName    = [string]$entityDict[$entityId].DisplayName
        EntityPrincipalName  = [string]$entityDict[$entityId].UserPrincipalName
        EntityType           = [string]$entityDict[$entityId].ObjectType 
        PrivilegeType        = [string]$PrivilegeType
        DirectoryRoleAdminName   = [string]$roleDict[$RoleId].DisplayName  
        ClassicSubscriptionAdmin = [string]$ClassicAdministrator
        RBACRoleAdminName        = [string]$roleDict[$RoleId].Name 
        SubscriptionName     = [string]$subscriptionDict[$SubscriptionID].Name
        SubscriptionID       = [string]$SubscriptionID
        SubscriptionStatus   = [string]$subscriptionDict[$SubscriptionID].State
        TenantDisplayName    = [string]$tenantDict[$TenantId].DisplayName
        TenantInitialName    = [string]$tenantDict[$TenantId].InitialDomainName
        DirectoryTenantID    = [string]$DirectoryTenantID
        EntityCreationDate   = [string]$EntityCreationDate
        EntityId             = [string]$entityDict[$entityId].ObjectId
        EntityHasPhoto       = [string]$entityDict[$entityId].EntityHasPhoto
        UserEnabled          = [string]$entityDict[$entityId].AccountEnabled
        OnPremisesSID        = [string]$entityDict[$entityId].OnPremisesSecurityIdentifier
        RoleId               = [string]$RoleId
        #RoleIsSystem         =[string]$roleDict[$RoleId].IsSystem
        RoleIsCustom         =[string]$customRole
        #RoleTemplateId       =[string]$roleDict[$RoleId].RoleTemplateId
        #RoleDisabled         =[string]$roleDict[$RoleId].RoleDisabled
        #RoleDescription      = [string]$roleDict[$RoleId].Description         
    }

    if ($RoleId) {
        $entityRand = [string]($entityDict[$entityId].ObjectId) + "-" + [string]$RoleId
    }
    else {
        #$rand = Get-Random
        $rand  = $SubscriptionID + $PrivilegeReason
        $entityRand = [string]($entityDict[$entityId].ObjectId) + "-" + [string]$rand
    }
    #if (-not $privilegedAzEntitiesDict.contains($entityRand)) {
    $privilegedAzEntitiesDict.add($entityRand,$entityLine)
    #}
    #else {
    #    write-host "else------------------------------------------------------------------------" -BackgroundColor Yellow
    #}
}


function Add-EntityToDict {
    [CmdletBinding()]
    param(
        $AzEntityObject,
        [switch]
        $externalUser
    )

    if ($externalUser){
        $externalUserObject = [PSCustomObject][ordered] @{
            DisplayName        = $AzEntityObject
            UserPrincipalName  = $AzEntityObject
            ObjectType         = "User"
            ObjectId           = "ExternalUser-" + $AzEntityObject
        }
        $entityDict.add($AzEntityObject, $externalUserObject)
    }
    else {
        $EntityId = $AzEntityObject.ObjectId
        if (-not $entityDict.contains($EntityId)) { 
            $usersPhotoFolder = $PSScriptRoot + "\PrivilegedUserPhotos"
            if ($AzEntityObject.ExtensionProperty."thumbnailPhoto@odata.mediaEditLink") {
                $entityHasPhoto = $true
                $photoFolderExists = Test-Path -Path $usersPhotoFolder
                if (-not $photoFolderExists) {
                    New-Item -ItemType directory -Path $usersPhotoFolder > $null
                }
                try {
                    Get-AzureADUserThumbnailPhoto -ObjectId $EntityId -FilePath $usersPhotoFolder -ErrorAction SilentlyContinue > $null
                    $entityHasPhoto = $true
                }
                catch {}
            }
            else {
                $entityHasPhoto = $false
            }        
            $AzEntityObject | Add-Member EntityHasPhoto $entityHasPhoto
            $entityDict.add($EntityId, $AzEntityObject)
        }
    }
}


function Add-RoleToDict {
    [CmdletBinding()]
    param(
        $RoleObject,
        [switch]
        $RbacRole
    )
    
    if ($RbacRole) {
        $RoleId = $RoleObject.Id
    }
    else {
        $RoleId = $RoleObject.ObjectId
    }

    if (-not $roleDict.contains($RoleId)) {  
        #$RoleObject | Add-Member IsCustomRole 90
        $roleDict.add($RoleId, $RoleObject)
    }
}

# Check for directory roles and add to the dict
function Check-DirectoryRolesEntities {
    [CmdletBinding()]
    param(
    [string]
    $direcotryRoleName
    )    
    $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq $direcotryRoleName}
    if ($role) {
        Add-RoleToDict -RoleObject $role
        $globalAdminDB = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Get-AzureADUser
        $globalAdminDB | foreach {
            Add-EntityToDict -AzEntityObject $_
            Add-PrivilegeAzureEntity -entityId $_.ObjectId -DirectoryTenantID $TenantId -PrivilegeReason $direcotryRoleName -RoleId $role.ObjectId
        }
    }
}


function Run-TenantScan {
    [CmdletBinding()]
    param(
        [string]
        $TenantId,
        [string]
        $UsedUserPrincipalName,
        [string]
        $UsedUserId
    )

    $tenantObject = Get-AzureADTenantDetail

    if (-not $tenantDict.contains($TenantId)) {      
        $initialDomainName = $tenantObject.VerifiedDomains | Where-Object {$_.Initial} | select Name
        $tenantObject | Add-Member "InitialDomainName" $initialDomainName.Name
        $tenantDict.add($TenantId, $tenantObject)
    }

    <#
    1.  Global Administrator / Company Administrator - Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities.
    2.	Application Administrator - Users in this role can create and manage all aspects of enterprise applications.
    3.	Authentication Administrator - Users with this role can set or reset non-password credentials. 
    4.	Cloud Application Administrator - Users in this role have the same permissions as the Application Administrator role, excluding the ability to manage application proxy.
    5.	Password Administrator / Helpdesk Administrator - Users with this role can change passwords, invalidate refresh tokens, manage service requests.
    6.	Privileged Role Administrator - Users with this role can manage role assignments in Azure Active Directory.
    7.	User Account Administrator - Can manage all aspects of users and groups, including resetting passwords for limited admins.
    #>

    $privilegedDirectoryRoles = @("Company Administrator","Application Administrator", "Authentication Administrator",`
        "Cloud Application Administrator", "Helpdesk Administrator", "Privileged Role Administrator", "User Account Administrator")
    $privilegedDirectoryRoles | foreach {
        Check-DirectoryRolesEntities -direcotryRoleName $_
    }
}


function Run-SubscriptionScan {
    [CmdletBinding()]
    param(
    [string]
    $subscriptionId
    )

    if (-not $subscriptionDict.contains($subscriptionId)) {      
        $subscriptionObject = Get-AzSubscription -SubscriptionId $subscriptionId
        $subscriptionDict.add($subscriptionId, $subscriptionObject)
    }

    $tenantId = $subscriptionDict[$subscriptionId].TenantId

    <#
    RABC privileged role names:
	1. Owner
	2. Contributor
	3. User Access Administrator
    #>
    $privilegedSubscriptionRoles = @("Owner","Contributor", "User Access Administrator")
    #$rbacRoles = Get-AzRoleAssignment -Scope "/subscriptions/"$subscriptionId
    $privilegedRbacRoles = @()
    $allRbacRoles = Get-AzRoleDefinition
    $allRbacRoles | foreach {
        # If this is a built-in RBAC role
        if (-not $_.IsCustom) {
            if ($privilegedSubscriptionRoles -contains $_.Name) {
                Add-RoleToDict -RoleObject $_ -RbacRole
                $privilegedRbacRoles += $_
            }
        }
        # to do : add this section:
        # If this RBAC role is custom made
        else {
            Write-Host "`nAnalyzing a Custom Role"  -ForegroundColor Yellow
            #Add-RoleToDict -RoleObject $_ -RbacRole
            #$privilegedRbacRoles += $_
        }
    }
    # Get the entities with the privileged RBAC roles
    #$rbacPrivilegedEntities = @()
    $subscriptionRoleAssignments = Get-AzRoleAssignment -IncludeClassicAdministrators
    # Check classic administrators:
    $subscriptionRoleAssignments | Where-Object {-not $_.RoleAssignmentId} | foreach {
        #$classicAdminObject = [PSCustomObject][ordered] @{
        #    ClassicAdmin       = $true
        #    DisplayName        = $_.DisplayName
        #    SignInName         = $_.SignInName
        #    RoleDefinitionName = $_.RoleDefinitionName
        #}

        $PrivilegeReason = $_.RoleDefinitionName
        $userPrincipalName = $_.SignInName
        #$userDisplayName = $_.DisplayName
        #$startUserName = $userPrincipalName.Substring(0,$userPrincipalName.IndexOf("@"))
        #$usersStartWith = Get-AzureADUser -SearchString $startUserName
        #$classicAdminUserObject = $usersStartWith | ? {$_.displayname -eq $userDisplayName}
        $AzEntityObject = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"
        # Check if the user is an external user
        if (-not $AzEntityObject) {
            #Write-Host "`External "Classic Administrator`" discovered:"$userPrincipalName
            Add-EntityToDict -AzEntityObject $userPrincipalName -externalUser
            Add-PrivilegeAzureEntity -entityId $userPrincipalName -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -DirectoryTenantID $TenantId -ClassicAdmin #-RoleId $role.ObjectId 
        }
        else {
            if (-not $entityDict.contains($AzEntityObject.ObjectId)){
                #$AzEntityObject = Get-AzureADUser -ObjectId $classicAdminUserObject.ObjectId
                Add-EntityToDict -AzEntityObject $AzEntityObject
            }
            #if (-not $privilegedAzEntitiesDict.contains($AzEntityObject.ObjectId)){
            Add-PrivilegeAzureEntity -entityId $AzEntityObject.ObjectId -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -DirectoryTenantID $TenantId -ClassicAdmin #-RoleId $role.ObjectId 
            #}
            #else {
            #    write-host "----"
            #}
        }
    }
    # Check for privileged RBAC roles
    $subscriptionRoleAssignments | Where-Object {$privilegedRbacRoles.Id -contains $_.RoleDefinitionId} | foreach {
        $rbacPrivilegedEntities = @()
        $PrivilegeReason = $_.RoleDefinitionName
        $roleId = $_.RoleDefinitionId
        #$rbacRoleAssignments = Get-AzRoleAssignment -RoleDefinitionId $_.Id -IncludeClassicAdministrators
        [string]$scope = "/subscriptions/" + $subscriptionId
        #$rbacRoleAssignments | foreach {
        if ([string]$_.scope -eq $scope) {
            if ($_.ObjectType -eq "User") {
                $rbacPrivilegedEntities += $_.ObjectId
            }
            elseif ($_.ObjectType -eq "Group") {
                # to do: to add Group information
                $newGroupCount = 1
                $firstGroup = $true
                $groupFromGroups = @()
                Do {
                    if ($firstGroup) {
                        $usersFromGroup = Get-AzureADGroupMember -ObjectId $_.ObjectId
                    }
                    else {
                        $usersFromGroup = $groupFromGroups | Get-AzureADGroupMember -ObjectId $_.ObjectId
                    }
                    $firstGroup = $false
                    $usersFromGroup = $usersFromGroup | where {$_.ObjectType -eq "User"}
                    $groupFromGroups = $usersFromGroup | where {$_.ObjectType -eq "Group"}
                    $newGroupCount = $groupFromGroups.count
                    $ownersOfGroup = Get-AzureADGroupOwner -ObjectId $_.ObjectId
                    $usersFromGroup, $ownersOfGroup | foreach {
                        $rbacPrivilegedEntities += $_.ObjectId
                    }
                } While ($newGroupCount -ne 0)
            }
           # }
                # to do : add this section:
                #else if it's service principle/managed identity
        }
    
        $rbacPrivilegedEntities | foreach {
            if (-not $entityDict.contains($_)){
                $AzEntityObject = Get-AzureADUser -ObjectId $_
                Add-EntityToDict -AzEntityObject $AzEntityObject
            }
            #if (-not $privilegedAzEntitiesDict.contains($_)) {
            Add-PrivilegeAzureEntity -entityId $_ -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -RoleId $roleId -DirectoryTenantID $TenantId
            #}
            #else {
            #    write-host "----"
            #}
        }
    }
    


    #to check - Get-AzureADGroupAppRoleAssignment
    
    #$rbacRolesFullScope = Get-AzRoleAssignment -Scope "/"


    #check for admin directory roles:

    #check owner of admin groups

    # serach for classic admins

#Get-AzADAppCredential
#Get-AzADApplication
#Get-AzADGroup
#Get-AzADGroupMember
#Get-AzADServicePrincipal
#Get-AzADSpCredential
#Get-AzADUser

#Get-AzUserAssignedIdentity -> didn't work

#Get-AzManagedApplication

}


function Write-AzureStealthResults {
    [CmdletBinding()]
    param(
    [switch]
    $cloudShellMode
    )
    $resultCSVpath = $PSScriptRoot + "\results.csv"
    #$resultCSVpath = "C:\WORK\Azure\AzureStealth\Tests\results.csv"
    #$resultHTMLpath = "C:\WORK\Azure\AzureStealth\Tests\results.html"
    if (-not $cloudShellMode) {
		$privilegedAzEntitiesDict.Values | sort -Descending EntityType | sort EntityDisplayName, PrivilegeType, RoleId | Export-Csv -path $resultCSVpath -NoTypeInformation
	}
	else {
		$cloudDriveInfo = Get-CloudDrive
		$localCloudShellPath = $cloudDriveInfo.MountPoint
		$resultCSVpath = $localCloudShellPath + "/AzureStealthScan-Results.csv"
		#cd /usr/asaf/clouddrive/
		#$string = "Hello World"
		$privilegedAzEntitiesDict.Values | sort -Descending EntityType | sort EntityDisplayName, PrivilegeType, RoleId | Export-Csv -path $resultCSVpath -NoTypeInformation
		#$string | Out-File -FilePath ./Hello.txt
	}
#$Header = @"
#<style>
#TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
#TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
#TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
#</style>
#"@
    #$privilegedAzEntitiesDict.Values | ConvertTo-Html -Head $Header | Out-File -FilePath $resultHTMLpath
    #Invoke-Item -Path $resultCSVpath
}


# | ConvertTo-HTML

function Scan-AzureStealth {
    [CmdletBinding()]
    param(
    [switch]
    $UseCurrentCred,
	[switch]
    $cloudShellMode
    )
    if (-not $UseCurrentCred) {
        $AzModule = Check-AzureModule
        if ($AzModule -eq $false) {
            Return
        }
        $AzConnection = Connect-AzureEnvironment
        if ($AzConnection -eq $false) {
            Return
        }
        $currentAzContext = Get-AzContext
        $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
        if ($AzConnection -eq $false) {
            $scanTheDirecotry = $false
        }
    }
    else {
        $currentAzContext = Get-AzContext
    }

    $privilegedAzEntitiesOutput = @()
    $privilegedAzEntitiesDict = @{}
    $entityDict = @{}
    $tenantDict = @{}
    $subscriptionDict = @{}
    $roleDict = @{}

    try {
        $usedUser = Get-AzADUser -UserPrincipalName $currentAzContext.Account
        Write-host "`n  [+] Running the scan with user: "$currentAzContext.Account
        $tenantList = Get-AzTenant
        #$tenantList | Add-TenantToDict -tenantObject $_
        Write-Host "`nAvailable Tanent ID/s:`n"
        Write-Host "  "($tenantList.Id | Format-Table | Out-String)
        $subscriptionList = Get-AzSubscription | select Name, Id, TenantId
        Write-Host "Available Subscription\s:"
        Write-Host ($subscriptionList | Format-Table | Out-String) -NoNewline
    }
    catch {
        Write-Host "Encountered an error - check again the inserted Azure Credentials" -BackgroundColor red
        Write-Host "There was a problem when trying to access the target Azure Tanent\Subscription" -BackgroundColor Red
        Write-Host "Please try again.." 
        Write-Host "You can also try different Azure user credentials or test the scan on a different environment" 
        Return
    }      

    $AzContextAutosave = (Get-AzContextAutosaveSetting).CacheDirectory
    if ($AzContextAutosave -eq "None") {
        Enable-AzContextAutosave
    }

    $usedUser = Get-AzADUser -UserPrincipalName $currentAzContext.Account

    # Scan all the available tanent\s
    $tenantList| foreach {
        Write-Host "  [+] Scanning tenant ID: "$_.Id
        Set-AzContext -Tenant $_.id > $null
        Run-TenantScan -TenantId  $_.id -UsedUserPrincipalName $usedUser.UserPrincipalName -UsedUserId $usedUser.Id
    }    

    # Scan all the available subscription\s
    $subscriptionList | foreach {
        Write-Host "`n  [+] Scanning Subscription Name: "$_.Name", ID: "$_.Id
        Set-AzContext -SubscriptionId $_.id > $null
        Run-SubscriptionScan -subscriptionId $_.id
    }

    Write-AzureStealthResults -cloudShellMode $cloudShellMode

    # Export\Print out the current user role and permission in the scanned tenant
    # Export Tanent info + Users Info
    
    if ($AzContextAutosave -eq "None") {
        Disable-AzContextAutosave
    }
      
}

function Scan-AzureWhoIAm {
    $userRoleAssignments = Get-AzRoleAssignment -ExpandPrincipalGroups -IncludeClassicAdministrators -SignInName $UsedUserPrincipalName 
    $userRoleAssignments | foreach {
        if ($_.Scope -eq "") {

        }
    }
}

function Escalate-toAzureGlobalAdmin {

}

function Escalate-toAzureSubscriptionOwner {

}