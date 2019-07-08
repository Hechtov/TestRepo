#Requires -Version 5.1
<#

###########################################################################################
#                                                                                         #
#    AzureStealth - Discover the most privileged users in Azure and secure\target them    #
#                                                                                         #
###########################################################################################
#                                                                                         #
#                                                                                         #
#                             Written by: Asaf Hecht (@Hechtov)                           #
#                                                                                         #
#                                                                                         #
###########################################################################################


Versions Notes:

Version 0.1 - 03.03.19
Version 0.2 - 21.03.19
Version 0.3 - 08.07.19

Direct run from GitHub:
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Hechtov/TestRepo/master/AzureStealth1.ps1')

#>

$AzureStealthVersion = "v0.3"

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
Write-Output " Discover the most privileged users in Azure and secure\target them :)`n"
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
        #$AzContext = Get-AzContext 
        if ($AzContext.Account) {
            Write-Host "The current Azure account context is set for:"
            Write-Host ($AzContext | select  Name, Account, Environment | Format-List | Out-String)  -NoNewline
            $answer = Read-Host "Do you want to use this Azure Account context? Press (y/Y or n/N)"
        }
        if ($answer.ToLower() -notmatch "y") {
            $AzAllCachedContext = Get-AzContext -ListAvailable
            $AzCachedContext = $AzAllCachedContext | Where-Object {($_.Tenant) -or ($_.TenantId)}
            if ($AzCachedContext) {
                Write-Host "The follwoing Azure user/s are available through the cache:`n"
                #$AzCachedContext = Get-AzContext -ListAvailable 
                $counter = 0
                $AzCachedContext | foreach {
                    $counter++
                    $contextAccount = $_.Account.id 
                    $contextName = $_.Name
                    #$contextNameEx = "*" + $contextAccount.Substring(0,$contextAccount.Length-2) + "*"
                    $contextNameEx = "*" + $contextAccount + "*"
                    if ($contextName -like $contextNameEx){
                        Write-Host "$counter) Name: $contextName"
                    }
                    else {
                        Write-Host "$counter) Name: $contextName - $contextAccount"
                    }
                
                }
                $contextAnswer = Read-Host "`nDo you want to use one of the above cached users?`nPress the user's number from above (or n/N for chosing a new user)"
                #Write-host "`nDo you want to use one of the above cached users?`nOtherwise the credentials cache will be refreshed with your new chosen user."
                #$contextAnswer = Read-Host "Press the user's number from above (or n/N for chosing a new user)"
                if ($contextAnswer.ToString() -le $counter) {
                    $contextNum = [int]$contextAnswer
                    $contextNum--
                    $chosenAccount = $AzCachedContext[$contextNum].Account.id
                    Write-Host "`nYou chose to proceed with $chosenAccount"
                    Set-AzContext -Context $AzCachedContext[$contextNum] -ErrorAction Stop  > $null
                    return $true
                }
            }
            #$AzAllCachedContext | Disconnect-AzAccount $_.Name

            Write-Host "Please connect to your desired Azure environment"
            Write-Host "These are the available Azure environments:"
            $AzEnvironment = Get-AzEnvironment | select Name, ResourceManagerUrl
            Write-Host ($AzEnvironment | Format-Table | Out-String)  -NoNewline
            $answer = read-host "Do you use the US-based `"AzureCloud`" environment? Press (y/Y or n/N)"
            $rand = Get-Random -Maximum 10000
            if ($answer.ToLower() -match "y") {
                Connect-AzAccount -ContextName "Azure$rand" -ErrorAction Stop > $null
            }
            else {
                $AzEnvironment = Read-Host "Ok, please write your Azure environment Name from the list above.`nAzure environment Name"
                Connect-AzAccount -ContextName "Azure$rand" -Environment $AzEnvironment -ErrorAction Stop > $null
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
        if ($tenantId){
            $AzAD = Connect-AzureAD -TenantId $tenantId -AccountId $accountId -ErrorAction Stop
        }
        else {
            $AzAD = Connect-AzureAD -AccountId $accountId -ErrorAction Stop
        }
        $directoryName = $AzAD.TenantDomain
        Write-Host "`n  [+] Connected to the Azure Active Directory: "$directoryName
    }
    catch {
         Write-Host "`nCouldn't connect to the Azure Active Directory using the chosen user" -BackgroundColor red
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
            $resultsFolder = $PSScriptRoot + "\Results-" + $resultsTime
            #$usersPhotoFolder = $PSScriptRoot + "\PrivilegedUserPhotos"
            $entityHasPhoto = ""
	        if ((-not $CloudShellMode) -and (-not $fullUserReconList)) {
		        if ($AzEntityObject.ExtensionProperty."thumbnailPhoto@odata.mediaEditLink") {
			        $entityHasPhoto = $true
		            $resultsFolderExists = Test-Path -Path $resultsFolder
		            if (-not $resultsFolderExists) {
			            New-Item -ItemType directory -Path $resultsFolder > $null
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

    
    if ($fullUserReconList){
        $usersLimit = 200000
        $allUsers = Get-AzureADUser -Top $usersLimit
        $allUsersNumber = $allUsers.count
        Write-Host "      Retrieving information on $allUsersNumber Azure AD users"  
        $allUsers | foreach {
            Add-EntityToDict -AzEntityObject $_
        }
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
    RABC privileged roles names:
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

function Write-AzureReconInfo {
    param(
    [string]
    $ResultsFolder,
    [switch]
    $CloudShellMode
    )
    if ($CloudShellMode) {
        $usersInfoPath = $resultsFolder + "/AzureUsers-Info.csv"
        $directoryInfoPath = $resultsFolder + "/AzureDirectory-Info.csv"
    }
    else {
        $usersInfoPath = $resultsFolder + "\AzureUsers-Info.csv"
        $directoryInfoPath = $resultsFolder + "\AzureDirectory-Info.csv"
    }
    $ofs = ','

    # to order the recon files csv
    # to open up the multi values properties
    $entityReconOutput = @()

    $entityDict.Values | foreach {
        $entityReconLine = [PSCustomObject][ordered] @{
                UserPrincipalName          = [string]$_.UserPrincipalName
                DisplayName                = [string]$_.DisplayName
                ObjectType                 = [string]$_.ObjectType
                UserType                   = [string]$_.UserType
                AccountEnabled             = [string]$_.AccountEnabled
                JobTitle                   = [string]$_.JobTitle
                Department                 = [string]$_.Department
                Mail                       = [string]$_.Mail
                Mobile                     = [string]$_.Mobile
                TelephoneNumber            = [string]$_.TelephoneNumber
                PreferredLanguage          = [string]$_.PreferredLanguage
                MailNickName               = [string]$_.MailNickName
                GivenName                  = [string]$_.GivenName
                Surname                    = [string]$_.Surname
                EntityHasMailPhoto         = [string]$_.EntityHasPhoto
                CreatedDateTime            = [string]$_.ExtensionProperty.createdDateTime
                OnPremisesSecurityIdentifier = [string]$_.OnPremisesSecurityIdentifier
                DirSyncEnabled             = [string]$_.DirSyncEnabled
                LastDirSyncTime            = [string]$_.LastDirSyncTime
                RefreshTokensValidFromDateTime = [string]$_.RefreshTokensValidFromDateTime
                UsageLocation              = [string]$_.UsageLocation
                CompanyName                = [string]$_.CompanyName
                Country                    = [string]$_.Country
                State                      = [string]$_.State
                City                       = [string]$_.City
                StreetAddress              = [string]$_.StreetAddress
                PostalCode                 = [string]$_.PostalCode
                PhysicalDeliveryOfficeName = [string]$_.PhysicalDeliveryOfficeName
                FacsimileTelephoneNumber   = [string]$_.FacsimileTelephoneNumber
                IsCompromised              = [string]$_.IsCompromised
                ImmutableId                = [string]$_.ImmutableId
                CreationType               = [string]$_.CreationType
                PasswordPolicies           = [string]$_.PasswordPolicies
                PasswordProfile            = [string]$_.PasswordProfile
                ShowInAddressList          = [string]$_.ShowInAddressList
                SipProxyAddress            = [string]$_.SipProxyAddress
                DeletionTimestamp          = [string]$_.DeletionTimestamp
                ObjectId                   = [string]$_.ObjectId
        }       
        $entityReconOutput += $entityReconLine
    }
    $entityReconOutput | Sort-Object UserPrincipalName | Export-Csv -path $usersInfoPath -NoTypeInformation

    $tenantReconOutput = @()
    $tenantDict.Values | foreach {
        $tenantReconLine = [PSCustomObject][ordered] @{
                InitialDomainName      = [string]$_.InitialDomainName
                DisplayName            = [string]$_.DisplayName
                ObjectType             = [string]$_.ObjectType
                DirSyncEnabled         = [string]$_.DirSyncEnabled
                CompanyLastDirSyncTime = [string]$_.CompanyLastDirSyncTime
                Country                = [string]$_.Country
                CountryLetterCode      = [string]$_.CountryLetterCode
                PreferredLanguage      = [string]$_.PreferredLanguage
                State                  = [string]$_.State
                City                   = [string]$_.City
                PostalCode             = [string]$_.PostalCode
                Street                 = [string]$_.Street
                TelephoneNumber        = [string]$_.TelephoneNumber
                MarketingNotificationEmails = [string]$_.MarketingNotificationEmails
                TechnicalNotificationMails  = [string]$_.TechnicalNotificationMails
                SecurityComplianceNotificationMails   = [string]$_.SecurityComplianceNotificationMails
                SecurityComplianceNotificationPhones  = [string]$_.SecurityComplianceNotificationPhones
                AssignedPlans          = [string]$_.AssignedPlans
                ProvisionedPlans       = [string]$_.ProvisionedPlans
                ProvisioningErrors     = [string]$_.ProvisioningErrors
                DeletionTimestamp      = [string]$_.DeletionTimestamp
                ObjectId               = [string]$_.ObjectId
        }       
        $tenantReconOutput += $tenantReconLine
    }
    $tenantReconOutput | Sort-Object InitialDomainName | Export-Csv -path $directoryInfoPath -NoTypeInformation


    # to add recon files in the case of CloudShell usage + opem folder
    # to write the  results link in the end
    # maybe to open the folder/link in the end (the link will be a good thing in the case of CloudShell)

    #$entityDict.Values | Sort-Object UserPrincipalName | Export-Csv -path $usersInfoPath -NoTypeInformation
    #$tenantDict.values | Sort-Object InitialDomainName | Export-Csv -path $directoryInfoPath -NoTypeInformation
}


function Write-AzureStealthResults {
    [CmdletBinding()]
    param(
    [switch]
    $CloudShellMode
    )
    
    #$resultCSVpath = "C:\WORK\Azure\AzureStealth\Tests\results.csv"
    #$resultHTMLpath = "C:\WORK\Azure\AzureStealth\Tests\results.html"
    #[string]$resultsTime = Get-Date -Format "yyyMMdd-HHmm"
    #[string]$resultsTime = Get-Date -Format "yyyMMdd"
    if (-not $cloudShellMode) {
        #[string]$resultsTime = Get-Date -Format "yyyMMdd-HHmm"
        $resultsFolder = $PSScriptRoot + "\Results-" + $resultsTime
		$resultsFolderExists = Test-Path -Path $resultsFolder
		if (-not $resultsFolderExists) {
			New-Item -ItemType directory -Path $resultsFolder > $null
		}
        $mainResultsPath = $resultsFolder + "\AzureStealth-Results.csv"
        $privilegedAzEntitiesDict.Values | Sort-Object -Descending EntityType | Sort-Object EntityDisplayName, PrivilegeType, RoleId | Export-Csv -path $mainResultsPath -NoTypeInformation
        Write-AzureReconInfo -ResultsFolder $resultsFolder
        Write-Host "`n  [+] Check the results folder - in the following location:`n      `"$resultsFolder`""
    }
    else {
		#Write-Host "finishing"
		$cloudDriveInfo = Get-CloudDrive
		#write-host $cloudDriveInfo
		$localCloudShellPath = $cloudDriveInfo.MountPoint
		#write-host $localCloudShellPath
        $resultsFolder = $localCloudShellPath + "/AzureStealth/Results-" + $resultsTime
        $resultsFolderExists = Test-Path -Path $resultsFolder
        if (-not $resultsFolderExists) {
			New-Item -ItemType directory -Path $resultsFolder > $null
		}
        $resultCSVpath = $resultsFolder + "/AzureStealthScan-Results.csv"
		#write-host $resultCSVpath
		#cd /usr/asaf/clouddrive/
		#$string = "HelloWorld2!"
		#$string | Out-File -FilePath $resultCSVpath
		$privilegedAzEntitiesDict.Values | sort-object -Descending EntityType | sort-object EntityDisplayName, PrivilegeType, RoleId | Export-Csv -path $resultCSVpath -NoTypeInformation
		Write-AzureReconInfo -ResultsFolder $resultsFolder -CloudShellMode
        $resultsZipPath = $localCloudShellPath + "/AzureStealth/Results-" + $resultsTime +".zip"
        Compress-Archive -Path $resultsFolder -CompressionLevel Optimal -DestinationPath $resultsZipPath -Update
        Export-File -Path $resultsZipPath

        #Write-Host "`n  [+] Completed the scan - check the results folder - in the following location:"
        #Write-Host $resultsFolder
	    $storageName = $cloudDriveInfo.Name
	    $fileShareName = $cloudDriveInfo.FileShareName
        Write-Host "`n  [+] Completed the scan - the results files are available for download from:`n      $resultsZipPath"
        Write-Host "`n  [+] You can also use the Azure Portal to view the results files:"
        Write-Host "      Go to => `"The Storage Accounts' main view`" => `"$storageName`" => `"Files view`""
	    Write-Host "      Choose the File Share: `"$fileShareName`""
        Write-Host "      In this File Share:"
        Write-Host "      Open the folders => `"AzureStealth`" and `"Results-"$resultsTime"`"`n"

	    #/home/asaf/clouddrive/AzureStealth/Results-20190321-1254/AzureStealthScan-Results.csv
	    #Write-Host $resultCSVpath
	    #Write-Host "`nThe details of this current CloudShell storage are:" -NoNewline
	    #$cloudDriveInfoString = $cloudDriveInfo | Out-String
	    #Write-Host $cloudDriveInfoString
        #Write-Host "In addition, you can easily go to the results folder using the following HTTPS link:"
    }
    #$privilegedAzEntitiesDict.Values | ConvertTo-Html -Head $Header | Out-File -FilePath $resultHTMLpath
    #Invoke-Item -Path $resultCSVpath
}


# | ConvertTo-HTML


function Start-AzureConnnection {
    [CmdletBinding()]
    param(
    [switch]
    $UseCurrentCred
	#[switch]
    #$CloudShellMode
    )

    
}


function Scan-AzureStealth {
    [CmdletBinding()]
    param(
    [switch]
    $UseCurrentCred
	#[switch]
    #$CloudShellMode
    )

    #if ($CloudShellMode) {
    #	$CloudShell = $true
    #}

    $CloudShellMode = $false
    try {
        $cloudShellRun = Get-CloudDrive
        $CloudShellMode = $true
    }
    catch {
        $CloudShellMode = $false
    }
    $AzModule = Check-AzureModule
    if ($AzModule -eq $false) {
        Return
    }
    if (-not $UseCurrentCred) {
        $AzConnection = Connect-AzureEnvironment
        if ($AzConnection -eq $false) {
            Return
        }
        $currentAzContext = Get-AzContext
    }
    else {
        $currentAzContext = Get-AzContext
    }
    if ($CloudShellMode) {
        try {
            Connect-AzureADservice
        }
        catch {
            Write-Host "Couldn't connect using the `"Connect-AzureADservice`" API call,`nThe tool will connect with `"Connect-AzureActiveDirectory `" call"
            $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
        }
    }
    else {
        $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
    }
    if ($AzConnection -eq $false) {
        $scanTheDirecotry = $false
        Write-host "Couldn't connect to the target Directory, the scan will continue but there might be errors" -ForegroundColor Yellow
    }

    $privilegedAzEntitiesOutput = @()
    $privilegedAzEntitiesDict = @{}
    $entityDict = @{}
    $tenantDict = @{}
    $subscriptionDict = @{}
    $roleDict = @{}
    [string]$resultsTime = Get-Date -Format "yyyMMdd"

    # Output to a result file all the information that was collected on all the AAD users
    $fullUserReconList = $true

    try {
        #$usedUser = Get-AzADUser -UserPrincipalName $currentAzContext.Account
        Write-host "`n  [+] Running the scan with user: "$currentAzContext.Account
        $tenantList = Get-AzTenant
        #$tenantList | Add-TenantToDict -tenantObject $_
        Write-Host "`nAvailable Tanent ID/s:`n"
        Write-Host "  "($tenantList.Id | Format-Table | Out-String)
        $subscriptionList = Get-AzSubscription | select Name, Id, TenantId
        if ($subscriptionList) {
            Write-Host "Available Subscription\s:"
            Write-Host ($subscriptionList | Format-Table | Out-String) -NoNewline
        }
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

    # Scan all the available tanent\s
    $tenantList| foreach {
        Write-Host "  [+] Scanning tenant ID: "$_.Id
        Set-AzContext -Tenant $_.id > $null
        $usedUser = Get-AzADUser -UserPrincipalName $currentAzContext.Account
        Run-TenantScan -TenantId  $_.id -UsedUserPrincipalName $usedUser.UserPrincipalName -UsedUserId $usedUser.Id
    }    

    # Scan all the available subscription\s
    $subscriptionList | foreach {
        Write-Host "`n  [+] Scanning Subscription Name: "$_.Name", ID: "$_.Id
        Set-AzContext -SubscriptionId $_.id > $null
        Run-SubscriptionScan -subscriptionId $_.id
    }
    
    Write-Host "`n  [+] Working on the results files"

    if ($CloudShellMode) {
    	Write-AzureStealthResults -CloudShellMode
    }
    else {
    	Write-AzureStealthResults
    }

    # Export\Print out the current user role and permission in the scanned tenant
    # Export Tanent info + Users Info
    
    if ($AzContextAutosave -eq "None") {
        Disable-AzContextAutosave
    }

    Write-Host "`n"
      
}

function Escalate-ToAzureADAdmin {
    [CmdletBinding()]
    param(
    [switch]
    $UseCurrentCred,
    [string]
    $CurrentRole
    #[string]
    #$targetUser
    )

    $CloudShellMode = $false
    try {
        $cloudShellRun = Get-CloudDrive
        $CloudShellMode = $true
    }
    catch {
        $CloudShellMode = $false
    }
    $AzModule = Check-AzureModule
    if ($AzModule -eq $false) {
        Return
    }
    if (-not $UseCurrentCred) {
        $AzConnection = Connect-AzureEnvironment
        if ($AzConnection -eq $false) {
            Return
        }
        $currentAzContext = Get-AzContext
    }
    else {
        $currentAzContext = Get-AzContext
    }
    if ($CloudShellMode) {
        try {
            Connect-AzureADservice
        }
        catch {
            Write-Host "Couldn't connect using the `"Connect-AzureADservice`" API call,`nThe tool will connect with `"Connect-AzureActiveDirectory `" call"
            $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
        }
    }
    else {
        $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
    }
    if ($AzConnection -eq $false) {
        $scanTheDirecotry = $false
        Write-host "Couldn't connect to the target Directory, the scan will continue but there might be errors" -ForegroundColor Yellow
    }
    
    $privilegedDirectoryRoles = @("Company Administrator","Application Administrator", "Authentication Administrator",`
        "Cloud Application Administrator", "Helpdesk Administrator", "Privileged Role Administrator", "User Account Administrator")
    <#
    1.  The goal = Global Administrator / Company Administrator - Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities.
    2.	Application Administrator - Users in this role can create and manage all aspects of enterprise applications.
    3.	*Authentication Administrator - Users with this role can set or reset non-password credentials. 
    4.	Cloud Application Administrator - Users in this role have the same permissions as the Application Administrator role, excluding the ability to manage application proxy.
    5.	*Password Administrator / Helpdesk Administrator - Users with this role can change passwords, invalidate refresh tokens, manage service requests.
    6.	Privileged Role Administrator - Users with this role can manage role assignments in Azure Active Directory.
    7.	*User Account Administrator - Can manage all aspects of users and groups, including resetting passwords for limited admins.

    #>
    <#$privilegedRolesInfo = @()
    $privilegedDirectoryRoles | foreach {
        $direcotryRoleName = $_
        $privilegeRole = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq $direcotryRoleName}
        $privilegedRolesInfo += $privilegeRole
    }#>

    $tenantList = Get-AzTenant
    $tenantList| foreach {
        Set-AzContext -Tenant $_.id > $null
    }
    $context = Get-AzContext
    $usedUser = $context.Account
    $usedUserInfo = Get-AzADUser -UserPrincipalName $currentAzContext.Account
    $usedUserADRoles = @()
    $privilegedUsedUserADRoles = @()

    # discover the current role
    Write-Host "`n  [+] You currently use the user: $usedUser`n"
    Get-AzureADDirectoryRole | foreach {
        $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId 
        $usedUserRole = $roleMembers | Where-Object {$_.UserPrincipalName -eq $usedUser}
        if ($usedUserRole) {
            #Write-Host "You currently use the user: $usedUser it has the following Azure AD roles:"
            $usedUserADRoles += $_
            if ($privilegedDirectoryRoles -contains $_.DisplayName) {
                $privilegedUsedUserADRoles += $_.DisplayName
            }
        }
    }
    if ($usedUserADRoles) {
        Write-Host "$usedUser has the following Azure AD roles:"
        $usedUserADRoles | foreach {Write-Host "   -"$_.DisplayName}
    }
    else {
        Write-Host "$usedUser doesn't have any of the Azure AD built-in roles"
    }
    if ($privilegedUsedUserADRoles -contains "Company Administrator") {
        Write-Host "`n  [+] Great, your current user: $usedUser - is already a `"Global Administrator`" and has full permissions"
        $escalationSuccess = $true
    }
    else {
        if ($privilegedUsedUserADRoles) {
            Write-Host "`n  [+] Great, you can escalate your privileges and get more permissions"
            $ofs = ","
            Write-Host "`nThe escalation could be done using the following user's role/s:`n$privilegedUsedUserADRoles"
        } 
    }

    # "Company Administrator"/"Global Administrator" AD Role's Object ID is "f6f5293d-5d50-4518-82a9-ff2833458e46"
    if (-not $escalationSuccess) {
        if ($privilegedUsedUserADRoles -contains "Privileged Role Administrator") {
            #try {
                Add-AzureADDirectoryRoleMember -ObjectId "f6f5293d-5d50-4518-82a9-ff2833458e46" -RefObjectId $usedUserInfo.Id
                Write-Host "`n  [+] Perfect! your user $usedUser is now a Global Administrator"
                $escalationSuccess = $true
            #}
            #catch {
            #    Write-Host "`nEncountered with an error, couldn't assign you the Global Administrator role, try another method"
            #}
        }
    }

    # if Helpdesk Administrator, the user can reset the password of a target global admin user
    #
    # the escatation will be from Helpdesk  admin to a full subscription admin - through reseting the password of a subscription owner or the owner of the admin group
    # or the admin of privileged application
    
    if ($privilegedUsedUserADRoles -contains "Helpdesk Administrator") {
        #$newPassword = Read-Host -AsSecureString
        $targetUseriD = ""
        #Set-AzureADUserPassword -ObjectId $targetUserid -Password $password
    }
    #$roles |  Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId  

    #$role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Company Administrator'}
    #Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Get-AzureADUser

    <#
    if (($CurrentRole -eq "Password Administrator") -or ($CurrentRole -eq "Helpdesk Administrator")) {
        $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq "Company Administrator"}
        if ($role) {
            Add-RoleToDict -RoleObject $role
            $globalAdminDB = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Get-AzureADUser
            if ($globalAdminDB) {
                $globalAdminCount = $globalAdminDB.count
                Write-Host "Discovered $globalAdminCount Global Administrators:"
                $counter = 0
                $globalAdminDB | foreach {
                    $counter++
                    $userPrincipalName = $_.UserPrincipalName | Out-String
                    Write-Host $counter") "$userPrincipalName -NoNewline
                    #Add-EntityToDict -AzEntityObject $_
                }
                $targetUserNum = Read-Host "What is the number of your target Global Administrator"
                $targetUserPrinciplName = $globalAdminDB[$counter-1].userPrincipalName | Out-String
                Write-Host "You chose to reset the password of: $targetUserPrinciplName"
                $answer = Read-Host "Do you want to proceed? (press y/Y for yes)"
                if ($answer.ToLower() -match "y") {
                    try {
                        $targetUserId = $globalAdminDB[$counter-1].ObjectId
                        Set-AzureADUserPassword -ObjectId  $targetUserId -Password "NewPassword123"
                        Write-Host "Great, the reset password request was completed.`nYou can now authenticate as $targetUserPrinciplName with the new password: `"NewPassword123`""

                    }
                    catch {
                        Write-Host "Sorry, there was a problem and the reset password request wasn't processed"
                    }
                    
                }
            }
        }
    }#>


    #if ($CurrentRole -eq "User Account Administrator") {
        
    #}
       
}

function Scan-AzureWhoAmI {
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

#Scan-AzureStealth -UseCurrentCred -CloudShellMode
