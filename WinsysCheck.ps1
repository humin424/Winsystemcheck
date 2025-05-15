#总是在反反复复中追问，才明白平平淡淡是最真

$date=Get-Date -Format "yyyy-MM-dd HH:mm:ss"

#1.获取mysql connector 文件

        $dllpath='C:\Windows\System32\MySql.Data.dll'

        try{
               if  (-not (Test-Path $dllpath)){

                Invoke-WebRequest http://10.66.254.155/download/MySql.Data.dll -OutFile C:\ProgramData\MySql.Data.dll

                Copy-Item -Path "C:\ProgramData\MySql.Data.dll" -Destination "C:\Windows\System32\MySql.Data.dll"

               }
 

        }
        catch{

                write-output "$date : MySQL.data.dll file not exists or http download false!" | out-file -filepath C:\ProgramData\xinghan.txt

        }

#开启数据库连接
    [void][system.Reflection.Assembly]::LoadWithPartialName("MySql.Data")

    [void][system.Reflection.Assembly]::LoadFrom($dllpath)

    $Server="10.66.254.155"

    $Database="IT"

    $user="it"

    $Password= "a*999999" 

    $charset="utf8"

    $connectionString = "server=$Server;uid=$user;pwd=$Password;database=$Database;charset=$charset;sslmode=none"

    $connection = New-Object MySql.Data.MySqlClient.MySqlConnection($connectionString)

    try
    {
            
                $connection.Open()

                $insertcommand = New-Object MySql.Data.MySqlClient.MySqlCommand

                $insertcommand.Connection=$connection

                
            }
            catch
            {
            
                write-output "MySQL无法连接" | out-file -filepath C:\ProgramData\xinghan.txt

    }

#导出system 安全数据库文件
        secedit /export /cfg c:\systemcheck.cfg

#定义文件路径
        $file = Get-ChildItem -Path c:\systemcheck.cfg



#获取基本信息

        $hostname=hostname

        $domainname=Get-WmiObject -Class win32_computersystem | Select-Object -ExpandProperty Domain

        $ip=Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.AddressState -eq "Preferred" -and ($_.PrefixLength -eq "24" -or $_.PrefixLength -eq "23")} | Select-Object IPAddress -ExpandProperty IPAddress

        $operasystem=Get-WmiObject -Class win32_operatingsystem | Select-Object -ExpandProperty caption



#账户密码策略要求
        $minimumpasswordage=(((Get-Content $file  | where {$_ -match "minimumpasswordage"}) | Select-Object -first 1) -split "= ")[-1]
        $maximumpasswordage=(((Get-Content $file  | where {$_ -match "maximumpasswordage"}) | Select-Object -first 1) -split "= ")[-1]
        $minimumpasswordlength=(((Get-Content $file  | where {$_ -match "minimumpasswordlength"})  | Select-Object -first 1) -split "= ")[-1]
        $PasswordComplexity=(((Get-Content $file  | where {$_ -match "PasswordComplexity"}) | Select-Object -first 1) -split "= ")[-1]
        $PasswordHistorySize=(((Get-Content $file  | where {$_ -match "PasswordHistorySize"}) | Select-Object -first 1) -split "= ")[-1]
        $LockoutBadCount=(((Get-Content $file  | where {$_ -match "LockoutBadCount"}) | Select-Object -first 1) -split "= ")[-1]
        $ResetLockoutCount=(((Get-Content $file  | where {$_ -match "ResetLockoutCount"}) | Select-Object -first 1) -split "= ")[-1]
        $LockoutDuration=(((Get-Content $file  | where {$_ -match "LockoutDuration"}) | Select-Object -first 1) -split "= ")[-1]
        $RequireLogonToChangePassword =(((Get-Content $file  | where {$_ -match "RequireLogonToChangePassword"}) | Select-Object -first 1) -split "= ")[-1]
        $NewAdministratorName =((((Get-Content $file  | where {$_ -match "NewAdministratorName"}) | Select-Object -first 1) -split "= ")[-1]).replace('"','')
        $NewGuestName  =((((Get-Content $file  | where {$_ -match "NewGuestName"}) | Select-Object -first 1) -split "= ")[-1]).replace('"','')
        $ClearTextPassword =(((Get-Content $file  | where {$_ -match "ClearTextPassword"}) | Select-Object -first 1) -split "= ")[-1]
        $LSAAnonymousNameLookup =(((Get-Content $file  | where {$_ -match "LSAAnonymousNameLookup"}) | Select-Object -first 1) -split "= ")[-1]
        $EnableAdminAccount =(((Get-Content $file  | where {$_ -match "EnableAdminAccount"}) | Select-Object -first 1) -split "= ")[-1]
        $EnableGuestAccount =(((Get-Content $file  | where {$_ -match "EnableGuestAccount"}) | Select-Object -first 1) -split "= ")[-1]


#审计日志开关
        $AuditSystemEvents  =(((Get-Content $file  | where {$_ -match "AuditSystemEvents"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditLogonEvents  =(((Get-Content $file  | where {$_ -match "AuditLogonEvents"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditObjectAccess  =(((Get-Content $file  | where {$_ -match "AuditObjectAccess"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditPrivilegeUse  =(((Get-Content $file  | where {$_ -match "AuditPrivilegeUse"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditPolicyChange  =(((Get-Content $file  | where {$_ -match "AuditPolicyChange"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditAccountManage  =(((Get-Content $file  | where {$_ -match "AuditAccountManage"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditProcessTracking  =(((Get-Content $file  | where {$_ -match "AuditProcessTracking"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditDSAccess  =(((Get-Content $file  | where {$_ -match "AuditDSAccess"}) | Select-Object -first 1) -split "= ")[-1]
        $AuditAccountLogon  =(((Get-Content $file  | where {$_ -match "AuditAccountLogon"}) | Select-Object -first 1) -split "= ")[-1]



#移动硬盘禁止

        $HKLM_Storage="hklm:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

        if(-not (Test-Path $HKLM_Storage))
        {
        $StorageDevices="Null"
        }
        else{

        $StorageDevices=(Get-ItemProperty -Path $HKLM_Storage).Deny_All

        }


#锁屏注册表读取

        $sid=Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnUserSID"

        $profilepath=get-wmiobject Win32_UserProfile | Where-Object {$_.SID -match $sid} |Select-Object -ExpandProperty LocalPath


#查询当前用户的注册表是否存在，来判断用户是否已经登录
        if(-not(Get-PSDrive HKU -ErrorAction SilentlyContinue))
        {
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
        }

        $sidpath="HKU:\$sid"

        if(Test-Path $sidpath)
        {
            $regpath="HKU:\$sid\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"

        }

        else{

#挂载单个用户注册表文件

        REG LOAD HKU\profile ($profilepath+"\ntuser.dat")

#定位注册表路径

        Set-Location Registry::\HKU\profile

        $regpath=  "\HKU\profile\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"

        } 


        if(Test-Path $regpath)
        {
        $ScreenSaveActive=(Get-ItemProperty -Path $regpath).ScreenSaveActive

        $ScreenSaverIsSecure=(Get-ItemProperty -Path $regpath).ScreenSaverIsSecure

        $ScreenSaveTimeOut=(Get-ItemProperty -Path $regpath).ScreenSaveTimeOut

        }

        if(Test-Path HKU:\profile){

        REG UNLOAD HKU\profile

        }

#检查系统是否激活

        $ActivationStatus = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus       

            $LicenseResult = switch($ActivationStatus.LicenseStatus){
            0	{"Unlicensed"}
            1	{"Licensed"}
            2	{"OOBGrace"}
            3	{"OOTGrace"}
            4	{"NonGenuineGrace"}
            5	{"Not Activated"}
            6	{"ExtendedGrace"}
            default {"Unknown"}
            }

#系统加固信息开始写入数据库

        $InsertSQLwinsyscheck = 'INSERT INTO systemcheck_windows(
                        date,
                        hostname,
                        domainname,
                        ip,
                        operasystem,
                        LicenseResult,
                        minimumpasswordage,
                        maximumpasswordage,
                        minimumpasswordlength,
                        passwordcomplexity,
                        passwordhistorysize,
                        lockoutbadcount,
                        resetlockoutcount,
                        lockoutduration,
                        requirelogontochangepassword,
                        newadministratorname,
                        newguestname,
                        cleartextpassword,
                        lsaanonymousnamelookup,
                        enableadminaccount,
                        enableguestaccount,
                        AuditSystemEvents,
                        AuditLogonEvents,
                        AuditObjectAccess,
                        AuditPrivilegeUse,
                        AuditPolicyChange,
                        AuditAccountManage,
                        AuditProcessTracking,
                        AuditDSAccess,
                        AuditAccountLogon,
                        StorageDevices,
                        ScreenSaveActive,
                        ScreenSaverIsSecure,
                        ScreenSaveTimeOut
                        )
                 SELECT
                        "'+$date+'",
                         "'+$hostname+'",
                         "'+$domainname+'",
                         "'+$ip+'",
                         "'+$operasystem+'",
                         "'+$LicenseResult+'",
                         "'+$minimumpasswordage+'",
                         "'+$maximumpasswordage+'",
                         "'+$minimumpasswordlength+'",
                         "'+$passwordcomplexity+'",
                         "'+$passwordhistorysize+'",
                         "'+$LockoutBadCount+'",
                         "'+$ResetLockoutCount+'",
                         "'+$LockoutDuration+'",
                         "'+$RequireLogonToChangePassword+'",
                         "'+$NewAdministratorName+'",
                         "'+$NewGuestName+'",
                         "'+$ClearTextPassword+'",
                         "'+$LSAAnonymousNameLookup+'",
                         "'+$EnableAdminAccount+'",
                         "'+$EnableGuestAccount+'",
                         "'+$AuditSystemEvents+'",
                         "'+$AuditLogonEvents+'",
                         "'+$AuditObjectAccess+'",
                         "'+$AuditPrivilegeUse+'",
                         "'+$AuditPolicyChange+'",
                         "'+$AuditAccountManage+'",
                         "'+$AuditProcessTracking+'",
                         "'+$AuditDSAccess+'",
                         "'+$AuditAccountLogon+'",
                         "'+$StorageDevices+'",
                         "'+$ScreenSaveActive+'",
                         "'+$ScreenSaverIsSecure+'",
                         "'+$ScreenSaveTimeOut+'"
                WHERE NOT EXISTS (SELECT * FROM `systemcheck_windows` WHERE hostname= "'+$hostname+'" AND DATE(date) = CURDATE());
                update `systemcheck_windows` set 
                        date="'+$date+'",
                        hostname= "'+$hostname+'",
                        domainname="'+$domainname+'",
                        ip="'+$ip+'",
                        operasystem="'+$operasystem+'",
                        LicenseResult="'+$LicenseResult+'",
                        minimumpasswordage= "'+$minimumpasswordage+'",
                        maximumpasswordage="'+$maximumpasswordage+'",
                        minimumpasswordlength="'+$minimumpasswordlength+'",
                        passwordcomplexity= "'+$passwordcomplexity+'",
                        passwordhistorysize="'+$passwordhistorysize+'",
                        lockoutbadcount= "'+$LockoutBadCount+'",
                        resetlockoutcount="'+$ResetLockoutCount+'",
                        lockoutduration="'+$LockoutDuration+'",
                        requirelogontochangepassword="'+$RequireLogonToChangePassword+'",
                        newadministratorname= "'+$NewAdministratorName+'",
                        newguestname= "'+$NewGuestName+'",
                        cleartextpassword="'+$ClearTextPassword+'",
                        lsaanonymousnamelookup="'+$LSAAnonymousNameLookup+'",
                        enableadminaccount="'+$EnableAdminAccount+'",
                        enableguestaccount="'+$EnableGuestAccount+'",
                        AuditSystemEvents="'+$AuditSystemEvents+'",
                        AuditLogonEvents="'+$AuditObjectAccess+'",
                        AuditObjectAccess="'+$AuditSystemEvents+'",
                        AuditPrivilegeUse="'+$AuditPrivilegeUse+'",
                        AuditPolicyChange="'+$AuditPolicyChange+'",
                        AuditAccountManage="'+$AuditAccountManage+'",
                        AuditProcessTracking= "'+$AuditProcessTracking+'",
                        AuditDSAccess="'+$AuditDSAccess+'",
                        AuditAccountLogon= "'+$AuditAccountLogon+'",
                        StorageDevices="'+$StorageDevices+'",
                        ScreenSaveActive= "'+$ScreenSaveActive+'",
                        ScreenSaverIsSecure="'+$ScreenSaverIsSecure+'",
                        ScreenSaveTimeOut="'+$ScreenSaveTimeOut+'"
                WHERE hostname="'+$hostname+'" AND DATE(date) = CURDATE()'

        $insertcommand.CommandText=$InsertSQLwinsyscheck

        $insertcommand.ExecuteNonQuery()


#CPU、内存信息及使用率

$mem=Get-WmiObject -Class win32_operatingsystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory

$cpu=Get-WmiObject Win32_Processor | Select-Object Name,ProcessorId,MaxClockSpeed,LoadPercentage

   try
            {
                $InsertSQLcpuMmUsage = 'INSERT into cpumm_usage(PSComputerName,TotalVisibleMemorySize,FreePhysicalMemory,CpuName,ProcessorId,MaxClockSpeed,LoadPercentage,Date)
                                        select 
                                                "'+$hostname+'",
                                                "'+$mem.TotalVisibleMemorySize+'",
                                                "'+$mem.FreePhysicalMemory+'",
                                                "'+$cpu.Name+'",
                                                "'+$cpu.ProcessorId+'",
                                                "'+$cpu.MaxClockSpeed+'",
                                                "'+$cpu.LoadPercentage+'",
                                                "'+$date+'"
                                        WHERE NOT EXISTS (SELECT * FROM `cpumm_usage` WHERE PSComputerName="'+$hostname+'" AND DATE(date) = CURDATE());
                                        UPDATE cpumm_usage SET
                                                TotalVisibleMemorySize="'+$mem.TotalVisibleMemorySize+'",
                                                FreePhysicalMemory="'+$mem.FreePhysicalMemory+'",
                                                CpuName="'+$cpu.Name+'",
                                                ProcessorId="'+$cpu.ProcessorId+'",
                                                MaxClockSpeed="'+$cpu.MaxClockSpeed+'",
                                                LoadPercentage="'+$cpu.LoadPercentage+'",
                                                Date="'+$date+'" 
                                                WHERE PSComputerName="'+$hostname+'" AND DATE(date) = CURDATE()'

                $insertcommand.CommandText=$InsertSQLcpuMmUsage
                $insertcommand.ExecuteNonQuery()


           }
            catch
                {

                }


#硬盘分区卷信息、使用率、Bitlocker


$disk=Get-WMIObject Win32_LogicalDisk | ?{$_.DriveType -eq '3'} | Select-Object PSComputerName,Caption,VolumeName,Description,FreeSpace,Size

 try
                            {

                                foreach($vol in $disk){

                                          try{

                                                $bitlocker=Get-BitLockerVolume | Where-Object {$_.MountPoint -eq  $vol.Caption} | Select-Object ProtectionStatus -ExpandProperty ProtectionStatus

                                          
                                          }
                                          catch{
                                          
                                                $bitlocker="当前系统不支持"
                                          }

                                          
                                        $insertSQLdiskUsages = 'INSERT into disk_usage(HostName,Caption,VolumeName,Description,FreeSpace,Size,Bitlocker,Date)
                                                                SELECT "'+$hostname+'",
                                                                        "'+$vol.Caption+'",
                                                                        "'+$vol.VolumeName+'",
                                                                        "'+$vol.Description+'",
                                                                        "'+$vol.FreeSpace+'",
                                                                        "'+$vol.Size+'",
                                                                        "'+$bitlocker+'",
                                                                        "'+$date+'"
                                                                WHERE NOT EXISTS (SELECT * FROM `disk_usage` WHERE HostName="'+$hostname+'" AND Caption="'+$vol.Caption+'"  AND DATE(date) = CURDATE());
                                                                UPDATE `disk_usage` SET
                                                                        Caption="'+$vol.Caption+'",
                                                                        VolumeName= "'+$vol.VolumeName+'",
                                                                        Description= "'+$vol.Description+'",
                                                                        FreeSpace="'+$vol.FreeSpace+'",
                                                                        Size="'+$vol.Size+'",
                                                                        Bitlocker="'+$bitlocker+'",
                                                                        Date= "'+$date+'"
                                                                WHERE HostName="'+$hostname+'" AND Caption="'+$vol.Caption+'" AND DATE(date) = CURDATE()'
                  
                                        $insertcommand.CommandText=$insertSQLdiskUsages
                                        $insertcommand.ExecuteNonQuery()

                                }

                            }
                            catch
                                {



                                }


#应用软件信息

$installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{ $_.DisplayName -ne $null } |  Select-Object DisplayName, DisplayVersion,Publisher,InstallDate,InstallLocation

$installed += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{ $_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion,Publisher,InstallDate


            try
            {

                foreach($soft in $installed){
                
                 $insertSQLsoftinstalled='INSERT into soft_installed(HostName,DisplayName,DisplayVersion,Publisher,InstallDate,Date)
                                              SELECT
                                                "'+$hostname+'",
                                                "'+$soft.DisplayName+'",
                                                "'+$soft.DisplayVersion+'",
                                                "'+$soft.Publisher+'",
                                                "'+$soft.InstallDate+'",
                                                "'+$date+'"
                                              where not exists (select * from soft_installed where Hostname="'+$hostname+'" and DisplayName="'+$soft.DisplayName+'" and Date(date)=curdate());
                                              update soft_installed set
                                                DisplayName="'+$soft.DisplayName+'",
                                                DisplayVersion = "'+$soft.DisplayVersion+'",
                                                Publisher= "'+$soft.Publisher+'",
                                                InstallDate="'+$soft.InstallDate+'",
                                                Date="'+$date+'"
                                              where Hostname="'+$hostname+'" and DisplayName="'+$soft.DisplayName+'" and Date(date)=curdate()'

                 $insertcommand.CommandText= $insertSQLsoftinstalled      
                 $insertcommand.ExecuteNonQuery()
                
                }

            }
            catch
            {
                
               
            }

#开始更新设备清单总表

        $zone = switch ($ip) {
                {($_ -like "*10.68.254.*") -or ($_ -like "*10.68.1.*")} {"生产区域"}
                {$_ -like "*10.66.254.*"}{"IT架构区域"}
                {$_ -like "*10.61.254.*"}{"数据中转区域"}
                {($_ -like "*192.168.100.*") -or ($_ -like "*192.168.101.*")}{"CCTV&Access区域"}
                {($_ -like "*10.12.254.*") -or ($_ -like "*10.12.1.*")}{"SM区域"}
                {($_ -like "*10.11.254.*") -or ($_ -like "*10.11.253.*") -or ($_ -like "*10.11.1.*")}{"研发区域"}
                {$_ -like "*10.60.*"}{"办公区域"}
                
                }
    
                $zone = $zone | Sort-Object -Unique

        $devicetype=switch($operasystem){

                {($_ -like "*Server*") -or ($_ -like "*Linux*")} {"服务器"}
                {$_ -like "*VMware*"} {"服务器"}
                Default {"客户端"}
        }
        
        $insertSQLdevicelist='INSERT INTO devicelist (devicetype, zone, hostname,ip,operasystem,date)
                                VALUES ("'+$devicetype+'", "'+$zone+'","'+$hostname+'","'+$ip+'","'+$operasystem+'","'+$date+'")
                                ON DUPLICATE KEY UPDATE 
                                devicetype="'+$devicetype+'",
                                zone="'+$zone+'",
                                ip="'+$ip+'",
                                operasystem="'+$operasystem+'",
                                date="'+$date+'"'

        $insertcommand.CommandText= $insertSQLdevicelist    
        $insertcommand.ExecuteNonQuery()

$connection.Close()