#Install-Module -Name SqlServer -AllowClobber -Force -> Install Module on Windows machine

# Load SQL Server cmdlets
Import-Module SqlServer
 
# Set variables
$ServerInstance = "ROGERPC\SQLEXPRESS22"
$DatabaseName = "roger_sierzno"
$BackupDir = "C:\sql_backup"
$ArchiveDir = "C:\sql_backup\Archive"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFile = "${BackupDir}\${DatabaseName}_${Timestamp}.bak"
$ArchiveFile = "${ArchiveDir}\${DatabaseName}_${Timestamp}.7z"
 
# Create backup and archive directories if they don't exist
if (!(Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir
}
if (!(Test-Path $ArchiveDir)) {
    New-Item -ItemType Directory -Path $ArchiveDir
}
 
# Backup the SQL Server database
Backup-SqlDatabase -ServerInstance $ServerInstance -Database $DatabaseName -BackupFile $BackupFile
Write-Host "Database backup completed successfully."
 
# Archive the backup using 7-Zip
& "C:\Program Files\7-Zip\7z.exe" a -t7z $ArchiveFile $BackupFile
Write-Host "Backup archived successfully."
 
# Remove the original backup file
Remove-Item $BackupFile
Write-Host "Original backup file removed."
