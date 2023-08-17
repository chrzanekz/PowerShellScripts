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
$SqlUsername = "sa"
$SqlPassword = "type_password here"

# Create backup and archive directories if they don't exist
if (!(Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir
}
if (!(Test-Path $ArchiveDir)) {
    New-Item -ItemType Directory -Path $ArchiveDir
}

# Construct the SQL Server authentication connection string
$ConnectionString = "Server=$ServerInstance;Database=$DatabaseName;User Id=$SqlUsername;Password=$SqlPassword;"

# Backup the SQL Server database using SQL Server authentication
Backup-SqlDatabase -ServerInstance $ServerInstance -Database $DatabaseName -BackupFile $BackupFile -Credential (Get-Credential -UserName $SqlUsername -Password $SqlPassword)
Write-Host "Database backup completed successfully."

# Archive the backup using 7-Zip (assuming 7-Zip is installed at the specified path)
$SevenZipExePath = "C:\Program Files\7-Zip\7z.exe"
if (Test-Path $SevenZipExePath) {
    & $SevenZipExePath a -t7z $ArchiveFile $BackupFile
    Write-Host "Backup archived successfully."
} else {
    Write-Host "7-Zip not found at the specified path. Backup was not archived."
}

# Remove the original backup file
Remove-Item $BackupFile
Write-Host "Original backup file removed."
