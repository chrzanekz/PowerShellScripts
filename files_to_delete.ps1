# Ścieżka do folderu, w którym chcesz usunąć pliki starsze niż 30 dni
$folderPath = "C:\Users\Roger\Backup_easyripok\"

# Liczba dni, po których pliki zostaną usunięte
$daysToKeep = 14

# Pobierz bieżącą datę
$currentDate = Get-Date

# Oblicz datę, która jest 30 dni wcześniej od bieżącej daty
$thresholdDate = $currentDate.AddDays(-$daysToKeep)

# Pobierz listę plików w folderze, które są starsze niż 30 dni
$filesToDelete = Get-ChildItem -Path $folderPath | Where-Object { $_.LastWriteTime -lt $thresholdDate }

# Usuń znalezione pliki
foreach ($file in $filesToDelete) {
    Remove-Item -Path $file.FullName -Force
    Write-Host "Usunięto plik: $($file.FullName)"
}

Write-Host "Zakończono usuwanie plików starszych niż $daysToKeep dni."
