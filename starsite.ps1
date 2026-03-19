
# Script complet pour lancer backend, frontend et vérifier la BDD
# À exécuter depuis la racine du projet

function Test-Postgres {
	$conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 5433
	return $conn.TcpTestSucceeded
}

Write-Host "--- Lancement du site complet ---"
Write-Host "Vérification de la base PostgreSQL sur 127.0.0.1:5433..."
if (-not (Test-Postgres)) {
	Write-Host "ERREUR : PostgreSQL n'est pas démarré sur le port 5433. Démarrez la BDD avant de lancer le site !" -ForegroundColor Red
	exit 1
}
else {
	Write-Host "PostgreSQL OK !" -ForegroundColor Green
}


# 1. Lancer le backend (API Express/Prisma)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location 'backend'; $env:HOST='127.0.0.1'; $env:PORT='3002'; npx ts-node --transpile-only index.ts" -WindowStyle Normal
Write-Host "Backend lancé sur http://127.0.0.1:3002" -ForegroundColor Cyan

# 2. Attendre 2 secondes pour laisser le backend démarrer
Start-Sleep -Seconds 2

# 3. Lancer le frontend (Vite/React) sur le port 5173
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location ..; npx vite --host 127.0.0.1 --port 5173" -WindowStyle Normal
Write-Host "Frontend lancé sur http://127.0.0.1:5173" -ForegroundColor Cyan

Write-Host "--- Tous les services sont lancés ! ---" -ForegroundColor Green
