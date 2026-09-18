Write-Host ("PSVersion: " + $PSVersionTable.PSVersion + " (" + $PSVersionTable.PSEdition + ")")
$t = [System.Net.Sockets.Socket]
Write-Host ("Assembly: " + $t.Assembly.Location)
foreach ($c in $t.GetConstructors()) { Write-Host ("CTOR: Socket(" + (($c.GetParameters() | ForEach-Object { $_.ParameterType.Name }) -join ', ') + ")") }
