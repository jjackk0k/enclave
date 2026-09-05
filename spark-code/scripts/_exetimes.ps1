$root = 'C:\Users\Jack\Downloads\enclave\spark-code'
foreach ($n in @('spark-menu.exe','spark-code.exe')) {
  $f = Get-Item (Join-Path $root $n) -ErrorAction SilentlyContinue
  if ($f) { "{0}  {1:yyyy-MM-dd HH:mm:ss}  {2:N0}" -f $n, $f.LastWriteTime, $f.Length }
}
