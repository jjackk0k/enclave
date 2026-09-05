$root = 'C:\Users\Jack\Downloads\enclave\spark-code'
Get-ChildItem -Recurse -File $root |
  Where-Object { $_.FullName -notmatch '\\.build-venv|\\build\\|__pycache__' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 25 |
  ForEach-Object { "{0:yyyy-MM-dd HH:mm}  {1,8:N0}  {2}" -f $_.LastWriteTime, $_.Length, $_.FullName }
