' run-hidden.vbs — launch a command with NO console window, ever.
' Usage: wscript run-hidden.vbs "<command line>"
' Jack's rule (2026-07-31): never spawn visible console windows for servers.
Set sh = CreateObject("WScript.Shell")
cmdline = ""
For i = 0 To WScript.Arguments.Count - 1
  cmdline = cmdline & WScript.Arguments(i) & " "
Next
sh.Run "cmd /c " & Trim(cmdline), 0, False
