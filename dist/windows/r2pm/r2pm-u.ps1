$R2_USER_PLUGINS=(radare2 -H R2_USER_PLUGINS)
Remove-Item -Confirm "${R2_USER_PLUGINS}\core_r2ghidra.dll"
Remove-Item -Confirm "${R2_USER_PLUGINS}\r2ghidra_sleigh"
