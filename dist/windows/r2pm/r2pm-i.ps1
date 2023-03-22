# powershell -executionpolicy unrestricted -command r2pm.ps1
$R2_USER_PLUGINS=(radare2 -H R2_USER_PLUGINS)
$V="5.8.2"
Remove-Item r2ghidra-${V}-w64.zip
Remove-Item r2ghidra_sleigh-${V}.zip
echo "Downloading blobs"
iwr -OutFile r2ghidra-${V}-w64.zip https://github.com/radareorg/r2ghidra/releases/download/${V}/r2ghidra-${V}-w64.zip
iwr -OutFile r2ghidra_sleigh-${V}.zip https://github.com/radareorg/r2ghidra/releases/download/${V}/r2ghidra_sleigh-${V}.zip
# python -m wget https://github.com/radareorg/r2ghidra/releases/download/${V}/r2ghidra-${V}-w64.zip
# python -m wget https://github.com/radareorg/r2ghidra/releases/download/${V}/r2ghidra_sleigh-${V}.zip
echo "Expanding blobs"
Expand-Archive -Force -Path r2ghidra-${V}-w64.zip
Expand-Archive -Force -Path r2ghidra_sleigh-${V}.zip
echo "Installing plugin"
Remove-Item "${R2_USER_PLUGINS}\core_r2ghidra.dll"
Move-Item -Path r2ghidra-${V}-w64\core_r2ghidra.dll -Force -Destination "${R2_USER_PLUGINS}\core_r2ghidra.dll"
Remove-Item "${R2_USER_PLUGINS}\r2ghidra_sleigh"
Move-Item -Path r2ghidra_sleigh-${V} -Force -Destination "${R2_USER_PLUGINS}\r2ghidra_sleigh"
