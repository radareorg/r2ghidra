@echo OFF
echo "Configuring the build directory with meson"
if EXIST w\meson-private\coredata.dat (
  meson setup w --reconfigure --buildtype=release
) else (
  meson setup w --buildtype=release
)
