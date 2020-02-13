#!/usr/bin/env sh
set -e
CONDA_INSTALLER_LINUX=Miniforge3-24.3.0-0-Linux-x86_64.sh
CONDA_INSTALLER_MACOS=Miniforge3-24.3.0-0-MacOSX-x86_64.sh
CONDA_NAME=Mambaforge

if [ -z "$ZWIK_CLIENT_SCRIPT" ] \
 || [ -z "$ZWIK_ROOT" ]; then
echo "ERROR: not all necessary environment variables are set correctly"
env | grep ZWIK
exit 1
fi

if [ -e "${ZWIK_ROOT}.uninstall" ]; then
  if find "$ZWIK_ROOT" -mindepth 1 -print -quit | grep -q .; then
    echo "Conda uninstall in progress, this can take some time"
    echo "If it takes too long, reboot and delete \"${ZWIK_ROOT}\""
    exit 1
  fi
fi
if [ -e "${ZWIK_ROOT}.uninstall" ]; then
  echo "Previous Conda version is successfully uninstalled, remove lock file"
  rm "${ZWIK_ROOT}.uninstall"
fi

if ! [ -x "${ZWIK_ROOT}/bin/python" ]; then
  echo "Install ${CONDA_NAME} (at ${ZWIK_ROOT})"
  if [ -x "${ZWIK_ROOT}" ]; then
    echo "Please remove the following directory manually: ${ZWIK_ROOT}"
    exit 1
  fi
  bin_dir="${HOME}/.local/bin"
  mkdir -p "${bin_dir}"
  if ! which bunzip2 > /dev/null 2>&1; then
    if ! [ -x "${bin_dir}/bzip2" ]; then
      echo "Installing missing installer dependencies"
      bzip2_url="${ZWIK_URL}/bzip2"
      bzip2_dst="${bin_dir}/bzip2"
      curl -f -# "${bzip2_url}" -o "${bzip2_dst}" || wget -nv "${bzip2_url}" -O "${bzip2_dst}"
      chmod +x "${bin_dir}/bzip2"
    fi
    if ! [ -x "${bin_dir}/bunzip2" ]; then
      ln -s bzip2 "${bin_dir}/bunzip2"
    fi
  fi
  echo "Fetching installer"
  installer="/tmp/conda-install.sh"
  if [ "$(uname)" = "Darwin" ]; then
    installer_url="${ZWIK_URL}/install-data/${CONDA_INSTALLER_MACOS}"
  else
    installer_url="${ZWIK_URL}/install-data/${CONDA_INSTALLER_LINUX}"
  fi
  curl -f -# "${installer_url}" -o "${installer}" || wget -nv "${installer_url}" -O "${installer}"

  echo "Running installer"
  PATH=${bin_dir}:${PATH} sh ${installer} -b -s -p "${ZWIK_ROOT}"
  rm ${installer}
else
  echo "${CONDA_NAME} already installed! (at ${ZWIK_ROOT})"
fi

if ! [ -f "$ZWIK_CLIENT_SCRIPT" ]; then
  echo "Fetching script (${ZWIK_CLIENT_SCRIPT})"
  zwik_script_dst=$(mktemp)
  zwik_settings_dst=$(mktemp)
  zwik_script_url="${ZWIK_URL}/install-data/zwik_client.py"
  zwik_settings_url="${ZWIK_URL}/install-data/zwik_client_settings.py"
  [ ! -z "$ZWIK_CLIENT_URL" ] && zwik_script_url="$ZWIK_CLIENT_URL" && zwik_settings_url=${$ZWIK_CLIENT_URL%.py}"_settings.py"
  curl -f -# "${zwik_settings_url}" -o "${zwik_settings_dst}" || wget -nv "${zwik_settings_url}" -O "${zwik_settings_dst}"
  curl -f -# "${zwik_script_url}" -o "${zwik_script_dst}" || wget -nv "${zwik_script_url}" -O "${zwik_script_dst}"

  mv "${zwik_settings_dst}" ${ZWIK_CLIENT_SCRIPT%.py}"_settings.py"
  mv "${zwik_script_dst}" "$ZWIK_CLIENT_SCRIPT"
else
  echo "Zwik client already installed!"
fi

if [ -z "$SKIP_INSTALLATION_CHECK" ]; then
  "${ZWIK_ROOT}/bin/python" "$ZWIK_CLIENT_SCRIPT" --check-installation --fix
fi
