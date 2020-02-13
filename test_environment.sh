if ! [ -z "$WORKSPACE" ]; then
  export ZWIK_ROOT="${WORKSPACE}/conda_tmp_root"
fi

export SCRIPT_DIR=$(dirname "$0")
export ZWIK_CLIENT_SCRIPT=${SCRIPT_DIR}/scripts/zwik_client.py
export ZWIK_INSTALLER=${SCRIPT_DIR}/scripts/zwik-install.sh
export SKIP_INSTALLATION_CHECK=1
sh ${SCRIPT_DIR}/bootstrap/zwik_environment --environment ${SCRIPT_DIR}/.zwik/zwik_environment.yml "$@"
