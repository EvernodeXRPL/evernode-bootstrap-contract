#!/bin/bash
# This script is used to replace the bootstrap contract with the user-supplied contract bundle.
# (The contract bundle archive must already exist on the current directory)

echo "Sashimono bootstrap contract upgrader."
echo "Execution lcl $1-$2"

archive_name="bundle.zip"
bootstrap_bin="bootstrap_contract"
install_script="install.sh"
patch_cfg="../patch.cfg"
patch_cfg_bk="../patch.cfg.bk"
contract_config="contract.config"
self_original_name="bootstrap_upgrade.sh" # Original name of this script before it was renamed to post_exec.sh
self_path=$(realpath $0)                  # Full path of this script.
self_name=$(basename $self_path)          # File name of this script.
self_dir=$(dirname $self_path)            # Parent path of this script.
post_exec_err_file="post_exec.err"

# If field exists, append to patch json.
function append_string_field() {
    local field=$1
    local req=$2 # '1' if empty value not allowed.
    val=$(jq ".$field" $contract_config)
    if [ "$val" != "null" ]; then
        if [ "$req" == "1" ] && [ ${#val} -eq 2 ]; then # Empty means "" or ''
            echo "$field cannot be empty."
            return 1
        fi
        [ "${patch_json: -1}" != "{" ] && patch_json="$patch_json,"
        patch_json="$patch_json${field##*.}:$val" # Append last . component field name with value.
    fi
    return 0
}

# If field exists, append to patch json.
function append_mode_field() {
    local field=$1
    val=$(jq ".$field" $contract_config)
    if [ "$val" != "null" ]; then
        if [ ${#val} -eq 2 ] || { [ "$val" != "\"public\"" ] && [ "$val" != "\"private\"" ]; }; then
            echo "Invalid $field mode. Valid values: public|private."
            return 1
        fi
        [ "${patch_json: -1}" != "{" ] && patch_json="$patch_json,"
        patch_json="$patch_json${field##*.}:$val" # Append last . component field name with value.
    fi
    return 0
}

# If field exists, append to patch json.
function append_gt0_field() {
    local field=$1
    local val=$(jq ".$field" $contract_config)
    if [ "$val" != "null" ]; then
        if [ "$val" -lt 0 ]; then
            echo "Invalid $field. Should be greater than zero."
            return 1
        fi
        [ "${patch_json: -1}" != "{" ] && patch_json="$patch_json,"
        patch_json="$patch_json${field##*.}:$val" # Append last . component field name with value.
    fi
    return 0
}

# If field exists, append to patch json.
function append_range_field() {
    local field=$1
    local min=$2
    local max=$3

    local val=$(jq ".$field" $contract_config)
    if [ "$val" != "null" ]; then
        if [ "$val" -le $min ] || [ "$val" -gt $max ]; then
            echo "$field must be between $min and $max inclusive."
            return 1
        fi
        [ "${patch_json: -1}" != "{" ] && patch_json="$patch_json,"
        patch_json="$patch_json${field##*.}:$val" # Append last . component field name with value.
    fi
    return 0
}

function print_err() {
    local error=$1
    log=$(jq . $post_exec_err_file)
    for key in $(jq -c 'keys[]' <<<$log); do
        log=$(jq ".$key = \"$error\"" <<<$log)
    done
    echo $log >$post_exec_err_file
}

function upgrade() {

    # Check for binary archive availability.
    if [ ! -f "$archive_name" ]; then
        echo "Required $archive_name not found. Exiting.."
        print_err "BundleNotFound"
        return 1
    fi

    # Unzipping the archive.

    # unzip command is used for zip extraction.
    if ! command -v unzip &>/dev/null; then
        echo "unzip utility not found. Exiting.."
        print_err "UnzipBundleNotFound"
        return 1
    fi

    unzip -o $archive_name >>/dev/null

    if [ -f "$contract_config" ]; then

        # jq command is used for json manipulation.
        if ! command -v jq &>/dev/null; then
            echo "jq utility not found. Exiting.."
            print_err "JqBundleNotFound"
            return 1
        fi

        # ********Config check********

        # bin_path is the only field that we require. Everything else can be ommitted.
        local bin_path=$(jq '.bin_path' $contract_config)
        if [ "$bin_path" == "null" ] || [ ${#bin_path} -eq 2 ]; then # Empty means "" or ''
            echo "bin_path cannot be empty"
            print_err "BinPathEmpty"
            return 1
        elif [ ! -f "${bin_path:1:-1}" ]; then
            echo "Given binary file: $bin_path not found"
            print_err "BinaryNotFound"
            return 1
        else
            patch_json="{bin_path:$bin_path"
        fi

        if ! append_string_field "bin_args"; then
            print_err "InvalidBinArgs"
            return 1
        fi

        env_config=$(jq '.environment' $contract_config)
        if [ "$env_config" != "null" ]; then
            jq -e '.environment|type!="object"' $contract_config >/dev/null &&
                echo "Contract environment config format is invalid. Its format should be an object with string keys and string values." &&
                print_err "InvalidEnvFormat" && return 1

            jq -e '[.environment|to_entries | .[] | select(.value|type!="string") ] | any' $contract_config >/dev/null &&
                echo "Each contract environment variable's type should be a string." &&
                print_err "InvalidEnvFormat" && return 1
            patch_json="$patch_json,environment:$env_config"
        fi

        if ! append_string_field "version" 1; then
            print_err "InvalidVersion"
            return 1
        fi

        if ! append_gt0_field "max_input_ledger_offset"; then
            print_err "InvalidMaxInputLedgerOffset"
            return 1
        fi

        local unl=$(jq '.unl' $contract_config)
        if [ "$unl" != "null" ]; then
            unl_res=$(jq '.unl? | map(length == 66 and startswith("ed")) | index(false)' $contract_config)
            if [ "$unl_res" != "null" ]; then
                echo "Unl pubkey invalid. Invalid format. Key should be 66 in length with ed prefix"
                print_err "InvalidUnlPubkey"
                return 1
            fi
            patch_json="$patch_json,unl:$unl"
        fi

        local consensus_config=$(jq '.consensus' $contract_config)
        if [ "$consensus_config" != "null" ]; then
            patch_json="$patch_json,consensus:{"

            if ! append_mode_field "consensus.mode"; then
                print_err "InvalidConsensusMode"
                return 1
            fi
            if ! append_range_field "consensus.roundtime" 0 3600000; then
                print_err "InvalidConsensusRoundtime"
                return 1
            fi
            if ! append_range_field "consensus.stage_slice" 0 33; then
                print_err "InvalidConsensusStageSlice"
                return 1
            fi
            if ! append_range_field "consensus.threshold" 1 100; then
                print_err "InvalidConsensusThreshold"
                return 1
            fi

            patch_json="$patch_json}"
        fi

        local npl_config=$(jq '.npl' $contract_config)
        if [ "$npl_config" != "null" ]; then
            patch_json="$patch_json,npl:{"

            if ! append_mode_field "npl.mode"; then
                print_err "InvalidNplMode"
                return 1
            fi

            patch_json="$patch_json}"
        fi

        local round_limits=$(jq '.round_limits' $contract_config)
        if [ "$round_limits" != "null" ]; then
            patch_json="$patch_json,round_limits:{"

            if ! append_gt0_field "round_limits.user_input_bytes"; then
                print_err "InvalidUserInputBytes"
                return 1
            fi
            if ! append_gt0_field "round_limits.user_output_bytes"; then
                print_err "InvalidUserOutputBytes"
                return 1
            fi
            if ! append_gt0_field "round_limits.npl_output_bytes"; then
                print_err "InvalidNplOutputBytes"
                return 1
            fi
            if ! append_gt0_field "round_limits.proc_cpu_seconds"; then
                print_err "InvalidProcCpuSeconds"
                return 1
            fi
            if ! append_gt0_field "round_limits.proc_mem_bytes"; then
                print_err "InvalidProcMemBytes"
                return 1
            fi
            if ! append_gt0_field "round_limits.proc_ofd_count"; then
                print_err "InvalidProcOfdCount"
                return 1
            fi

            patch_json="$patch_json}"
        fi

        patch_json="$patch_json}"

        echo "All $contract_config checks passed."

        echo "Updating $patch_cfg file."
        echo "All $contract_config checks passed."

        echo "Updating $patch_cfg file."
        temp_cfg="../temp.cfg"
        echo "{}" >$temp_cfg
        new_patch_temp=$(jq -M ". + $patch_json" $temp_cfg)
        echo $new_patch_temp >$temp_cfg
        local new_patch=$(jq -M -s '.[0] * .[1]' $patch_cfg $temp_cfg) # Merge jsons.
        rm $temp_cfg
        cp $patch_cfg $patch_cfg_bk # Make a backup.
        echo "$new_patch" >$patch_cfg

        # Remove contract.config after patch file update.
        rm $contract_config
    fi

    # *****Install Script*****.
    if [ -f "$install_script" ]; then
        echo "$install_script found. Executing..."

        chmod +x $install_script
        ./$install_script
        installcode=$?

        rm $install_script

        if [ "$installcode" -eq "0" ]; then
            echo "$install_script executed successfully."
            return 0
        else
            echo "$install_script ended with exit code:$installcode"
            print_err "InstallScriptFailed"
            return 1
        fi
    fi

    return 0
}

function rollback() {
    # Restore self-script original name (Because hp requires it to be named post_exec.sh before execution)
    cp $self_name $self_original_name
    # Restore patch.cfg if backup exists
    [ -f $patch_cfg_bk ] && mv $patch_cfg_bk $patch_cfg
    # Remove all files except the ones we need.
    find . -not \( -name $bootstrap_bin -or -name $self_original_name -or -name $post_exec_err_file \) -delete
    return 1
}

# Perform upgrade and rollback if failed.
upgrade
upgradecode=$?

pushd $self_dir >/dev/null 2>&1
if [ "$upgradecode" -eq "0" ]; then
    # We have upgraded the contract successfully. Cleanup bootstrap contract resources.
    echo "Upgrade successful. Cleaning up."
    rm -f $archive_name $bootstrap_bin $patch_cfg_bk $post_exec_err_file
else
    echo "Upgrade failed. Rolling back."
    rollback
fi
finalcode=$?
popd >/dev/null 2>&1

exit $finalcode
