#!/usr/bin/env bash

# Host Inventory Collector for Linux
# Integrates process, service, configuration, cron, and download scans.

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_OUTPUT="linux_inventory_$TIMESTAMP"

echo "Starting Linux Host Inventory Collection..."

################################################################################
# 1. Process Inventory
################################################################################
echo "[1/5] Collecting Process Inventory..."
PROCESS_OUTPUT="process_inventory.csv"
echo "PID,Name,Category,Type,Executable,Script,Hash" > "$PROCESS_OUTPUT"

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    name=$(cat /proc/$pid/comm 2>/dev/null)
    cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    user=$(stat -c '%U' /proc/$pid 2>/dev/null)

    category="User Process"
    [[ "$user" == "root" ]] && category="System Service"
    grep -qaE 'docker|kubepods|containerd' /proc/$pid/cgroup 2>/dev/null && category="Container Process"

    type="Executable"
    script="-"
    hash="N/A"

    if [[ ! -e /proc/$pid/exe ]]; then
        type="Kernel Thread"
        exe="-"
    fi

    if [[ "$exe" != "-" && -f "$exe" ]]; then
        hash=$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')
    fi

    interpreter_list="python python3 node bash sh perl ruby java"
    for interp in $interpreter_list; do
        if [[ "$name" == "$interp"* ]]; then
            type="Interpreter"
            script_candidate=$(echo "$cmdline" | awk '{print $2}')
            if [[ -f "$script_candidate" ]]; then
                script="$script_candidate"
                hash=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
            fi
        fi
    done

    echo "\"$pid\",\"$name\",\"$category\",\"$type\",\"$exe\",\"$script\",\"$hash\"" >> "$PROCESS_OUTPUT"
done

################################################################################
# 2. Service Inventory
################################################################################
echo "[2/5] Collecting Service Inventory..."
SERVICE_OUTPUT="linux_service_hashes.csv"
echo "ServiceName,State,ExecPath,Hash" > "$SERVICE_OUTPUT"

services=$(systemctl list-unit-files --type=service --no-legend | awk '{print $1}')
for service in $services; do
    state=$(systemctl is-active "$service" 2>/dev/null)
    exec_raw=$(systemctl show "$service" -p ExecStart --value 2>/dev/null)
    exec_path=$(echo "$exec_raw" | grep -o 'path=[^ ;]*' | head -1 | cut -d= -f2)

    if [[ -z "$exec_path" ]]; then
        exec_path="Not Found"
        hash="N/A"
    elif [[ -f "$exec_path" ]]; then
        hash=$(sha256sum "$exec_path" 2>/dev/null | awk '{print $1}')
    else
        hash="File Missing"
    fi
    echo "\"$service\",\"$state\",\"$exec_path\",\"$hash\"" >> "$SERVICE_OUTPUT"
done

################################################################################
# 3. Configuration File Inventory
################################################################################
echo "[3/5] Collecting Configuration File Inventory..."
CONFIG_OUTPUT="linux_config_file_inventory.csv"
echo "FileName,FullPath,FileType,SHA256" > "$CONFIG_OUTPUT"

directories=("/etc" "/etc/nginx" "/etc/apache2" "/etc/systemd" "/opt")
extensions=("*.conf" "*.cfg" "*.cnf" "*.yaml" "*.yml" "*.json" "*.xml" "*.ini")

for dir in "${directories[@]}"; do
    if [[ -d "$dir" ]]; then
        for ext in "${extensions[@]}"; do
            find "$dir" -type f -name "$ext" 2>/dev/null | while read -r file; do
                filename=$(basename "$file")
                filetype=$(file -b "$file")
                hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
                echo "\"$filename\",\"$file\",\"$filetype\",\"$hash\"" >> "$CONFIG_OUTPUT"
            done
        done
    fi
done

################################################################################
# 4. Cron Job Inventory
################################################################################
echo "[4/5] Collecting Cron Job Inventory..."
CRON_OUTPUT="linux_cron_inventory.csv"
echo "CronSource,CommandPath,FileType,SHA256" > "$CRON_OUTPUT"

if [[ -f /etc/crontab ]]; then
    grep -v '^#' /etc/crontab | awk '{print $7}' | while read -r cmd; do
        if [[ -f "$cmd" ]]; then
            filetype=$(file -b "$cmd")
            hash=$(sha256sum "$cmd" 2>/dev/null | awk '{print $1}')
        else
            filetype="Command/Script"
            hash="N/A"
        fi
        echo "\"/etc/crontab\",\"$cmd\",\"$filetype\",\"$hash\"" >> "$CRON_OUTPUT"
    done
fi

cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for dir in "${cron_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        find "$dir" -type f 2>/dev/null | while read -r file; do
            filetype=$(file -b "$file")
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            echo "\"$dir\",\"$file\",\"$filetype\",\"$hash\"" >> "$CRON_OUTPUT"
        done
    fi
done

for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v '^#' | awk '{print $6}' | while read -r cmd; do
        [[ -z "$cmd" ]] && continue
        if [[ -f "$cmd" ]]; then
            filetype=$(file -b "$cmd")
            hash=$(sha256sum "$cmd" 2>/dev/null | awk '{print $1}')
        else
            filetype="Command"
            hash="N/A"
        fi
        echo "\"User:$user\",\"$cmd\",\"$filetype\",\"$hash\"" >> "$CRON_OUTPUT"
    done
done

################################################################################
# 5. Download Artifact Inventory
################################################################################
echo "[5/5] Collecting Download Artifact Inventory..."
DOWNLOAD_OUTPUT="linux_download_hashes.csv"
DOWNLOAD_DIR="$HOME/Downloads"
echo "FileName,FullPath,FileType,SHA256" > "$DOWNLOAD_OUTPUT"

if [[ -d "$DOWNLOAD_DIR" ]]; then
    find "$DOWNLOAD_DIR" -type f 2>/dev/null | while read -r file; do
        filename=$(basename "$file")
        filetype=$(file -b "$file")
        hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        echo "\"$filename\",\"$file\",\"$filetype\",\"$hash\"" >> "$DOWNLOAD_OUTPUT"
    done
fi

echo "Inventory complete. Files generated:"
echo "- $PROCESS_OUTPUT"
echo "- $SERVICE_OUTPUT"
echo "- $CONFIG_OUTPUT"
echo "- $CRON_OUTPUT"
echo "- $DOWNLOAD_OUTPUT"
