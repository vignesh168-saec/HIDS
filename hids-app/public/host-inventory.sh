#!/usr/bin/env bash

# Host Inventory Collector for Linux
# Integrates process, service, configuration, cron, and download scans into a unified CSV.

OUTPUT_CSV="System_Inventory.csv"

echo "Starting Linux Host Inventory Collection..."

# Initialize CSV with unified headers
echo "Category,Name,Path,Additional,Status,Hash" > "$OUTPUT_CSV"

# Helper to append to CSV with proper quoting
append_to_csv() {
    local category=$1
    local name=$2
    local path=$3
    local additional=$4
    local status=$5
    local hash=$6
    echo "\"$category\",\"$name\",\"$path\",\"$additional\",\"$status\",\"$hash\"" >> "$OUTPUT_CSV"
}

################################################################################
# 1. Process Inventory
################################################################################
echo "[1/5] Collecting Process Inventory..."

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    [[ ! -d "$pid_dir" ]] && continue
    name=$(cat /proc/$pid/comm 2>/dev/null)
    cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | sed 's/"/""/g')
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    user=$(stat -c '%U' /proc/$pid 2>/dev/null)

    # Classification
    proc_category="User Process"
    [[ "$user" == "root" ]] && proc_category="System Service"
    grep -qaE 'docker|kubepods|containerd' /proc/$pid/cgroup 2>/dev/null && proc_category="Container Process"

    type="Executable"
    script="-"
    hash="N/A"
    status="OK"

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

    append_to_csv "Process" "$name" "$exe" "PID:$pid; Cat:$proc_category; Type:$type; Script:$script" "$status" "$hash"
done

################################################################################
# 2. Service Inventory
################################################################################
echo "[2/5] Collecting Service Inventory..."

services=$(systemctl list-unit-files --type=service --no-legend | awk '{print $1}')
for service in $services; do
    state=$(systemctl is-active "$service" 2>/dev/null)
    exec_raw=$(systemctl show "$service" -p ExecStart --value 2>/dev/null)
    exec_path=$(echo "$exec_raw" | grep -o 'path=[^ ;]*' | head -1 | cut -d= -f2)

    if [[ -z "$exec_path" ]]; then
        exec_path="Not Found"
        hash="N/A"
        status="Missing"
    elif [[ -f "$exec_path" ]]; then
        hash=$(sha256sum "$exec_path" 2>/dev/null | awk '{print $1}')
        status="OK"
    else
        hash="File Missing"
        status="Error"
    fi
    append_to_csv "Service" "$service" "$exec_path" "State:$state" "$status" "$hash"
done

################################################################################
# 3. Configuration File Inventory
################################################################################
echo "[3/5] Collecting Configuration File Inventory..."

directories=("/etc" "/etc/nginx" "/etc/apache2" "/etc/systemd" "/opt")
extensions=("*.conf" "*.cfg" "*.cnf" "*.yaml" "*.yml" "*.json" "*.xml" "*.ini")

for dir in "${directories[@]}"; do
    if [[ -d "$dir" ]]; then
        for ext in "${extensions[@]}"; do
            find "$dir" -maxdepth 3 -type f -name "$ext" 2>/dev/null | while read -r file; do
                filename=$(basename "$file")
                filetype=$(file -b "$file" | sed 's/"/""/g')
                filetype=$(file -b "$file" | sed 's/"/""/g')
                hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
                # Capture content snippet (first 500 chars) for rule-based scanning
                content_snippet=$(head -c 500 "$file" | tr -d '\n\r' | sed 's/"/""/g')
                append_to_csv "ConfigFile" "$filename" "$file" "Type:$filetype; Content:[$content_snippet]" "Found" "$hash"
            done
        done
    fi
done

################################################################################
# 4. Cron Job Inventory
################################################################################
echo "[4/5] Collecting Cron Job Inventory..."

if [[ -f /etc/crontab ]]; then
    # Capture full command (column 7 onwards) and trim trailing whitespace
    grep -v '^#' /etc/crontab | grep '/' | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//' | while read -r cmd; do
        [[ -z "${cmd// }" ]] && continue
        # Extract the binary name (first word) for the Name column
        bin_name=$(echo "$cmd" | awk '{print $1}')
        if [[ -f "$bin_name" ]]; then
            filetype=$(file -b "$bin_name" | sed 's/"/""/g')
            hash=$(sha256sum "$bin_name" 2>/dev/null | awk '{print $1}')
            status="OK"
        else
            filetype="Command/Script"
            hash="N/A"
            status="Found"
        fi
        append_to_csv "CronJob" "$(basename "$bin_name")" "$cmd" "Source:/etc/crontab; Type:$filetype" "$status" "$hash"
    done
fi

cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for dir in "${cron_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        find "$dir" -type f 2>/dev/null | while read -r file; do
            filetype=$(file -b "$file" | sed 's/"/""/g')
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            # Capture content snippet for rule-based scanning
            content_snippet=$(head -c 500 "$file" | tr -d '\n\r' | sed 's/"/""/g')
            append_to_csv "CronJob" "$(basename "$file")" "$file" "Source:$dir; Type:$filetype; Content:[$content_snippet]" "OK" "$hash"
        done
    fi
done

for user in $(cut -f1 -d: /etc/passwd); do
    # Capture full command (column 6 onwards) while ignoring environment variables (containing =)
    crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -v '=' | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//' | while read -r cmd; do
        [[ -z "${cmd// }" ]] && continue
        # Extract the binary name (first word) for the Name column
        bin_name=$(echo "$cmd" | awk '{print $1}')
        if [[ -f "$bin_name" ]]; then
            filetype=$(file -b "$bin_name" | sed 's/"/""/g')
            hash=$(sha256sum "$bin_name" 2>/dev/null | awk '{print $1}')
            status="OK"
        else
            filetype="Command"
            hash="N/A"
            status="Found"
        fi
        append_to_csv "CronJob" "$(basename "$bin_name")" "$cmd" "User:$user; Type:$filetype" "$status" "$hash"
    done
done

################################################################################
# 5. Download Artifact Inventory
################################################################################
echo "[5/5] Collecting Download Artifact Inventory..."

# Identify users with home directories in /home/ or root to scan their Downloads
# Filter: UIDs >= 500 (common for users) or root, or any user with a home in /home/
awk -F: '($3 == 0 || $3 >= 500 || $6 ~ /^\/home/) {print $1 ":" $6}' /etc/passwd | while IFS=: read -r user home; do
    DOWNLOAD_DIR="$home/Downloads"
    if [[ -d "$DOWNLOAD_DIR" ]]; then
        echo "  - Scanning Downloads for user: $user ($DOWNLOAD_DIR)"
        find "$DOWNLOAD_DIR" -maxdepth 2 -type f 2>/dev/null | while read -r file; do
            filename=$(basename "$file")
            filetype=$(file -b "$file" | sed 's/"/""/g')
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            append_to_csv "DownloadsFile" "$filename" "$file" "Owner:$user; Type:$filetype" "OK" "$hash"
        done
    fi
done

echo "Inventory complete. Unified file generated: $OUTPUT_CSV"
