# myPlatformManager
Platform Management for Bare Metal Servers using IPMI.

# Usage
```
ipmi_control.py --help
usage: ipmi_control.py [-h]
                       [--action {status,power_on,power_off,power_off_hard,power_reset,power_cycle,force_pxe,boot_disk,boot_bios,boot_safe,identify_on,identify_off,sel_clear,sel_list}]
                       [--hosts HOSTS [HOSTS ...]] [--config CONFIG] [--parallel] [--output {text,json}] [--log-file LOG_FILE] [--verbose] [--validate-nodes] [--dry-run]

IPMI control for cluster nodes

options:
  -h, --help            show this help message and exit
  --action {status,power_on,power_off,power_off_hard,power_reset,power_cycle,force_pxe,boot_disk,boot_bios,boot_safe,identify_on,identify_off,sel_clear,sel_list}
                        Action to perform (default: status)
  --hosts HOSTS [HOSTS ...]
                        List of nodes or patterns to target
  --config CONFIG, -c CONFIG
                        Configuration file path (YAML or JSON)
  --parallel, -p        Execute commands in parallel
  --output {text,json}, -o {text,json}
                        Output format (default: text)
  --log-file LOG_FILE   Log file path
  --verbose, -v         Enable verbose logging
  --validate-nodes      Validate node reachability before executing commands
  --dry-run             Show what would be done without executing

Examples:
  ipmi_control.py --action status
  ipmi_control.py --action power_on --hosts node001
  echo "node001-lom" | ipmi_control.py --action status
  ipmi_control.py --hosts node00 node01 --action power_off --parallel
  ipmi_control.py --config /etc/ipmi_control.yaml --action status
  ipmi_control.py --action sel_list --hosts node001 --output json
```
