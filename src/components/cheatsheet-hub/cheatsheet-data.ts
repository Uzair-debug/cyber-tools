// IT & DevOps Command Cheat-Sheet Database

export type CommandCategory = 'Windows & PowerShell' | 'Linux & Bash' | 'Git Recovery' | 'Docker & Containers' | 'Networking & Diagnostics';

export interface CommandItem {
  id: string;
  title: string;
  category: CommandCategory;
  description: string;
  commandTemplate: string;
  tags: string[];
  explanationNotes?: string[];
}

export const COMMAND_ITEMS: CommandItem[] = [
  // =========================================================================
  // 1. WINDOWS & POWERSHELL
  // =========================================================================
  {
    id: 'win-robocopy-mirror',
    title: 'Robocopy High-Speed Multi-Threaded Mirror',
    category: 'Windows & PowerShell',
    description: 'Mirrors directory structure with multi-threading, restartable mode, retry limits, and log output.',
    commandTemplate: 'robocopy "<source>" "<destination>" /MIR /MT:16 /R:2 /W:5 /NP /LOG:"<logPath>"',
    tags: ['robocopy', 'backup', 'file-copy', 'mirror', 'windows', 'sync'],
    explanationNotes: [
      '/MIR: Mirrors directory tree (purges files in destination that no longer exist in source).',
      '/MT:16: Uses 16 parallel worker threads for high throughput.',
      '/R:2 /W:5: Retries locked files twice with a 5-second wait.',
      '/NP: Suppresses progress percentage to prevent huge log files.',
    ],
  },
  {
    id: 'win-find-port-pid',
    title: 'Find Process Holding Port (Netstat & PowerShell)',
    category: 'Windows & PowerShell',
    description: 'Finds the exact Process ID (PID) and executable name listening on a specific TCP port.',
    commandTemplate: 'Get-NetTCPConnection -LocalPort <port> | Select-Object LocalAddress, LocalPort, State, OwningProcess, @{N="ProcessName";E={(Get-Process -Id $_.OwningProcess).ProcessName}}',
    tags: ['netstat', 'port', 'pid', 'process', 'powershell', 'kill'],
    explanationNotes: [
      'CMD Alternative: netstat -ano | findstr :<port>',
      'To terminate the locking process: Stop-Process -Id <pid> -Force',
    ],
  },
  {
    id: 'win-dism-sfc-repair',
    title: 'Repair Corrupted Windows System Files (SFC & DISM)',
    category: 'Windows & PowerShell',
    description: 'Repairs corrupted Windows Component Store and replaces damaged operating system files.',
    commandTemplate: 'DISM /Online /Cleanup-Image /RestoreHealth; sfc /scannow',
    tags: ['dism', 'sfc', 'repair', 'windows', 'bsod', 'corrupt'],
    explanationNotes: [
      'DISM /Online /Cleanup-Image /RestoreHealth downloads healthy files from Windows Update.',
      'sfc /scannow verifies and replaces all protected system binaries.',
    ],
  },
  {
    id: 'win-find-large-files',
    title: 'Find Top 20 Largest Files Over 1GB',
    category: 'Windows & PowerShell',
    description: 'Recursively scans a target directory and lists the largest space-consuming files.',
    commandTemplate: 'Get-ChildItem -Path "<source>" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 1GB } | Sort-Object Length -Descending | Select-Object -First 20 FullName, @{N="SizeGB";E={[math]::round($_.Length/1GB, 2)}}',
    tags: ['disk-space', 'large-files', 'cleanup', 'storage', 'powershell'],
    explanationNotes: [
      'Helps identify hidden VM virtual disks (.vhdx), ISO images, and SQL transaction logs (.ldf).',
    ],
  },
  {
    id: 'win-flush-dns-reset-stack',
    title: 'Flush DNS & Complete Network Stack Reset',
    category: 'Windows & PowerShell',
    description: 'Flushes DNS resolver cache and resets Winsock catalog and TCP/IP stack.',
    commandTemplate: 'ipconfig /flushdns; netsh int ip reset; netsh winsock reset',
    tags: ['dns', 'network', 'winsock', 'troubleshooting', 'ipconfig'],
    explanationNotes: [
      'Requires an elevated (Administrator) Command Prompt or PowerShell terminal.',
      'A system reboot is required to reinitialize Winsock.',
    ],
  },
  {
    id: 'win-new-firewall-rule',
    title: 'Open Inbound Port in Windows Firewall',
    category: 'Windows & PowerShell',
    description: 'Creates an inbound rule allowing TCP traffic on a specified port.',
    commandTemplate: 'New-NetFirewallRule -DisplayName "<ruleName>" -Direction Inbound -LocalPort <port> -Protocol TCP -Action Allow -Profile Any',
    tags: ['firewall', 'port', 'security', 'powershell', 'inbound'],
  },

  // =========================================================================
  // 2. LINUX & BASH
  // =========================================================================
  {
    id: 'linux-rsync-ssh',
    title: 'Rsync Directory Mirror over Custom SSH Port',
    category: 'Linux & Bash',
    description: 'Syncs directory contents to a remote server with compression, delta transfer, and progress bar.',
    commandTemplate: 'rsync -avzP --delete -e "ssh -p <port>" "<source>" <user>@<host>:"<destination>"',
    tags: ['rsync', 'ssh', 'backup', 'sync', 'linux', 'file-transfer'],
    explanationNotes: [
      '-a: Archive mode (preserves permissions, timestamps, symlinks, and ownership).',
      '-v: Verbose output.',
      '-z: Compresses data during network transit.',
      '-P: Displays live progress bar and resumes interrupted files.',
      '--delete: Removes files in destination that no longer exist in source.',
    ],
  },
  {
    id: 'linux-find-delete-older',
    title: 'Find & Delete Files Older Than 30 Days',
    category: 'Linux & Bash',
    description: 'Recursively finds files in a directory modified more than 30 days ago and deletes them.',
    commandTemplate: 'find "<source>" -type f -mtime +30 -exec rm -f {} +',
    tags: ['find', 'delete', 'cleanup', 'retention', 'bash', 'logs'],
    explanationNotes: [
      '-mtime +30: Matches files modified strictly more than 30 days ago.',
      '-exec rm -f {} +: Runs rm in batch mode for high performance without argument list limit.',
    ],
  },
  {
    id: 'linux-top-disk-usage',
    title: 'Top 10 Largest Directories & Files',
    category: 'Linux & Bash',
    description: 'Scans directory tree and prints the top 10 largest folders/files in human-readable units.',
    commandTemplate: 'du -ah "<source>" 2>/dev/null | sort -rh | head -n 10',
    tags: ['disk-usage', 'du', 'storage', 'cleanup', 'bash'],
  },
  {
    id: 'linux-listening-ports',
    title: 'List All Active Listening Ports & Sockets (ss)',
    category: 'Linux & Bash',
    description: 'Displays all active TCP and UDP listening sockets along with process names.',
    commandTemplate: 'ss -tulpn',
    tags: ['ports', 'network', 'sockets', 'ss', 'netstat', 'linux'],
    explanationNotes: [
      '-t: TCP sockets',
      '-u: UDP sockets',
      '-l: Listening sockets only',
      '-p: Show process using socket (requires sudo)',
      '-n: Numeric addresses (no DNS reverse resolution for speed)',
    ],
  },
  {
    id: 'linux-journalctl-service',
    title: 'Follow Live Systemd Service Logs with Journalctl',
    category: 'Linux & Bash',
    description: 'Streams live log output for a systemd daemon service with recent history.',
    commandTemplate: 'journalctl -u <serviceName> -f -n 100 --no-pager',
    tags: ['systemd', 'journalctl', 'logs', 'troubleshooting', 'linux'],
  },
  {
    id: 'linux-tar-compress-extract',
    title: 'Create & Extract Gzip Tarball Archives',
    category: 'Linux & Bash',
    description: 'Compresses a folder into a .tar.gz archive and command to unpack it.',
    commandTemplate: 'tar -czvf archive.tar.gz "<source>"  # To Extract: tar -xzvf archive.tar.gz -C "<destination>"',
    tags: ['tar', 'gzip', 'archive', 'compress', 'linux'],
  },

  // =========================================================================
  // 3. GIT EMERGENCY RECOVERY
  // =========================================================================
  {
    id: 'git-undo-commit-keep-changes',
    title: 'Undo Last Commit (Keep Changes in Staging)',
    category: 'Git Recovery',
    description: 'Rolls back the latest commit but leaves all your file edits staged and intact.',
    commandTemplate: 'git reset --soft HEAD~1',
    tags: ['git', 'undo', 'reset', 'commit', 'recovery'],
    explanationNotes: [
      'Perfect when you committed too early or want to change files before recommitting.',
    ],
  },
  {
    id: 'git-undo-commit-discard-all',
    title: 'Undo Last Commit (Discard All Changes Completely)',
    category: 'Git Recovery',
    description: 'CAUTION: Completely wipes the last commit and discards all changes in working directory.',
    commandTemplate: 'git reset --hard HEAD~1',
    tags: ['git', 'undo', 'reset-hard', 'discard'],
    explanationNotes: [
      'WARNING: Any uncommitted changes will be permanently lost.',
    ],
  },
  {
    id: 'git-stash-untracked',
    title: 'Stash Everything (Including Untracked Files)',
    category: 'Git Recovery',
    description: 'Temporarily stores all local changes including newly created untracked files.',
    commandTemplate: 'git stash -u  # To Restore: git stash pop',
    tags: ['git', 'stash', 'untracked', 'workspace'],
    explanationNotes: [
      '-u (--include-untracked): Includes files you have not yet added to git tracking.',
    ],
  },
  {
    id: 'git-amend-message',
    title: 'Amend Latest Commit Message',
    category: 'Git Recovery',
    description: 'Updates the commit message of your most recent commit without altering code.',
    commandTemplate: 'git commit --amend -m "<newCommitMessage>"',
    tags: ['git', 'amend', 'message', 'typo'],
  },
  {
    id: 'git-clean-untracked',
    title: 'Purge All Untracked Files & Directories',
    category: 'Git Recovery',
    description: 'Cleans up untracked files, temp files, and build artifacts from repository tree.',
    commandTemplate: 'git clean -fd  # Dry-run first: git clean -nd',
    tags: ['git', 'clean', 'purge', 'untracked'],
    explanationNotes: [
      '-f: Force delete.',
      '-d: Remove untracked directories in addition to untracked files.',
    ],
  },
  {
    id: 'git-find-deleted-string',
    title: 'Find Commit That Introduced or Deleted a String',
    category: 'Git Recovery',
    description: 'Searches git commit history for commits that added or removed specific code.',
    commandTemplate: 'git log -c -S "<searchString>" --source --all',
    tags: ['git', 'pickaxe', 'search-history', 'forensics'],
  },

  // =========================================================================
  // 4. DOCKER & CONTAINER OPERATIONS
  // =========================================================================
  {
    id: 'docker-nuclear-prune',
    title: 'Nuclear Docker Cleanup (Reclaim Maximum Disk Space)',
    category: 'Docker & Containers',
    description: 'Purges all stopped containers, unused networks, dangling images, and anonymous volumes.',
    commandTemplate: 'docker system prune -a --volumes -f',
    tags: ['docker', 'prune', 'cleanup', 'storage', 'containers'],
    explanationNotes: [
      '-a: Removes all unused images, not just dangling ones.',
      '--volumes: Prunes all unused Docker storage volumes.',
      '-f: Do not prompt for confirmation.',
    ],
  },
  {
    id: 'docker-inspect-container-ip',
    title: 'Extract Container Internal IP Address',
    category: 'Docker & Containers',
    description: 'Queries Docker daemon to retrieve the internal bridge network IP of a container.',
    commandTemplate: "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <containerId>",
    tags: ['docker', 'ip', 'network', 'inspect', 'container'],
  },
  {
    id: 'docker-exec-shell',
    title: 'Attach Interactive Shell to Running Container',
    category: 'Docker & Containers',
    description: 'Spawns an interactive bash/sh shell inside an active container environment.',
    commandTemplate: 'docker exec -it <containerId> /bin/sh',
    tags: ['docker', 'exec', 'shell', 'bash', 'terminal'],
    explanationNotes: [
      'If Alpine Linux, use /bin/sh. If Ubuntu/Debian, you can also use /bin/bash.',
    ],
  },
  {
    id: 'docker-live-stats',
    title: 'Inspect Container CPU & Memory Resource Stats',
    category: 'Docker & Containers',
    description: 'Outputs resource consumption (CPU %, Memory, Network I/O) for all active containers.',
    commandTemplate: 'docker stats --no-stream',
    tags: ['docker', 'stats', 'memory', 'cpu', 'resources'],
  },

  // =========================================================================
  // 5. NETWORKING & DIAGNOSTICS
  // =========================================================================
  {
    id: 'net-test-port-powershell',
    title: 'Test TCP Port Connectivity Without Telnet (PowerShell)',
    category: 'Networking & Diagnostics',
    description: 'Checks if a remote server port is reachable, resolving DNS and testing TCP handshake.',
    commandTemplate: 'Test-NetConnection -ComputerName <host> -Port <port>',
    tags: ['test-netconnection', 'tnc', 'port-check', 'powershell', 'telnet'],
    explanationNotes: [
      'Built into all modern Windows versions, replacing legacy telnet client.',
    ],
  },
  {
    id: 'net-test-port-nc',
    title: 'Test Port Connectivity via Netcat (Linux)',
    category: 'Networking & Diagnostics',
    description: 'Zero-timeout socket connection test to verify port reachability.',
    commandTemplate: 'nc -zv <host> <port>',
    tags: ['netcat', 'nc', 'port-test', 'linux'],
    explanationNotes: [
      '-z: Zero-I/O mode (scans without sending data).',
      '-v: Verbose output showing whether connection succeeded or failed.',
    ],
  },
  {
    id: 'net-openssl-cert-check',
    title: 'Inspect SSL Certificate Expiry & Issuer via OpenSSL CLI',
    category: 'Networking & Diagnostics',
    description: 'Connects to an HTTPS server and extracts valid date ranges, SANs, and issuer.',
    commandTemplate: 'openssl s_client -connect <host>:443 -servername <host> 2>/dev/null | openssl x509 -noout -dates -subject -issuer',
    tags: ['openssl', 'ssl', 'tls', 'certificate', 'expiry'],
  },
  {
    id: 'net-dig-trace',
    title: 'Trace Full DNS Delegation Path (Dig)',
    category: 'Networking & Diagnostics',
    description: 'Queries DNS hierarchy starting from root nameservers down to authoritative SOA.',
    commandTemplate: 'dig +trace +nodnssec <host>',
    tags: ['dig', 'dns', 'trace', 'nameservers', 'networking'],
  },
];
