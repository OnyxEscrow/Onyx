# Scripts Directory

This directory contains automation scripts for the Monero Marketplace project. All scripts are available in both PowerShell (`.ps1`) and Bash (`.sh`) versions.

## Platform Support

- **Windows**: Use `.ps1` scripts with PowerShell
- **Linux/Ubuntu**: Use `.sh` scripts with Bash

## Quick Reference

### Setup & Installation

| Script | Description |
|--------|-------------|
| `ubuntu-setup.sh` | Automated Ubuntu environment setup (Rust, Tor, Monero) |
| `setup-monero-testnet.sh` | Setup Monero testnet wallet and RPC |
| `check-environment.sh` | Verify complete development environment |

### Testing

| Script | Description |
|--------|-------------|
| `test-rpc.sh` | Test Monero RPC connectivity |
| `pre-commit.sh` | Run all pre-commit checks |

### Security

| Script | Description |
|--------|-------------|
| `check-security-theatre.sh` | Detect security theatre patterns |
| `check-monero-tor.sh` | Verify Monero/Tor security patterns |
| `security-dashboard.sh` | Display security metrics dashboard |
| `security-alerts.sh` | Show security alerts |

### Reality Checks

| Script | Description |
|--------|-------------|
| `auto-reality-check-tor.sh` | Generate Tor reality check for function |
| `validate-reality-check-tor.sh` | Validate existing reality check |

### Development

| Script | Description |
|--------|-------------|
| `new-spec.sh` | Create new function specification |
| `update-metrics.sh` | Update project metrics |

## Usage Examples

### First-Time Setup (Ubuntu)

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run automated setup
./scripts/ubuntu-setup.sh

# Verify environment
./scripts/check-environment.sh
```

### Daily Development Workflow

```bash
# Start Monero testnet (once per session)
./scripts/setup-monero-testnet.sh

# Before committing
./scripts/pre-commit.sh

# Check security
./scripts/check-security-theatre.sh --verbose

# Run tests
cargo test --workspace
```

### Creating New Features

```bash
# 1. Create specification
./scripts/new-spec.sh my_function

# 2. Edit spec
vim docs/specs/my_function.md

# 3. Implement function
vim wallet/src/my_module.rs

# 4. Create reality check (if network function)
./scripts/auto-reality-check-tor.sh my_function

# 5. Validate reality check
./scripts/validate-reality-check-tor.sh my_function

# 6. Commit (pre-commit hook runs automatically)
git add .
git commit -m "Add my_function"
```

## Script Details

### ubuntu-setup.sh

**Purpose**: Complete automated setup for Ubuntu development environment

**What it does**:
- Updates system packages
- Installs build dependencies (gcc, make, pkg-config, libssl-dev)
- Installs and starts Tor daemon
- Installs Rust toolchain via rustup
- Downloads and extracts Monero CLI
- Configures git pre-commit hooks
- Builds the project
- Runs initial tests

**Usage**:
```bash
./scripts/ubuntu-setup.sh
```

**Requirements**: Ubuntu 20.04+, sudo privileges, internet connection

### check-environment.sh

**Purpose**: Verify all required tools and services are installed and running

**What it checks**:
- System tools (curl, wget, git, jq)
- Build tools (gcc, make, pkg-config)
- Rust toolchain (rustc, cargo, rustfmt, clippy)
- Tor daemon and SOCKS proxy
- Monero CLI binaries
- Running services (monerod, wallet-rpc)
- Network ports (Tor, Monero RPC)
- Project structure
- OPSEC configuration

**Usage**:
```bash
./scripts/check-environment.sh
```

**Exit codes**:
- `0`: All checks passed
- `1`: Critical failures detected

### setup-monero-testnet.sh

**Purpose**: Setup and start Monero testnet wallet RPC

**What it does**:
- Downloads Monero CLI if not present
- Starts testnet daemon (`monerod --testnet`)
- Creates testnet wallet (with empty password for testing)
- Starts wallet RPC on `127.0.0.1:18082`
- Tests RPC connectivity

**Usage**:
```bash
./scripts/setup-monero-testnet.sh --wallet buyer
./scripts/setup-monero-testnet.sh --wallet seller --path ~/custom-path
```

**Parameters**:
- `--wallet NAME`: Wallet name (default: "buyer")
- `--path PATH`: Monero installation path (default: `~/monero-testnet`)

### pre-commit.sh

**Purpose**: Run all pre-commit validation checks

**What it checks**:
1. Compilation (`cargo check`)
2. Code formatting (`cargo fmt --check`)
3. Clippy lints (`cargo clippy -- -D warnings`)
4. Unit tests (`cargo test`)
5. Spec coverage
6. Unwrap usage
7. TODO comments
8. Security theatre patterns
9. Monero/Tor security patterns
10. Metrics update

**Usage**:
```bash
# Manual run
./scripts/pre-commit.sh

# Automatically runs via git hook
git commit -m "message"
```

**Exit codes**:
- `0`: All checks passed (or warnings only)
- `1`: Errors detected, commit blocked

### check-security-theatre.sh

**Purpose**: Detect security theatre patterns in Rust code

**Detects**:
- Unwrapped results (`.unwrap()`)
- Placeholder comments (TODO, FIXME, HACK)
- Panic macros (`panic!`, `todo!`, `unimplemented!`)
- Hardcoded credentials
- Debug print statements (`println!`, `dbg!`)
- Weak assertions (`assert!(true)`)

**Usage**:
```bash
# Standard scan
./scripts/check-security-theatre.sh

# Verbose output
./scripts/check-security-theatre.sh --verbose

# Custom path
./scripts/check-security-theatre.sh --path src/wallet

# Custom ignore file
./scripts/check-security-theatre.sh --ignore .custom-ignore
```

**Exception handling**: Add patterns to `.security-theatre-ignore`:
```
cli/src/test_tool.rs:println!
**/tests/*.rs:expect\(".*"\)
```

### test-rpc.sh

**Purpose**: Verify Monero RPC connectivity and basic operations

**Tests**:
1. Endpoint reachability
2. `get_version` RPC call
3. `get_address` RPC call
4. `get_balance` RPC call
5. `is_multisig` RPC call

**Usage**:
```bash
./scripts/test-rpc.sh
```

**Requirements**: Monero wallet RPC running on `127.0.0.1:18082`

## Script Conventions

### Error Handling

All scripts follow these conventions:
- Exit code `0` for success
- Exit code `1` for failure
- Use `set -e` to exit on first error (when appropriate)

### Colors

Scripts use consistent color coding:
- **Red**: Errors, failures
- **Green**: Success, pass
- **Yellow**: Warnings, important info
- **Cyan**: Informational messages, section headers
- **Blue**: Step headers

### Output Format

```bash
# Section headers
echo -e "${CYAN}═══ Section Name ═══${NC}"

# Status messages
echo -e "${GREEN}✅ Success message${NC}"
echo -e "${RED}❌ Error message${NC}"
echo -e "${YELLOW}⚠️  Warning message${NC}"
```

## Making Scripts Executable

On first clone, make all scripts executable:

```bash
chmod +x scripts/*.sh
```

Or use the setup script which does this automatically:

```bash
./scripts/ubuntu-setup.sh
```

## Troubleshooting

### Permission Denied

```bash
chmod +x scripts/*.sh
```

### Script Not Found

Ensure you're running from project root:

```bash
cd "$(git rev-parse --show-toplevel)"
./scripts/script-name.sh
```

### Dependencies Missing

Run environment check:

```bash
./scripts/check-environment.sh
```

Then install missing dependencies:

```bash
./scripts/ubuntu-setup.sh
```

## Converting from Windows

If migrating from Windows development:

| Windows (PowerShell) | Ubuntu (Bash) |
|---------------------|---------------|
| `.\scripts\pre-commit.ps1` | `./scripts/pre-commit.sh` |
| `Start-Process` | `./command &` or `systemctl start` |
| `Get-Process` | `ps aux \| grep` or `pgrep` |
| `Stop-Process` | `pkill` |
| `Test-Path` | `[[ -f file ]]` or `[[ -d dir ]]` |
| `Write-Host "msg" -ForegroundColor Green` | `echo -e "${GREEN}msg${NC}"` |

## Security Notes

### OPSEC Compliance

All scripts follow project OPSEC guidelines:
- Monero RPC binds to `127.0.0.1` only
- Tor connections use SOCKS5 proxy
- No sensitive data logged (.onion, keys, IPs)
- Empty passwords for testnet only

### Script Validation

Before running any script:
1. Review source code
2. Check for hardcoded credentials
3. Verify network operations use Tor
4. Ensure RPC binds to localhost only

### Safe Testing

Always use testnet:
- Testnet XMR has no real value
- Mistakes won't cost money
- Faster synchronization
- Safe for experimentation

## Contributing

When adding new scripts:

1. **Create both versions** (`.ps1` and `.sh`)
2. **Add documentation** to this README
3. **Follow conventions** (colors, error handling)
4. **Test thoroughly** on target platform
5. Update project documentation with new commands

## Resources

- [Bash scripting guide](https://www.gnu.org/software/bash/manual/)
- [Monero RPC documentation](https://www.getmonero.org/resources/developer-guides/wallet-rpc.html)
- [Tor documentation](https://www.torproject.org/docs/)

---

**Last Updated**: 2025-10-16
**Platform**: Cross-platform (Windows PowerShell / Linux Bash)
