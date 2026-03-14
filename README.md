# DNS Email Security Checker

A Python command-line tool that performs comprehensive checks on email-related DNS records and visualises their security posture using color-coded output.

## Features

This tool checks and validates the following email security records:

- **MX Records** - Mail exchange records for email delivery
- **SPF (Sender Policy Framework)** - Validates authorised email senders and counts DNS lookups
- **DKIM (DomainKeys Identified Mail)** - Checks for email signing keys
- **DMARC (Domain-based Message Authentication)** - Email authentication policy with alignment checks
- **MTA-STS (SMTP Mail Transfer Agent Strict Transport Security)** - Enforces secure SMTP connections
- **BIMI (Brand Indicators for Message Identification)** - Verifies brand logo presence

## Color-Coded Output

The tool uses a traffic light system to indicate record quality:

- 🟢 **Green** - Record is present and properly configured
- 🟡 **Yellow** - Record exists but has warnings (e.g., SPF lookup limit exceeded, DMARC alignment not strict)
- 🔴 **Red** - Record is missing or misconfigured

## Requirements

- Python 3.x
- `dnspython` library
- `requests` library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/alan-berger/dnstoolbox.git
cd dnstoolbox
```

2. Install required dependencies:
```bash
pip install dnspython requests
```

## Usage

### Command Line Argument

```bash
./dns_checker.py example.com
```

or

```bash
python3 dns_checker.py example.com
```

### Interactive Mode

Run without arguments to be prompted for a domain:

```bash
./dns_checker.py
```

## Example Output

```
--- DNS & Policy Check Results ---
MX Records: ['10 mail.example.com.']
SPF Record: ['v=spf1 include:_spf.example.com ~all', 'DNS Lookups: 1']
DKIM Record (selectors=default, selector1, selector2): ['default: v=DKIM1; k=rsa; p=MIGfMA0...']
DMARC Record: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com', 'Policy=REJECT, ASPF=R, ADKIM=R']
MTA-STS Record: ['v=STSv1; id=20231201', 'Policy file found at https://mta-sts.example.com/.well-known/mta-sts.txt']
BIMI Record: ['v=BIMI1; l=https://example.com/logo.svg', 'Logo found at https://example.com/logo.svg']
```

## How It Works

### SPF Validation
- Counts DNS lookup mechanisms (include, a, mx, ptr, exists, redirect)
- Warns if lookup count exceeds 10 (RFC 7208 limit)

### DMARC Analysis
- Checks enforcement policy (none/quarantine/reject)
- Evaluates SPF and DKIM alignment modes (relaxed/strict)
- Color codes based on policy strength and alignment settings

### MTA-STS Verification
- Validates DNS TXT record presence
- Attempts to fetch and verify the policy file at `https://mta-sts.{domain}/.well-known/mta-sts.txt`

### BIMI Validation
- Checks for BIMI TXT record at `default._bimi.{domain}`
- Validates logo accessibility at the specified URL

### DKIM Detection
- Tests common selectors: `default`, `selector1`, `selector2`
- Can be extended to check additional selectors

## Technical Details

- Uses `dnspython` for DNS queries
- Implements proper timeout and error handling
- Follows RFC standards for SPF (RFC 7208) and DMARC
- Custom User-Agent for HTTP requests to avoid blocking

## Limitations

- DKIM checks only test common selector names (default, selector1, selector2)
- Requires internet connectivity for DNS lookups and HTTP checks
- Does not perform deep policy file parsing for MTA-STS

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Author

Created to help system administrators and security professionals quickly assess email security configurations.

## Acknowledgments

- RFC 7208 (SPF)
- RFC 6376 (DKIM)
- RFC 7489 (DMARC)
- RFC 8461 (MTA-STS)
- BIMI Working Group Specifications
