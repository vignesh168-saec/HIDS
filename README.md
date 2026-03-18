# HID Frontend

A minimal Next.js site that lets users download a Windows PowerShell script to collect a unified host inventory and provides instructions to run it.

## Local Development

### Frontend (Port 3000)
```bash
npm install
npm run dev
```

### Threat Analysis Backend (Port 2999)
The backend service processes uploaded CSV files and performs VirusTotal analysis.
```bash
cd backend
npm install
# Add your VIRUSTOTAL_API_KEY to backend/.env
node index.js
```

Then open http://localhost:3000

## Features

- **Inventory Generation**: Download and run `host-inventory.ps1` (Windows) or `host-inventory.sh` (Linux) to collect system telemetry.
- **Threat Analysis**: Upload generated CSV files to cross-reference hashes against VirusTotal.
- **Automated Reporting**: Generates a filtered Excel report (`Analysis_Report.xlsx`) containing only files with a `flaggedCount > 0`.

## What users see

- A clear download button for `host-inventory.ps1` (Windows) and `host-inventory.sh` (Linux)
- Step-by-step instructions to unblock/adjust policy and run the script
- **NEW**: An "Upload & Analyze" section to submit CSV files for processing.
- Progress updates during analysis (note: free-tier VirusTotal lookups take ~15s per unique hash).
- Automatic download of the results Excel file.

## Script location

The script is served from `public/host-inventory.ps1` and available at `/host-inventory.ps1`.

## Security guidance

- Encourage users to verify the script integrity: `Get-FileHash -Algorithm SHA256 .\\host-inventory.ps1`
- Consider serving the script via HTTPS and enabling subresource integrity where applicable.

## Deploying

Any static hosting compatible with Next.js or platforms like Vercel work well. On Vercel, just import the repo; no extra configuration is needed for the `public` asset.
