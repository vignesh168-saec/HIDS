# HID Frontend

A minimal Next.js site that lets users download a Windows PowerShell script to collect a unified host inventory and provides instructions to run it.

## Local Development

```bash
npm install
npm run dev
```

Then open http://localhost:3000

## Build & Start

```bash
npm run build
npm run start
```

## What users see

- A clear download button for `host-inventory.ps1` (Windows) and `host-inventory.sh` (Linux)
- Step-by-step instructions to unblock/adjust policy and run the script
- Notes on where the CSV is written: `C:\\System_Inventory.csv` (Windows) or `./System_Inventory.csv` (Linux)
- High-level description of what is collected (config files, processes with hashes, services with hashes, Downloads file hashes, etc.)

## Script location

The script is served from `public/host-inventory.ps1` and available at `/host-inventory.ps1`.

## Security guidance

- Encourage users to verify the script integrity: `Get-FileHash -Algorithm SHA256 .\\host-inventory.ps1`
- Consider serving the script via HTTPS and enabling subresource integrity where applicable.

## Deploying

Any static hosting compatible with Next.js or platforms like Vercel work well. On Vercel, just import the repo; no extra configuration is needed for the `public` asset.
