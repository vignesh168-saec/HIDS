'use client';

import * as React from 'react';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Box from '@mui/material/Box';
import WindowIcon from '@mui/icons-material/Window';
import TerminalIcon from '@mui/icons-material/Terminal';
import DownloadIcon from '@mui/icons-material/Download';
import Link from 'next/link';
import { ThemeProvider, createTheme, styled } from '@mui/material/styles';

// Premium dark-themed MUI instance
const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: '#60a5fa', // Bright blue
        },
        background: {
            default: 'transparent',
        },
    },
    typography: {
        fontFamily: 'inherit',
    },
});

const StyledTab = styled(Tab)(({ theme }) => ({
    textTransform: 'none',
    minWidth: 0,
    [theme.breakpoints.up('sm')]: {
        minWidth: 0,
    },
    fontWeight: 600,
    marginRight: theme.spacing(1),
    color: 'rgba(255, 255, 255, 0.5)',
    borderRadius: '8px',
    transition: 'all 0.2s ease',
    '&:hover': {
        color: 'rgba(255, 255, 255, 0.8)',
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        opacity: 1,
    },
    '&.Mui-selected': {
        color: '#fff',
        backgroundColor: 'rgba(96, 165, 250, 0.1)',
    },
    '&.Mui-focusVisible': {
        backgroundColor: 'rgba(100, 95, 228, 0.32)',
    },
}));

interface TabPanelProps {
    children?: React.ReactNode;
    index: number;
    value: number;
}

function CustomTabPanel(props: TabPanelProps) {
    const { children, value, index, ...other } = props;

    return (
        <div
            role="tabpanel"
            hidden={value !== index}
            id={`simple-tabpanel-${index}`}
            aria-labelledby={`simple-tab-${index}`}
            {...other}
        >
            {value === index && (
                <Box sx={{ py: 3 }}>
                    {children}
                </Box>
            )}
        </div>
    );
}

export default function OSSwitcher() {
    const [value, setValue] = React.useState(0);

    const handleChange = (event: React.SyntheticEvent, newValue: number) => {
        setValue(newValue);
    };

    return (
        <ThemeProvider theme={theme}>
            <Box sx={{ width: '100%', mt: 4 }}>
                <Box sx={{ borderBottom: 1, borderColor: 'rgba(255,255,255,0.1)', mb: 2 }}>
                    <Tabs
                        value={value}
                        onChange={handleChange}
                        aria-label="os switcher tabs"
                        TabIndicatorProps={{
                            style: {
                                height: '3px',
                                borderRadius: '3px 3px 0 0',
                                backgroundColor: '#60a5fa'
                            }
                        }}
                    >
                        <StyledTab
                            icon={<WindowIcon sx={{ fontSize: 20 }} />}
                            label="Windows"
                            iconPosition="start"
                        />
                        <StyledTab
                            icon={<TerminalIcon sx={{ fontSize: 20 }} />}
                            label="Linux"
                            iconPosition="start"
                        />
                    </Tabs>
                </Box>

                <CustomTabPanel value={value} index={0}>
                    <div className="space-y-6">
                        <div className="rounded-xl border border-white/10 p-6 bg-zinc-900/50 backdrop-blur-sm shadow-xl transition-all hover:border-blue-500/30">
                            <h3 className="text-xl font-medium mb-3 text-white flex items-center gap-2">
                                <WindowIcon className="text-blue-400" />
                                Windows Inventory Script
                            </h3>
                            <p className="text-sm text-neutral-400 mb-6">
                                Download and run this PowerShell script as Administrator to collect system inventory.
                            </p>
                            <div className="flex items-center gap-3">
                                <Link
                                    href="/host-inventory.ps1"
                                    download
                                    className="group inline-flex items-center gap-2 rounded-lg h-12 px-6 text-sm font-semibold bg-white text-black hover:bg-neutral-200 transition-all active:scale-95"
                                >
                                    <DownloadIcon sx={{ fontSize: 18 }} />
                                    Download host-inventory.ps1
                                </Link>
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/10 p-6 bg-zinc-900/50 backdrop-blur-sm shadow-xl transition-all hover:border-blue-500/20">
                            <h3 className="text-lg font-medium mb-4 text-white">How to run on Windows</h3>
                            <div className="space-y-4">
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">1</span>
                                    <p className="text-sm text-neutral-300">Open Windows PowerShell as <b>Administrator</b>.</p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">2</span>
                                    <p className="text-sm text-neutral-300">Navigate to Downloads: <code className="bg-black/40 px-2 py-1 rounded text-blue-300 border border-white/5">cd $env:USERPROFILE\Downloads</code></p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">3</span>
                                    <p className="text-sm text-neutral-300">Bypass execution policy: <code className="bg-black/40 px-2 py-1 rounded text-blue-300 border border-white/5">Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass</code></p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">4</span>
                                    <p className="text-sm text-neutral-300">Run the script: <code className="bg-black/40 px-2 py-1 rounded text-blue-300 border border-white/5">./host-inventory.ps1</code></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </CustomTabPanel>

                <CustomTabPanel value={value} index={1}>
                    <div className="space-y-6">
                        <div className="rounded-xl border border-white/10 p-6 bg-zinc-900/50 backdrop-blur-sm shadow-xl transition-all hover:border-blue-500/30">
                            <h3 className="text-xl font-medium mb-3 text-white flex items-center gap-2">
                                <TerminalIcon className="text-blue-400" />
                                Linux Inventory Script
                            </h3>
                            <p className="text-sm text-neutral-400 mb-6">
                                Download and run this integrated Bash script to collect process, service, and config inventory.
                            </p>
                            <div className="flex items-center gap-3">
                                <Link
                                    href="/host-inventory.sh"
                                    download
                                    className="group inline-flex items-center gap-2 rounded-lg h-12 px-6 text-sm font-semibold bg-white text-black hover:bg-neutral-200 transition-all active:scale-95"
                                >
                                    <DownloadIcon sx={{ fontSize: 18 }} />
                                    Download host-inventory.sh
                                </Link>
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/10 p-6 bg-zinc-900/50 backdrop-blur-sm shadow-xl transition-all hover:border-blue-500/20">
                            <h3 className="text-lg font-medium mb-4 text-white">How to run on Linux</h3>
                            <div className="space-y-4">
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">1</span>
                                    <p className="text-sm text-neutral-300">Open your terminal.</p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">2</span>
                                    <p className="text-sm text-neutral-300">Make the script executable: <code className="bg-black/40 px-2 py-1 rounded text-blue-300 border border-white/5">chmod +x host-inventory.sh</code></p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">3</span>
                                    <p className="text-sm text-neutral-300">Run the script: <code className="bg-black/40 px-2 py-1 rounded text-blue-300 border border-white/5">./host-inventory.sh</code></p>
                                </div>
                                <div className="flex gap-4 items-start">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold">4</span>
                                    <p className="text-sm text-neutral-300">Check generated CSV files in the current directory.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </CustomTabPanel>
            </Box>
        </ThemeProvider>
    );
}
