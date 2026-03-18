'use client';

import * as React from 'react';
import { Box, Button, Typography, Paper, LinearProgress, Alert, Stack } from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FilePresentIcon from '@mui/icons-material/FilePresent';
import SecurityIcon from '@mui/icons-material/Security';
import { ThemeProvider, createTheme, styled } from '@mui/material/styles';

const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: '#60a5fa', // Bright blue
        },
        background: {
            default: 'transparent',
            paper: 'rgba(24, 24, 27, 0.8)', // Zinc 900 with opacity
        },
    },
    typography: {
        fontFamily: 'inherit',
    },
});

const VisuallyHiddenInput = styled('input')({
    clip: 'rect(0 0 0 0)',
    clipPath: 'inset(50%)',
    height: 1,
    overflow: 'hidden',
    position: 'absolute',
    bottom: 0,
    left: 0,
    whiteSpace: 'nowrap',
    width: 1,
});

const DropZone = styled(Paper)(({ theme }) => ({
    padding: theme.spacing(4),
    textAlign: 'center',
    cursor: 'pointer',
    border: '2px dashed rgba(255, 255, 255, 0.1)',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    transition: 'all 0.2s ease',
    '&:hover': {
        borderColor: theme.palette.primary.main,
        backgroundColor: 'rgba(96, 165, 250, 0.05)',
    },
}));

export default function UploadInventory() {
    const [files, setFiles] = React.useState<File[]>([]);
    const [uploading, setUploading] = React.useState(false);
    const [status, setStatus] = React.useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.files) {
            setFiles(Array.from(event.target.files));
            setStatus(null);
        }
    };

    const handleUpload = async () => {
        if (files.length === 0) return;

        setUploading(true);
        setStatus({ type: 'info', message: 'Analyzing hashes... This can take a few minutes due to VirusTotal rate limits.' });

        const formData = new FormData();
        files.forEach(file => {
            formData.append('files', file);
        });

        try {
            const response = await fetch('http://localhost:2999/upload', {
                method: 'POST',
                body: formData,
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'Analysis_Report.xlsx';
                document.body.appendChild(a);
                a.click();
                a.remove();
                setStatus({ type: 'success', message: 'Analysis complete! The report has been downloaded.' });
                setFiles([]);
            } else {
                const errorText = await response.text();
                setStatus({ type: 'error', message: `Upload failed: ${errorText}` });
            }
        } catch (error) {
            setStatus({ type: 'error', message: 'Error connecting to the analysis server.' });
        } finally {
            setUploading(false);
        }
    };

    return (
        <ThemeProvider theme={theme}>
            <Box sx={{ mt: 8 }}>
                <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <SecurityIcon sx={{ color: '#60a5fa' }} />
                    Hash Analysis & Threat Intelligence
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 4 }}>
                    Upload your collected inventory CSV to cross-reference file hashes against VirusTotal threats. Only flagged results (flaggedCount &gt; 0) will be included in the final Excel report.
                </Typography>

                <Paper sx={{ p: 4, borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(24, 24, 27, 0.4)', backdropFilter: 'blur(8px)' }}>
                    <Stack spacing={3}>
                        {!uploading && (
                            <DropZone onClick={() => document.getElementById('inventory-upload')?.click()}>
                                <VisuallyHiddenInput 
                                    id="inventory-upload" 
                                    type="file" 
                                    multiple 
                                    accept=".csv" 
                                    onChange={handleFileChange} 
                                />
                                <CloudUploadIcon sx={{ fontSize: 40, color: 'rgba(255,255,255,0.3)', mb: 2 }} />
                                <Typography variant="h6" fontWeight={500}>
                                    Select CSV Inventory Files
                                </Typography>
                                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)' }}>
                                    Drag and drop or click to browse
                                </Typography>
                            </DropZone>
                        )}

                        {files.length > 0 && !uploading && (
                            <Box>
                                <Typography variant="subtitle2" sx={{ mb: 1.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <FilePresentIcon sx={{ fontSize: 18 }} />
                                    Selected Files ({files.length}):
                                </Typography>
                                <Stack spacing={1}>
                                    {files.map((file, idx) => (
                                        <Typography key={idx} variant="caption" sx={{ color: 'rgba(255,255,255,0.6)', backgroundColor: 'rgba(255,255,255,0.05)', p: 1, borderRadius: 1 }}>
                                            {file.name} ({(file.size / 1024).toFixed(1)} KB)
                                        </Typography>
                                    ))}
                                </Stack>
                            </Box>
                        )}

                        {uploading && (
                            <Box sx={{ py: 2 }}>
                                <LinearProgress sx={{ borderRadius: 1, height: 6 }} />
                                <Typography variant="caption" sx={{ display: 'block', mt: 1.5, textAlign: 'center', color: 'rgba(255,255,255,0.5)' }}>
                                    We&apos;re currently cross-referencing your hashes. This takes about 15 seconds per unique hash.
                                </Typography>
                            </Box>
                        )}

                        {status && (
                            <Alert severity={status.type} sx={{ borderRadius: 2 }}>
                                {status.message}
                            </Alert>
                        )}

                        <Button
                            variant="contained"
                            disabled={files.length === 0 || uploading}
                            onClick={handleUpload}
                            disableElevation
                            sx={{
                                height: 48,
                                borderRadius: 2,
                                fontWeight: 600,
                                textTransform: 'none',
                                fontSize: '0.95rem'
                            }}
                        >
                            {uploading ? 'Processing...' : 'Run Analysis'}
                        </Button>
                    </Stack>
                </Paper>
            </Box>
        </ThemeProvider>
    );
}
