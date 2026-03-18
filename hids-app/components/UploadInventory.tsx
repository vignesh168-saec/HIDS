'use client';

import * as React from 'react';
import { Box, Button, Typography, Paper, LinearProgress, Alert, Stack, Chip } from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FilePresentIcon from '@mui/icons-material/FilePresent';
import SecurityIcon from '@mui/icons-material/Security';
import TimerIcon from '@mui/icons-material/Timer';
import BugReportIcon from '@mui/icons-material/BugReport';
import { styled } from '@mui/material/styles';

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

const DropZone = styled(Paper, {
    shouldForwardProp: (prop) => prop !== 'isDragging'
})<{ isDragging?: boolean }>(({ theme, isDragging }) => ({
    padding: theme.spacing(4),
    textAlign: 'center',
    cursor: 'pointer',
    border: '2px dashed',
    borderColor: isDragging ? theme.palette.primary.main : 'rgba(255, 255, 255, 0.1)',
    backgroundColor: isDragging ? 'rgba(96, 165, 250, 0.08)' : 'rgba(255, 255, 255, 0.02)',
    transition: 'all 0.2s ease',
    '&:hover': {
        borderColor: theme.palette.primary.main,
        backgroundColor: 'rgba(96, 165, 250, 0.05)',
    },
}));

interface ProgressState {
    processed: number;
    total: number;
    flaggedCount: number;
    currentFile: string;
    status: 'processing' | 'complete' | 'error';
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, '') || '';

export default function UploadInventory() {
    const [files, setFiles] = React.useState<File[]>([]);
    const [uploading, setUploading] = React.useState(false);
    const [isDragging, setIsDragging] = React.useState(false);
    const [progress, setProgress] = React.useState<ProgressState | null>(null);
    const [eta, setEta] = React.useState<string | null>(null);
    const [startTime, setStartTime] = React.useState<number | null>(null);
    const [status, setStatus] = React.useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.files) {
            setFiles(Array.from(event.target.files));
            setStatus(null);
            setProgress(null);
        }
    };

    const formatTime = (ms: number) => {
        const totalSeconds = Math.floor(ms / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
    };

    const handleUpload = async () => {
        if (files.length === 0) return;

        setUploading(true);
        setStatus(null);
        setStartTime(Date.now());

        const formData = new FormData();
        files.forEach(file => formData.append('files', file));

        try {
            const response = await fetch(`${API_BASE_URL}/upload`, {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText);
            }

            const { jobId } = await response.json();

            // Connect to SSE for progress
            const eventSource = new EventSource(`${API_BASE_URL}/jobs/${jobId}/progress`);

            eventSource.onmessage = (event) => {
                const data: ProgressState = JSON.parse(event.data);
                setProgress(data);

                // Calculate ETA
                if (data.processed > 0 && startTime) {
                    const elapsed = Date.now() - startTime;
                    const timePerHash = elapsed / data.processed;
                    const remainingHashes = data.total - data.processed;
                    const remainingTime = remainingHashes * timePerHash;
                    setEta(formatTime(remainingTime));
                }

                if (data.status === 'complete') {
                    eventSource.close();
                    setUploading(false);
                    setStatus({ type: 'success', message: 'Analysis complete! Downloading report...' });
                    window.location.href = `${API_BASE_URL}/jobs/${jobId}/download`;
                }

                if (data.status === 'error') {
                    eventSource.close();
                    setUploading(false);
                    setStatus({ type: 'error', message: 'Analysis failed on server.' });
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                setUploading(false);
                setStatus({ type: 'error', message: 'Connection to analysis server lost.' });
            };

        } catch (error) {
            setUploading(false);
            const errorMessage = error instanceof Error ? error.message : 'Error connecting to the analysis server.';
            setStatus({ type: 'error', message: errorMessage });
        }
    };

    const percentComplete = progress ? Math.round((progress.processed / progress.total) * 100) : 0;

    return (
        <Box sx={{ mt: 8 }}>
                <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <SecurityIcon sx={{ color: '#60a5fa' }} />
                    Hash Analysis & Threat Intelligence
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 4 }}>
                    Upload your collected inventory CSV. Only flagged results will be included in the final Excel report.
                </Typography>

                <Paper sx={{ p: 4, borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(24, 24, 27, 0.4)', backdropFilter: 'blur(8px)' }}>
                    <Stack spacing={3}>
                        {!uploading && !progress && (
                            <DropZone
                                isDragging={isDragging}
                                onClick={() => document.getElementById('inventory-upload')?.click()}
                                onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true); }}
                                onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true); }}
                                onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false); }}
                                onDrop={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    setIsDragging(false);
                                    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                                        setFiles(Array.from(e.dataTransfer.files));
                                        setStatus(null);
                                        setProgress(null);
                                    }
                                }}
                            >
                                <VisuallyHiddenInput
                                    id="inventory-upload"
                                    type="file"
                                    accept=".csv"
                                    onChange={handleFileChange}
                                />
                                <CloudUploadIcon sx={{ fontSize: 40, color: 'rgba(255,255,255,0.3)', mb: 2 }} />
                                <Typography variant="h6" fontWeight={500}>
                                    Select CSV Inventory File
                                </Typography>
                                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)' }}>
                                    Drag and drop or click to browse
                                </Typography>
                            </DropZone>
                        )}

                        {files.length > 0 && !uploading && !progress && (
                            <Box>
                                <Typography variant="subtitle2" sx={{ mb: 1.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <FilePresentIcon sx={{ fontSize: 18 }} />
                                    Selected File:
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

                        {uploading && progress && (
                            <Box sx={{ py: 2 }}>
                                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                                    <Typography variant="subtitle2" fontWeight={600}>
                                        Analyzing hashes... {percentComplete}%
                                    </Typography>
                                    <Stack direction="row" spacing={1}>
                                        {eta && (
                                            <Chip
                                                size="small"
                                                icon={<TimerIcon style={{ fontSize: 14 }} />}
                                                label={`ETA: ${eta}`}
                                                variant="outlined"
                                                sx={{ borderColor: 'rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.6)' }}
                                            />
                                        )}
                                        <Chip
                                            size="small"
                                            icon={<BugReportIcon style={{ fontSize: 14 }} />}
                                            label={`${progress.flaggedCount} flagged`}
                                            color={progress.flaggedCount > 0 ? "error" : "default"}
                                            variant={progress.flaggedCount > 0 ? "filled" : "outlined"}
                                        />
                                    </Stack>
                                </Stack>

                                <LinearProgress
                                    variant="determinate"
                                    value={percentComplete}
                                    sx={{ borderRadius: 1, height: 8, mb: 2 }}
                                />

                                <Typography variant="caption" sx={{ display: 'block', color: 'rgba(255,255,255,0.4)', fontStyle: 'italic' }}>
                                    {progress.status === 'processing' ? `Current: ${progress.currentFile}` : 'Finalizing report...'}
                                </Typography>

                                <Typography variant="caption" sx={{ display: 'block', mt: 1, textAlign: 'center', color: 'rgba(255,255,255,0.5)' }}>
                                    {progress.processed} of {progress.total} unique hashes checked.
                                </Typography>
                            </Box>
                        )}

                        {status && (
                            <Alert severity={status.type} sx={{ borderRadius: 2 }}>
                                {status.message}
                            </Alert>
                        )}

                        {!progress && (
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
                                {uploading ? 'Initializing...' : 'Run Analysis'}
                            </Button>
                        )}

                        {progress && progress.status === 'complete' && (
                            <Button
                                variant="outlined"
                                onClick={() => { setProgress(null); setFiles([]); setStatus(null); }}
                                sx={{ borderRadius: 2, textTransform: 'none' }}
                            >
                                Analyze More Files
                            </Button>
                        )}
                    </Stack>
                </Paper>
            </Box>
    );
}
