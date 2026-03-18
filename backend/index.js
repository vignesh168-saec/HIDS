const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const axios = require('axios');
const ExcelJS = require('exceljs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 2999;
const vtApiKey = process.env.VIRUSTOTAL_API_KEY;

app.use(cors());
app.use(express.json());

// In-memory job store
const activeJobs = new Map();

// Configure multer for memory storage
const upload = multer({ storage: multer.memoryStorage() });

// Queue for VirusTotal requests to respect rate limits
const vtRequestQueue = [];
let isProcessingQueue = false;

const processQueue = async () => {
    if (isProcessingQueue || vtRequestQueue.length === 0) return;
    isProcessingQueue = true;

    while (vtRequestQueue.length > 0) {
        const { hash, resolve, reject } = vtRequestQueue.shift();
        try {
            const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
                headers: { 'x-apikey': vtApiKey }
            });
            const stats = response.data.data.attributes.last_analysis_stats;
            const flaggedCount = stats.malicious + stats.suspicious;
            resolve(flaggedCount);
        } catch (error) {
            if (error.response && error.response.status === 404) {
                resolve(0);
            } else if (error.response && error.response.status === 429) {
                vtRequestQueue.unshift({ hash, resolve, reject });
                console.log('Rate limit hit, waiting 60s...');
                await new Promise(r => setTimeout(r, 60000));
            } else {
                console.error(`Error checking hash ${hash}:`, error.message);
                resolve(0);
            }
        }
        await new Promise(r => setTimeout(r, 15000)); // 15s delay for free tier
    }
    isProcessingQueue = false;
};

const getFlaggedCount = (hash) => {
    return new Promise((resolve, reject) => {
        vtRequestQueue.push({ hash, resolve, reject });
        processQueue();
    });
};

// Background task to process files
const runAnalysis = async (jobId, files) => {
    const job = activeJobs.get(jobId);
    const allResults = [];

    try {
        for (const file of files) {
            const content = file.buffer.toString();
            const records = parse(content, { columns: true, skip_empty_lines: true });

            for (const record of records) {
                const hash = record.Hash;
                const path = record.Path;
                const name = record.Name;

                if (hash && hash.length === 64 && /^[a-fA-F0-9]+$/.test(hash)) {
                    job.currentFile = name;
                    const flaggedCount = await getFlaggedCount(hash);
                    job.processed++;
                    if (flaggedCount > 0) {
                        job.flaggedCount++;
                        allResults.push({ filename: name, flaggedCount, filePath: path });
                    }
                }
            }
        }

        // Generate Excel
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Flagged Files');
        worksheet.columns = [
            { header: 'Filename', key: 'filename', width: 30 },
            { header: 'Flagged Count', key: 'flaggedCount', width: 15 },
            { header: 'File Path', key: 'filePath', width: 50 }
        ];
        allResults.forEach(r => worksheet.addRow(r));
        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE0E0E0' } };

        job.reportBuffer = await workbook.xlsx.writeBuffer();
        job.status = 'complete';
    } catch (error) {
        console.error(`Job ${jobId} failed:`, error);
        job.status = 'error';
        job.error = error.message;
    }
};

app.post('/upload', upload.array('files'), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).send('No files uploaded.');

        let totalHashes = 0;
        for (const file of req.files) {
            const records = parse(file.buffer.toString(), { columns: true, skip_empty_lines: true });
            totalHashes += records.filter(r => r.Hash && r.Hash.length === 64).length;
        }

        const jobId = crypto.randomUUID();
        activeJobs.set(jobId, {
            id: jobId,
            total: totalHashes,
            processed: 0,
            flaggedCount: 0,
            currentFile: '',
            status: 'processing',
            reportBuffer: null
        });

        runAnalysis(jobId, req.files); // Run in background

        res.json({ jobId });
    } catch (error) {
        res.status(500).send('Error initializing upload.');
    }
});

app.get('/jobs/:id/progress', (req, res) => {
    const jobId = req.params.id;
    const job = activeJobs.get(jobId);

    if (!job) return res.status(404).send('Job not found.');

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const interval = setInterval(() => {
        res.write(`data: ${JSON.stringify({
            processed: job.processed,
            total: job.total,
            flaggedCount: job.flaggedCount,
            currentFile: job.currentFile,
            status: job.status
        })}\n\n`);

        if (job.status === 'complete' || job.status === 'error') {
            clearInterval(interval);
            res.end();
        }
    }, 1000);

    req.on('close', () => clearInterval(interval));
});

app.get('/jobs/:id/download', (req, res) => {
    const job = activeJobs.get(req.params.id);
    if (!job || !job.reportBuffer) return res.status(404).send('Report not ready.');

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Analysis_Report.xlsx');
    res.send(job.reportBuffer);

    // Optional: Keep job for a few minutes for retry, but here we clean up
    // activeJobs.delete(req.params.id);
});

app.listen(port, () => console.log(`Backend listening at http://localhost:${port}`));
