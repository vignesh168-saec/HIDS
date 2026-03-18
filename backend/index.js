const express = require('express');
console.log('🚀 Backend server starting...');
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

// Configure multer for memory storage with limits
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 1
    }
});

// Queue for VirusTotal requests to respect rate limits
const vtRequestQueue = [];
let isProcessingQueue = false;

const processQueue = async () => {
    if (isProcessingQueue || vtRequestQueue.length === 0) return;
    isProcessingQueue = true;
    console.log(`⏳ Processing VT Queue: ${vtRequestQueue.length} items pending...`);

    while (vtRequestQueue.length > 0) {
        const { hash, resolve, reject } = vtRequestQueue.shift();
        console.log(`🔍 Checking hash: ${hash}...`);
        try {
            const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
                headers: { 'x-apikey': vtApiKey }
            });
            const attrs = response.data.data.attributes;
            const stats = attrs.last_analysis_stats;
            const results = attrs.last_analysis_results || {};
            
            console.log(`✅ VT Result for ${hash}: ${stats.malicious + stats.suspicious} detections.`);

            // Get top 3 detection names
            const detections = Object.values(results)
                .filter(r => r.category === 'malicious' || r.category === 'suspicious')
                .map(r => r.result)
                .filter(Boolean)
                .slice(0, 3);

            resolve({
                flaggedCount: stats.malicious + stats.suspicious,
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                detections: detections.join(', '),
                hash: hash
            });
        } catch (error) {
            if (error.response && error.response.status === 404) {
                console.log(`ℹ️ Hash ${hash} not found in VT database.`);
                resolve({ flaggedCount: 0, malicious: 0, suspicious: 0, detections: '', hash });
            } else if (error.response && error.response.status === 429) {
                vtRequestQueue.unshift({ hash, resolve, reject });
                console.log('🛑 VT Rate limit hit, waiting 60s...');
                await new Promise(r => setTimeout(r, 60000));
            } else {
                console.error(`❌ Error checking hash ${hash}:`, error.message);
                resolve({ flaggedCount: 0, malicious: 0, suspicious: 0, detections: '', hash });
            }
        }
        console.log(`⏲️ Resting for 15s (VT rate limit compliance)...`);
        await new Promise(r => setTimeout(r, 15000)); // 15s delay for free tier
    }
    isProcessingQueue = false;
    console.log('✅ VT Queue processing paused/empty.');
};

const getVTAnalysis = (hash) => {
    return new Promise((resolve, reject) => {
        vtRequestQueue.push({ hash, resolve, reject });
        processQueue();
    });
};

// Background task to process files
const runAnalysis = async (jobId, files) => {
    const job = activeJobs.get(jobId);
    if (!job) return;
    const allResults = [];
    console.log(`🏗️ Starting background analysis for Job ${jobId}...`);

    try {
        for (const file of files) {
            console.log(`📄 Parsing file: ${file.originalname}`);
            const content = file.buffer.toString();
            const records = parse(content, { columns: true, skip_empty_lines: true });

            for (const record of records) {
                const hash = record.Hash;
                const path = record.Path;
                const name = record.Name;
                const category = record.Category || 'Unknown';

                if (hash && hash.length === 64 && /^[a-fA-F0-9]+$/.test(hash)) {
                    job.currentFile = name;
                    console.log(`🔬 Analyzing ${name} (${hash.substring(0, 8)}...)`);
                    const analysis = await getVTAnalysis(hash);
                    job.processed++;
                    
                    if (analysis.flaggedCount > 0) {
                        job.flaggedCount++;
                        console.log(`🚩 FLAGGED: ${name} (Matches: ${analysis.flaggedCount})`);
                        allResults.push({
                            category,
                            filename: name,
                            flaggedCount: analysis.flaggedCount,
                            malicious: analysis.malicious,
                            suspicious: analysis.suspicious,
                            vtLink: { text: 'View on VirusTotal', hyperlink: `https://www.virustotal.com/gui/file/${hash}` },
                            detections: analysis.detections,
                            filePath: path
                        });
                    }
                }
            }
        }

        console.log(`📊 Generating Excel report for Job ${jobId} with ${allResults.length} detections...`);
        // Generate Enriched Excel
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Security Analysis');

        // 1. Summary Header
        worksheet.mergeCells('A1:H1');
        const titleCell = worksheet.getCell('A1');
        titleCell.value = 'HOST INVENTORY SECURITY ANALYSIS SUMMARY';
        titleCell.font = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
        titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } }; // Slate 800
        titleCell.alignment = { horizontal: 'center' };

        worksheet.getRow(2).values = ['Total Unique Hashes', 'Total Flagged', 'Malicious Found', 'Suspicious Found'];
        worksheet.getRow(2).font = { bold: true };
        
        const totalMalicious = allResults.reduce((sum, r) => sum + r.malicious, 0);
        const totalSuspicious = allResults.reduce((sum, r) => sum + r.suspicious, 0);
        worksheet.getRow(3).values = [job.total, job.flaggedCount, totalMalicious, totalSuspicious];

        // 2. Data Table
        const headerRowIndex = 5;
        worksheet.columns = [
            { header: 'Category', key: 'category', width: 15 },
            { header: 'Filename', key: 'filename', width: 25 },
            { header: 'Flagged Count', key: 'flaggedCount', width: 15 },
            { header: 'Malicious', key: 'malicious', width: 12 },
            { header: 'Suspicious', key: 'suspicious', width: 12 },
            { header: 'VirusTotal Link', key: 'vtLink', width: 20 },
            { header: 'Top Detections', key: 'detections', width: 40 },
            { header: 'File Path', key: 'filePath', width: 50 }
        ];

        // Apply column headers to the specific row
        const headerRow = worksheet.getRow(headerRowIndex);
        headerRow.values = worksheet.columns.map(c => c.header);
        headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        headerRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF334155' } }; // Slate 700

        // Add Data
        allResults.forEach((r, idx) => {
            const row = worksheet.addRow(r);
            // Column F is the link
            row.getCell(6).font = { color: { argb: 'FF3B82F6' }, underline: true };
        });

        // 3. Conditional Formatting (Flagged Count is Column C / Index 3)
        if (allResults.length > 0) {
            worksheet.addConditionalFormatting({
                ref: `C${headerRowIndex + 1}:C${headerRowIndex + allResults.length}`,
                rules: [
                    {
                        type: 'cellIs',
                        operator: 'greaterThanOrEqual',
                        formulae: [10],
                        style: { fill: { type: 'pattern', pattern: 'solid', bgColor: { argb: 'FFFCA5A5' } }, font: { color: { argb: 'FF991B1B' } } } // Red
                    },
                    {
                        type: 'cellIs',
                        operator: 'between',
                        formulae: [1, 9],
                        style: { fill: { type: 'pattern', pattern: 'solid', bgColor: { argb: 'FFFED7AA' } }, font: { color: { argb: 'FF9A3412' } } } // Orange
                    }
                ]
            });
        }

        job.reportBuffer = await workbook.xlsx.writeBuffer();
        job.status = 'complete';
        console.log(`✨ Job ${jobId} finalized. Report ready.`);
    } catch (error) {
        console.error(`❌ Job ${jobId} failed:`, error);
        job.status = 'error';
        job.error = error.message;
    }
};

app.post('/upload', (req, res) => {
    console.log('📥 Incoming upload request...');
    upload.array('files', 5)(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            console.warn(`⚠️ Multer error: ${err.code}`);
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).send('File too large. Max 10MB.');
            }
            if (err.code === 'LIMIT_FILE_COUNT') {
                return res.status(413).send('Max 5 files per upload.');
            }
            return res.status(400).send(err.message);
        } else if (err) {
            console.error('❌ Upload error:', err);
            return res.status(500).send('Upload failed.');
        }

        if (!req.files || req.files.length === 0) {
            console.warn('⚠️ No files received in request.');
            return res.status(400).send('No files selected.');
        }

        try {
            let totalHashes = 0;
            const requiredHeaders = ['Category', 'Name', 'Path', 'Hash'];

            for (const file of req.files) {
                console.log(`🔎 Validating CSV: ${file.originalname}`);
                const records = parse(file.buffer.toString(), { columns: true, skip_empty_lines: true });
                
                if (records.length === 0) {
                    console.warn(`⚠️ File ${file.originalname} is empty.`);
                    return res.status(400).send('The uploaded file is empty.');
                }

                const headers = Object.keys(records[0]);
                const missing = requiredHeaders.filter(h => !headers.includes(h));
                if (missing.length > 0) {
                    console.warn(`⚠️ Missing columns in ${file.originalname}: ${missing.join(', ')}`);
                    return res.status(400).send('Invalid file format. Please upload a valid inventory CSV generated by our script.');
                }

                const validHashes = records.filter(r => r.Hash && r.Hash.length === 64 && /^[a-fA-F0-9]+$/.test(r.Hash));
                if (validHashes.length === 0) {
                    console.warn(`⚠️ No valid hashes found in ${file.originalname}.`);
                    return res.status(400).send('No valid SHA-256 hashes found in this file.');
                }

                totalHashes += validHashes.length;
            }

            const jobId = crypto.randomUUID();
            console.log(`✅ Upload valid. Initializing Job ${jobId} with ${totalHashes} hashes.`);
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
            console.error('❌ Error initializing job:', error);
            res.status(500).send('Internal server error.');
        }
    });
});

app.get('/jobs/:id/progress', (req, res) => {
    const jobId = req.params.id;
    const job = activeJobs.get(jobId);

    if (!job) {
        console.warn(`⚠️ Progress request for non-existent Job ${jobId}`);
        return res.status(404).send('Job not found.');
    }

    console.log(`📡 Opening SSE stream for Job ${jobId}`);
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
            console.log(`🔌 Closing SSE stream for Job ${jobId} (${job.status})`);
            clearInterval(interval);
            res.end();
        }
    }, 1000);

    req.on('close', () => {
        console.log(`🔌 Client disconnected from Job ${jobId}`);
        clearInterval(interval);
    });
});

app.get('/jobs/:id/download', (req, res) => {
    const jobId = req.params.id;
    const job = activeJobs.get(jobId);

    if (!job || !job.reportBuffer) {
        console.warn(`⚠️ Download request for missing/incomplete Job ${jobId}`);
        return res.status(404).send('Report not ready or job not found.');
    }

    console.log(`📦 Serving Excel report for Job ${jobId}`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Analysis_Report.xlsx');
    res.send(job.reportBuffer);
    
    // Cleanup
    activeJobs.delete(jobId);
    console.log(`🗑️ Job ${jobId} data cleaned up after download.`);
});

app.listen(port, () => {
    console.log(`----------------------------------------`);
    console.log(`🚀 HID Backend Service running on port ${port}`);
    console.log(`⏲️ Rate limits: 4 requests per minute (VT Free Tier)`);
    console.log(`----------------------------------------`);
});
