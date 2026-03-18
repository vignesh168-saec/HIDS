const express = require('express');
console.log('🚀 Backend server starting...');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const axios = require('axios');
const ExcelJS = require('exceljs');
const crypto = require('crypto');
const Groq = require('groq-sdk');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 2999;
const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
const groqApiKey = process.env.GROQ_API_KEY;

// Fail fast if VT API key is missing
if (!vtApiKey || vtApiKey.trim() === "") {
    console.error('❌ CRITICAL ERROR: VIRUSTOTAL_API_KEY is not set in .env file.');
    console.error('The server cannot function without a valid VirusTotal API key.');
    process.exit(1);
}

// Groq LLM setup (optional — degrades gracefully if missing)
let groqClient = null;
if (groqApiKey && groqApiKey.trim() !== '') {
    groqClient = new Groq({ apiKey: groqApiKey });
    console.log('🤖 Groq LLM enabled — AI recommendations will be generated for flagged files.');
} else {
    console.warn('⚠️ GROQ_API_KEY not set. AI recommendations will be skipped.');
}

app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        uptime: process.uptime(),
        api_key_configured: !!vtApiKey,
        active_jobs: activeJobs.size
    });
});

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

// LLM-powered remediation recommendation (Groq / Llama 3)
const getLLMRecommendation = async (fileInfo) => {
    if (!groqClient) return 'AI recommendations unavailable (API key not configured).';

    const prompt = `You are a cybersecurity analyst. Given the following VirusTotal detection result, provide a concise remediation recommendation in under 100 words.

File: ${fileInfo.filename}
Path: ${fileInfo.filePath}
Category: ${fileInfo.category}
Malicious Detections: ${fileInfo.malicious}
Suspicious Detections: ${fileInfo.suspicious}
Top Detection Names: ${fileInfo.detections}

Rules:
- Use cautious language ("may indicate", "suggests", not "this IS malware")
- Provide 1-2 specific actionable steps
- Mention if the filename mimics a known legitimate program
- Do NOT present uncertain analysis as confirmed fact
- Keep the tone professional and helpful`;

    try {
        const response = await groqClient.chat.completions.create({
            messages: [{ role: 'user', content: prompt }],
            model: 'llama-3.1-8b-instant',
            temperature: 0.3,
            max_tokens: 200
        });
        const recommendation = response.choices[0]?.message?.content?.trim();
        console.log(`🤖 AI recommendation generated for ${fileInfo.filename}`);
        return recommendation || 'No recommendation generated.';
    } catch (error) {
        console.error(`⚠️ LLM error for ${fileInfo.filename}:`, error.message);
        return 'AI recommendation could not be generated for this entry.';
    }
};

// Background task to process files with Duplicate Hash Deduplication
const runAnalysis = async (jobId, files) => {
    const job = activeJobs.get(jobId);
    if (!job) return;
    
    console.log(`🏗️ Starting background analysis for Job ${jobId}...`);

    try {
        // Step 1: Parse all files and gather all records
        const allRecords = [];
        for (const file of files) {
            console.log(`📄 Reading file: ${file.originalname}`);
            const content = file.buffer.toString();
            const records = parse(content, { columns: true, skip_empty_lines: true });
            allRecords.push(...records);
        }

        // Step 2: Identify unique valid SHA-256 hashes
        const uniqueHashes = new Set();
        allRecords.forEach(record => {
            const hash = record.Hash;
            if (hash && hash.length === 64 && /^[a-fA-F0-9]+$/.test(hash)) {
                uniqueHashes.add(hash);
            }
        });

        // Update job total to be the number of UNIQUE hashes (this is what we actually check)
        job.total = uniqueHashes.size;
        console.log(`🗜️ Deduplication complete: ${allRecords.length} rows reduced to ${uniqueHashes.size} unique hashes.`);

        // Step 3: Analyze each UNIQUE hash
        const resultsMap = new Map();
        for (const hash of uniqueHashes) {
            const representativeRecord = allRecords.find(r => r.Hash === hash);
            job.currentFile = representativeRecord ? representativeRecord.Name : 'System File';
            
            console.log(`🔬 Analyzing unique hash: ${hash.substring(0, 8)}... (${job.currentFile})`);
            const analysis = await getVTAnalysis(hash);
            resultsMap.set(hash, analysis);
            job.processed++;

            if (analysis.flaggedCount > 0) {
                job.flaggedCount++;
                console.log(`🚩 FLAGGED: ${job.currentFile} (${analysis.flaggedCount} matches)`);
            }
        }

        // Step 3.5: Generate AI recommendations for FLAGGED unique hashes
        const aiRecommendations = new Map();
        const flaggedHashes = Array.from(resultsMap.entries()).filter(([, a]) => a.flaggedCount > 0);

        if (flaggedHashes.length > 0 && groqClient) {
            console.log(`🤖 Generating AI recommendations for ${flaggedHashes.length} flagged file(s)...`);
            job.currentFile = 'Generating AI insights...';

            for (const [hash, analysis] of flaggedHashes) {
                const record = allRecords.find(r => r.Hash === hash);
                const recommendation = await getLLMRecommendation({
                    filename: record?.Name || 'Unknown',
                    filePath: record?.Path || 'Unknown',
                    category: record?.Category || 'Unknown',
                    malicious: analysis.malicious,
                    suspicious: analysis.suspicious,
                    detections: analysis.detections
                });
                aiRecommendations.set(hash, recommendation);
            }
            console.log(`✅ AI recommendations complete for ${aiRecommendations.size} entries.`);
        } else if (flaggedHashes.length > 0) {
            console.log('⏭️ Skipping AI recommendations (Groq API key not configured).');
        }

        // Step 4: Map results back to ORIGINAL records for the final report
        const finalResultsForExcel = [];
        console.log(`📊 Reconstructing full report from ${allRecords.length} inventory items...`);

        for (const record of allRecords) {
            const hash = record.Hash;
            const analysis = resultsMap.get(hash);

            if (analysis && analysis.flaggedCount > 0) {
                finalResultsForExcel.push({
                    category: record.Category || 'Unknown',
                    filename: record.Name,
                    flaggedCount: analysis.flaggedCount,
                    malicious: analysis.malicious,
                    suspicious: analysis.suspicious,
                    vtLink: { text: 'View on VirusTotal', hyperlink: `https://www.virustotal.com/gui/file/${hash}` },
                    detections: analysis.detections,
                    aiRecommendation: aiRecommendations.get(hash) || 'N/A',
                    filePath: record.Path
                });
            }
        }

        console.log(`📊 Generating Excel report with ${finalResultsForExcel.length} total flagged entries...`);
        // Generate Enriched Excel
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Security Analysis');

        // 1. Summary Header
        worksheet.mergeCells('A1:I1');
        const titleCell = worksheet.getCell('A1');
        titleCell.value = 'HOST INVENTORY SECURITY ANALYSIS SUMMARY';
        titleCell.font = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
        titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } };
        titleCell.alignment = { horizontal: 'center' };

        worksheet.getRow(2).values = ['Total Unique Hashes', 'Total Unique Flagged', 'Malicious Found', 'Suspicious Found'];
        worksheet.getRow(2).font = { bold: true };
        
        const totalMalicious = Array.from(resultsMap.values()).reduce((sum, r) => sum + r.malicious, 0);
        const totalSuspicious = Array.from(resultsMap.values()).reduce((sum, r) => sum + r.suspicious, 0);
        worksheet.getRow(3).values = [job.total, job.flaggedCount, totalMalicious, totalSuspicious];

        // AI Disclaimer row
        worksheet.mergeCells('A4:I4');
        const disclaimerCell = worksheet.getCell('A4');
        disclaimerCell.value = '⚠️ AI recommendations are guidance only — not a substitute for professional malware analysis.';
        disclaimerCell.font = { italic: true, size: 9, color: { argb: 'FF94A3B8' } };

        // 2. Data Table
        const headerRowIndex = 6;
        worksheet.columns = [
            { header: 'Category', key: 'category', width: 15 },
            { header: 'Filename', key: 'filename', width: 25 },
            { header: 'Flagged Count', key: 'flaggedCount', width: 15 },
            { header: 'Malicious', key: 'malicious', width: 12 },
            { header: 'Suspicious', key: 'suspicious', width: 12 },
            { header: 'VirusTotal Link', key: 'vtLink', width: 20 },
            { header: 'Top Detections', key: 'detections', width: 40 },
            { header: 'AI Recommendation', key: 'aiRecommendation', width: 60 },
            { header: 'File Path', key: 'filePath', width: 50 }
        ];

        // Apply column headers to the specific row
        const headerRow = worksheet.getRow(headerRowIndex);
        headerRow.values = worksheet.columns.map(c => c.header);
        headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        headerRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF334155' } };

        // Add Data
        finalResultsForExcel.forEach((r) => {
            const row = worksheet.addRow(r);
            
            // Use the most compatible way to set a hyperlink using an Excel formula
            const linkCell = row.getCell('vtLink');
            linkCell.value = {
                formula: `HYPERLINK("${r.vtLink.hyperlink}", "View on VirusTotal")`,
                result: 'View on VirusTotal'
            };
            linkCell.font = { color: { argb: 'FF3B82F6' }, underline: true };

            // AI Recommendation styling — word wrap + italic
            const aiCell = row.getCell('aiRecommendation');
            aiCell.alignment = { wrapText: true, vertical: 'top' };
            aiCell.font = { italic: true, size: 10, color: { argb: 'FF64748B' } };
        });

        // 3. Conditional Formatting (Flagged Count = Column C)
        if (finalResultsForExcel.length > 0) {
            worksheet.addConditionalFormatting({
                ref: `C${headerRowIndex + 1}:C${headerRowIndex + finalResultsForExcel.length}`,
                rules: [
                    {
                        type: 'cellIs',
                        operator: 'greaterThanOrEqual',
                        formulae: [10],
                        style: { fill: { type: 'pattern', pattern: 'solid', bgColor: { argb: 'FFFCA5A5' } }, font: { color: { argb: 'FF991B1B' } } }
                    },
                    {
                        type: 'cellIs',
                        operator: 'between',
                        formulae: [1, 9],
                        style: { fill: { type: 'pattern', pattern: 'solid', bgColor: { argb: 'FFFED7AA' } }, font: { color: { argb: 'FF9A3412' } } }
                    }
                ]
            });
        }

        job.reportBuffer = await workbook.xlsx.writeBuffer();
        job.status = 'complete';
        console.log(`✨ Job ${jobId} finalized. Deduplication saved ${allRecords.length - job.total} API calls!`);
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
