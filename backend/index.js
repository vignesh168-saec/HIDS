const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const axios = require('axios');
const ExcelJS = require('exceljs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 2999;
const vtApiKey = process.env.VIRUSTOTAL_API_KEY;

app.use(cors());
app.use(express.json());

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
                resolve(0); // Not found in VT is 0 flags
            } else if (error.response && error.response.status === 429) {
                // Rate limit hit, put back in queue and wait
                vtRequestQueue.unshift({ hash, resolve, reject });
                console.log('Rate limit hit, waiting 60s...');
                await new Promise(r => setTimeout(r, 60000));
            } else {
                console.error(`Error checking hash ${hash}:`, error.message);
                resolve(0); // Treat error as 0 flags for now
            }
        }
        // Wait 15 seconds between requests for free tier (4 req/min)
        await new Promise(r => setTimeout(r, 15000));
    }

    isProcessingQueue = false;
};

const getFlaggedCount = (hash) => {
    return new Promise((resolve, reject) => {
        vtRequestQueue.push({ hash, resolve, reject });
        processQueue();
    });
};

app.post('/upload', upload.array('files'), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).send('No files uploaded.');
        }

        const allResults = [];

        for (const file of req.files) {
            const content = file.buffer.toString();
            const records = parse(content, {
                columns: true,
                skip_empty_lines: true
            });

            for (const record of records) {
                const hash = record.Hash;
                const path = record.Path;
                const name = record.Name;

                if (hash && hash.length === 64 && /^[a-fA-F0-9]+$/.test(hash)) {
                    console.log(`Checking hash: ${hash} for file: ${name}`);
                    const flaggedCount = await getFlaggedCount(hash);
                    if (flaggedCount > 0) {
                        allResults.push({
                            filename: name,
                            flaggedCount: flaggedCount,
                            filePath: path
                        });
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

        allResults.forEach(result => {
            worksheet.addRow(result);
        });

        // Set header styling
        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE0E0E0' }
        };

        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Analysis_Report.xlsx');
        res.send(buffer);

    } catch (error) {
        console.error('Upload processing error:', error);
        res.status(500).send('Error processing files.');
    }
});

app.listen(port, () => {
    console.log(`Backend listening at http://localhost:${port}`);
});
