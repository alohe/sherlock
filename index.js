import express from 'express';
import { spawn } from 'node:child_process';
import rateLimit from 'express-rate-limit';
import NodeCache from 'node-cache';

const app = express();
const PORT = process.env.PORT || 3000;

// Enable JSON parsing
app.use(express.json());

// Initialize cache with 1 hour TTL
const cache = new NodeCache({ stdTTL: 3600 });

// Rate limiting - 10 requests per minute
const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10, // limit each IP to 10 requests per windowMs
    message: { error: 'Too many requests', status: 429 }
});

// Basic security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        code: 500
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.use(limiter);

// Input validation middleware
const validateUsernames = (req, res, next) => {
    const usernames = req.params.usernames;
    
    if (!usernames) {
        return res.status(400).json({
            status: 'error',
            message: 'Usernames parameter is required',
            code: 400
        });
    }

    const usernameArray = usernames.split(',');
    if (usernameArray.length > 5) {
        return res.status(400).json({
            status: 'error',
            message: 'Maximum 5 usernames allowed per request',
            code: 400
        });
    }

    const invalidUsernames = usernameArray.filter(username => 
        !/^[a-zA-Z0-9_-]{1,30}$/.test(username)
    );

    if (invalidUsernames.length > 0) {
        return res.status(400).json({
            status: 'error',
            message: 'Invalid username format detected',
            invalidUsernames,
            code: 400
        });
    }

    next();
};

app.get('/check/:usernames', validateUsernames, async (req, res) => {
    const startTime = Date.now();
    const usernames = req.params.usernames.split(',');
    
    try {
        // Check cache first
        const cacheKey = usernames.sort().join(',');
        const cachedResults = cache.get(cacheKey);
        if (cachedResults) {
            const duration = Date.now() - startTime;
            console.log(`Cache hit! Returned results in ${duration}ms`);
            return res.status(200).json({
                status: 'success',
                results: cachedResults,
                metadata: {
                    duration: `${duration}ms`,
                    source: 'cache',
                    timestamp: new Date().toISOString()
                },
                code: 200
            });
        }

        const command = 'sherlock';
        const args = usernames;

        const process = spawn(command, args);
        let output = '';

        process.stdout.on('data', (data) => {
            output += data.toString();
        });

        process.stderr.on('data', (data) => {
            console.error(`Sherlock Error: ${data.toString()}`);
        });

        const timeout = setTimeout(() => {
            process.kill();
            return res.status(504).json({
                status: 'error',
                message: 'Request timeout',
                code: 504
            });
        }, 300000); // 5 minute timeout

        process.on('close', (code) => {
            clearTimeout(timeout);
            const duration = Date.now() - startTime;
            
            if (code !== 0) {
                console.log(`Request failed after ${duration}ms`);
                return res.status(500).json({
                    status: 'error',
                    message: 'Error executing Sherlock',
                    metadata: {
                        duration: `${duration}ms`,
                        exitCode: code
                    },
                    code: 500
                });
            }

            const results = parseSherlockOutput(output);
            const totalResults = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
            console.log(`Request completed in ${duration}ms, found ${totalResults} results`);
            
            // Store results in cache
            cache.set(cacheKey, results);
            
            res.status(200).json({
                status: 'success',
                results,
                metadata: {
                    duration: `${duration}ms`,
                    source: 'sherlock',
                    totalResults,
                    timestamp: new Date().toISOString()
                },
                code: 200
            });
        });

    } catch (error) {
        console.error('Unexpected error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal server error',
            code: 500
        });
    }
});

function parseSherlockOutput(output) {
    const lines = output.split('\n');
    const results = {};
    let currentUser = '';

    try {
        for (const line of lines) {
            if (line.startsWith('[*] Checking username')) {
                currentUser = line.split(' ')[3];
                results[currentUser] = [];
            } else if (line.startsWith('[+]')) {
                const parts = line.split(': ');
                if (parts.length === 2) {
                    results[currentUser].push({
                        site: parts[0].replace('[+]', '').trim(),
                        url: parts[1].trim(),
                        verified: true
                    });
                }
            }
        }
        return results;
    } catch (error) {
        console.error('Error parsing Sherlock output:', error);
        throw new Error('Failed to parse Sherlock output');
    }
}

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        status: 'error',
        message: 'Route not found',
        code: 404
    });
});

app.listen(PORT, () => {
    console.log(`Sherlock API running on http://localhost:${PORT}`);
});
