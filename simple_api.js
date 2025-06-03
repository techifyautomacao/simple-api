const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs').promises;
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const url = require('url');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');

// Get the directory where the script is located using __dirname
const APP_DIR = __dirname;

const app = express();
const server = http.createServer(app);

// Constants
const MAX_RECORDS = 50;

// WebSocket server with proxy path support
const wss = new WebSocket.Server({ 
    noServer: true
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'"],
            "connect-src": ["'self'", "ws://localhost:3006", "ws://localhost:3007", "ws://localhost:3008", "wss://codeserver.api-coolify.onlinecenter.com.br"]
        }
    }
}));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(cookieParser());

// Authentication middleware
const AUTH_TOKEN = 'Bearer uzJtmYh8DrCuAK5td3APLxvYds704hOslXZJd7a';
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization;
    
    if (!token || token !== AUTH_TOKEN) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// Constants for UUID cookie
const UUID_COOKIE_NAME = 'user_uuid';
const UUID_COOKIE_MAX_AGE = 1000 * 24 * 60 * 60 * 1000; // 1000 days in milliseconds

// Data file paths - using absolute path
const DATA_DIR = path.join(APP_DIR, 'data');

// Helper function to ensure data directory exists
async function ensureDataDir() {
    try {
        await fs.access(DATA_DIR);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.mkdir(DATA_DIR, { recursive: true });
        } else {
            throw error;
        }
    }
}

// Helper function to get user file path
function getUserFilePath(uuid) {
    return path.join(DATA_DIR, `${uuid}.json`);
}

// Helper function to read user data
async function readUserData(uuid) {
    try {
        await ensureDataDir();
        const userFilePath = getUserFilePath(uuid);
        const data = await fs.readFile(userFilePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            // Create empty data file for user
            const emptyData = [];
            await fs.writeFile(getUserFilePath(uuid), JSON.stringify(emptyData, null, 2));
            return emptyData;
        }
        throw error;
    }
}

// Helper function to write user data
async function writeUserData(uuid, data, changeInfo) {
    // Sort by ID to ensure we keep the newest records
    data.sort((a, b) => b.id - a.id);
    
    // Keep only the newest MAX_RECORDS records
    if (data.length > MAX_RECORDS) {
        data = data.slice(0, MAX_RECORDS);
    }
    
    await ensureDataDir();
    // Ensure proper JSON formatting with indentation
    const jsonData = JSON.stringify(data, null, 2);
    await fs.writeFile(getUserFilePath(uuid), jsonData);
    broadcastUserData(uuid, changeInfo);
}

// Helper function to get or create UUID
function getOrCreateUuid(req, res) {
    // Check if UUID exists in cookie
    let uuid = req.cookies[UUID_COOKIE_NAME];
    
    // If no UUID in cookie, create a new one
    if (!uuid) {
        uuid = uuidv4();
        
        // Set cookie with long expiration
        res.cookie(UUID_COOKIE_NAME, uuid, {
            maxAge: UUID_COOKIE_MAX_AGE,
            httpOnly: true,
            path: '/'
        });
    }
    
    return uuid;
}

// Map to store WebSocket connections by UUID
const wsConnectionsByUuid = new Map();

// Broadcast data to clients with specific UUID
function broadcastUserData(uuid, changeInfo = null) {
    readUserData(uuid).then(data => {
        const message = {
            type: 'update',
            data,
            changeInfo
        };
        
        // Get WebSocket connections for this UUID
        const connections = wsConnectionsByUuid.get(uuid) || [];
        
        connections.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(message));
            }
        });
    });
}

// Handle WebSocket upgrade
server.on('upgrade', (request, socket, head) => {
    const parsedUrl = url.parse(request.url, true);
    const { pathname } = parsedUrl;
    
    // Extract UUID from path
    const pathParts = pathname.split('/');
    const uuidIndex = pathParts.findIndex(part => 
        part.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
    );
    
    if (uuidIndex !== -1) {
        const uuid = pathParts[uuidIndex];
        
        wss.handleUpgrade(request, socket, head, (ws) => {
            // Store UUID with the WebSocket connection
            ws.uuid = uuid;
            wss.emit('connection', ws, request);
        });
    } else if (pathname === '/proxy/3006' || pathname === '/proxy/3007' || pathname === '/') {
        // Legacy path handling (should redirect in HTTP layer)
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else {
        socket.destroy();
    }
});

// WebSocket connection handler
wss.on('connection', (ws, request) => {
    console.log('New WebSocket connection');
    
    const uuid = ws.uuid;
    if (uuid) {
        // Add this connection to the map for the UUID
        if (!wsConnectionsByUuid.has(uuid)) {
            wsConnectionsByUuid.set(uuid, []);
        }
        wsConnectionsByUuid.get(uuid).push(ws);
        
        // Send initial data
        readUserData(uuid).then(data => {
            ws.send(JSON.stringify({ type: 'update', data }));
        });
        
        // Clean up when connection closes
        ws.on('close', () => {
            const connections = wsConnectionsByUuid.get(uuid) || [];
            const index = connections.indexOf(ws);
            if (index !== -1) {
                connections.splice(index, 1);
            }
            if (connections.length === 0) {
                wsConnectionsByUuid.delete(uuid);
            }
        });
    } else {
        // Legacy connection without UUID
        readUserData('default').then(data => {
            ws.send(JSON.stringify({ type: 'update', data }));
        });
    }

    ws.on('error', console.error);
});

// Helper function to extract UUID from URL
function extractUuidFromUrl(req) {
    const pathParts = req.path.split('/');
    const uuidIndex = pathParts.findIndex(part => 
        part.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
    );
    
    return uuidIndex !== -1 ? pathParts[uuidIndex] : null;
}

// Create CRUD handlers
const createCrudHandlers = () => ({
    create: async (req, res) => {
        try {
            const { name, profissao } = req.body;
            if (!name || !profissao) {
                return res.status(400).json({ error: 'Name e occupation são obrigatórios' });
            }

            // Get UUID from URL or cookie
            const urlUuid = extractUuidFromUrl(req);
            const uuid = urlUuid || getOrCreateUuid(req, res);
            
            const data = await readUserData(uuid);
            const newId = data.length > 0 ? Math.max(...data.map(r => r.id)) + 1 : 1;
            const now = new Date().toISOString();
            
            const newRecord = {
                id: newId,
                name,
                profissao,
                dataCriacao: now,
                dataEdicao: now
            };

            data.push(newRecord);
            await writeUserData(uuid, data, {
                type: 'create',
                id: newId,
                timestamp: now
            });
            res.status(201).json(newRecord);
        } catch (error) {
            console.error('Error in create handler:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    read: async (req, res) => {
        try {
            // Get UUID from URL or cookie
            const urlUuid = extractUuidFromUrl(req);
            const uuid = urlUuid || getOrCreateUuid(req, res);
            
            const { id, name, profissao } = req.query;
            let data = await readUserData(uuid);
            
            // Aplicar filtros se fornecidos
            if (id) {
                data = data.filter(record => record.id === parseInt(id));
            }
            
            if (name) {
                const nameLowerCase = name.toLowerCase();
                data = data.filter(record => 
                    record.name.toLowerCase().includes(nameLowerCase)
                );
            }
            
            if (profissao) {
                const profissaoLowerCase = profissao.toLowerCase();
                data = data.filter(record => 
                    record.profissao.toLowerCase().includes(profissaoLowerCase)
                );
            }
            
            res.json(data);
        } catch (error) {
            console.error('Error in read handler:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    update: async (req, res) => {
        try {
            const { id } = req.params;
            const { name, profissao } = req.body;
            
            if (!name || !profissao) {
                return res.status(400).json({ error: 'Name e occupation são obrigatórios' });
            }

            // Get UUID from URL or cookie
            const urlUuid = extractUuidFromUrl(req);
            const uuid = urlUuid || getOrCreateUuid(req, res);
            
            const data = await readUserData(uuid);
            const index = data.findIndex(r => r.id === parseInt(id));
            
            if (index === -1) {
                return res.status(404).json({ error: 'Registro não encontrado' });
            }

            const now = new Date().toISOString();
            data[index] = {
                ...data[index],
                name,
                profissao,
                dataEdicao: now
            };

            await writeUserData(uuid, data, {
                type: 'update',
                id: parseInt(id),
                timestamp: now
            });
            res.status(200).json(data[index]);
        } catch (error) {
            console.error('Error in update handler:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    delete: async (req, res) => {
        try {
            const { id } = req.params;
            
            // Get UUID from URL or cookie
            const urlUuid = extractUuidFromUrl(req);
            const uuid = urlUuid || getOrCreateUuid(req, res);
            
            const data = await readUserData(uuid);
            const index = data.findIndex(r => r.id === parseInt(id));
            
            if (index === -1) {
                return res.status(404).json({ error: 'Registro não encontrado' });
            }

            const now = new Date().toISOString();
            data.splice(index, 1);
            await writeUserData(uuid, data, {
                type: 'delete',
                id: parseInt(id),
                timestamp: now
            });
            res.status(204).send();
        } catch (error) {
            console.error('Error in delete handler:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
});

const handlers = createCrudHandlers();

// UUID redirect middleware
const uuidRedirectMiddleware = (req, res, next) => {
    // Skip for static files and API endpoints
    if (req.path.includes('.') || req.path.includes('/create') || 
        req.path.includes('/read') || req.path.includes('/update') || 
        req.path.includes('/delete')) {
        return next();
    }
    
    // Check if URL already contains a UUID
    const urlUuid = extractUuidFromUrl(req);
    if (urlUuid) {
        return next();
    }
    
    // Get or create UUID from cookie
    const uuid = getOrCreateUuid(req, res);
    
    // Construct redirect URL with UUID
    let redirectUrl = req.originalUrl;
    if (redirectUrl.endsWith('/')) {
        redirectUrl = redirectUrl.slice(0, -1);
    }
    redirectUrl = `${redirectUrl}/${uuid}`;
    
    // Redirect to URL with UUID
    res.redirect(redirectUrl);
};

// Mount routes for both paths
const mountRoutes = (router, prefix = '') => {
    // Add UUID redirect middleware
    router.use(prefix, uuidRedirectMiddleware);
    
    // API routes
    router.post(`${prefix}/:uuid?/create`, authenticateToken, handlers.create);
    router.get(`${prefix}/:uuid?/read`, authenticateToken, handlers.read);
    router.put(`${prefix}/:uuid?/update/:id`, authenticateToken, handlers.update);
    router.delete(`${prefix}/:uuid?/delete/:id`, authenticateToken, handlers.delete);
    
    // Serve static files
    router.use(prefix, express.static(path.join(APP_DIR, 'public')));
    
    // View routes
    router.get(`${prefix}/:uuid?/view`, (req, res) => {
        res.sendFile(path.join(APP_DIR, 'public', 'index.html'));
    });
    
    // UUID route - serve index.html for UUID path
    router.get(`${prefix}/:uuid`, (req, res) => {
        // Check if the parameter is a valid UUID
        const uuid = req.params.uuid;
        if (uuid.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
            res.sendFile(path.join(APP_DIR, 'public', 'index.html'));
        } else {
            res.status(404).send('Not found');
        }
    });
    
    // Root redirect
    router.get(prefix, (req, res) => {
        const uuid = getOrCreateUuid(req, res);
        res.redirect(`${prefix}/${uuid}/view`);
    });
};

// Mount routes for all paths
mountRoutes(app, '/proxy/3006');
mountRoutes(app, '/proxy/3007');
mountRoutes(app);

const PORT = process.env.PORT || 3006;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Application directory: ${APP_DIR}`);
});
