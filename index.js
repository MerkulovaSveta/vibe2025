const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const cookie = require('cookie');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');

// Telegram bot token
const TELEGRAM_TOKEN = '7730296042:AAFvOdbRI37_dz3UsRNeH3SvEDCyGrnRZOo';
const bot = new TelegramBot(TELEGRAM_TOKEN, {polling: true});

// Database setup
const db = new sqlite3.Database('./todo.db', (err) => {
    if (err) {
        console.error('Database error:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            salt TEXT,
            telegram_chat_id TEXT
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            text TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    });
}

function dbQuery(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function dbRun(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

const sessions = {};

function createSession(userId, username) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    sessions[sessionId] = { userId, username };
    return sessionId;
}

function getSession(sessionId) {
    return sessions[sessionId];
}

function deleteSession(sessionId) {
    delete sessions[sessionId];
}

// HTTP Server
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const cookies = cookie.parse(req.headers.cookie || '');
    
    // Serve static files
    if (req.url === '/') {
        try {
            const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Error loading index.html');
        }
        return;
    }
    
    // API endpoints
    if (req.method === 'POST' && parsedUrl.pathname === '/login') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { username, password } = JSON.parse(body);
                const user = await dbQuery('SELECT * FROM users WHERE username = ?', [username]);
                
                if (user.length === 0) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Invalid username or password' }));
                    return;
                }
                
                const hashedPassword = hashPassword(password, user[0].salt);
                if (hashedPassword !== user[0].password) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Invalid username or password' }));
                    return;
                }
                
                const sessionId = createSession(user[0].id, user[0].username);
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'Set-Cookie': cookie.serialize('sessionId', sessionId, {
                        httpOnly: true,
                        maxAge: 60 * 60 * 24 * 7
                    })
                });
                res.end(JSON.stringify({ 
                    success: true, 
                    userId: user[0].id, 
                    username: user[0].username 
                }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Login failed' }));
            }
        });
        return;
    }
    
    if (req.method === 'POST' && parsedUrl.pathname === '/register') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { username, password } = JSON.parse(body);
                
                if (!username || !password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Username and password are required' }));
                    return;
                }
                
                const salt = crypto.randomBytes(16).toString('hex');
                const hashedPassword = hashPassword(password, salt);
                
                try {
                    await dbRun(
                        'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                        [username, hashedPassword, salt]
                    );
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } catch (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, message: 'Username already exists' }));
                    } else {
                        throw err;
                    }
                }
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Registration failed' }));
            }
        });
        return;
    }
    
    if (req.method === 'POST' && parsedUrl.pathname === '/logout') {
        if (cookies.sessionId) {
            deleteSession(cookies.sessionId);
        }
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie.serialize('sessionId', '', {
                httpOnly: true,
                expires: new Date(0)
            })
        });
        res.end(JSON.stringify({ success: true }));
        return;
    }
    
    if (req.method === 'GET' && parsedUrl.pathname === '/check-auth') {
        const session = cookies.sessionId ? getSession(cookies.sessionId) : null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            loggedIn: !!session,
            userId: session?.userId,
            username: session?.username
        }));
        return;
    }
    
    // Protected routes
    const session = cookies.sessionId ? getSession(cookies.sessionId) : null;
    if (!session) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
    }

    if (req.method === 'GET' && parsedUrl.pathname === '/items') {
        try {
            const items = await dbQuery('SELECT id, text FROM items WHERE user_id = ?', [session.userId]);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(items));
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to fetch items' }));
        }
        return;
    }
    
    if (req.method === 'POST' && parsedUrl.pathname === '/items') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                await dbRun(
                    'INSERT INTO items (user_id, text) VALUES (?, ?)',
                    [session.userId, text]
                );
                res.writeHead(201, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to add item' }));
            }
        });
        return;
    }
    
    if (req.method === 'PUT' && parsedUrl.pathname.startsWith('/items/')) {
        const id = parsedUrl.pathname.split('/')[2];
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                const result = await dbRun(
                    'UPDATE items SET text = ? WHERE id = ? AND user_id = ?',
                    [text, id, session.userId]
                );
                
                if (result.changes === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Item not found or not owned by user' }));
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                }
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to update item' }));
            }
        });
        return;
    }
    
    if (req.method === 'DELETE' && parsedUrl.pathname.startsWith('/items/')) {
        const id = parsedUrl.pathname.split('/')[2];
        try {
            const result = await dbRun(
                'DELETE FROM items WHERE id = ? AND user_id = ?',
                [id, session.userId]
            );
            
            if (result.changes === 0) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Item not found or not owned by user' }));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            }
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to delete item' }));
        }
        return;
    }
    
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
});

// Telegram Bot Logic
const userAuthStates = {}; // Stores temporary auth data for users

bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    bot.sendMessage(chatId, 'Добро пожаловать в To-Do List бот! Для доступа к вашим задачам сначала авторизуйтесь:\n\n1. Введите команду /login\n2. Затем введите ваш логин и пароль в формате: логин:пароль');
});

// Хранилище для состояний пользователей
const userSessions = {};

bot.onText(/\/login/, (msg) => {
    const chatId = msg.chat.id;
    userSessions[chatId] = { state: 'awaiting_credentials' };
    bot.sendMessage(chatId, 'Пожалуйста, введите ваш логин и пароль в формате:\nлогин:пароль\n\nНапример: myusername:mypassword');
});

bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text;
    
    if (text.startsWith('/')) return;
    
    if (userSessions[chatId] && userSessions[chatId].state === 'awaiting_credentials') {
        try {
            const [username, password] = text.split(':');
            
            if (!username || !password) {
                bot.sendMessage(chatId, 'Неверный формат. Пожалуйста, введите в формате: логин:пароль');
                return;
            }
            
            const user = await dbQuery('SELECT * FROM users WHERE username = ?', [username.trim()]);
            
            if (user.length === 0) {
                bot.sendMessage(chatId, '❌ Пользователь не найден');
                return;
            }
            
            const hashedPassword = hashPassword(password.trim(), user[0].salt);
            if (hashedPassword !== user[0].password) {
                bot.sendMessage(chatId, '❌ Неверный пароль');
                return;
            }
            
            // Сохраняем ID пользователя в сессии
            userSessions[chatId] = {
                userId: user[0].id,
                username: user[0].username,
                state: 'authenticated'
            };
            
            bot.sendMessage(chatId, '✅ Авторизация успешна! Теперь вы можете использовать команду /get_todos для получения вашего списка задач.');
        } catch (error) {
            console.error('Auth error:', error);
            bot.sendMessage(chatId, '⚠️ Произошла ошибка при авторизации');
        }
    }
});

bot.onText(/\/get_todos/, async (msg) => {
    const chatId = msg.chat.id;
    
    // Проверяем, авторизован ли пользователь в этом чате
    if (!userSessions[chatId] || userSessions[chatId].state !== 'authenticated') {
        bot.sendMessage(chatId, '❌ Вы не авторизованы. Пожалуйста, используйте /login для авторизации.');
        return;
    }
    
    try {
        // Получаем задачи только для текущего авторизованного пользователя
        const todos = await dbQuery('SELECT text FROM items WHERE user_id = ?', [userSessions[chatId].userId]);
        
        if (todos.length === 0) {
            bot.sendMessage(chatId, '📝 Ваш список задач пуст. Добавьте задачи на сайте!');
            return;
        }
        
        let message = `📝 Ваши задачи (пользователь: ${userSessions[chatId].username}):\n\n`;
        todos.forEach((todo, index) => {
            message += `${index + 1}. ${todo.text}\n`;
        });
        
        bot.sendMessage(chatId, message);
    } catch (error) {
        console.error('Error getting todos:', error);
        bot.sendMessage(chatId, '⚠️ Произошла ошибка при получении задач');
    }
});

// Start server
const PORT = 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
console.log('Telegram bot запущен!');