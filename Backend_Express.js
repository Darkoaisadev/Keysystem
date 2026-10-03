/**
 * KeySystem Backend - Node.js Express
 * Production-ready external authentication server
 * 
 * Requirements:
 * - Node.js 14+
 * - npm install express body-parser redis dotenv bcryptjs uuid
 * 
 * Environment Variables:
 * - ADMIN_TOKEN=your-secret-admin-token
 * - REDIS_URL=redis://localhost:6379
 * - PORT=3000
 */

const express = require('express');
const bodyParser = require('body-parser');
const redis = require('redis');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();

// ==================== CONFIGURATION ====================

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-this-token';
const MAX_ATTEMPTS = 3;
const ATTEMPT_COOLDOWN = 30; // seconds
const REQUEST_RATE_LIMIT = 10; // per minute per device
const PORT = process.env.PORT || 3000;

// ==================== REDIS SETUP ====================

const redisClient = redis.createClient({
	url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.on('connect', () => console.log('[Backend] Connected to Redis'));

redisClient.connect();

// ==================== MIDDLEWARE ====================

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
	console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
	next();
});

// ==================== HELPER FUNCTIONS ====================

async function getKey(keyString) {
	const data = await redisClient.get(`key:${keyString}`);
	return data ? JSON.parse(data) : null;
}

async function setKey(keyString, data, expireSeconds = null) {
	const serialized = JSON.stringify(data);
	if (expireSeconds) {
		await redisClient.setEx(`key:${keyString}`, expireSeconds, serialized);
	} else {
		await redisClient.set(`key:${keyString}`, serialized);
	}
}

async function getAttempts(deviceId) {
	const data = await redisClient.get(`attempts:${deviceId}`);
	return data ? parseInt(data) : 0;
}

async function incrementAttempts(deviceId) {
	const current = await getAttempts(deviceId);
	const newCount = current + 1;
	await redisClient.setEx(`attempts:${deviceId}`, ATTEMPT_COOLDOWN, newCount.toString());
	return newCount;
}

async function resetAttempts(deviceId) {
	await redisClient.del(`attempts:${deviceId}`);
}

async function checkRateLimit(deviceId) {
	const now = Date.now();
	const key = `ratelimit:${deviceId}:${Math.floor(now / 60000)}`;
	const current = await redisClient.get(key);
	const count = current ? parseInt(current) + 1 : 1;
	
	if (count > REQUEST_RATE_LIMIT) {
		return false;
	}
	
	await redisClient.setEx(key, 60, count.toString());
	return true;
}

function validateKeyFormat(key) {
	return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key);
}

function generateKey() {
	const segments = [];
	for (let i = 0; i < 4; i++) {
		const segment = crypto.randomBytes(2).toString('hex').toUpperCase().slice(0, 4);
		segments.push(segment);
	}
	return segments.join('-');
}

function logSecurityEvent(eventType, details) {
	console.log(`[SECURITY] ${eventType}`, details);
	// In production, send to logging service (Sentry, DataDog, etc.)
}

// ==================== ROUTE HANDLERS ====================

/**
 * POST /validate
 * Check if a key is valid (format check)
 */
app.post('/validate', async (req, res) => {
	try {
		const { key, placeId } = req.body;
		
		if (!key || !validateKeyFormat(key)) {
			return res.status(400).json({ valid: false, message: 'Invalid key format.' });
		}
		
		const keyData = await getKey(key);
		
		if (!keyData) {
			logSecurityEvent('INVALID_KEY_ATTEMPT', { key, placeId });
			return res.json({ valid: false, message: 'Key not found.' });
		}
		
		if (keyData.status !== 'active') {
			logSecurityEvent('DEACTIVATED_KEY_ATTEMPT', { key });
			return res.json({ valid: false, message: 'This key has been deactivated.' });
		}
		
		return res.json({ valid: true, message: 'Key is valid.' });
	} catch (err) {
		console.error('Validation error:', err);
		return res.status(500).json({ valid: false, message: 'Server error.' });
	}
});

/**
 * POST /bind
 * Bind a key to a device
 */
app.post('/bind', async (req, res) => {
	try {
		const { key, deviceId, placeId, timestamp } = req.body;
		
		if (!validateKeyFormat(key) || !deviceId) {
			return res.status(400).json({ success: false, message: 'Invalid request.' });
		}
		
		// Rate limit
		const allowed = await checkRateLimit(deviceId);
		if (!allowed) {
			logSecurityEvent('RATE_LIMIT_EXCEEDED', { deviceId });
			return res.status(429).json({ success: false, message: 'Too many requests.' });
		}
		
		const keyData = await getKey(key);
		
		if (!keyData) {
			return res.json({ success: false, message: 'Key not found.' });
		}
		
		if (keyData.status !== 'active') {
			return res.json({ success: false, message: 'This key has been deactivated.' });
		}
		
		// Check if already bound to different device
		if (keyData.boundDevice && keyData.boundDevice !== deviceId) {
			logSecurityEvent('KEY_REBIND_ATTEMPT', { key, boundDevice: keyData.boundDevice, attemptDevice: deviceId });
			return res.json({ success: false, message: 'This key is already bound to another device.' });
		}
		
		// Bind device
		keyData.boundDevice = deviceId;
		keyData.lastBoundTime = Date.now();
		keyData.boundCount = (keyData.boundCount || 0) + 1;
		
		await setKey(key, keyData);
		await resetAttempts(deviceId);
		
		logSecurityEvent('DEVICE_BOUND', { key, deviceId });
		
		return res.json({ success: true, message: 'Device bound successfully.' });
	} catch (err) {
		console.error('Bind error:', err);
		return res.status(500).json({ success: false, message: 'Server error.' });
	}
});

/**
 * POST /verify
 * Verify existing authorization (check device binding)
 */
app.post('/verify', async (req, res) => {
	try {
		const { key, deviceId, placeId } = req.body;
		
		if (!validateKeyFormat(key) || !deviceId) {
			return res.status(400).json({ valid: false });
		}
		
		// Rate limit
		const allowed = await checkRateLimit(deviceId);
		if (!allowed) {
			return res.status(429).json({ valid: false });
		}
		
		const keyData = await getKey(key);
		
		if (!keyData || keyData.status !== 'active') {
			return res.json({ valid: false });
		}
		
		// Check device binding
		if (keyData.boundDevice && keyData.boundDevice !== deviceId) {
			logSecurityEvent('DEVICE_MISMATCH', {
				key,
				boundDevice: keyData.boundDevice,
				attemptDevice: deviceId
			});
			return res.json({ valid: false, message: 'Key bound to different device.' });
		}
		
		// Update last auth
		keyData.lastAuth = Date.now();
		keyData.authCount = (keyData.authCount || 0) + 1;
		await setKey(key, keyData);
		
		await resetAttempts(deviceId);
		
		return res.json({ valid: true });
	} catch (err) {
		console.error('Verify error:', err);
		return res.status(500).json({ valid: false });
	}
});

/**
 * POST /admin/genkeyperm
 * Generate a permanent key (admin only)
 */
app.post('/admin/genkeyperm', async (req, res) => {
	try {
		const { adminToken, placeId, timestamp } = req.body;
		
		// Validate admin token
		if (adminToken !== ADMIN_TOKEN) {
			logSecurityEvent('INVALID_ADMIN_TOKEN', { timestamp });
			return res.status(401).json({ success: false, message: 'Unauthorized.' });
		}
		
		// Check timestamp is recent (prevent replay attacks)
		const now = Date.now() / 1000;
		if (Math.abs(now - timestamp) > 30) {
			logSecurityEvent('REPLAY_ATTACK_ATTEMPT', { timestamp });
			return res.status(401).json({ success: false, message: 'Request expired.' });
		}
		
		// Generate unique key
		let key;
		let exists = true;
		while (exists) {
			key = generateKey();
			const existing = await getKey(key);
			exists = existing !== null;
		}
		
		// Store key
		const keyData = {
			key,
			status: 'active',
			createdAt: Date.now(),
			createdBy: 'admin',
			boundDevice: null,
			authCount: 0,
			boundCount: 0
		};
		
		await setKey(key, keyData);
		logSecurityEvent('KEY_GENERATED', { key });
		
		return res.json({ success: true, key, message: 'Key generated successfully.' });
	} catch (err) {
		console.error('Gen key error:', err);
		return res.status(500).json({ success: false, message: 'Server error.' });
	}
});

/**
 * POST /admin/deactivate
 * Deactivate a key (admin only)
 */
app.post('/admin/deactivate', async (req, res) => {
	try {
		const { key, adminToken, placeId, timestamp } = req.body;
		
		// Validate admin token
		if (adminToken !== ADMIN_TOKEN) {
			logSecurityEvent('INVALID_ADMIN_TOKEN', { timestamp });
			return res.status(401).json({ success: false, message: 'Unauthorized.' });
		}
		
		if (!validateKeyFormat(key)) {
			return res.status(400).json({ success: false, message: 'Invalid key format.' });
		}
		
		const keyData = await getKey(key);
		
		if (!keyData) {
			return res.json({ success: false, message: 'Key not found.' });
		}
		
		if (keyData.status === 'deactivated') {
			return res.json({ success: false, message: 'This key is already deactivated.' });
		}
		
		// Deactivate
		keyData.status = 'deactivated';
		keyData.deactivatedAt = Date.now();
		
		await setKey(key, keyData);
		logSecurityEvent('KEY_DEACTIVATED', { key });
		
		return res.json({ success: true, message: 'Key deactivated.' });
	} catch (err) {
		console.error('Deactivate error:', err);
		return res.status(500).json({ success: false, message: 'Server error.' });
	}
});

// ==================== ERROR HANDLING ====================

app.use((req, res) => {
	return res.status(404).json({ error: 'Not found.' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
	console.log(`[Backend] KeySystem server listening on port ${PORT}`);
	console.log(`[Backend] Admin token configured: ${ADMIN_TOKEN !== 'change-this-token' ? 'YES' : 'NO (CHANGE IMMEDIATELY)'}`);
});
