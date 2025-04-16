import expressPkg from 'express';
import corsPkg from 'cors';
import geoip from 'geoip-lite';
import sqlite3 from 'sqlite3';
import net from 'net';
import { DateTime } from 'luxon';

type DBLogRow = {
  id: number;
  ip: string;
  port: number;
  timestamp: string;
};

const express = expressPkg();
const cors = corsPkg();
express.use(cors);

const db = new sqlite3.Database('honeypot.db');

// ✅ Ensure table is created before anything else
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      port INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// 🕵️ Honeypot listener
const tcpServer = net.createServer((socket) => {
  const ip = socket.remoteAddress?.replace(/^::ffff:/, '') || 'unknown';
  const port = socket.remotePort || 0;

  console.log(`[⚠️] Attack detected from ${ip}:${port}`);

  db.run(
    'INSERT INTO logs (ip, port) VALUES (?, ?)',
    [ip, port]
  );

  socket.write('Fake SSH Service\n');
  socket.destroy();
});

tcpServer.listen(2222, () => {
  console.log(`[🔥] Honeypot listening on port 2222`);
});

// 🧠 /logs endpoint
express.get('/logs', (_req, res) => {
  db.all('SELECT * FROM logs ORDER BY id DESC', [], (err, rows: DBLogRow[]) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: err.message });
    }

    const enrichedLogs = rows.map((row) => {
      const ipToCheck = ['::1', '127.0.0.1'].includes(row.ip) ? '8.8.8.8' : row.ip;
      const geo = geoip.lookup(ipToCheck);

      let country = 'Unknown';
      let city = 'Unknown';

      if (geo) {
        country = geo.country || 'Unknown';
        city = geo.city || 'Unknown';

        if (geo.country === 'US' && geo.region) {
          city += ` (${geo.region})`;
        }
      }

      let istTime = row.timestamp;
      try {
        const utcTime = DateTime.fromSQL(row.timestamp, { zone: 'utc' });
        if (utcTime.isValid) {
          istTime = utcTime.setZone('Asia/Kolkata').toFormat('yyyy-MM-dd HH:mm:ss');
        }
      } catch (e) {
        console.error('Timestamp conversion error:', e);
      }

      return {
        id: row.id,
        ip: row.ip,
        port: row.port,
        country,
        city,
        timestamp: istTime,
      };
    });

    res.json(enrichedLogs);
  });
});

express.listen(3001, () => {
  console.log('✅ API running at http://localhost:3001/logs');
});