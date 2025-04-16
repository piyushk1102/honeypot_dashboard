/**https://qwerty123456-generatehoneypot.web.val.run

/** @jsxImportSource https://esm.sh/react@18.2.0 */
import { createRoot } from "https://esm.sh/react-dom@18.2.0/client";
import React, { useEffect, useState } from "https://esm.sh/react@18.2.0";

interface AttackLog {
  id: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  threat_level: "LOW" | "MEDIUM" | "HIGH";
  attack_type?: string;
}

function AttackLogTable({ logs }) {
  return (
    <table
      style={{
        width: "100%",
        borderCollapse: "collapse",
        backgroundColor: "white",
        boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
      }}
    >
      <thead>
        <tr style={{ backgroundColor: "#f4f4f4" }}>
          <th>Timestamp</th>
          <th>IP</th>
          <th>Method</th>
          <th>Path</th>
          <th>Threat Level</th>
          <th>Attack Type</th>
        </tr>
      </thead>
      <tbody>
        {logs.map(log => (
          <tr
            key={log.id}
            style={{
              backgroundColor: log.threat_level === "HIGH"
                ? "#ffdddd"
                : log.threat_level === "MEDIUM"
                ? "#fff3cd"
                : "#e6f3ff",
            }}
          >
            <td>{new Date(log.timestamp).toLocaleString()}</td>
            <td>{log.ip}</td>
            <td>{log.method}</td>
            <td>{log.path}</td>
            <td>{log.threat_level}</td>
            <td>{log.attack_type || "Unknown"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function App() {
  const [attackLogs, setAttackLogs] = useState<AttackLog[]>([]);
  const [statsummary, setStatSummary] = useState({
    totalAttempts: 0,
    highThreatCount: 0,
    uniqueIPs: 0,
  });
  const [error, setError] = useState<string | null>(null);

  const fetchAttackLogs = () => {
    // Use the full URL of the current val to ensure correct endpoint
    fetch(`${window.location.origin}/attack-logs`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        setAttackLogs(data.logs || []);
        setStatSummary(
          data.summary || {
            totalAttempts: 0,
            highThreatCount: 0,
            uniqueIPs: 0,
          },
        );
        setError(null);
      })
      .catch(error => {
        console.error("Failed to fetch attack logs:", error);
        setError(`Failed to load attack logs: ${error.message}`);
      });
  };

  useEffect(() => {
    fetchAttackLogs();
    const interval = setInterval(fetchAttackLogs, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      style={{
        fontFamily: "monospace",
        maxWidth: "1200px",
        margin: "auto",
        padding: "20px",
        backgroundColor: "#1a1a2e",
        color: "#e0e0e0",
      }}
    >
      <h1>🕵️ Cyber Attack Honeypot Dashboard</h1>

      {error && (
        <div
          style={{
            backgroundColor: "#ff4d4d",
            color: "white",
            padding: "10px",
            marginBottom: "20px",
          }}
        >
          {error}
        </div>
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "20px",
          backgroundColor: "#16213e",
          padding: "15px",
          borderRadius: "5px",
        }}
      >
        <div>
          Total Attack Attempts: <strong>{statsummary.totalAttempts}</strong>
        </div>
        <div>
          High Threat Attempts: <strong style={{ color: "red" }}>{statsummary.highThreatCount}</strong>
        </div>
        <div>
          Unique IPs: <strong>{statsummary.uniqueIPs}</strong>
        </div>
      </div>

      <AttackLogTable logs={attackLogs} />

      <a
        href={import.meta.url.replace("esm.town", "val.town")}
        target="_top"
        style={{ color: "#888", textDecoration: "none", display: "block", marginTop: "20px" }}
      >
        View Source
      </a>
    </div>
  );
}

function client() {
  createRoot(document.getElementById("root")).render(<App />);
}
if (typeof document !== "undefined") { client(); }

export default async function server(request: Request): Promise<Response> {
  const { sqlite } = await import("https://esm.town/v/stevekrouse/sqlite");
  const KEY = new URL(import.meta.url).pathname.split("/").at(-1);
  const SCHEMA_VERSION = 1;

  // Create attack logs table
  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS ${KEY}_attack_logs_${SCHEMA_VERSION} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip TEXT NOT NULL,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      headers TEXT,
      body TEXT,
      threat_level TEXT NOT NULL,
      attack_type TEXT
    )
  `);

  // Handle attack log retrieval
  if (new URL(request.url).pathname === "/attack-logs") {
    try {
      const logs = await sqlite.execute(`
        SELECT * FROM ${KEY}_attack_logs_${SCHEMA_VERSION} 
        ORDER BY timestamp DESC 
        LIMIT 100
      `);

      const summary = await sqlite.execute(`
        SELECT 
          COUNT(*) as totalAttempts,
          COUNT(CASE WHEN threat_level = 'HIGH' THEN 1 END) as highThreatCount,
          COUNT(DISTINCT ip) as uniqueIPs
        FROM ${KEY}_attack_logs_${SCHEMA_VERSION}
      `);

      return new Response(
        JSON.stringify({
          logs: logs.rows || [],
          summary: summary.rows[0] || {
            totalAttempts: 0,
            highThreatCount: 0,
            uniqueIPs: 0,
          },
        }),
        {
          headers: { "Content-Type": "application/json" },
        },
      );
    } catch (error) {
      console.error("Error retrieving attack logs:", error);
      return new Response(
        JSON.stringify({
          logs: [],
          summary: {
            totalAttempts: 0,
            highThreatCount: 0,
            uniqueIPs: 0,
          },
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
  }

  // Honeypot logic
  const ip = request.headers.get("x-forwarded-for") || "unknown";
  let threatLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW";
  let attackType = "Reconnaissance";

  // Analyze request for potential threats
  const headers = Object.fromEntries(request.headers);
  const body = await request.text();

  // Threat detection heuristics
  if (body.includes("<?php") || body.includes("cmd=")) {
    threatLevel = "HIGH";
    attackType = "Remote Code Execution";
  } else if (headers["user-agent"]?.includes("sqlmap") || body.includes("UNION SELECT")) {
    threatLevel = "HIGH";
    attackType = "SQL Injection";
  } else if (request.method !== "GET" && body.length > 1024) {
    threatLevel = "MEDIUM";
    attackType = "Potential Payload";
  }

  // Log the attack attempt
  try {
    await sqlite.execute(
      `INSERT INTO ${KEY}_attack_logs_${SCHEMA_VERSION} 
      (ip, method, path, headers, body, threat_level, attack_type) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        ip,
        request.method,
        new URL(request.url).pathname,
        JSON.stringify(headers),
        body.slice(0, 1024), // Limit body size
        threatLevel,
        attackType,
      ],
    );
  } catch (error) {
    console.error("Error logging attack:", error);
  }

  // Simulate vulnerable endpoints to attract attacks
  return new Response(
    `
    <html>
      <head>
        <title>Vulnerable Server</title>
        <script>
          // Add this to help diagnose any client-side issues
          window.addEventListener('error', function(event) {
            console.error('Uncaught error:', event.error);
          });
        </script>
      </head>
      <body>
        <h1>Default Web Page</h1>
        <form method="post" action="/admin/login">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Login">
        </form>
        <div id="root"></div>
        <script src="https://esm.town/v/std/catch"></script>
        <script type="module" src="${import.meta.url}"></script>
      </body>
    </html>
  `,
    {
      status: 200,
      headers: { "Content-Type": "text/html" },
    },
  );
}