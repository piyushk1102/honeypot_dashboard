import React, { useEffect, useState } from 'react';
import './App.css';

interface Log {
  id: number;
  ip: string;
  port: number;
  country: string;
  city: string;
  timestamp: string;
}

function App() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:3001/logs')
      .then((res) => res.json())
      .then((data) => {
        setLogs(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Error fetching logs:', err);
        setLoading(false);
      });
  }, []);

  return (
    <div className="app-container">
      <h1 className="title">🛡️ Honeypot Attack Logs</h1>

      {loading ? (
        <p className="loading">Loading logs...</p>
      ) : logs.length === 0 ? (
        <p className="no-logs">No logs yet...</p>
      ) : (
        <div className="table-container">
          <table className="log-table">
            <thead>
              <tr>
                <th>#</th>
                <th>IP Address</th>
                <th>Port</th>
                <th>Country</th>
                <th>City</th>
                <th>Timestamp (IST)</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td>{log.id}</td>
                  <td>{log.ip}</td>
                  <td>{log.port}</td>
                  <td>{log.country}</td>
                  <td>{log.city}</td>
                  <td>{log.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default App;