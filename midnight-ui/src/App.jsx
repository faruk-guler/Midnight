import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const [stats, setStats] = useState({
    threats: 0,
    privacy: 0,
    network: 0,
    blocked: 0,
    services: []
  });
  const [agents, setAgents] = useState({});
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [trends, setTrends] = useState({});
  const [entropyThreshold, setEntropyThreshold] = useState(4.5);
  const [commandStatus, setCommandStatus] = useState({ msg: '', type: 'info' });
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    localStorage.setItem('theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    
    let ws;
    const connectWS = () => {
      ws = new WebSocket('ws://localhost:4800/ws');
      ws.onopen = () => setIsConnected(true);
      ws.onclose = () => {
        setIsConnected(false);
        setTimeout(connectWS, 3000); // Auto-reconnect
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'alert') {
              // Alerts are integrated via rules engine
          } else if (data.type === 'fleet_update') {
            setAgents(data.data);
          } else {
            setLogs((prev) => [data, ...prev].slice(0, 100));
            updateIntelligence(data);
          }
        } catch (e) { console.error("Malformed log received:", e); }
      };
    };

    connectWS();
    fetchAuditLogs();
    fetchTrends();
    fetchAgents();

    return () => ws?.close();
  }, [theme]);

  const fetchAgents = async () => {
    try {
      const resp = await fetch('http://localhost:4800/api/agents');
      const data = await resp.json();
      setAgents(data || {});
    } catch (e) { console.error(e); }
  };

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  const fetchAuditLogs = async () => {
    try {
      const resp = await fetch('http://localhost:4800/api/audit');
      const data = await resp.json();
      setAuditLogs(data || []);
    } catch (e) { console.error(e); }
  };

  const fetchTrends = async () => {
    try {
      const resp = await fetch('http://localhost:4800/api/trends');
      const data = await resp.json();
      setTrends(data || {});
    } catch (e) { console.error(e); }
  };

  const handleExport = () => {
    window.open('http://localhost:4800/api/export', '_blank');
  };

  const sendCommand = async (hostname, command) => {
    setCommandStatus({ msg: `Dispatching ${command}...`, type: 'info' });
    try {
      const resp = await fetch('http://localhost:4800/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname, command })
      });
      if (resp.ok) {
        setCommandStatus({ msg: `SENT: ${command} queued for ${hostname === '*' ? 'Fleet' : hostname}`, type: 'success' });
        setTimeout(() => setCommandStatus({ msg: '', type: 'info' }), 4000);
        fetchAuditLogs(); // Refresh to see the command in audit
      } else {
        throw new Error('C2 Dispatch Failed');
      }
    } catch (e) {
      setCommandStatus({ msg: `FAILED: Link to Command Center broken`, type: 'error' });
      setTimeout(() => setCommandStatus({ msg: '', type: 'info' }), 5000);
    }
  };
  const updateIntelligence = (log) => {
    setStats(prev => {
      const newStats = { ...prev };
      if (log.severity === 'CRITICAL' || log.severity === 'HIGH') newStats.threats++;
      if (log.category === 'Privacy') newStats.privacy++;
      if (log.category === 'Network') newStats.network++;
      if (log.category === 'Firewall' || log.category === 'Hardening') newStats.blocked++;
      if (log.services) newStats.services = log.services;
      return newStats;
    });

    if (log.hostname) {
      setAgents(prev => {
        const existing = prev[log.hostname] || {};
        return {
          ...prev,
          [log.hostname]: {
            ...existing,
            hostname: log.hostname,
            ip: log.src_ip || log.dst_ip || existing.ip || 'N/A',
            os: log.os || existing.os || 'Linux',
            last_seen: new Date().toISOString(),
            services: log.services || existing.services || [],
            status: existing.status || 'ONLINE',
            risk_score: existing.risk_score || 0
          }
        };
      });
    }
  };

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'var(--critical)';
      case 'HIGH': return 'var(--high)';
      case 'MEDIUM': return 'var(--medium)';
      default: return 'var(--low)';
    }
  };

  return (
    <div className="MIDNIGHT-app" data-theme={theme}>
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <img src="/logo.png" alt="MIDNIGHT LOGO" style={{width: '52px', height: '52px', borderRadius: '8px', objectFit: 'contain', boxShadow: '0 4px 15px rgba(0,0,0,0.4)'}} />
            <span style={{fontFamily: 'Orbitron', marginLeft: '12px'}}>MIDNIGHT</span>
          </div>
        </div>

        <nav className="sidebar-menu">
          <div className={`sidebar-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>
            Dashboard
          </div>
          <div className={`sidebar-item ${activeTab === 'manage' ? 'active' : ''}`} onClick={() => setActiveTab('manage')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
            MANAGEMENT
          </div>
          <div className={`sidebar-item ${activeTab === 'blocked' ? 'active' : ''}`} onClick={() => setActiveTab('blocked')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m4 5 14 12"/></svg>
            Blocked IPs
          </div>
          <div className={`sidebar-item ${activeTab === 'vulns' ? 'active' : ''}`} onClick={() => setActiveTab('vulns')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="8" height="14" x="8" y="6" rx="4"/><path d="m19 7-3 2"/><path d="m5 7 3 2"/><path d="m19 19-3-2"/><path d="m5 19 3-2"/><path d="M20 13h-4"/><path d="M4 13h4"/><path d="m10 4 1 2"/><path d="m14 4-1 2"/></svg>
            Vulnerabilities
          </div>
          <div className={`sidebar-item ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => { setActiveTab('audit'); fetchAuditLogs(); }}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/></svg>
            Audit Logs
          </div>
          <div className={`sidebar-item ${activeTab === 'agents' ? 'active' : ''}`} onClick={() => { setActiveTab('agents'); fetchAgents(); }}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>
            Fleet Assets
          </div>
          <div className={`sidebar-item ${activeTab === 'about' ? 'active' : ''}`} onClick={() => setActiveTab('about')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            About
          </div>
        </nav>

        <div className="theme-toggle-container">
          <span style={{color: 'var(--text-muted)', fontWeight: 600}}>Dark Mode</span>
          <label className="toggle-switch">
             <input type="checkbox" checked={theme === 'dark'} onChange={toggleTheme} />
             <span className="toggle-slider"></span>
          </label>
        </div>
      </aside>

      <div className="main-content">
        <div className="content-header">
           <div className="page-title">{activeTab.toUpperCase()} {activeTab === 'manage' ? 'COMMAND CENTER' : 'OVERVIEW'}</div>
           <div style={{display: 'flex', gap: '1rem', alignItems: 'center'}}>
             {commandStatus.msg && (
                <div style={{
                  fontSize: '0.8rem', 
                  color: commandStatus.type === 'error' ? 'var(--danger-color)' : (commandStatus.type === 'success' ? 'var(--success-color)' : 'var(--primary-color)'), 
                  fontWeight: 800,
                  padding: '4px 10px',
                  background: 'rgba(0,0,0,0.05)',
                  borderRadius: '12px'
                }} className="animate-fade-up">
                  {commandStatus.msg}
                </div>
             )}
             <div style={{display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px', background: 'var(--tertiary-bg-color)', borderRadius: '8px', fontSize: '0.85rem', fontWeight: 600}}>
                <span style={{color: isConnected ? 'var(--success-color)' : 'var(--danger-color)', animation: isConnected ? 'pulse 2s infinite' : 'none'}}>●</span> 
                {isConnected ? 'LIVE C2 LINK ACTIVE' : 'C2 LINK DOWN - RECONNECTING...'}
             </div>
             <button onClick={handleExport} className="btn-secure">EXPORT DATA (CSV)</button>
           </div>
        </div>

        <section className="page-body animate-fade-up">
           <div className="dashboard-cards">
              <div className="card">
                 <div className="card-header"><span className="card-title">Threat Alerts</span></div>
                 <div className="card-value" style={{color: 'var(--danger-color)'}}>{stats.threats}</div>
              </div>
              <div className="card">
                 <div className="card-header"><span className="card-title">C2 Control Status</span></div>
                 <div className="card-value" style={{color: 'var(--success-color)'}}>SYNCED</div>
              </div>
              <div className="card">
                 <div className="card-header"><span className="card-title">Managed Fleet</span></div>
                 <div className="card-value">{Object.keys(agents).length} <span style={{fontSize: '1rem', opacity: 0.5}}>Devices</span></div>
              </div>
           </div>

           {activeTab === 'manage' && (
             <div style={{display: 'grid', gridTemplateColumns: '1fr 400px', gap: '1.5rem'}}>
                <div className="data-table-container">
                   <div style={{padding: '1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 700}}>AGENT INTERACTIVE CONTROL</div>
                   <table className="data-table">
                      <thead>
                        <tr><th>HOSTNAME</th><th>IP</th><th>STATUS</th><th>ACTIONS</th></tr>
                      </thead>
                      <tbody>
                        {Object.values(agents).map((agent, i) => (
                          <tr key={i}>
                            <td style={{fontWeight: 700}}>{agent.hostname}</td>
                            <td>{agent.ip}</td>
                            <td>
                               <span className={`badge ${agent.status === 'ONLINE' ? 'badge-success' : (agent.status === 'QUARANTINED' ? 'badge-warning' : 'badge-info')}`}>
                                  {agent.status === 'ONLINE' ? 'ACTIVE' : (agent.status || 'MANAGED')}
                               </span>
                            </td>
                            <td>
                               <div style={{display: 'flex', gap: '8px'}}>
                                  <button onClick={() => sendCommand(agent.hostname, 'SCAN_NOW')} className="btn-secure" style={{padding: '4px 8px', fontSize: '0.7rem'}}>DEEP SCAN</button>
                                  <button onClick={() => sendCommand(agent.hostname, 'SHUTDOWN')} className="btn-secure" style={{padding: '4px 8px', fontSize: '0.7rem', background: 'var(--danger-color)'}}>SHUTDOWN</button>
                               </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                   </table>
                </div>

                <div className="sidebar-widgets">
                   <div className="card">
                      <div className="card-header"><span className="card-title">Global Security Policy</span></div>
                      <div style={{marginTop: '1rem'}}>
                         <label style={{fontSize: '0.85rem', fontWeight: 600, display: 'block', marginBottom: '8px'}}>DGA Entropy Threshold: {entropyThreshold}</label>
                         <input 
                           type="range" min="3.0" max="7.0" step="0.1" 
                           value={entropyThreshold} 
                           onChange={(e) => setEntropyThreshold(parseFloat(e.target.value))}
                           onMouseUp={() => sendCommand('*', `SET_ENTROPY:${entropyThreshold}`)}
                           style={{width: '100%', cursor: 'pointer'}} 
                         />
                         <p style={{fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '10px'}}>
                           Lower values increase detection sensitivity for randomized domains but may cause false positives.
                         </p>
                      </div>
                      <div style={{marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border-color)'}}>
                         <button className="btn-secure" style={{width: '100%'}} onClick={() => sendCommand('*', 'POLICY_SYNC')}>FORCE GLOBAL POLICY SYNC</button>
                      </div>
                   </div>
                </div>
             </div>
           )}

           {(activeTab === 'dashboard' || activeTab === 'access') && (
              <div style={{display: 'grid', gridTemplateColumns: '1fr 340px', gap: '1.5rem'}}>
                 <div className="data-table-container">
                    <div style={{padding: '1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 700}}>{activeTab.toUpperCase()} FORENSIC STREAM</div>
                    <div className="alert-feed">
                       {logs.map((log, index) => (
                         <div key={index} className="alert-item animate-fade-up">
                            <div className="sev-indicator" style={{background: getSeverityStyle(log.severity)}}></div>
                            <div style={{flex: 1}}>
                               <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '4px'}}>
                                  <span style={{fontSize: '0.75rem', fontWeight: 800, color: 'var(--primary-color)'}}>{log.category?.toUpperCase() || 'SYSTEM'}</span>
                                  <span style={{fontSize: '0.75rem', color: 'var(--text-muted)'}}>{new Date(log.timestamp).toLocaleTimeString()} @ {log.hostname}</span>
                               </div>
                               <div style={{fontWeight: 600, fontSize: '0.95rem'}}>{log.rule || log.message || log.details}</div>
                            </div>
                         </div>
                       ))}
                       {logs.length === 0 && <div style={{padding: '3rem', textAlign: 'center', opacity: 0.5}}>No telemetry data detected in the last stream cycle.</div>}
                    </div>
                 </div>
                 <div className="sidebar-widgets">
                    <div className="card" style={{marginBottom: '1.5rem'}}>
                       <div className="card-header"><span className="card-title">Threat Intensity</span></div>
                       <div style={{display: 'flex', alignItems: 'flex-end', gap: '2px', height: '60px'}}>
                         {Object.entries(trends).map(([h, count], i) => (<div key={i} style={{flex: 1, background: 'var(--primary-color)', opacity: 0.7, height: `${Math.min(count * 20, 100)}%`}}></div>))}
                       </div>
                    </div>
                 </div>
              </div>
           )}

                      {activeTab === 'agents' && (
              <div className="data-table-container">
                 <table className="data-table">
                    <thead><tr><th>STATUS</th><th>HOSTNAME</th><th>IP ADDRESS</th><th>SYSTEM</th><th>RISK</th><th>LAST SEEN</th></tr></thead>
                    <tbody>
                       {Object.values(agents).map((agent, i) => (
                         <tr key={i} onClick={() => setSelectedAgent(agent)} style={{cursor: 'pointer'}}>
                            <td>
                               <span style={{
                                 color: agent.status === 'ONLINE' ? 'var(--success-color)' : (agent.status === 'QUARANTINED' ? 'var(--warning-color)' : 'var(--danger-color)'), 
                                 animation: agent.status === 'ONLINE' ? 'pulse 2s infinite' : 'none',
                                 fontWeight: 800,
                                 fontSize: '0.85rem'
                               }}>● {agent.status || 'OFFLINE'}</span>
                            </td>
                            <td style={{fontWeight: 700}}>{agent.hostname}</td>
                            <td style={{color: 'var(--primary-color)'}}>{agent.ip}</td>
                            <td>{agent.os}</td>
                            <td><span className={`badge ${agent.risk_score > 7 ? 'badge-danger' : (agent.risk_score > 4 ? 'badge-warning' : 'badge-success')}`}>{agent.risk_score || 0}/10</span></td>
                            <td>{agent.last_seen ? new Date(agent.last_seen).toLocaleTimeString() : 'N/A'}</td>
                         </tr>
                       ))}
                    </tbody>
                 </table>
              </div>
           )}

           {activeTab === 'blocked' && (
              <div className="data-table-container">
                 <div style={{padding: '1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 700}}>SITUATION: RECENTLY BLACKLISTED ASSETS & IPs</div>
                 <table className="data-table">
                    <thead><tr><th>TIMESTAMP</th><th>TARGET IP / DOMAIN</th><th>REASON</th><th>ACTION</th></tr></thead>
                    <tbody>
                       {logs.filter(l => l.type === 'DGA-Alert' || l.type === 'hardening_violation' || l.message?.includes('Block')).map((log, i) => (
                         <tr key={i}>
                            <td style={{fontSize: '0.8rem', opacity: 0.7}}>{log.timestamp}</td>
                            <td style={{fontWeight: 700, color: 'var(--danger-color)'}}>{log.ip || log.domain || 'N/A'}</td>
                            <td><span className="badge badge-warning">{log.type?.replace('_', ' ').toUpperCase() || 'UNKNOWN'}</span></td>
                            <td><span style={{color: 'var(--danger-color)', fontWeight: 800}}>DROP / REJECTED</span></td>
                         </tr>
                       ))}
                       {logs.filter(l => l.type === 'DGA-Alert' || l.type === 'hardening_violation' || l.message?.includes('Block')).length === 0 && (
                         <tr><td colSpan="4" style={{textAlign: 'center', padding: '2rem', opacity: 0.5}}>No active blocks in recent history. System is clear.</td></tr>
                       )}
                    </tbody>
                 </table>
              </div>
           )}

           {activeTab === 'vulns' && (
              <div className="data-table-container">
                 <div style={{padding: '1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 700}}>SITUATION: DETECTED ASSET VULNERABILITIES</div>
                 <table className="data-table">
                    <thead><tr><th>SEVERITY</th><th>ASSET</th><th>VULNERABILITY ID</th><th>FINDING</th></tr></thead>
                    <tbody>
                       {logs.filter(l => l.type === 'vulnerability_report').map((log, i) => (
                         <tr key={i}>
                            <td><span className={`badge ${log.severity === 'high' ? 'badge-danger' : 'badge-warning'}`}>{log.severity?.toUpperCase() || 'MEDIUM'}</span></td>
                            <td style={{fontWeight: 700}}>{log.hostname || 'REMOTE_ASSET'}</td>
                            <td style={{fontFamily: 'monospace', fontSize: '0.8rem'}}>{log.vuln_id || 'ID-UNKNOWN'}</td>
                            <td style={{fontSize: '0.85rem'}}>{log.message}</td>
                         </tr>
                       ))}
                       {logs.filter(l => l.type === 'vulnerability_report').length === 0 && (
                         <tr><td colSpan="4" style={{textAlign: 'center', padding: '2rem', opacity: 0.5}}>No vulnerabilities detected in latest scans. Assets are hardened.</td></tr>
                       )}
                    </tbody>
                 </table>
              </div>
           )}

           {activeTab === 'audit' && (
             <div className="data-table-container">
                <table className="data-table">
                   <thead><tr><th>TIMESTAMP</th><th>PRINCIPAL</th><th>ACTION</th><th>FORENSIC METADATA</th></tr></thead>
                   <tbody>
                      {auditLogs.map((log, i) => (
                        <tr key={i}>
                           <td style={{fontSize: '0.8rem', opacity: 0.7}}>{new Date(log.timestamp).toLocaleString()}</td>
                           <td style={{fontWeight: 700, color: 'var(--primary-color)'}}>{log.user.toUpperCase()}</td>
                           <td>{log.action}</td>
                           <td style={{fontSize: '0.8rem', opacity: 0.8}}>{log.details}</td>
                        </tr>
                      ))}
                   </tbody>
                </table>
             </div>
           )}

           {activeTab === 'about' && (
              <div className="animate-fade-up" style={{maxWidth: '900px', margin: '0 auto'}}>
                 <div className="card" style={{padding: '3rem', textAlign: 'center', background: 'var(--secondary-bg-color)', border: '1px solid var(--border-color)', borderRadius: '16px'}}>
                    <img src="/logo.png" alt="MIDNIGHT" style={{width: '120px', marginBottom: '1.5rem', filter: 'drop-shadow(0 0 15px rgba(94, 129, 244, 0.4))'}} />
                    <h1 style={{fontSize: '2.5rem', fontFamily: 'Orbitron', marginBottom: '0.5rem', letterSpacing: '2px'}}>MIDNIGHT SOC</h1>
                    <p style={{color: 'var(--primary-color)', fontWeight: 800, fontSize: '1.1rem', marginBottom: '2rem'}}>MASTER v8.5 [HARDENED EDITION]</p>
                    
                    <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', textAlign: 'left', marginTop: '3rem'}}>
                       <div className="card" style={{background: 'var(--background-color)', border: '1px solid var(--border-color)'}}>
                          <h3 style={{fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '1rem', textTransform: 'uppercase'}}>System Architecture</h3>
                          <ul style={{listStyle: 'none', padding: 0, fontSize: '0.9rem', color: 'var(--text-color)'}}>
                             <li style={{marginBottom: '8px'}}>🚀 <strong>Backend Engine:</strong> Golang 1.26 (Fiber Framework)</li>
                             <li style={{marginBottom: '8px'}}>⚛️ <strong>Frontend Core:</strong> React 18 + Vite</li>
                             <li style={{marginBottom: '8px'}}>📡 <strong>Telemetry:</strong> eBPF Kernel-Level Logging</li>
                             <li style={{marginBottom: '8px'}}>🏛️ <strong>C2 Protocol:</strong> Bi-Directional HTTP/WS Relay</li>
                          </ul>
                       </div>
                       <div className="card" style={{background: 'var(--background-color)', border: '1px solid var(--border-color)'}}>
                          <h3 style={{fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '1rem', textTransform: 'uppercase'}}>Active Protection Modules</h3>
                          <ul style={{listStyle: 'none', padding: 0, fontSize: '0.9rem', color: 'var(--text-color)'}}>
                             <li style={{marginBottom: '8px'}}>🛡️ <strong>IdentityGuard:</strong> IAM & Policy Analysis</li>
                             <li style={{marginBottom: '8px'}}>🌐 <strong>DGA Shield:</strong> Domain Generation Intelligence</li>
                             <li style={{marginBottom: '8px'}}>⚙️ <strong>OT/SCADA Guard:</strong> Industrial Protocol Monitor</li>
                             <li style={{marginBottom: '8px'}}>⚓ <strong>PortGuard:</strong> Adaptive Firewall & Shifting</li>
                          </ul>
                       </div>
                    </div>

                    <div style={{marginTop: '3rem', padding: '1.5rem', borderTop: '1px solid var(--border-color)', fontSize: '0.85rem', color: 'var(--text-muted)'}}>
                       Designed & Developed for Professional SOC Command & Control Operations.<br/>
                       <strong>Status:</strong> MISSION READY | <strong>Security Level:</strong> MAXIMUM
                    </div>
                 </div>
              </div>
           )}
        </section>

        {selectedAgent && (
           <div className="modal-overlay" onClick={() => setSelectedAgent(null)}>
              <div className="modal-content animate-fade-up" onClick={e => e.stopPropagation()} style={{background: 'var(--secondary-bg-color)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '2rem', maxWidth: '800px', width: '90%', position: 'relative'}}>
                 <button className="btn-close" onClick={() => setSelectedAgent(null)} style={{position: 'absolute', top: '1rem', right: '1rem', background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.5rem', cursor: 'pointer'}}>&times;</button>
                 <div style={{display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '2rem'}}>
                    <div style={{width: '80px', height: '80px', background: 'linear-gradient(135deg, var(--primary-color), var(--secondary-color))', borderRadius: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '2.5rem', fontWeight: 900, boxShadow: '0 4px 15px rgba(0,0,0,0.3)'}}>M</div>
                    <div>
                       <h2 style={{fontFamily: 'Orbitron', fontSize: '1.5rem'}}>{selectedAgent.hostname}</h2>
                       <span style={{fontSize: '0.9rem', color: 'var(--text-muted)'}}>{selectedAgent.ip} | {selectedAgent.os}</span>
                    </div>
                 </div>

                 <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem'}}>
                    <div className="card" style={{background: 'var(--background-color)', border: '1px solid var(--border-color)'}}>
                       <h3 style={{fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '1rem'}}>Asset Status & Commands</h3>
                       <div style={{display: 'flex', flexDirection: 'column', gap: '12px'}}>
                          <div style={{display: 'flex', justifyContent: 'space-between'}}>
                             <span>C2 Link</span>
                             <span style={{color: 'var(--success-color)', fontWeight: 700}}>{selectedAgent.status}</span>
                          </div>
                          <div style={{display: 'flex', justifyContent: 'space-between'}}>
                             <span>Risk Level</span>
                             <span style={{color: selectedAgent.risk_score > 5 ? 'var(--danger-color)' : 'var(--success-color)', fontWeight: 700}}>{selectedAgent.risk_score || 0}/10</span>
                          </div>
                          <div style={{marginTop: '1rem', display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
                             <button className="btn-secure" onClick={() => sendCommand(selectedAgent.hostname, 'SCAN_NOW')}>FORCE SCAN</button>
                             {selectedAgent.status === 'QUARANTINED' ? (
                                <button className="btn-secure" style={{background: 'var(--success-color)'}} onClick={() => sendCommand(selectedAgent.hostname, 'RELEASE')}>RELEASE ASSET</button>
                             ) : (
                                <button className="btn-secure" style={{background: 'var(--danger-color)'}} onClick={() => sendCommand(selectedAgent.hostname, 'QUARANTINE')}>QUARANTINE</button>
                             )}
                          </div>
                       </div>
                    </div>
                    <div className="card" style={{background: 'var(--background-color)', border: '1px solid var(--border-color)'}}>
                       <h3 style={{fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '1rem'}}>Active Modules & Intel</h3>
                       <div style={{fontSize: '0.85rem'}}>
                          <p style={{marginBottom: '0.5rem'}}><strong>Detected Services:</strong></p>
                          <div style={{display: 'flex', gap: '4px', flexWrap: 'wrap'}}>
                             {(selectedAgent.services || []).map((s, i) => (
                                <span key={i} className="badge badge-info" style={{fontSize: '0.7rem'}}>{s}</span>
                             ))}
                          </div>
                       </div>
                    </div>
                 </div>
              </div>
           </div>
        )}
      </div>
    </div>
  );
}

export default App;
