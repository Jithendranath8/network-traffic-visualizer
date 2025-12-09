/**
 * Network Traffic Analyzer & Security Monitoring Dashboard
 * Complete frontend implementation
 */

(function() {
  'use strict';

  // Global state
  let metricsWS = null;
  let alertsWS = null;
  let flowsWS = null;
  let protocolChart = null;
  let bandwidthChart = null;
  let geoMap = null;
  let networkGraph = null;
  let currentView = 'dashboard';
  
  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', init);

  function init() {
    setupNavigation();
    setupCharts();
    setupWebSockets();
    setupEventHandlers();
    loadInitialData();
    setupAnimations();
  }

  // Enhanced animations and visual effects
  function setupAnimations() {
    // Animate metric values on update
    const animateValue = (element, start, end, duration) => {
      if (!element) return;
      const startTime = performance.now();
      const isNumeric = !isNaN(parseFloat(start)) && !isNaN(parseFloat(end));
      
      if (!isNumeric) {
        element.textContent = end;
        return;
      }
      
      const animate = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = start + (end - start) * easeOut;
        
        if (element.id === 'packetsPerSec' || element.id === 'activeSessions') {
          element.textContent = Math.round(current);
        } else {
          element.textContent = end; // For bandwidth, keep original formatting
        }
        
        if (progress < 1) {
          requestAnimationFrame(animate);
        }
      };
      requestAnimationFrame(animate);
    };

    // Observe metric value changes
    const metricObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' || mutation.type === 'characterData') {
          const element = mutation.target;
          if (element.classList && element.classList.contains('metric-value')) {
            element.style.transform = 'scale(1.1)';
            setTimeout(() => {
              element.style.transform = 'scale(1)';
            }, 200);
          }
        }
      });
    });

    // Observe all metric values
    document.querySelectorAll('.metric-value').forEach(el => {
      metricObserver.observe(el, { childList: true, characterData: true, subtree: true });
    });

    // Add ripple effect to buttons
    document.addEventListener('click', (e) => {
      if (e.target.matches('button, .nav-btn, .ack-btn, .view-packets-btn, .view-packet-detail-btn')) {
        const button = e.target;
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.width = ripple.style.height = size + 'px';
        ripple.style.left = x + 'px';
        ripple.style.top = y + 'px';
        ripple.style.position = 'absolute';
        ripple.style.borderRadius = '50%';
        ripple.style.background = 'rgba(255, 255, 255, 0.3)';
        ripple.style.transform = 'scale(0)';
        ripple.style.animation = 'ripple 0.6s ease-out';
        ripple.style.pointerEvents = 'none';
        
        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
      }
    });

    // Add CSS for ripple animation
    if (!document.getElementById('dynamicStyles')) {
      const style = document.createElement('style');
      style.id = 'dynamicStyles';
      style.textContent = `
        @keyframes ripple {
          to {
            transform: scale(4);
            opacity: 0;
          }
        }
        .metric-value {
          transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
      `;
      document.head.appendChild(style);
    }

    // Parallax effect on scroll
    let lastScroll = 0;
    window.addEventListener('scroll', () => {
      const currentScroll = window.pageYOffset;
      const cards = document.querySelectorAll('.card');
      
      cards.forEach((card, index) => {
        const speed = 0.1 + (index % 3) * 0.05;
        const yPos = -(currentScroll * speed);
        card.style.transform = `translateY(${yPos}px)`;
      });
      
      lastScroll = currentScroll;
    }, { passive: true });

    // Glow effect on hover for cards
    document.querySelectorAll('.card').forEach(card => {
      card.addEventListener('mouseenter', function() {
        this.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
      });
    });
  }

  // Navigation
  function setupNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const views = document.querySelectorAll('.view');
    
    navButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const viewName = btn.dataset.view;
        
        // Update active states
        navButtons.forEach(b => b.classList.remove('active'));
        views.forEach(v => v.classList.remove('active'));
        
        btn.classList.add('active');
        document.getElementById(`${viewName}View`).classList.add('active');
        currentView = viewName;
        
        // Initialize view-specific components
        switch(viewName) {
          case 'sessions':
            loadSessions();
            break;
          case 'geo':
            initGeoMap();
            break;
          case 'graph':
            initNetworkGraph();
            break;
          case 'timeline':
            initTimeline();
            break;
        }
      });
    });
  }

  // Charts setup
  function setupCharts() {
    const protocolCtx = document.getElementById('protocolChart')?.getContext('2d');
    const bandwidthCtx = document.getElementById('bandwidthChart')?.getContext('2d');
    
    if (protocolCtx) {
      protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
          labels: ['TCP', 'UDP', 'ICMP', 'Other'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: ['#60a5fa', '#34d399', '#fbbf24', '#a78bfa'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#9ca3af' } }
          }
        }
      });
    }
    
    if (bandwidthCtx) {
      bandwidthChart = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Bytes/sec',
            data: [],
            borderColor: '#00f0ff',
            backgroundColor: 'rgba(0, 240, 255, 0.15)',
            tension: 0.3,
            pointRadius: 0,
            fill: true,
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 200 },
          scales: {
            x: { 
              ticks: { color: '#9ca3af', maxTicksLimit: 10 },
              grid: { color: 'rgba(255, 255, 255, 0.05)' }
            },
            y: { 
              beginAtZero: true,
              ticks: { 
                color: '#9ca3af',
                callback: function(value) {
                  if (value >= 1000000) return (value / 1000000).toFixed(1) + 'MB';
                  if (value >= 1000) return (value / 1000).toFixed(1) + 'KB';
                  return value + 'B';
                }
              },
              grid: { color: 'rgba(255, 255, 255, 0.05)' }
            }
          },
          plugins: {
            legend: { 
              labels: { color: '#9ca3af' },
              display: false
            }
          }
        }
      });
    }
  }

  // WebSocket connections
  function setupWebSockets() {
    connectMetricsWS();
    connectAlertsWS();
    connectFlowsWS();
  }

  function connectMetricsWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    metricsWS = new WebSocket(`${proto}://${location.host}/ws/metrics`);
    
    metricsWS.onopen = () => {
      updateStatus('Connected', 'success');
    };
    
    metricsWS.onclose = () => {
      updateStatus('Disconnected. Reconnecting...', 'warning');
      setTimeout(connectMetricsWS, 2000);
    };
    
    metricsWS.onerror = () => {
      updateStatus('Connection error', 'error');
    };
    
    metricsWS.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        updateMetrics(data);
      } catch (e) {
        console.error('Invalid metrics data', e);
      }
    };
  }

  function connectAlertsWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    alertsWS = new WebSocket(`${proto}://${location.host}/ws/alerts`);
    
    alertsWS.onopen = () => console.log('Alerts WS connected');
    alertsWS.onclose = () => setTimeout(connectAlertsWS, 2000);
    alertsWS.onerror = () => console.error('Alerts WS error');
    
    alertsWS.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.alerts && data.alerts.length > 0) {
          displayNewAlerts(data.alerts);
        }
      } catch (e) {
        console.error('Invalid alerts data', e);
      }
    };
  }

  function connectFlowsWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    flowsWS = new WebSocket(`${proto}://${location.host}/ws/flows`);
    
    flowsWS.onopen = () => console.log('Flows WS connected');
    flowsWS.onclose = () => setTimeout(connectFlowsWS, 2000);
    flowsWS.onerror = () => console.error('Flows WS error');
    
    flowsWS.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (currentView === 'sessions') {
          displayFlows(data.flows || []);
        }
        if (currentView === 'graph') {
          updateNetworkGraph(data.flows || []);
        }
      } catch (e) {
        console.error('Invalid flows data', e);
      }
    };
  }

  // Update metrics display
  function updateMetrics(data) {
    // Protocol chart
    if (protocolChart && data.protocol_counts) {
      protocolChart.data.datasets[0].data = [
        data.protocol_counts.tcp || 0,
        data.protocol_counts.udp || 0,
        data.protocol_counts.icmp || 0,
        data.protocol_counts.other || 0
      ];
      protocolChart.update('none');
    }
    
    // Bandwidth chart
    if (bandwidthChart && data.bandwidth_series) {
      const series = data.bandwidth_series.slice(-60); // Last 60 points
      bandwidthChart.data.labels = series.map(p => 
        new Date(p.timestamp_ms).toLocaleTimeString()
      );
      bandwidthChart.data.datasets[0].data = series.map(p => p.bytes);
      bandwidthChart.update('none');
      
      // Update bandwidth metric
      const latest = series[series.length - 1];
      if (latest) {
        document.getElementById('bandwidth').textContent = formatBytes(latest.bytes) + '/s';
      }
    }
    
    // Top talkers
    if (data.top_talkers) {
      updateTopTalkers(data.top_talkers);
    }
    
    // Live metrics
    if (data.packets_per_sec !== undefined) {
      document.getElementById('packetsPerSec').textContent = data.packets_per_sec.toFixed(1);
    }
    if (data.active_sessions !== undefined) {
      document.getElementById('activeSessions').textContent = data.active_sessions;
    }
  }

  function updateTopTalkers(talkers) {
    const tbody = document.querySelector('#talkersTable tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    talkers.slice(0, 10).forEach((t, index) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${t.ip}</td>
        <td>${formatBytes(t.bytes)}</td>
        <td>${t.packets}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Session Explorer
  async function loadSessions() {
    try {
      const ipFilter = document.getElementById('sessionFilterIP')?.value || '';
      const protocolFilter = document.getElementById('sessionFilterProtocol')?.value || '';
      
      let url = '/flows?limit=100';
      if (ipFilter) url += `&src_ip=${encodeURIComponent(ipFilter)}`;
      if (protocolFilter) url += `&protocol=${encodeURIComponent(protocolFilter)}`;
      
      console.log('Loading sessions with URL:', url);
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      const data = await res.json();
      console.log('Loaded flows:', data.flows?.length || 0);
      displayFlows(data.flows || []);
    } catch (e) {
      console.error('Failed to load sessions', e);
      alert('Failed to load sessions: ' + e.message);
    }
  }

  function displayFlows(flows) {
    const tbody = document.querySelector('#sessionsTable tbody');
    if (!tbody) return;
    
    
    if (flows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 40px;">No active sessions</td></tr>';
      return;
    }
    
    tbody.innerHTML = '';
    flows.forEach((flow , index) => {
      const tr = document.createElement('tr');
      // tr.style.cursor = 'pointer';

      const srcPort = flow.src_port ;
      const dstPort = flow.dst_port ;
      const protocol = flow.protocol ;
      const bytes = formatBytes(flow.total_bytes || 0);
      const packets = flow.packet_count || 0;
      const duration = formatDuration(flow.duration || 0);
      const flags = Array.isArray(flow.tcp_flags) ? flow.tcp_flags.join(', ') : (flow.tcp_flags );
      
      tr.innerHTML = `
        <td>${flow.src_ip } → ${flow.dst_ip }</td>
        <td>${srcPort}:${dstPort}</td>
        <td>${protocol}</td>
        <td>${bytes}</td>
        <td>${packets}</td>
        <td>${duration}</td>
        <td>${flags}</td>
        <td><button class="view-packets-btn" data-flow-key="${flow.src_ip}-${flow.dst_ip}-${flow.src_port}-${flow.dst_port}-${flow.protocol}">View Packets</button></td>
      `;
      
      // Add click handler to row
      tr.addEventListener('click', (e) => {
        if (!e.target.classList.contains('view-packets-btn')) {
          showFlowPackets(flow);
        }
      });
      
      // Add click handler to button
      const btn = tr.querySelector('.view-packets-btn');
      if (btn) {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          e.preventDefault();
          console.log('View Packets button clicked for flow:', flow);
          showFlowPackets(flow);
        });
      } else {
        console.warn('View Packets button not found in row');
      }
      
      tbody.appendChild(tr);
    });
  }

  async function showFlowPackets(flow) {
    try {
      console.log('Loading packets for flow:', flow);
      // Load recent packets and filter by flow
      const res = await fetch('/packets?limit=500');
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      const data = await res.json();
      
      // Filter packets matching this flow
      const flowPackets = (data.packets || []).filter(pkt => {
        const matchSrc = pkt.src_ip === flow.src_ip && pkt.src_port === flow.src_port;
        const matchDst = pkt.dst_ip === flow.dst_ip && pkt.dst_port === flow.dst_port;
        const matchReverse = pkt.src_ip === flow.dst_ip && pkt.src_port === flow.dst_port &&
                             pkt.dst_ip === flow.src_ip && pkt.dst_port === flow.src_port;
        return (matchSrc && matchDst) || matchReverse;
      });
      
      console.log(`Found ${flowPackets.length} packets for flow`);
      displayPacketModal(flow, flowPackets);
    } catch (e) {
      console.error('Failed to load packets', e);
      alert('Failed to load packets: ' + e.message);
    }
  }

  function displayPacketModal(flow, packets) {
    // Validate flow object
    if (!flow) {
      console.error('Flow object is null or undefined');
      alert('Invalid flow data. Please try again.');
      return;
    }
    
    if (!flow.src_ip || !flow.dst_ip) {
      console.error('Flow missing required properties:', flow);
      alert('Flow data is incomplete. Please try again.');
      return;
    }
    
    // Create or update modal
    let modal = document.getElementById('packetModal');
    
    // Check if modal exists but is missing required structure
    const needsRecreation = modal && (!modal.querySelector('#flowInfo') || !modal.querySelector('#packetsTable'));
    
    if (!modal || needsRecreation) {
      // Remove old modal if it exists but is broken
      if (modal && needsRecreation) {
        try {
          modal.remove();
        } catch (e) {
          console.warn('Error removing old modal:', e);
        }
      }
      
      modal = document.createElement('div');
      modal.id = 'packetModal';
      modal.className = 'modal';
      modal.style.display = 'none';
      
      const modalHTML = `
        <div class="modal-content">
          <div class="modal-header">
            <h2>Packets for Flow</h2>
            <button class="modal-close">&times;</button>
          </div>
          <div class="modal-body">
            <div id="flowInfo" style="margin-bottom: 20px; padding: 15px; background: #1f2937; border-radius: 8px;"></div>
            <div style="max-height: 500px; overflow-y: auto;">
              <table id="packetsTable" style="width: 100%;">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Size</th>
                    <th>Info</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody></tbody>
              </table>
            </div>
          </div>
        </div>
      `;
      
      modal.innerHTML = modalHTML;
      document.body.appendChild(modal);
      
      // Close button handler - use event delegation to avoid duplicate listeners
      modal.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-close')) {
          modal.style.display = 'none';
        } else if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
    }
    
    // Ensure modal exists
    if (!modal) {
      console.error('Failed to create modal');
      alert('Failed to create modal. Please refresh the page.');
      return;
    }
    
    // Update flow info - elements should exist after innerHTML
    let flowInfo = modal.querySelector('#flowInfo');
    if (!flowInfo) {
      console.error('flowInfo element not found in modal');
      console.log('Modal structure:', modal.innerHTML.substring(0, 200));
      // Recreate modal structure
      const modalContent = modal.querySelector('.modal-content');
      if (modalContent) {
        const modalBody = modalContent.querySelector('.modal-body');
        if (modalBody) {
          // Ensure flowInfo exists
          flowInfo = modalBody.querySelector('#flowInfo');
          if (!flowInfo) {
            flowInfo = document.createElement('div');
            flowInfo.id = 'flowInfo';
            flowInfo.style.marginBottom = '20px';
            flowInfo.style.padding = '15px';
            flowInfo.style.background = '#1f2937';
            flowInfo.style.borderRadius = '8px';
            modalBody.insertBefore(flowInfo, modalBody.firstChild);
          }
        }
      }
      
      // Final check
      if (!flowInfo) {
        flowInfo = modal.querySelector('#flowInfo');
        if (!flowInfo) {
          console.error('Failed to create flowInfo element');
          alert('Modal structure error. Please refresh the page.');
          return;
        }
      }
    }
    
    try {
      flowInfo.innerHTML = `
        <strong>Flow:</strong> ${flow.src_ip || 'N/A'}:${flow.src_port || 'N/A'} → ${flow.dst_ip || 'N/A'}:${flow.dst_port || 'N/A'}<br>
        <strong>Protocol:</strong> ${flow.protocol || 'N/A'}<br>
        <strong>Total Bytes:</strong> ${formatBytes(flow.total_bytes || 0)} | 
        <strong>Packets:</strong> ${flow.packet_count || 0} | 
        <strong>Duration:</strong> ${formatDuration(flow.duration || 0)}
      `;
    } catch (e) {
      console.error('Error setting flowInfo innerHTML:', e);
      alert('Error displaying flow information: ' + e.message);
      return;
    }
    
    // Update packets table
    let tbody = modal.querySelector('#packetsTable tbody');
    if (!tbody) {
      console.error('Packets table tbody not found, attempting to create it');
      const packetsTable = modal.querySelector('#packetsTable');
      if (packetsTable) {
        // Check if thead exists, if not create full table structure
        if (!packetsTable.querySelector('thead')) {
          packetsTable.innerHTML = `
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Size</th>
                <th>Info</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody></tbody>
          `;
        } else {
          // Just add tbody if it's missing
          tbody = document.createElement('tbody');
          packetsTable.appendChild(tbody);
        }
        tbody = modal.querySelector('#packetsTable tbody');
      }
      
      if (!tbody) {
        console.error('Failed to create packets table tbody');
        alert('Table structure error. Please refresh the page.');
        return;
      }
    }
    
      tbody.innerHTML = '';
      
      if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px;">No packets found for this flow</td></tr>';
      } else {
        packets.forEach(pkt => {
          const tr = document.createElement('tr');
          tr.className = 'packet-row';
          tr.style.cursor = 'pointer';
          tr.innerHTML = `
            <td>${pkt.src_ip}:${pkt.src_port || '-'}</td>
            <td>${pkt.dst_ip}:${pkt.dst_port || '-'}</td>
            <td>${pkt.protocol}</td>
            <td>${formatBytes(pkt.size_bytes)}</td>
            <td><button class="view-packet-detail-btn" data-packet-id="${pkt.id}">Details</button></td>
          `;
          
          tr.addEventListener('click', (e) => {
            if (!e.target.classList.contains('view-packet-detail-btn')) {
              showPacketDetail(pkt.id);
            }
          });
          
          const detailBtn = tr.querySelector('.view-packet-detail-btn');
          if (detailBtn) {
            detailBtn.addEventListener('click', (e) => {
              e.stopPropagation();
              showPacketDetail(pkt.id);
            });
          }
          
          tbody.appendChild(tr);
        });
      }
      
    // Show the modal
    if (modal) {
      modal.style.display = 'flex';
    } else {
      console.error('Modal is null, cannot display');
      alert('Failed to display modal. Please refresh the page.');
    }
  }

  async function showPacketDetail(packetId) {
    try {
      const res = await fetch(`/packets/${packetId}`);
      const pkt = await res.json();
      
      // Create detail modal
      let detailModal = document.getElementById('packetDetailModal');
      if (!detailModal) {
        detailModal = document.createElement('div');
        detailModal.id = 'packetDetailModal';
        detailModal.className = 'modal';
        detailModal.innerHTML = `
          <div class="modal-content" style="max-width: 800px;">
            <div class="modal-header">
              <h2>Packet Details</h2>
              <button class="modal-close">&times;</button>
            </div>
            <div class="modal-body" id="packetDetailBody"></div>
          </div>
        `;
        document.body.appendChild(detailModal);
        
        detailModal.querySelector('.modal-close').addEventListener('click', () => {
          detailModal.style.display = 'none';
        });
        
        detailModal.addEventListener('click', (e) => {
          if (e.target === detailModal) {
            detailModal.style.display = 'none';
          }
        });
      }
      
      const body = detailModal.querySelector('#packetDetailBody');
      body.innerHTML = `
        <div style="font-family: monospace; background: #111827; padding: 20px; border-radius: 8px; overflow-x: auto;">
          <div><strong>Timestamp:</strong> ${new Date(pkt.timestamp_ms).toLocaleString()}</div>
          <div><strong>Source IP:</strong> ${pkt.src_ip}</div>
          <div><strong>Source Port:</strong> ${pkt.src_port || 'N/A'}</div>
          <div><strong>Destination IP:</strong> ${pkt.dst_ip}</div>
          <div><strong>Destination Port:</strong> ${pkt.dst_port || 'N/A'}</div>
          <div><strong>Protocol:</strong> ${pkt.protocol}</div>
          <div><strong>Size:</strong> ${formatBytes(pkt.size_bytes)}</div>
          <div><strong>Data Length:</strong> ${formatBytes(pkt.data_length)}</div>
          <div><strong>Flags:</strong> ${pkt.flags || 'N/A'}</div>
          <div><strong>Info:</strong> ${pkt.info || 'N/A'}</div>
          ${pkt.domain ? `<div><strong>DNS Domain:</strong> ${pkt.domain}</div>` : ''}
        </div>
      `;
      
      detailModal.style.display = 'flex';
    } catch (e) {
      console.error('Failed to load packet details', e);
      showNotification('Error', 'Failed to load packet details', 'error');
    }
  }

  // Alert Center
  async function loadAlerts() {
    try {
      const unackOnly = document.getElementById('alertsUnacknowledgedOnly')?.checked || false;
      const res = await fetch(`/alerts?limit=100&unacknowledged_only=${unackOnly}`);
      const data = await res.json();
      displayAlerts(data.alerts || []);
    } catch (e) {
      console.error('Failed to load alerts', e);
    }
  }

  function displayAlerts(alerts) {
    const container = document.getElementById('alertsTimeline');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (alerts.length === 0) {
      container.innerHTML = '<div style="text-align: center; padding: 40px;">No alerts</div>';
      return;
    }
    
    alerts.forEach(alert => {
      const severityClass = `severity-${alert.severity}`;
      const alertEl = document.createElement('div');
      alertEl.className = `alert-item ${severityClass}`;
      alertEl.innerHTML = `
        <div class="alert-header">
          <span class="alert-type">${alert.alert_type}</span>
          <span class="alert-severity">${alert.severity.toUpperCase()}</span>
          ${alert.acknowledged ? '<span class="alert-ack">ACK</span>' : ''}
        </div>
        <div class="alert-time">${new Date(alert.timestamp * 1000).toLocaleString()}</div>
        <div class="alert-source">Source: ${alert.source_ip}</div>
        <div class="alert-description">${alert.description}</div>
        ${!alert.acknowledged ? `<button class="ack-btn" data-timestamp="${alert.timestamp}" data-ip="${alert.source_ip}">Acknowledge</button>` : ''}
      `;
      
      const ackBtn = alertEl.querySelector('.ack-btn');
      if (ackBtn) {
        ackBtn.addEventListener('click', () => acknowledgeAlert(alert.timestamp, alert.source_ip));
      }
      
      container.appendChild(alertEl);
    });
  }

  function displayNewAlerts(alerts) {
    // Show notification for new alerts
    alerts.forEach(alert => {
      if (alert.severity === 'critical' || alert.severity === 'high') {
        showNotification(`Security Alert: ${alert.alert_type}`, alert.description, 'error');
      }
    });
    
    // Refresh alerts if on alerts view
    if (currentView === 'alerts') {
      loadAlerts();
    }
  }

  async function acknowledgeAlert(timestamp, sourceIp) {
    try {
      const res = await fetch(`/alerts/${timestamp}/acknowledge?source_ip=${encodeURIComponent(sourceIp)}`, {
        method: 'POST'
      });
      if (res.ok) {
        loadAlerts();
      }
    } catch (e) {
      console.error('Failed to acknowledge alert', e);
    }
  }

  // Geo IP Map
  function initGeoMap() {
    const mapEl = document.getElementById('geoMap');
    if (!mapEl || geoMap) return;
    
    geoMap = L.map('geoMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '©️ OpenStreetMap contributors'
    }).addTo(geoMap);
    
    loadGeoData();
  }

  async function loadGeoData() {
    try {
      const res = await fetch('/top-talkers?limit=50&with_geo=true');
      const talkers = await res.json();
      
      if (!geoMap) return;
      
      talkers.forEach(talker => {
        if (talker.geo && talker.geo.latitude && talker.geo.longitude) {
          const marker = L.circleMarker([talker.geo.latitude, talker.geo.longitude], {
            radius: Math.min(20, Math.max(5, talker.bytes / 1000000)),
            fillColor: '#3b82f6',
            color: '#fff',
            weight: 2,
            opacity: 1,
            fillOpacity: 0.6
          }).addTo(geoMap);
          
          marker.bindPopup(`
            <strong>${talker.ip}</strong><br>
            ${talker.geo.country || 'Unknown'}<br>
            ${formatBytes(talker.bytes)} / ${talker.packets} packets
          `);
        }
      });
    } catch (e) {
      console.error('Failed to load geo data', e);
    }
  }

  // Network Graph
  function initNetworkGraph() {
    const graphEl = document.getElementById('networkGraph');
    if (!graphEl) return;
    
    const width = graphEl.clientWidth;
    const height = 600;
    
    const svg = d3.select('#networkGraph')
      .append('svg')
      .attr('width', width)
      .attr('height', height);
    
    networkGraph = { svg, width, height };
    updateNetworkGraph([]);
  }

  function updateNetworkGraph(flows) {
    if (!networkGraph) return;
    
    const { svg, width, height } = networkGraph;
    svg.selectAll('*').remove();
    
    // Build nodes and links from flows
    const nodesMap = new Map();
    const links = [];
    
    flows.forEach(flow => {
      if (!nodesMap.has(flow.src_ip)) {
        nodesMap.set(flow.src_ip, { id: flow.src_ip, group: 1 });
      }
      if (!nodesMap.has(flow.dst_ip)) {
        nodesMap.set(flow.dst_ip, { id: flow.dst_ip, group: 2 });
      }
      links.push({
        source: flow.src_ip,
        target: flow.dst_ip,
        value: flow.total_bytes
      });
    });
    
    const nodes = Array.from(nodesMap.values());
    
    if (nodes.length === 0) {
      svg.append('text')
        .attr('x', width / 2)
        .attr('y', height / 2)
        .attr('text-anchor', 'middle')
        .attr('fill', '#9ca3af')
        .text('No network connections');
      return;
    }
    
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2));
    
    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', '#60a5fa')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.sqrt(d.value) / 1000);
    
    const node = svg.append('g')
      .selectAll('circle')
      .data(nodes)
      .enter().append('circle')
      .attr('r', 8)
      .attr('fill', '#3b82f6')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));
    
    const label = svg.append('g')
      .selectAll('text')
      .data(nodes)
      .enter().append('text')
      .text(d => d.id)
      .attr('font-size', 10)
      .attr('fill', '#e5e7eb')
      .attr('dx', 12)
      .attr('dy', 4);
    
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      
      node
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);
      
      label
        .attr('x', d => d.x)
        .attr('y', d => d.y);
    });
    
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }
    
    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }
    
    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }
  }

  // Timeline Replay
  function initTimeline() {
    // Timeline chart setup
    const timelineEl = document.getElementById('timelineChart');
    if (!timelineEl) return;
    
    // Simple timeline visualization
    timelineEl.innerHTML = '<div style="text-align: center; padding: 40px; color: #9ca3af;">Upload a PCAP file to begin playback</div>';
  }

  async function uploadPCAP() {
    const fileInput = document.getElementById('pcapFileInput');
    const speedInput = document.getElementById('pcapSpeed');
    const uploadBtn = document.getElementById('uploadPcap');
    const timelineEl = document.getElementById('timelineChart');
    
    if (!fileInput || !fileInput.files.length) {
      updateTimelineStatus('error', ' Please select a PCAP file first');
      return;
    }
    
    const file = fileInput.files[0];
    const speed = parseFloat(speedInput?.value) || 1.0;
    
    console.log('📤 Uploading PCAP file:', file.name, 'Size:', file.size, 'Speed:', speed + 'x');
    
    // Show loading state
    if (uploadBtn) {
      uploadBtn.disabled = true;
      uploadBtn.textContent = 'Uploading...';
    }
    
    // Show upload progress in timeline
    updateTimelineStatus('uploading', {
      message: '📤 Uploading PCAP file...',
      file: file.name,
      size: formatBytes(file.size),
      speed: speed + 'x'
    });
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('speed', speed.toString());
    
    try {
      const startTime = Date.now();
      const res = await fetch('/pcap/upload', {
        method: 'POST',
        body: formData
      });
      
      const uploadTime = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log('📥 Response status:', res.status, res.statusText, `(${uploadTime}s)`);
      
      if (!res.ok) {
        const errorText = await res.text();
        console.error(' Upload failed:', errorText);
        updateTimelineStatus('error', {
          message: ` Upload failed (${res.status})`,
          error: errorText,
          file: file.name
        });
        if (uploadBtn) {
          uploadBtn.disabled = false;
          uploadBtn.textContent = 'Upload & Play';
        }
        return;
      }
      
      const data = await res.json();
      console.log('Upload response:', data);
      
      if (data.success) {
        // Show success status in timeline
        updateTimelineStatus('success', {
          message: 'PCAP Upload Successful',
          response: data.message,
          filename: data.filename || file.name,
          speed: speed + 'x',
          uploadTime: uploadTime + 's'
        });
        
        showNotification('PCAP Upload', data.message, 'success');
        
        // Start monitoring stats immediately and continuously
        let statsCheckCount = 0;
        const maxChecks = 30; // Check for 60 seconds (30 × 2s)
        let statsInterval = null;
        let hasSeenActivity = false;
        
        // Check immediately, then every 2 seconds
        const checkStats = async () => {
          try {
            const statsRes = await fetch('/stats');
            if (!statsRes.ok) {
              console.error(' Stats request failed:', statsRes.status, statsRes.statusText);
              return;
            }
            
            const stats = await statsRes.json();
            statsCheckCount++;
            
            const packetsPerSec = stats.packets_per_sec || 0;
            const activeSessions = stats.active_sessions || 0;
            const bandwidth = stats.bandwidth_bytes_per_sec || 0;
            
            console.log(`Stats check #${statsCheckCount}:`, {
              packets_per_sec: packetsPerSec,
              active_sessions: activeSessions,
              bandwidth_bytes_per_sec: bandwidth,
              top_talkers: stats.top_talkers?.length || 0,
              protocol_distribution: stats.protocol_distribution
            });
            
            // Update timeline with live stats
            updateTimelineStatus('playing', {
              message: 'PCAP Replay Active',
              filename: data.filename || file.name,
              speed: speed + 'x',
              packetsPerSec: packetsPerSec,
              activeSessions: activeSessions,
              bandwidth: formatBytes(bandwidth) + '/s',
              checkCount: statsCheckCount,
              maxChecks: maxChecks
            });
            
            // Track if we've seen any activity
            if (packetsPerSec > 0 || activeSessions > 0 || bandwidth > 0) {
              if (!hasSeenActivity) {
                console.log('PCAP replay is working! Packets detected.');
                hasSeenActivity = true;
              }
            } else if (statsCheckCount > 5 && !hasSeenActivity) {
              console.warn('No packets detected after 10 seconds.');
              console.warn('Possible issues:');
              console.warn('   1. PCAP file might be empty or corrupted');
              console.warn('   2. PCAP replay might have finished already');
              console.warn('   3. Packets might not be processing correctly');
              console.warn('   → Click "Check Debug Info" button to investigate');
            }
            
            if (statsCheckCount >= maxChecks) {
              if (statsInterval) {
                clearInterval(statsInterval);
                statsInterval = null;
              }
              console.log('Stats monitoring completed');
              if (!hasSeenActivity) {
                console.error(' No activity detected during entire monitoring period!');
              }
            }
          } catch (e) {
            console.error(' Failed to check stats:', e);
            statsCheckCount++;
            if (statsCheckCount >= maxChecks && statsInterval) {
              clearInterval(statsInterval);
              statsInterval = null;
            }
          }
        };
        
        // Check immediately
        checkStats();
        
        // Then check every 2 seconds
        statsInterval = setInterval(checkStats, 2000);
        
      } else {
        updateTimelineStatus('error', {
          message: ' Upload Failed',
          error: data.error || 'Unknown error',
          file: file.name
        });
        showNotification('PCAP Upload Failed', data.error || 'Unknown error', 'error');
      }
    } catch (e) {
      console.error(' Failed to upload PCAP', e);
      updateTimelineStatus('error', {
        message: ' Upload Error',
        error: e.message,
        file: file.name
      });
      showNotification('Upload Error', e.message, 'error');
    } finally {
      if (uploadBtn) {
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload & Play';
      }
    }
  }
  
  // Function to update timeline status display
  function updateTimelineStatus(status, data) {
    const timelineEl = document.getElementById('timelineChart');
    if (!timelineEl) return;
    
    let html = '';
    
    if (status === 'uploading') {
      html = `
        <div style="padding: 30px; text-align: center; background: rgba(0, 102, 255, 0.1); border-radius: 8px; border: 2px solid rgba(0, 102, 255, 0.3);">
          <div style="font-size: 24px; margin-bottom: 15px;">${data.message}</div>
          <div style="color: #9ca3af; margin: 10px 0;">
            <strong>File:</strong> ${data.file}<br>
            <strong>Size:</strong> ${data.size}<br>
            <strong>Speed:</strong> ${data.speed}
          </div>
          <div style="margin-top: 20px;">
            <div class="spinner" style="display: inline-block; width: 20px; height: 20px; border: 3px solid rgba(0, 240, 255, 0.3); border-top-color: #00f0ff; border-radius: 50%; animation: spin 1s linear infinite;"></div>
            <div style="margin-top: 10px; color: #9ca3af;">Please wait...</div>
          </div>
        </div>
      `;
    } else if (status === 'success') {
      html = `
        <div style="padding: 30px; text-align: center; background: rgba(0, 255, 136, 0.1); border-radius: 8px; border: 2px solid rgba(0, 255, 136, 0.3);">
          <div style="font-size: 24px; color: #00ff88; margin-bottom: 15px;">${data.message}</div>
          <div style="color: #fff; margin: 15px 0; line-height: 1.8;">
            <div><strong>Response:</strong> ${data.response}</div>
            <div><strong>Filename:</strong> ${data.filename}</div>
            <div><strong>Replay Speed:</strong> ${data.speed}</div>
            <div><strong>Upload Time:</strong> ${data.uploadTime}</div>
          </div>
          <div style="margin-top: 20px; padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 6px;">
            <div style="color: #00f0ff; font-weight: bold; margin-bottom: 10px;">📊 Monitoring Replay Status...</div>
            <div style="color: #9ca3af; font-size: 14px;">Checking stats every 2 seconds...</div>
          </div>
        </div>
      `;
    } else if (status === 'playing') {
      html = `
        <div style="padding: 30px; background: rgba(0, 240, 255, 0.05); border-radius: 8px; border: 2px solid rgba(0, 240, 255, 0.3);">
          <div style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 24px; color: #00f0ff; margin-bottom: 10px;">${data.message}</div>
            <div style="color: #9ca3af; font-size: 14px;">File: ${data.filename} | Speed: ${data.speed}</div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
            <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 6px; border-left: 3px solid #00f0ff;">
              <div style="color: #9ca3af; font-size: 12px; margin-bottom: 5px;">Packets/sec</div>
              <div style="color: #00f0ff; font-size: 24px; font-weight: bold;">${data.packetsPerSec.toLocaleString()}</div>
            </div>
            <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 6px; border-left: 3px solid #b026ff;">
              <div style="color: #9ca3af; font-size: 12px; margin-bottom: 5px;">Active Sessions</div>
              <div style="color: #b026ff; font-size: 24px; font-weight: bold;">${data.activeSessions}</div>
            </div>
            <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 6px; border-left: 3px solid #00ff88;">
              <div style="color: #9ca3af; font-size: 12px; margin-bottom: 5px;">Bandwidth</div>
              <div style="color: #00ff88; font-size: 20px; font-weight: bold;">${data.bandwidth}</div>
            </div>
          </div>
          <div style="margin-top: 15px; text-align: center; color: #707080; font-size: 12px;">
            Status checks: ${data.checkCount}/${data.maxChecks || 30} | Watch the Dashboard for live updates!
            ${data.packetsPerSec === 0 && data.checkCount > 3 ? '<br><span style="color: #ff6600;">⚠️ No packets detected yet. Click "Check Debug Info" below or check backend logs.</span>' : ''}
          </div>
          <div style="margin-top: 10px; text-align: center;">
            <button onclick="checkDebugInfo()" style="padding: 8px 16px; background: rgba(0, 240, 255, 0.2); border: 1px solid #00f0ff; color: #00f0ff; border-radius: 4px; cursor: pointer; font-size: 12px;">🔍 Check Debug Info</button>
          </div>
        </div>
      `;
    } else if (status === 'error') {
      html = `
        <div style="padding: 30px; text-align: center; background: rgba(255, 51, 102, 0.1); border-radius: 8px; border: 2px solid rgba(255, 51, 102, 0.3);">
          <div style="font-size: 24px; color: #ff3366; margin-bottom: 15px;">${data.message}</div>
          ${data.error ? `<div style="color: #ffaaaa; margin: 15px 0; padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 6px; font-family: monospace; font-size: 14px;">${data.error}</div>` : ''}
          ${data.file ? `<div style="color: #9ca3af; margin-top: 10px;">File: ${data.file}</div>` : ''}
        </div>
      `;
    } else if (status === 'ready') {
      html = `
        <div style="padding: 30px; text-align: center; background: rgba(176, 38, 255, 0.1); border-radius: 8px; border: 2px solid rgba(176, 38, 255, 0.3);">
          <div style="font-size: 24px; color: #b026ff; margin-bottom: 15px;">${data.message}</div>
          <div style="color: #fff; margin: 15px 0; line-height: 1.8;">
            <div><strong>File:</strong> ${data.file}</div>
            <div><strong>Size:</strong> ${data.size}</div>
          </div>
          <div style="margin-top: 20px; color: #9ca3af;">${data.instruction}</div>
        </div>
      `;
    } else if (status === 'stopped') {
      html = `
        <div style="padding: 30px; text-align: center; background: rgba(255, 102, 0, 0.1); border-radius: 8px; border: 2px solid rgba(255, 102, 0, 0.3);">
          <div style="font-size: 24px; color: #ff6600; margin-bottom: 15px;">${data.message}</div>
          <div style="color: #fff; margin: 15px 0;">${data.response}</div>
          <div style="margin-top: 20px; color: #9ca3af;">Upload a new file to begin playback</div>
        </div>
      `;
    } else {
      html = `<div style="text-align: center; padding: 40px; color: #9ca3af;">${data.message || 'Upload a PCAP file to begin playback'}</div>`;
    }
    
    timelineEl.innerHTML = html;
  }

  async function stopPCAP() {
    const stopBtn = document.getElementById('stopPcap');
    
    if (stopBtn) {
      stopBtn.disabled = true;
      stopBtn.textContent = 'Stopping...';
    }
    
    updateTimelineStatus('uploading', {
      message: '⏹️ Stopping PCAP replay...',
      file: '',
      size: '',
      speed: ''
    });
    
    try {
      console.log('⏹️ Stopping PCAP replay...');
      const res = await fetch('/pcap/replay/stop', { method: 'POST' });
      
      if (!res.ok) {
        const errorText = await res.text();
        console.error(' Stop failed:', errorText);
        updateTimelineStatus('error', {
          message: ' Failed to stop replay',
          error: errorText,
          file: ''
        });
        if (stopBtn) {
          stopBtn.disabled = false;
          stopBtn.textContent = 'Stop';
        }
        return;
      }
      
      const data = await res.json();
      console.log('Stop response:', data);
      
      showNotification('PCAP Replay', data.message || 'Replay stopped', 'info');
      
      // Update timeline message
      updateTimelineStatus('stopped', {
        message: '⏹️ PCAP Replay Stopped',
        response: data.message || 'Replay stopped successfully'
      });
    } catch (e) {
      console.error(' Failed to stop PCAP replay', e);
      updateTimelineStatus('error', {
        message: ' Error stopping replay',
        error: e.message,
        file: ''
      });
    } finally {
      if (stopBtn) {
        stopBtn.disabled = false;
        stopBtn.textContent = 'Stop';
      }
    }
  }

  // Event handlers
  function setupEventHandlers() {
    // Session refresh button
    const refreshSessions = document.getElementById('refreshSessions');
    if (refreshSessions) {
      refreshSessions.addEventListener('click', loadSessions);
    }
    
    // Auto-refresh on filter change
    const sessionFilterIP = document.getElementById('sessionFilterIP');
    if (sessionFilterIP) {
      let filterTimeout;
      sessionFilterIP.addEventListener('input', () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(() => {
          loadSessions();
        }, 500); // Debounce: wait 500ms after user stops typing
      });
    }
    
    const sessionFilterProtocol = document.getElementById('sessionFilterProtocol');
    if (sessionFilterProtocol) {
      sessionFilterProtocol.addEventListener('change', (e) => {
        console.log('Protocol filter changed to:', e.target.value);
        loadSessions();
      });
    } else {
      console.error('sessionFilterProtocol element not found');
    }
    
    // Auto-refresh sessions when viewing sessions tab
    const sessionsNavBtn = document.querySelector('[data-view="sessions"]');
    if (sessionsNavBtn) {
      sessionsNavBtn.addEventListener('click', () => {
        loadSessions();
      });
    }
    
    // Alert refresh
    const refreshAlerts = document.getElementById('refreshAlerts');
    if (refreshAlerts) {
      refreshAlerts.addEventListener('click', loadAlerts);
    }
    
    // PCAP controls
    const uploadPcap = document.getElementById('uploadPcap');
    if (uploadPcap) {
      uploadPcap.addEventListener('click', uploadPCAP);
    }
    
    const stopPcap = document.getElementById('stopPcap');
    if (stopPcap) {
      stopPcap.addEventListener('click', stopPCAP);
    }
    
    const pcapSpeed = document.getElementById('pcapSpeed');
    if (pcapSpeed) {
      pcapSpeed.addEventListener('input', (e) => {
        const label = document.getElementById('pcapSpeedLabel');
        if (label) {
          label.textContent = e.target.value + 'x';
        }
      });
    }
    
    // Add file input change handler for better UX
    if (fileInput) {
      fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
          console.log('📁 File selected:', file.name, 'Size:', formatBytes(file.size));
          updateTimelineStatus('ready', {
            message: '📁 File Ready',
            file: file.name,
            size: formatBytes(file.size),
            instruction: 'Click "Upload & Play" to start replay'
          });
        }
      });
    }
    
    // Initialize timeline display
    updateTimelineStatus('initial', {
      message: 'Upload a PCAP file to begin playback'
    });
  }

  // Initial data load
  function loadInitialData() {
    loadSessions();
    loadAlerts();
  }

  // Utility functions
  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  function formatDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(1) + 's';
    if (seconds < 3600) return (seconds / 60).toFixed(1) + 'm';
    return (seconds / 3600).toFixed(1) + 'h';
  }

  function updateStatus(message, type = 'info') {
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.textContent = message;
      statusEl.className = `status-${type}`;
    }
  }

  function showNotification(title, message, type = 'info') {
    // Simple notification (can be enhanced with a proper notification system)
    console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
    // In production, use a proper notification library
  }

  // Debug function to check backend status
  async function checkDebugInfo() {
    try {
      console.log('🔍 Checking debug info...');
      const res = await fetch('/debug');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      const debug = await res.json();
      
      console.log('📊 Debug Info:', debug);
      
      // Create or get modal
      let modal = document.getElementById('packetModal');
      if (!modal) {
        modal = document.createElement('div');
        modal.id = 'packetModal';
        modal.className = 'modal';
        document.body.appendChild(modal);
      }
      
      modal.innerHTML = `
        <div class="modal-content" style="max-width: 900px; max-height: 80vh; overflow-y: auto;">
          <div class="modal-header">
            <h2>Debug Information</h2>
            <button class="modal-close">&times;</button>
          </div>
          <div class="modal-body" style="font-family: monospace; font-size: 12px; background: #111827; padding: 20px; border-radius: 8px; overflow-x: auto;">
            <div style="margin-bottom: 20px;">
              <h3 style="color: #00f0ff;">PCAP Replay Status:</h3>
              <div style="color: #fff; margin-left: 20px; line-height: 1.8;">
                <div>Is Playing: <strong style="color: ${debug.pcap_replay?.is_playing ? '#00ff88' : '#ff3366'}">${debug.pcap_replay?.is_playing ? 'Yes' : ' No'}</strong></div>
                ${debug.pcap_replay?.filename ? `<div>File: ${debug.pcap_replay.filename}</div>` : ''}
                ${debug.pcap_replay?.speed ? `<div>Speed: ${debug.pcap_replay.speed}x</div>` : ''}
                ${debug.pcap_replay?.packets_loaded ? `<div>Packets Loaded: ${debug.pcap_replay.packets_loaded}</div>` : ''}
              </div>
            </div>
            <div style="margin-bottom: 20px;">
              <h3 style="color: #00f0ff;">Current Stats:</h3>
              <div style="color: #fff; margin-left: 20px; line-height: 1.8;">
                <div>Packets/sec: <strong>${debug.current_stats?.packets_per_sec || 0}</strong></div>
                <div>Bandwidth: <strong>${formatBytes(debug.current_stats?.bandwidth_bytes_per_sec || 0)}/s</strong></div>
                <div>Active Sessions: <strong>${debug.current_stats?.active_sessions || 0}</strong></div>
              </div>
            </div>
            <div style="margin-bottom: 20px;">
              <h3 style="color: #00f0ff;">System Status:</h3>
              <div style="color: #fff; margin-left: 20px; line-height: 1.8;">
                <div>Packets in Store: ${debug.packets_in_store || 0}</div>
                <div>Total Packets Aggregated: ${debug.total_packets_aggregated || 0}</div>
                <div>Active Flows: ${debug.active_flows || 0}</div>
                <div>Sniffer Active: ${debug.sniffer_active ? 'Yes' : 'No'}</div>
              </div>
            </div>
            <div>
              <h3 style="color: #00f0ff;">Full Debug Data:</h3>
              <pre style="background: #0a0a0f; padding: 15px; border-radius: 6px; overflow-x: auto; color: #9ca3af;">${JSON.stringify(debug, null, 2)}</pre>
            </div>
          </div>
        </div>
      `;
      
      modal.style.display = 'flex';
      
      const closeBtn = modal.querySelector('.modal-close');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          modal.style.display = 'none';
        });
      }
      
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
      
      // Also update timeline with key info if replay is active
      if (debug.pcap_replay?.is_playing) {
        const timelineEl = document.getElementById('timelineChart');
        if (timelineEl) {
          const currentContent = timelineEl.innerHTML;
          if (!currentContent.includes('Debug Info:')) {
            timelineEl.innerHTML = currentContent + `
              <div style="margin-top: 15px; padding: 15px; background: rgba(255, 102, 0, 0.1); border-radius: 6px; border: 1px solid rgba(255, 102, 0, 0.3);">
                <div style="color: #ff6600; font-weight: bold; margin-bottom: 10px;"> Debug Info:</div>
                <div style="color: #fff; font-size: 12px; line-height: 1.6;">
                  <div>PCAP Replay Active: ${debug.pcap_replay.is_playing ? 'Yes' : 'No'}</div>
                  ${debug.pcap_replay.filename ? `<div>File: ${debug.pcap_replay.filename}</div>` : ''}
                  ${debug.pcap_replay.speed ? `<div>Speed: ${debug.pcap_replay.speed}x</div>` : ''}
                  ${debug.pcap_replay.packets_loaded ? `<div>Packets Loaded: ${debug.pcap_replay.packets_loaded}</div>` : ''}
                  <div>Current Packets/sec: ${debug.current_stats?.packets_per_sec || 0}</div>
                </div>
              </div>
            `;
          }
        }
      }
    } catch (e) {
      console.error('Failed to get debug info:', e);
      alert('Failed to get debug info: ' + e.message + '\n\nCheck browser console for details.');
    }
  }

  // Make functions available globally
  window.checkDebugInfo = checkDebugInfo;
  window.acknowledgeAlert = acknowledgeAlert;

})();