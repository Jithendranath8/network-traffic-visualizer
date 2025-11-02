(function() {
  console.log('Network Traffic Analyzer script loading...');
  
  const statusEl = document.getElementById('status');
  if (!statusEl) {
    console.error('Status element not found!');
  }

  // Charts setup
  const protocolCtx = document.getElementById('protocolChart').getContext('2d');
  const bandwidthCtx = document.getElementById('bandwidthChart').getContext('2d');

  const protocolChart = new Chart(protocolCtx, {
    type: 'pie',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'Other'],
      datasets: [{
        label: 'Protocols',
        data: [0, 0, 0, 0],
        backgroundColor: ['#60a5fa', '#34d399', '#fbbf24', '#a78bfa'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      animation: { duration: 300 }
    }
  });

  const bandwidthChart = new Chart(bandwidthCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Bytes/sec',
        data: [],
        borderColor: '#60a5fa',
        backgroundColor: 'rgba(96,165,250,0.15)',
        tension: 0.3,
        pointRadius: 0,
        fill: true
      }]
    },
    options: {
      responsive: true,
      animation: { duration: 200 },
      scales: {
        x: { ticks: { color: '#9ca3af' }, grid: { color: '#232735' } },
        y: { ticks: { color: '#9ca3af' }, grid: { color: '#232735' } }
      },
      plugins: {
        legend: { labels: { color: '#e5e7eb' } }
      }
    }
  });

  function updateTopTalkers(talkers) {
    const tbody = document.querySelector('#talkersTable tbody');
    tbody.innerHTML = '';
    talkers.slice(0, 10).forEach(t => {
      const tr = document.createElement('tr');
      const ipTd = document.createElement('td'); ipTd.textContent = t.ip;
      const bytesTd = document.createElement('td'); bytesTd.textContent = t.bytes;
      const pktsTd = document.createElement('td'); pktsTd.textContent = t.packets;
      tr.appendChild(ipTd); tr.appendChild(bytesTd); tr.appendChild(pktsTd);
      tbody.appendChild(tr);
    });
  }

  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => { 
      if (statusEl) statusEl.textContent = 'Connected'; 
    };
    ws.onclose = () => { 
      if (statusEl) statusEl.textContent = 'Disconnected. Reconnecting...'; 
      setTimeout(connectWS, 1000); 
    };
    ws.onerror = (e) => { 
      // WebSocket errors are expected if server isn't fully ready, don't spam console
      if (statusEl) statusEl.textContent = 'Connecting...'; 
      // Don't close immediately, let onclose handle it
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        // Protocols
        const pc = msg.protocol_counts || { tcp: 0, udp: 0, icmp: 0, other: 0 };
        protocolChart.data.datasets[0].data = [pc.tcp||0, pc.udp||0, pc.icmp||0, pc.other||0];
        protocolChart.update('none');

        // Bandwidth series
        const series = msg.bandwidth_series || [];
        bandwidthChart.data.labels = series.map(p => new Date(p.timestamp_ms).toLocaleTimeString());
        bandwidthChart.data.datasets[0].data = series.map(p => p.bytes);
        bandwidthChart.update('none');

        // Top talkers
        updateTopTalkers(msg.top_talkers || []);
      } catch (e) {
        console.error('Invalid WS data', e);
      }
    };
  }

  connectWS();

  // Packet list functionality
  const packetsTableBody = document.getElementById('packetsTableBody');
  const refreshPacketsBtn = document.getElementById('refreshPackets');
  const packetModal = document.getElementById('packetModal');
  const packetDetailContent = document.getElementById('packetDetailContent');
  const closeModal = document.querySelector('.close');

  const packetCountEl = document.getElementById('packetCount');
  const captureStatusEl = document.getElementById('captureStatus');
  const captureHelpEl = document.getElementById('captureHelp');
  let lastPacketCount = 0;

  // Verify elements exist
  if (!packetsTableBody) {
    console.error('packetsTableBody element not found!');
  }
  if (!packetCountEl) {
    console.error('packetCount element not found!');
  }

  async function fetchPackets() {
    if (!packetCountEl) {
      console.error('packetCountEl not found, cannot update');
      return;
    }
    
    try {
      console.log('Fetching packets from /packets?limit=100...');
      const res = await fetch('/packets?limit=100');
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      const data = await res.json();
      console.log('Fetched packets data:', data); // Debug
      const packets = data.packets || [];
      console.log('Packets array length:', packets.length); // Debug
      displayPackets(packets);
      
      // Update packet count
      const count = packets.length;
      if (packetCountEl) {
        packetCountEl.textContent = `(${count} packet${count !== 1 ? 's' : ''})`;
      }
      
      // Update capture status
      if (captureStatusEl) {
        if (count === 0) {
          captureStatusEl.textContent = 'Status: Waiting for packets...';
          captureStatusEl.style.background = '#374151';
          captureStatusEl.style.color = '#9ca3af';
          if (captureHelpEl) captureHelpEl.style.display = 'block';
        } else if (count > lastPacketCount) {
          captureStatusEl.textContent = 'Status: ✓ Capturing (live)';
          captureStatusEl.style.background = '#065f46';
          captureStatusEl.style.color = '#34d399';
          if (captureHelpEl) captureHelpEl.style.display = 'none';
        } else if (count === lastPacketCount && count > 0) {
          captureStatusEl.textContent = 'Status: ⚠ No new packets';
          captureStatusEl.style.background = '#78350f';
          captureStatusEl.style.color = '#fbbf24';
          if (captureHelpEl) captureHelpEl.style.display = 'block';
        }
      }
      
      lastPacketCount = count;
    } catch (e) {
      console.error('Failed to fetch packets', e);
      packetCountEl.textContent = '(error loading)';
      captureStatusEl.textContent = 'Status: ✗ Error';
      captureStatusEl.style.background = '#7f1d1d';
      captureStatusEl.style.color = '#f87171';
    }
  }

  function displayPackets(packets) {
    if (!packetsTableBody) {
      console.error('Cannot display packets: packetsTableBody element not found');
      return;
    }
    
    packetsTableBody.innerHTML = '';
    console.log('Displaying packets, count:', packets?.length || 0);
    
    if (!packets || packets.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td colspan="7" style="text-align: center; padding: 40px; color: var(--muted);">
          <div style="font-size: 14px;">
            <strong>No packets captured yet.</strong><br>
            <span style="font-size: 12px; margin-top: 8px; display: block;">
              Generate some network traffic (browse websites, ping servers, etc.) to see packets here.<br>
              Make sure you have selected the correct network interface and have proper permissions.
            </span>
          </div>
        </td>
      `;
      packetsTableBody.appendChild(tr);
      return;
    }
    
    packets.forEach((pkt, idx) => {
      try {
        const tr = document.createElement('tr');
        const time = new Date(pkt.timestamp_ms);
        const timeStr = time.toLocaleTimeString() + '.' + String(time.getMilliseconds()).padStart(3, '0');
        const src = pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : (pkt.src_ip || 'N/A');
        const dst = pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : (pkt.dst_ip || 'N/A');
        
        tr.innerHTML = `
          <td>${pkt.id || idx}</td>
          <td>${timeStr}</td>
          <td>${src}</td>
          <td>${dst}</td>
          <td>${pkt.protocol || 'N/A'}</td>
          <td>${pkt.size_bytes || 0}</td>
          <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${pkt.info || ''}</td>
        `;
        tr.onclick = () => showPacketDetail(pkt.id);
        tr.style.cursor = 'pointer';
        packetsTableBody.appendChild(tr);
      } catch (e) {
        console.error('Error rendering packet:', e, pkt);
      }
    });
    
    console.log(`Successfully rendered ${packets.length} packets in table`);
  }

  async function showPacketDetail(packetId) {
    try {
      const res = await fetch(`/packets/${packetId}`);
      const pkt = await res.json();
      
      const time = new Date(pkt.timestamp_ms);
      const timeStr = time.toLocaleString();
      
      packetDetailContent.innerHTML = `
        <div class="packet-detail-section">
          <h3>General Information</h3>
          <div class="detail-row">
            <span class="detail-label">Packet ID:</span>
            <span class="detail-value">${pkt.id}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Timestamp:</span>
            <span class="detail-value">${timeStr}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Protocol:</span>
            <span class="detail-value">${pkt.protocol}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Total Size:</span>
            <span class="detail-value">${pkt.size_bytes} bytes</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Data Length:</span>
            <span class="detail-value">${pkt.data_length} bytes</span>
          </div>
        </div>

        <div class="packet-detail-section">
          <h3>Address Information</h3>
          <div class="detail-row">
            <span class="detail-label">Source IP:</span>
            <span class="detail-value">${pkt.src_ip}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Destination IP:</span>
            <span class="detail-value">${pkt.dst_ip}</span>
          </div>
          ${pkt.src_port ? `
          <div class="detail-row">
            <span class="detail-label">Source Port:</span>
            <span class="detail-value">${pkt.src_port}</span>
          </div>` : ''}
          ${pkt.dst_port ? `
          <div class="detail-row">
            <span class="detail-label">Destination Port:</span>
            <span class="detail-value">${pkt.dst_port}</span>
          </div>` : ''}
        </div>

        ${pkt.flags ? `
        <div class="packet-detail-section">
          <h3>TCP Flags</h3>
          <div class="detail-row">
            <span class="detail-label">Flags:</span>
            <span class="detail-value">${pkt.flags}</span>
          </div>
        </div>` : ''}

        <div class="packet-detail-section">
          <h3>Summary</h3>
          <div class="detail-row">
            <span class="detail-label">Info:</span>
            <span class="detail-value">${pkt.info || 'N/A'}</span>
          </div>
        </div>
      `;
      
      packetModal.style.display = 'block';
    } catch (e) {
      console.error('Failed to fetch packet detail', e);
      alert('Failed to load packet details');
    }
  }

  // Setup button handlers
  if (refreshPacketsBtn) {
    refreshPacketsBtn.onclick = fetchPackets;
  }
  if (closeModal) {
    closeModal.onclick = () => { packetModal.style.display = 'none'; };
  }
  window.onclick = (e) => { if (e.target === packetModal) packetModal.style.display = 'none'; };

  // Auto-refresh packets every 2 seconds
  console.log('=== Packet Capture Setup ===');
  console.log('packetsTableBody exists:', !!packetsTableBody);
  console.log('packetCountEl exists:', !!packetCountEl);
  console.log('captureStatusEl exists:', !!captureStatusEl);
  
  // Force initial fetch - wait a bit for DOM to be ready
  console.log('Starting initial packet fetch in 1 second...');
  setTimeout(() => {
    console.log('=== INITIAL FETCH ===');
    fetchPackets().catch(e => console.error('Initial fetch failed:', e));
  }, 1000);
  
  // Set up interval - fetch every 2 seconds
  console.log('Setting up 2-second auto-refresh interval...');
  setInterval(() => {
    fetchPackets().catch(e => console.error('Interval fetch failed:', e));
  }, 2000);
  
  console.log('=== Packet Capture Setup Complete ===');
})();