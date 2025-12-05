// --- DOM ELEMENTS ---
const scanBtn = document.getElementById('scanBtn');
const deviceList = document.getElementById('deviceList');
const orbitContainer = document.getElementById('orbitContainer');
const detailsPanel = document.getElementById('detailsPanel');
const assetCountLabel = document.getElementById('assetCount');
const activeTargetLabel = document.getElementById('activeTarget');
const aiBtn = document.getElementById('aiBtn');
const aiModal = document.getElementById('aiModal');
const aiText = document.getElementById('aiText');
const aiLoader = document.getElementById('aiLoader');
const closeModal = document.querySelector('.close-modal');
const viewToggleBtn = document.getElementById('viewToggleBtn');
const mapDiv = document.getElementById('networkMap');
const downloadBtn = document.getElementById('downloadBtn');

// --- STATE ---
let currentDeviceData = [];
let selectedDevice = null; // FIX: New variable to track selection
let riskChartInstance = null;
let networkInstance = null;
let isMapView = false;

// --- FALLBACK DATA ---
const mockData = [{ ip: "192.168.1.1", type: "Router", vulns: [{ port: 80, service: "HTTP", risk: "low", info: "Web Interface", remediation: "Use HTTPS" }] }];

// --- INITIALIZATION ---
scanBtn.addEventListener('click', startScan);

if(closeModal) {
    closeModal.onclick = () => aiModal.classList.add('hidden');
    window.onclick = (e) => { if(e.target == aiModal) aiModal.classList.add('hidden'); }
}

const closeDetailsBtn = document.querySelector('.close-details');
if(closeDetailsBtn) {
    closeDetailsBtn.addEventListener('click', () => detailsPanel.classList.add('hidden'));
}

// --- CORE SCAN FUNCTION ---
async function startScan() {
    const ip = document.getElementById('targetIp').value;
    const isDeep = document.getElementById('deepScanToggle')?.checked || false;

    // UI Loading State
    deviceList.innerHTML = `<div style="padding:20px; text-align:center; color:#94a3b8;"><i class="fa-solid fa-spinner fa-spin"></i> Scanning...</div>`;
    activeTargetLabel.innerText = "Scanning...";
    if(isDeep) showToast("Deep Scan Initiated...", "info");

    try {
        const res = await fetch('http://localhost:3000/ip-send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, deepScan: isDeep })
        });

        if (!res.ok) throw new Error("Server Error");
        const data = await res.json();
        
        currentDeviceData = data;
        
        // FIX: Default to first device if available
        if(data.length > 0) {
            selectedDevice = data[0];
        }

        activeTargetLabel.innerText = ip;
        updateAssetCount(data.length);
        renderDeviceList(data);
        
        // Refresh map if active
        if(isMapView) renderNetworkMap(data);
        else if(selectedDevice) renderOrbitSystem(selectedDevice); // Render the selected one immediately
        
        showToast("Scan Complete", "success");

    } catch (err) {
        console.error(err);
        showToast("Scan Failed. Using Simulation.", "error");
        setTimeout(() => {
            currentDeviceData = mockData;
            selectedDevice = mockData[0];
            updateAssetCount(mockData.length);
            renderDeviceList(mockData);
        }, 1000);
    }
}

// --- SIDEBAR LIST ---
function renderDeviceList(devices) {
    deviceList.innerHTML = '';
    updateRiskChart(devices); 

    if(devices.length === 0) {
        deviceList.innerHTML = '<div class="empty-state">No devices found.</div>';
        return;
    }

    devices.forEach((device) => {
        const card = document.createElement('div');
        card.className = 'device-card';
        
        // Calculate Score
        let score = 100;
        if(device.vulns) {
            const high = device.vulns.filter(v => v.risk === 'high').length;
            const med = device.vulns.filter(v => v.risk === 'medium').length;
            score -= (high * 25) + (med * 10);
        }
        if(score < 0) score = 0;
        
        let scoreColor = '#10b981'; // Green
        if(score < 50) scoreColor = '#ef4444'; // Red
        else if(score < 80) scoreColor = '#f59e0b'; // Orange

        // Name Logic
        let displayName = device.type;
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(device.type);
        if(isIp) displayName = "Unknown Device";

        let icon = 'server';
        const typeLower = (device.type || '').toLowerCase();
        if(typeLower.includes('router')) icon = 'wifi';
        if(typeLower.includes('phone') || typeLower.includes('android')) icon = 'mobile-screen';
        if(typeLower.includes('apple')) icon = 'apple';
        if(typeLower.includes('windows') || typeLower.includes('pc')) icon = 'desktop';

        card.innerHTML = `
            <div class="card-icon" style="color: ${scoreColor}">
                <i class="fa-solid fa-${icon}"></i>
            </div>
            <div class="card-info">
                <h4 style="font-weight:700; color:white;">${displayName}</h4>
                <p style="font-family:monospace; opacity:0.7;">${device.ip}</p>
                <div style="font-size:10px; margin-top:4px; color:${scoreColor}; font-weight:700;">
                    Score: ${score}/100
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            // FIX: Update the global selected device
            selectedDevice = device; 
            
            // Visual Update
            document.querySelectorAll('.device-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');

            isMapView = false;
            orbitContainer.classList.remove('hidden');
            mapDiv.classList.add('hidden');
            renderOrbitSystem(device);
        });

        deviceList.appendChild(card);
    });
}

// --- RISK ANALYTICS CHART ---
function updateRiskChart(devices) {
    const ctx = document.getElementById('riskChart');
    if(!ctx) return;
    
    let h=0, m=0, l=0;
    devices.forEach(d => {
        if(d.vulns) {
            h += d.vulns.filter(v=>v.risk==='high').length;
            m += d.vulns.filter(v=>v.risk==='medium').length;
            l += d.vulns.filter(v=>v.risk==='low').length;
        }
    });

    if(riskChartInstance) riskChartInstance.destroy();
    
    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Warning', 'Safe'],
            datasets: [{ data: [h, m, l], backgroundColor: ['#ef4444','#f59e0b','#10b981'], borderWidth: 0 }]
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { display: false } } }
    });
}

// --- SOLAR SYSTEM VISUALIZATION ---
function renderOrbitSystem(device) {
    orbitContainer.innerHTML = '';
    detailsPanel.classList.add('hidden');
    
    // Update Active Target Label
    if(activeTargetLabel) activeTargetLabel.innerText = `${device.type} (${device.ip})`;

    const core = document.createElement('div');
    core.className = 'core-node';
    core.innerHTML = `<i class="fa-solid fa-server"></i><span>${device.ip}</span>`;
    orbitContainer.appendChild(core);

    if(!device.vulns) return;

    const total = device.vulns.length;
    const step = (2*Math.PI)/total;
    
    device.vulns.forEach((v, i) => {
        const angle = i * step;
        let r = 200;
        if(v.risk === 'high') r = 120;
        else if(v.risk === 'medium') r = 160;

        const x = Math.cos(angle) * r;
        const y = Math.sin(angle) * r;

        const node = document.createElement('div');
        node.className = `vuln-node risk-${v.risk}`;
        node.style.left = '50%'; node.style.top = '50%';
        node.style.marginLeft = '-20px'; node.style.marginTop = '-20px';
        node.style.transform = `translate(${x}px, ${y}px)`;
        node.innerHTML = `<span>${v.port}</span>`;

        node.addEventListener('mouseenter', () => {
            detailsPanel.classList.remove('hidden');
            
            const badge = document.getElementById('vulnRiskBadge');
            badge.innerText = v.risk.toUpperCase();
            badge.style.background = v.risk === 'high' ? '#ef4444' : v.risk === 'medium' ? '#f59e0b' : '#10b981';

            document.getElementById('detailTitle').innerText = `Port ${v.port} (${v.service})`;
            document.getElementById('detailDesc').innerText = v.info;
            document.getElementById('detailFix').innerText = v.remediation || "No fix available.";
            document.querySelector('.remediation-box').style.borderLeftColor = badge.style.background;
        });

        orbitContainer.appendChild(node);
    });
    
    [120, 160, 200].forEach(r => {
        const ring = document.createElement('div');
        ring.className = 'ring';
        ring.style.width = (r*2)+'px'; ring.style.height = (r*2)+'px';
        orbitContainer.appendChild(ring);
    });
}

// --- NETWORK TOPOLOGY MAP ---
if(viewToggleBtn) {
    viewToggleBtn.addEventListener('click', () => {
        isMapView = !isMapView;
        if(isMapView) {
            orbitContainer.classList.add('hidden');
            mapDiv.classList.remove('hidden');
            renderNetworkMap(currentDeviceData);
            showToast("Topology View Active", "info");
        } else {
            orbitContainer.classList.remove('hidden');
            mapDiv.classList.add('hidden');
        }
    });
}

function renderNetworkMap(devices) {
    if(!devices || !devices.length) return;
    const nodes = [{id: 'gw', label: 'Gateway', shape: 'hexagon', color: '#6366f1', font: {color:'white'}, size: 30}];
    const edges = [];

    devices.forEach((d, i) => {
        const typeStr = (d.type || 'unknown').toLowerCase();
        let shape = 'dot';
        if(typeStr.includes('windows')) shape = 'square';
        if(typeStr.includes('apple')) shape = 'diamond';
        if(typeStr.includes('router')) shape = 'hexagon';

        const isHigh = d.vulns && d.vulns.some(v => v.risk === 'high');
        const color = isHigh ? '#ef4444' : '#10b981';

        const id = i + 100;
        nodes.push({ id: id, label: `${d.type}\n${d.ip}`, shape: shape, color: color, font: {color:'#cbd5e1'} });
        edges.push({ from: 'gw', to: id, color: {color:'#475569', opacity:0.4} });
    });

    if(networkInstance) networkInstance.destroy();
    networkInstance = new vis.Network(mapDiv, { nodes, edges }, {
        physics: { stabilization: false, barnesHut: { gravitationalConstant: -3000 } },
        interaction: { hover: true }
    });
    
    networkInstance.on("click", (p) => {
        if(p.nodes.length) {
            const idx = p.nodes[0] - 100;
            const device = devices[idx];
            if(device) {
                // FIX: Update selectedDevice when clicking map node
                selectedDevice = device;
                
                isMapView = false;
                orbitContainer.classList.remove('hidden');
                mapDiv.classList.add('hidden');
                renderOrbitSystem(device);
                showToast(`Inspecting ${device.ip}`, "info");
            }
        }
    });
}

// --- AI ANALYST ---
aiBtn.addEventListener('click', async () => {
    // FIX: Use 'selectedDevice' instead of just checking array length
    const target = selectedDevice || currentDeviceData[0];

    if(!target) return showToast("Select a device first!", "error");
    
    aiModal.classList.remove('hidden');
    aiLoader.classList.remove('hidden');
    aiText.innerText = "";
    
    try {
        const res = await fetch('http://localhost:3000/ai-analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            // FIX: Send the currently selected device
            body: JSON.stringify({ scanData: target }) 
        });
        const d = await res.json();
        aiLoader.classList.add('hidden');
        typeWriterEffect(d.analysis || "No analysis returned.");
    } catch {
        aiLoader.classList.add('hidden');
        aiText.innerText = "Error connecting to AI.";
    }
});

function typeWriterEffect(text) {
    let i = 0; aiText.innerHTML = "";
    function type() {
        if (i < text.length) {
            aiText.innerHTML += text.charAt(i) === '\n' ? '<br>' : text.charAt(i);
            i++;
            setTimeout(type, 15);
        }
    }
    type();
}

// --- PDF EXPORT ---
if(downloadBtn) {
    downloadBtn.addEventListener('click', () => {
        if(!window.jspdf) return showToast("PDF Library Missing", "error");
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFillColor(15, 23, 42); doc.rect(0, 0, 210, 30, "F");
        doc.setTextColor(255,255,255); doc.setFontSize(18); doc.text("Security Report", 10, 20);
        
        let y=40;
        currentDeviceData.forEach(d => {
            doc.setTextColor(0,0,0); doc.setFontSize(14); doc.setFont("helvetica", "bold");
            doc.text(`${d.type} (${d.ip})`, 10, y);
            y+=10;
            doc.setFont("helvetica", "normal"); doc.setFontSize(10);
            if(d.vulns) d.vulns.forEach(v => { 
                doc.setTextColor(v.risk==='high'?200:0, 0, 0);
                doc.text(`[${v.risk.toUpperCase()}] Port ${v.port}: ${v.info}`, 15, y); y+=7; 
            });
            y+=10;
            if(y > 270) { doc.addPage(); y=20; }
        });
        doc.save("security-report.pdf");
    });
}

// --- HELPERS ---
function updateAssetCount(n) { if(assetCountLabel) assetCountLabel.innerText = n; }

function showToast(msg, type) {
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<i class="fa-solid fa-circle-info"></i> ${msg}`;
    document.getElementById('toastContainer').appendChild(t);
    setTimeout(() => { t.style.opacity='0'; setTimeout(()=>t.remove(),300); }, 3000);
}