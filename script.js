

        // --- LOGIC ---
        
        // Mock Data for Demo Fallback
        const MOCK_DATA = [
            { 
                ip: "192.168.1.15", type: "Linux Server", os: "Ubuntu 20.04", 
                vulns: [
                    { port: 22, service: "SSH", risk: "low", info: "OpenSSH 7.2 Protocol 2.0", fix: "Disable Root Login. Use Keys." },
                    { port: 80, service: "HTTP", risk: "medium", info: "Apache 2.4.18", fix: "Enable HTTPS (Certbot)." },
                    { port: 3306, service: "MySQL", risk: "high", info: "MySQL 5.7 root access", fix: "Bind to localhost only. Set strong password." }
                ] 
            },
            { ip: "192.168.1.100", type: "Workstation", os: "Windows 10", vulns: [] },
            { ip: "192.168.1.1", type: "Gateway", os: "Cisco IOS", vulns: [{ port: 23, service: "Telnet", risk: "high", info: "Unencrypted Admin", fix: "Disable Telnet. Use SSH." }] }
        ];

        // State
        let currentData = [];
        let selectedDevice = null;
        let selectedVuln = null; // Track current vulnerability for script generation
        let chartInstance = null;
        let mapInstance = null;
        let isMapView = false;

        // Elements
        const els = {
            scanBtn: document.getElementById('scanBtn'),
            voiceBtn: document.getElementById('voiceBtn'),
            deviceList: document.getElementById('deviceList'),
            orbit: document.getElementById('orbitContainer'),
            map: document.getElementById('networkMap'),
            details: document.getElementById('detailsPanel'),
            scanFx: document.getElementById('scanFx'),
            aiModal: document.getElementById('aiModal'),
            aiText: document.getElementById('aiText'),
            assetCount: document.getElementById('assetCount'),
            targetIp: document.getElementById('targetIp'),
            generateScriptBtn: document.getElementById('generateScriptBtn')
        };

        // Init Chart
        const ctx = document.getElementById('riskChart').getContext('2d');
        chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Med', 'Low'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#ff2a6d', '#ffc800', '#05d5fa'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                cutout: '70%',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });

        // Listeners
        els.scanBtn.addEventListener('click', runScan);
        els.voiceBtn.addEventListener('click', startVoiceCommand);
        document.querySelector('.close-details').addEventListener('click', () => els.details.classList.remove('visible'));
        document.getElementById('aiBtn').addEventListener('click', openAI);
        document.querySelector('.close-modal').addEventListener('click', () => els.aiModal.classList.remove('open'));
        document.getElementById('viewToggleBtn').addEventListener('click', toggleView);
        document.getElementById('downloadBtn').addEventListener('click', exportPDF);
        els.generateScriptBtn.addEventListener('click', generateFixScript);

        // --- VOICE CONTROL ---
        function startVoiceCommand() {
            if (!('webkitSpeechRecognition' in window)) {
                alert("Voice control not supported in this browser. Try Chrome.");
                return;
            }
            
            const recognition = new webkitSpeechRecognition();
            recognition.lang = 'en-US';
            recognition.start();

            els.voiceBtn.classList.add('listening');

            recognition.onresult = (event) => {
                const command = event.results[0][0].transcript.toLowerCase();
                console.log("Voice Command:", command);
                
                if (command.includes("scan")) {
                    // Extract IP if spoken, otherwise just run
                    const words = command.split(" ");
                    const potentialIp = words.find(w => w.match(/\d+\.\d+\.\d+\.\d+/));
                    if(potentialIp) els.targetIp.value = potentialIp;
                    runScan();
                } else if (command.includes("topology") || command.includes("map")) {
                    if(!isMapView) toggleView();
                } else if (command.includes("orbit") || command.includes("solar")) {
                    if(isMapView) toggleView();
                } else if (command.includes("report") || command.includes("download")) {
                    exportPDF();
                }
                
                els.voiceBtn.classList.remove('listening');
            };

            recognition.onerror = () => els.voiceBtn.classList.remove('listening');
            recognition.onend = () => els.voiceBtn.classList.remove('listening');
        }

        async function runScan() {
            const ip = els.targetIp.value;
            const isDeep = true; 

            // UI Loading State
            document.querySelector('.main-workspace').classList.add('scanning');
            els.deviceList.innerHTML = `<div style="padding:20px; text-align:center; color:var(--primary); font-family:var(--font-code);"><i class="fa-solid fa-radar fa-spin"></i> SCANNING NETBLOCK...</div>`;
            els.scanFx.style.opacity = '1'; 

            try {
                // Real Backend Call
                const res = await fetch('http://localhost:3000/ip-send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip, deepScan: isDeep })
                });

                if (!res.ok) throw new Error("Server Error");
                const data = await res.json();
                
                // Success
                document.querySelector('.main-workspace').classList.remove('scanning');
                els.scanFx.style.opacity = '0';
                processResults(data);

            } catch (err) {
                console.error(err);
                // Fallback / Error Handling
                document.querySelector('.main-workspace').classList.remove('scanning');
                els.scanFx.style.opacity = '0';
                
                // Use mock data as fallback or show error
                els.deviceList.innerHTML = `<div style="padding:20px; text-align:center; color:var(--risk-high); font-size:12px;"><i class="fa-solid fa-triangle-exclamation"></i> Server Offline. Loading Simulation Data...</div>`;
                
                setTimeout(() => {
                    processResults(MOCK_DATA);
                }, 1500);
            }
        }

        function processResults(data) {
            currentData = data;
            els.assetCount.innerText = data.length;
            renderList(data);
            updateChart(data);
            
            // Select first
            if(data.length > 0) selectDevice(data[0]);
        }

        function renderList(data) {
            els.deviceList.innerHTML = '';
            data.forEach((d, idx) => {
                const el = document.createElement('div');
                el.className = 'device-card';
                el.innerHTML = `
                    <i class="fa-solid fa-${d.type.includes('Server')?'server': d.type.includes('Gateway')?'wifi':'desktop'} d-icon"></i>
                    <div class="d-info">
                        <h4>${d.type}</h4>
                        <p>${d.ip}</p>
                    </div>
                `;
                el.onclick = () => {
                    document.querySelectorAll('.device-card').forEach(c => c.classList.remove('active'));
                    el.classList.add('active');
                    selectDevice(d);
                };
                els.deviceList.appendChild(el);
            });
            // Active first
            if(els.deviceList.firstChild) els.deviceList.firstChild.classList.add('active');
        }

        function selectDevice(d) {
            selectedDevice = d;
            document.getElementById('activeTarget').innerText = `${d.ip} [${d.os || 'Unknown OS'}]`;
            
            if(isMapView) return; // Map handles its own selection visual
            
            renderOrbit(d);
        }

        function renderOrbit(d) {
            els.orbit.innerHTML = '';
            els.details.classList.remove('visible');

            // Add Rings
            [140, 220, 300].forEach(size => {
                const ring = document.createElement('div');
                ring.className = 'orbit-ring';
                ring.style.width = size + 'px'; ring.style.height = size + 'px';
                els.orbit.appendChild(ring);
            });

            // Core
            const core = document.createElement('div');
            core.className = 'core-node';
            core.innerHTML = `<i class="fa-solid fa-server"></i><span>${d.ip}</span>`;
            els.orbit.appendChild(core);

            if(!d.vulns) return;

            // Satellites
            const total = d.vulns.length;
            const angleStep = (2 * Math.PI) / total;

            d.vulns.forEach((v, i) => {
                const angle = i * angleStep;
                const dist = v.risk === 'high' ? 70 : v.risk === 'medium' ? 110 : 150; // Different orbits based on risk
                
                const x = Math.cos(angle) * dist;
                const y = Math.sin(angle) * dist;

                const node = document.createElement('div');
                node.className = `vuln-node risk-${v.risk}`;
                node.style.transform = `translate(${x}px, ${y}px)`;
                // Fix for hover effect logic in CSS requiring variables or pure transform
                // Instead of CSS translate, we use left/top for base pos
                node.style.left = '50%'; node.style.top = '50%';
                node.style.marginTop = '-22px'; node.style.marginLeft = '-22px'; // center
                
                node.innerHTML = `<span>${v.port}</span>`;
                
                node.onclick = () => showDetails(v);
                
                els.orbit.appendChild(node);
            });
        }

        function showDetails(v) {
            selectedVuln = v; // Store for script generation
            const p = els.details;
            const colors = { high: '#ff2a6d', medium: '#ffc800', low: '#05d5fa' };
            
            document.getElementById('vulnRiskBadge').innerText = v.risk.toUpperCase();
            document.getElementById('vulnRiskBadge').style.background = colors[v.risk];
            document.getElementById('detailTitle').innerText = `Port ${v.port} (${v.service})`;
            document.getElementById('detailDesc').innerText = v.info;
            document.getElementById('detailFix').innerText = v.remediation || v.fix || "No specific fix data.";
            
            p.classList.add('visible');
        }

        // --- SCRIPT GENERATION ---
        function generateFixScript() {
            if(!selectedVuln) return;
            
            let scriptContent = `#!/bin/bash\n# Net-Sentinel Auto-Remediation Script\n# Target Port: ${selectedVuln.port} (${selectedVuln.service})\n\n`;
            scriptContent += `echo "Starting security patch for Port ${selectedVuln.port}..."\n`;
            
            // Logic based on service (Simple examples)
            if(selectedVuln.port == 80) {
                scriptContent += `\n# Secure HTTP\nsudo ufw allow 443/tcp\nsudo ufw delete allow 80/tcp\necho "Please install Certbot: sudo apt install certbot"\n`;
            } else if (selectedVuln.port == 22) {
                scriptContent += `\n# Hardening SSH\nsudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config\nsudo systemctl restart ssh\n`;
            } else {
                scriptContent += `\n# General Firewall Rule\nsudo ufw deny ${selectedVuln.port}\n`;
            }

            scriptContent += `\necho "Remediation steps applied. Verify connectivity."`;

            const blob = new Blob([scriptContent], { type: "text/x-sh" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `fix_port_${selectedVuln.port}.sh`;
            link.click();
        }

        function updateChart(data) {
            let h=0, m=0, l=0;
            data.forEach(d => {
                if(d.vulns) {
                    h += d.vulns.filter(v=>v.risk==='high').length;
                    m += d.vulns.filter(v=>v.risk==='medium').length;
                    l += d.vulns.filter(v=>v.risk==='low').length;
                }
            });
            chartInstance.data.datasets[0].data = [h, m, l];
            chartInstance.update();
        }

        // --- AI ---
        async function openAI() {
            if(!selectedDevice) return alert("Select a target first.");
            
            els.aiModal.classList.add('open');
            document.getElementById('aiLoader').classList.remove('hidden');
            els.aiText.innerHTML = ""; // Clear previous

            try {
                // Try to reach backend
                const res = await fetch('http://localhost:3000/ai-analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ scanData: selectedDevice }) 
                });
                
                if (!res.ok) throw new Error("AI Service Unavailable");
                const d = await res.json();
                
                document.getElementById('aiLoader').classList.add('hidden');
                typeWriter(d.analysis || "No analysis returned from neural core.");

            } catch (err) {
                console.error("Backend offline, generating simulation...");
                document.getElementById('aiLoader').classList.add('hidden');
                
                // GENERATE DYNAMIC SIMULATION TEXT
                const target = selectedDevice;
                const date = new Date().toISOString().split('T')[0];
                let simText = `[SECURE-NET AI DIAGNOSTIC - ${date}]\n`;
                simText += `TARGET: ${target.ip} (${target.type})\n`;
                simText += `OS KERNEL: ${target.os || "Unknown"}\n\n`;

                if(target.vulns && target.vulns.length > 0) {
                    // Sort by risk
                    const sorted = [...target.vulns].sort((a,b) => (a.risk==='high'?-1:1));
                    const v = sorted[0];

                    simText += `!! CRITICAL VULNERABILITY DETECTED !!\n`;
                    simText += `VECTOR: Port ${v.port} / ${v.service}\n`;
                    simText += `THREAT ASSESSMENT: ${v.info}\n\n`;
                    
                    simText += `AI REMEDIATION STRATEGY:\n`;
                    simText += `1. IMMEDIATE: ${v.remediation || v.fix || "Patch service immediately."}\n`;
                    simText += `2. CONFIGURATION: Implement strict ACLs for port ${v.port}.\n`;
                    simText += `3. LONG-TERM: Schedule automated patch management cycle.\n`;
                    
                    if(v.risk === 'high') {
                         simText += `\nWARNING: High risk vector requires urgent attention to prevent remote code execution.`;
                    }
                } else {
                    simText += `STATUS: SYSTEM SECURE\n`;
                    simText += `No active vulnerability vectors detected in current scan depth.\n\n`;
                    simText += `RECOMMENDATION:\n- Maintain firewall rules.\n- Continue periodic deep scans.`;
                }

                typeWriter(simText);
            }
        }

        function typeWriter(txt) {
            let i = 0;
            const speed = 10; // Faster
            function type() {
                if(i < txt.length) {
                    els.aiText.innerHTML += txt.charAt(i) === '\n' ? '<br>' : txt.charAt(i);
                    i++;
                    setTimeout(type, speed);
                }
            }
            type();
        }

        // --- MAP ---
        function toggleView() {
            isMapView = !isMapView;
            const btn = document.getElementById('viewToggleBtn');
            
            if(isMapView) {
                // Show Map
                els.orbit.classList.add('hidden');
                els.map.classList.remove('hidden');
                
                if(btn) btn.innerHTML = '<i class="fa-solid fa-globe"></i> View Orbit';
                
                // Allow CSS transition to settle before drawing canvas
                setTimeout(renderMap, 50);
            } else {
                // Show Orbit
                els.orbit.classList.remove('hidden');
                els.map.classList.add('hidden');
                
                if(btn) btn.innerHTML = '<i class="fa-solid fa-network-wired"></i> Topology';
            }
        }

        function renderMap() {
            const nodes = [{id:0, label:'Internet', color:'#fff', shape:'dot'}];
            const edges = [];
            currentData.forEach((d, i) => {
                const id = i+1;
                const isHigh = d.vulns && d.vulns.some(v=>v.risk==='high');
                nodes.push({
                    id: id, 
                    label: `${d.type}\n${d.ip}`, 
                    color: isHigh ? '#ff2a6d' : '#05d5fa',
                    shape: d.type.includes('Gateway') ? 'diamond' : 'dot',
                    font: { color: '#cbd5e1', face: 'Inter' }
                });
                edges.push({from: 0, to: id, color:{color:'rgba(255,255,255,0.2)'}});
            });

            if(mapInstance) mapInstance.destroy();
            mapInstance = new vis.Network(els.map, {nodes, edges}, {
                physics: { stabilization: false, barnesHut: { gravitationalConstant: -4000 } },
                nodes: { borderWidth: 2, shadow:true },
                interaction: { hover: true }
            });
        }

        function exportPDF() {
            const doc = new window.jspdf.jsPDF();
            doc.setFontSize(20); doc.text("Net-Sentinel Security Report", 10, 20);
            doc.setFontSize(12); doc.text(`Generated: ${new Date().toLocaleDateString()}`, 10, 30);
            
            let y = 50;
            currentData.forEach(d => {
                doc.setFont("helvetica", "bold");
                doc.text(`Target: ${d.ip} (${d.type})`, 10, y);
                y += 10;
                if(d.vulns) {
                    d.vulns.forEach(v => {
                        doc.setFont("helvetica", "normal");
                        doc.setTextColor(v.risk==='high'?200:0, 0, 0);
                        doc.text(` - [${v.risk.toUpperCase()}] Port ${v.port}: ${v.service}`, 15, y);
                        y += 7;
                        doc.setTextColor(0,0,0);
                    });
                }
                y += 10;
            });
            doc.save("NetSentinel_Report.pdf");
        }

