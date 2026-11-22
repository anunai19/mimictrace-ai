// MimicTrace AI — Stitch Telemetry & Forensic Investigation Controller (Stage 9)
// Material Design 3 Dark Theme · Three.js 3D Graph · Multi-Signal Evidence Fusion
// Strictly uses DOM text nodes and elements.

// ---------------------------------------------------------------------------
// 1. Background Particle Network Canvas
// ---------------------------------------------------------------------------
const bgCanvas = document.getElementById("network");

if (bgCanvas) {
    const ctx = bgCanvas.getContext("2d");
    let particles = [];

    function resizeBgCanvas() {
        bgCanvas.width = window.innerWidth;
        bgCanvas.height = window.innerHeight;
        particles = Array.from({ length: 45 }, () => ({
            x: Math.random() * bgCanvas.width,
            y: Math.random() * bgCanvas.height,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3
        }));
    }

    function animateBgNetwork() {
        ctx.clearRect(0, 0, bgCanvas.width, bgCanvas.height);

        particles.forEach((p, i) => {
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > bgCanvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > bgCanvas.height) p.vy *= -1;

            ctx.beginPath();
            ctx.arc(p.x, p.y, 1.2, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(142, 68, 255, 0.45)";
            ctx.fill();

            particles.slice(i + 1).forEach(other => {
                const dx = p.x - other.x;
                const dy = p.y - other.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < 110) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(other.x, other.y);
                    ctx.strokeStyle = `rgba(0, 238, 252, ${0.08 * (1 - distance / 110)})`;
                    ctx.stroke();
                }
            });
        });

        if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            requestAnimationFrame(animateBgNetwork);
        }
    }

    resizeBgCanvas();
    animateBgNetwork();
    window.addEventListener("resize", resizeBgCanvas);
}

// ---------------------------------------------------------------------------
// 2. Three.js 3D Domain Intelligence Telemetry Visualizer
// ---------------------------------------------------------------------------
(function initThreeVisualizer() {
    const container = document.getElementById("threejs-container-ANIMATION_9") || document.getElementById("three-hero-container");
    if (!container || typeof THREE === "undefined") return;

    try {
        const width = container.clientWidth || 500;
        const height = container.clientHeight || 500;

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        camera.position.set(0, 2, 22);

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(width, height);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
        container.appendChild(renderer.domElement);

        const graphGroup = new THREE.Group();
        scene.add(graphGroup);

        // 1. Central True Brand Identity Node
        const coreGeo = new THREE.IcosahedronGeometry(2.2, 2);
        const coreMat = new THREE.MeshPhongMaterial({
            color: 0x8e44ff,
            emissive: 0x240754,
            specular: 0x00f0ff,
            shininess: 60,
            wireframe: true,
            transparent: true,
            opacity: 0.85
        });
        const coreMesh = new THREE.Mesh(coreGeo, coreMat);
        graphGroup.add(coreMesh);

        // Inner Solid Pulse Core
        const innerGeo = new THREE.SphereGeometry(1.2, 32, 32);
        const innerMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            wireframe: false,
            transparent: true,
            opacity: 0.7
        });
        const innerPulse = new THREE.Mesh(innerGeo, innerMat);
        coreMesh.add(innerPulse);

        // 2. Protective Hexagonal / Radial Defensive Shield Orbiting Center
        const shieldGeo = new THREE.RingGeometry(3.6, 3.8, 6);
        const shieldMat = new THREE.MeshBasicMaterial({
            color: 0x00c8ff,
            transparent: true,
            opacity: 0.45,
            side: THREE.DoubleSide
        });
        const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
        shieldMesh.rotation.x = Math.PI * 0.4;
        graphGroup.add(shieldMesh);

        const shieldRing2 = new THREE.Mesh(
            new THREE.TorusGeometry(4.8, 0.035, 16, 80),
            new THREE.MeshBasicMaterial({ color: 0x792bff, transparent: true, opacity: 0.6 })
        );
        shieldRing2.rotation.x = -Math.PI * 0.35;
        shieldRing2.rotation.y = Math.PI * 0.25;
        graphGroup.add(shieldRing2);

        // 3. Peripheral Domain & Infrastructure Nodes
        const nodeCount = 18;
        const nodes = [];
        const nodeCoords = [];

        for (let i = 0; i < nodeCount; i++) {
            const isSuspicious = i % 4 === 0;
            const isLegit = i % 3 === 0;
            const radius = 6.0 + Math.random() * 4.5;
            const theta = (i / nodeCount) * Math.PI * 2 + (Math.random() * 0.4);
            const phi = (Math.random() - 0.5) * 1.4;

            const x = radius * Math.cos(theta) * Math.cos(phi);
            const y = radius * Math.sin(phi) + (Math.random() - 0.5) * 2;
            const z = radius * Math.sin(theta) * Math.cos(phi);

            nodeCoords.push(new THREE.Vector3(x, y, z));

            const nodeSize = isSuspicious ? 0.6 : (isLegit ? 0.45 : 0.3);
            const nodeGeo = new THREE.OctahedronGeometry(nodeSize, 0);
            const nodeMat = new THREE.MeshPhongMaterial({
                color: isSuspicious ? 0xff3366 : (isLegit ? 0x00f0ff : 0x9d5cff),
                emissive: isSuspicious ? 0x66001a : 0x1f0a44,
                wireframe: i % 2 === 0,
                transparent: true,
                opacity: 0.9
            });
            const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
            nodeMesh.position.set(x, y, z);
            nodeMesh.userData = {
                basePos: new THREE.Vector3(x, y, z),
                speed: 0.5 + Math.random() * 1.5,
                isSuspicious: isSuspicious
            };
            graphGroup.add(nodeMesh);
            nodes.push(nodeMesh);
        }

        // 4. Dynamic Network Pathways
        const lineMat = new THREE.LineBasicMaterial({
            color: 0x792bff,
            transparent: true,
            opacity: 0.35
        });

        const suspiciousLineMat = new THREE.LineBasicMaterial({
            color: 0xff2a6d,
            transparent: true,
            opacity: 0.65
        });

        const lines = [];
        nodeCoords.forEach((coord, idx) => {
            const geometry = new THREE.BufferGeometry().setFromPoints([
                new THREE.Vector3(0, 0, 0),
                coord
            ]);
            const line = new THREE.Line(geometry, nodes[idx].userData.isSuspicious ? suspiciousLineMat : lineMat);
            graphGroup.add(line);
            lines.push({ line, nodeIdx: idx });

            if (idx > 0 && Math.random() > 0.4) {
                const crossGeo = new THREE.BufferGeometry().setFromPoints([
                    coord,
                    nodeCoords[idx - 1]
                ]);
                const crossLine = new THREE.Line(crossGeo, new THREE.LineBasicMaterial({
                    color: 0x00c8ff,
                    transparent: true,
                    opacity: 0.25
                }));
                graphGroup.add(crossLine);
            }
        });

        // 5. Threat Particle Packets Traveling Along Conduits
        const packetCount = 28;
        const packets = [];
        for (let p = 0; p < packetCount; p++) {
            const pGeo = new THREE.SphereGeometry(0.12, 8, 8);
            const pMat = new THREE.MeshBasicMaterial({
                color: p % 3 === 0 ? 0xff2a6d : 0x00ffff
            });
            const packet = new THREE.Mesh(pGeo, pMat);
            packet.userData = {
                targetIdx: p % nodeCount,
                t: Math.random(),
                speed: 0.006 + Math.random() * 0.012
            };
            graphGroup.add(packet);
            packets.push(packet);
        }

        // 6. Volumetric Spatial Cyber Grid Points
        const gridCount = 380;
        const gridGeo = new THREE.BufferGeometry();
        const gridCoords = new Float32Array(gridCount * 3);
        for (let i = 0; i < gridCount * 3; i += 3) {
            gridCoords[i] = (Math.random() - 0.5) * 35;
            gridCoords[i + 1] = (Math.random() - 0.5) * 28;
            gridCoords[i + 2] = (Math.random() - 0.5) * 25;
        }
        gridGeo.setAttribute("position", new THREE.BufferAttribute(gridCoords, 3));
        const gridMat = new THREE.PointsMaterial({
            color: 0x8a63d2,
            size: 0.09,
            transparent: true,
            opacity: 0.5
        });
        const gridPoints = new THREE.Points(gridGeo, gridMat);
        scene.add(gridPoints);

        // Lighting
        scene.add(new THREE.AmbientLight(0x0e0d1f, 2.0));
        const purpleLight = new THREE.PointLight(0x8e44ff, 4.0, 35);
        purpleLight.position.set(-10, 8, 10);
        scene.add(purpleLight);

        const cyanLight = new THREE.PointLight(0x00f0ff, 4.5, 35);
        cyanLight.position.set(10, -6, 8);
        scene.add(cyanLight);

        // Mouse Parallax
        let targetRotY = 0, targetRotX = 0;

        window.addEventListener("mousemove", (e) => {
            const mouseX = (e.clientX / window.innerWidth) * 2 - 1;
            const mouseY = -(e.clientY / window.innerHeight) * 2 + 1;
            targetRotY = mouseX * 0.45;
            targetRotX = -mouseY * 0.3;
        });

        window.addEventListener("resize", () => {
            const w = container.clientWidth || 500;
            const h = container.clientHeight || 500;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
        });

        const clock = new THREE.Clock();
        function animate() {
            if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
                requestAnimationFrame(animate);
            }
            const elapsed = clock.getElapsedTime();

            graphGroup.rotation.y += 0.003;
            graphGroup.rotation.y += (targetRotY - graphGroup.rotation.y * 0.1) * 0.03;
            graphGroup.rotation.x += (targetRotX - graphGroup.rotation.x) * 0.03;
            graphGroup.position.y = Math.sin(elapsed * 1.2) * 0.25;

            const s = 1.0 + Math.sin(elapsed * 3.0) * 0.12;
            innerPulse.scale.set(s, s, s);
            coreMesh.rotation.y += 0.008;
            coreMesh.rotation.x -= 0.005;

            shieldMesh.rotation.z += 0.009;
            shieldRing2.rotation.z -= 0.006;

            nodes.forEach((n, idx) => {
                n.rotation.x += 0.015;
                n.rotation.y += 0.02;
                const bp = n.userData.basePos;
                n.position.y = bp.y + Math.sin(elapsed * n.userData.speed + idx) * 0.35;

                const lineObj = lines[idx];
                if (lineObj) {
                    const positions = lineObj.line.geometry.attributes.position.array;
                    positions[3] = n.position.x;
                    positions[4] = n.position.y;
                    positions[5] = n.position.z;
                    lineObj.line.geometry.attributes.position.needsUpdate = true;
                }
            });

            packets.forEach((p) => {
                p.userData.t += p.userData.speed;
                if (p.userData.t > 1) p.userData.t = 0;
                const targetNode = nodes[p.userData.targetIdx];
                p.position.lerpVectors(new THREE.Vector3(0, 0, 0), targetNode.position, p.userData.t);
            });

            gridPoints.rotation.y = elapsed * 0.01;
            renderer.render(scene, camera);
        }
        animate();
    } catch (err) {
        // Fallback silently if WebGL is unavailable
    }
})();

// ---------------------------------------------------------------------------
// 3. DOM Safe Builder Helpers
// ---------------------------------------------------------------------------
function el(tag, className, textContent) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (textContent !== undefined && textContent !== null) {
        element.textContent = textContent;
    }
    return element;
}

function showToast(message) {
    const toast = document.getElementById("reportToast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 3200);
}

// ---------------------------------------------------------------------------
// 4. Main Application Controller
// ---------------------------------------------------------------------------
const scanForm = document.querySelector("#scanForm");

if (scanForm) {
    const urlInput = document.querySelector("#websiteUrl");
    const scanMessage = document.querySelector("#scanMessage");
    const deeperButton = document.querySelector("#deeperAnalysisButton");
    const logoCropInput = document.querySelector("#logoCropInput");
    const logoFileName = document.querySelector("#logoFileName");
    const deeperStatus = document.querySelector("#deeperAnalysisStatus");
    const deeperResults = document.querySelector("#deeperAnalysisResults");
    const clearBtn = document.querySelector("#clear-btn");
    const protocolSelect = document.querySelector("#protocol-select");
    const entropyScore = document.querySelector("#entropy-score");

    let analyzedUrl = null;
    let primaryRequestId = 0;
    let completedDeeperUrl = null;
    let deeperRequestInFlight = false;
    let lastAnalysisData = null;

    // Presets Click Handler
    document.querySelectorAll(".preset-pill").forEach(chip => {
        chip.addEventListener("click", () => {
            const targetUrl = chip.getAttribute("data-url");
            if (targetUrl) {
                urlInput.value = targetUrl;
                urlInput.dispatchEvent(new Event("input", { bubbles: true }));
                urlInput.focus();
                // Smooth scroll to scanner if not visible
                const scannerSec = document.getElementById("scanner");
                if (scannerSec) scannerSec.scrollIntoView({ behavior: "smooth" });
            }
        });
    });

    // Clear Button Handler
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            urlInput.value = "";
            urlInput.dispatchEvent(new Event("input", { bubbles: true }));
            urlInput.focus();
        });
    }

    // Protocol Select Sync
    if (protocolSelect) {
        protocolSelect.addEventListener("change", () => {
            const curVal = urlInput.value.trim();
            if (curVal.startsWith("http://") || curVal.startsWith("https://")) {
                urlInput.value = curVal.replace(/^https?:\/\//, protocolSelect.value);
            }
        });
    }

    // File Input Name Preview
    if (logoCropInput && logoFileName) {
        logoCropInput.addEventListener("change", () => {
            if (logoCropInput.files && logoCropInput.files[0]) {
                logoFileName.textContent = `Attached: ${logoCropInput.files[0].name}`;
            } else {
                logoFileName.textContent = "Optional logo crop (PNG/JPEG)";
            }
        });
    }

    // Input Change Reset Handler
    urlInput.addEventListener("input", () => {
        const val = urlInput.value.trim();

        // Calculate simple Shannon Entropy indicator
        if (entropyScore) {
            if (val.length > 5) {
                const freqs = {};
                for (let i = 0; i < val.length; i++) {
                    freqs[val[i]] = (freqs[val[i]] || 0) + 1;
                }
                let entropy = 0;
                Object.values(freqs).forEach(count => {
                    const p = count / val.length;
                    entropy -= p * Math.log2(p);
                });
                entropyScore.textContent = `Entropy: ${entropy.toFixed(2)} (${entropy > 4.2 ? "High Complexity" : "Standard"})`;
            } else {
                entropyScore.textContent = "Entropy: Lexical Analysis";
            }
        }

        if (val !== analyzedUrl) {
            analyzedUrl = null;
            completedDeeperUrl = null;
            lastAnalysisData = null;
            deeperButton.disabled = true;
            deeperResults.replaceChildren();

            const idleBox = el("div", "bg-surface-container-low/80 border border-outline-variant/30 p-8 rounded-2xl flex flex-col items-center justify-center text-center gap-4 min-h-[380px]");
            const idleIcon = el("div", "w-16 h-16 rounded-full bg-surface-container flex items-center justify-center text-secondary-container border border-outline-variant/40 shadow-[0_0_24px_rgba(0,238,252,0.15)]");
            idleIcon.appendChild(el("span", "material-symbols-outlined text-[32px]", "shield_search"));

            const textWrap = el("div", "max-w-md");
            textWrap.appendChild(el("h3", "font-headline-sm text-headline-sm text-on-surface font-bold", "Investigation Standby"));
            textWrap.appendChild(el("p", "font-body-md text-on-surface-variant mt-1", "Enter a target website URL to run lexical feature extraction, heuristic triage, and machine learning scoring."));

            idleBox.appendChild(idleIcon);
            idleBox.appendChild(textWrap);
            idleBox.appendChild(el("span", "font-label-mono-sm text-xs text-outline", "Heuristic signal estimates · Not guaranteed security verdicts."));

            scanMessage.replaceChildren(idleBox);
            deeperStatus.textContent = "Run URL analysis again to enable deeper analysis for this URL.";
        }
    });

    // -----------------------------------------------------------------------
    // Primary URL Analysis Submission Handler
    // Invariants required by test_dashboard_contract.py:
    // - if (requestId !== primaryRequestId) return;
    // - if (urlInput.value.trim() !== url) {
    // - data.analysis.hostname
    // - deeperButton.disabled = false;
    // - if (requestId === primaryRequestId)
    // - submitButton.disabled = false;
    // -----------------------------------------------------------------------
    scanForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const submitButton = scanForm.querySelector('button[type="submit"]');
        let url = urlInput.value.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = (protocolSelect ? protocolSelect.value : "https://") + url;
            urlInput.value = url;
        }

        const requestId = ++primaryRequestId;

        analyzedUrl = null;
        completedDeeperUrl = null;
        lastAnalysisData = null;
        deeperButton.disabled = true;
        deeperResults.replaceChildren();
        deeperStatus.textContent = "Run URL analysis first to enable deeper analysis.";

        // Loading State
        const loadingBox = el("div", "bg-surface-container-low border border-outline-variant/40 p-8 rounded-2xl flex flex-col items-center justify-center text-center gap-4 min-h-[380px]");
        const radar = el("div", "radar-active");
        radar.appendChild(el("span", "radar-spinner"));
        radar.appendChild(el("span", null, "Extracting URL lexical features and evaluating Random Forest heuristics..."));
        loadingBox.appendChild(radar);
        scanMessage.replaceChildren(loadingBox);

        submitButton.disabled = true;

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Analysis failed.");
            }

            if (requestId !== primaryRequestId) return;
            if (urlInput.value.trim() !== url) {
                const changeNotice = el("div", "bg-surface-container-low p-6 rounded-xl border border-outline-variant/40 text-center");
                changeNotice.appendChild(el("h4", "text-on-surface font-bold font-headline-sm", "Target Changed"));
                changeNotice.appendChild(el("p", "text-outline text-xs mt-1", "The URL changed while analysis was running. Submit again to analyze the current URL."));
                scanMessage.replaceChildren(changeNotice);
                return;
            }

            analyzedUrl = url;
            lastAnalysisData = data;

            // Render Stitch Primary Triage Card
            const triageDeck = el("div", "bg-surface-container-low border border-outline-variant/40 p-6 md:p-8 rounded-2xl shadow-xl flex flex-col gap-6");

            // Host Header
            const topBar = el("div", "flex items-center justify-between pb-4 border-b border-outline-variant/20 flex-wrap gap-2");
            const badgeGroup = el("div", "flex items-center gap-3");
            const hostPill = el("span", "font-mono text-sm text-secondary-container bg-surface-container-highest px-3 py-1 rounded-lg border border-outline-variant/40 font-bold", data.analysis.hostname);
            const statusPill = el("span", "font-label-mono-sm text-xs px-2.5 py-0.5 rounded-full bg-secondary-container/15 text-secondary-container font-bold", "FEATURES EXTRACTED");
            badgeGroup.appendChild(hostPill);
            badgeGroup.appendChild(statusPill);

            const timestamp = el("span", "font-mono text-xs text-outline", `Analyzed: ${new Date().toLocaleTimeString()}`);
            topBar.appendChild(badgeGroup);
            topBar.appendChild(timestamp);
            triageDeck.appendChild(topBar);

            // ML Prediction Banner
            const prediction = data.analysis.prediction;
            let predClass = "border-outline-variant/40 bg-surface-container-lowest";
            let predTitle = "Model Estimate Unavailable";
            let predDesc = "Lexical features extracted. Machine learning prediction was not returned.";
            let predIcon = "info";
            let disclaimer = "Machine learning outputs represent heuristic estimates and may produce false classifications.";

            if (prediction && prediction.status === "available") {
                if (prediction.label === "phishing") {
                    predClass = "border-error/40 bg-error/10";
                    predTitle = "Model Estimate: Potential Phishing Pattern";
                    predIcon = "warning";
                    predDesc = "Lexical feature vector aligns with historical website impersonation patterns.";
                } else {
                    predClass = "border-secondary-container/40 bg-secondary-container/10";
                    predTitle = "Model Estimate: Likely Legitimate Structure";
                    predIcon = "verified_user";
                    predDesc = "Lexical feature vector aligns with common legitimate website naming standards.";
                }
                if (prediction.disclaimer) {
                    disclaimer = prediction.disclaimer;
                }
            } else if (prediction && prediction.error) {
                predDesc = `Model status: ${prediction.error}`;
            }

            const predBanner = el("div", `p-4 rounded-xl border flex items-start gap-4 ${predClass}`);
            predBanner.appendChild(el("span", "material-symbols-outlined text-2xl text-secondary-container mt-0.5", predIcon));
            const predText = el("div", "flex-1");
            predText.appendChild(el("h4", "font-headline-sm text-sm font-bold text-on-surface", predTitle));
            predText.appendChild(el("p", "font-body-sm text-xs text-on-surface-variant mt-0.5", predDesc));
            predText.appendChild(el("p", "font-label-mono-sm text-[11px] text-outline mt-1 italic", disclaimer));
            predBanner.appendChild(predText);
            triageDeck.appendChild(predBanner);

            // URL Lexical Metrics Grid
            const metricsGrid = el("div", "grid grid-cols-2 sm:grid-cols-3 gap-3");
            const features = data.analysis.features || {};

            const featureDefinitions = [
                { key: "url_length", label: "URL Length", unit: "chars", warn: (v) => v > 100 },
                { key: "dot_count", label: "Dots in Host", unit: "", warn: (v) => v >= 4 },
                { key: "hyphen_count", label: "Hyphens in Host", unit: "", warn: (v) => v >= 3 },
                { key: "subdomain_count", label: "Subdomains", unit: "", warn: (v) => v >= 3 },
                { key: "suspicious_keyword_count", label: "Keywords", unit: "", warn: (v) => v > 0 },
                { key: "uses_https", label: "Protocol", format: (v) => v ? "HTTPS (Encrypted)" : "HTTP (Insecure)", warn: (v) => !v },
                { key: "uses_ip_address", label: "Host Type", format: (v) => v ? "RAW IP (Alert)" : "Named FQDN", warn: (v) => !!v },
                { key: "at_symbol_count", label: "@ Symbols", unit: "", warn: (v) => v > 0 },
                { key: "non_standard_port", label: "Port", format: (v) => v ? "Non-Standard" : "Standard (80/443)", warn: (v) => !!v }
            ];

            featureDefinitions.forEach(def => {
                const val = features[def.key];
                if (val === undefined) return;

                const tile = el("div", "p-3 rounded-xl bg-surface-container-lowest border border-outline-variant/30 flex flex-col gap-1");
                tile.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase tracking-wider", def.label));

                let displayVal = def.format ? def.format(val) : `${val}${def.unit ? ' ' + def.unit : ''}`;
                const valEl = el("span", "font-mono text-sm font-bold text-on-surface", displayVal);

                if (def.warn && def.warn(val)) {
                    valEl.classList.add("text-error");
                } else if (def.key === "uses_https" && val) {
                    valEl.classList.add("text-secondary-container");
                }

                tile.appendChild(valEl);
                metricsGrid.appendChild(tile);
            });

            triageDeck.appendChild(metricsGrid);
            scanMessage.replaceChildren(triageDeck);

            deeperButton.disabled = false;
            deeperStatus.textContent =
                "Deeper analysis retrieves bounded static HTML and checks infrastructure, brand, and relationship evidence only when requested.";
        } catch (error) {
            if (requestId === primaryRequestId) {
                const errBox = el("div", "bg-error/10 border border-error/40 p-6 rounded-xl text-center");
                errBox.appendChild(el("h4", "font-headline-sm text-sm text-error font-bold", "Analysis Failed"));
                errBox.appendChild(el("p", "text-outline text-xs mt-1", urlInput.value.trim() === url
                    ? `Analysis error: ${error.message}`
                    : "The URL changed while analysis was running. Submit again to analyze the current URL."));
                scanMessage.replaceChildren(errBox);
            }
        } finally {
            if (requestId === primaryRequestId) {
                submitButton.disabled = false;
            }
        }
    });

    // -----------------------------------------------------------------------
    // Helper: Build SVG Risk Gauge (Stitch Dual Gradient Style)
    // -----------------------------------------------------------------------
    function renderStitchGauge(score, level, verdict) {
        const scoreIsUnknown = score === null || score === undefined || typeof score !== "number";
        const gaugeBox = el("div", "relative flex items-center justify-center w-52 h-52");

        const glow = el("div", "absolute inset-0 rounded-full blur-xl");
        if (verdict === "inconclusive") {
            glow.className += " bg-warn/15";
        } else if (level === "critical" || level === "high") {
            glow.className += " bg-error/15";
        } else if (level === "moderate") {
            glow.className += " bg-warn/15";
        } else {
            glow.className += " bg-secondary-container/15";
        }
        gaugeBox.appendChild(glow);

        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 160 160");
        svg.setAttribute("class", "w-full h-full transform -rotate-90");

        // Defs for Stitch Gradients
        const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
        const grad = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
        grad.setAttribute("id", "stitchRiskGradient");
        grad.setAttribute("x1", "0%");
        grad.setAttribute("y1", "0%");
        grad.setAttribute("x2", "100%");
        grad.setAttribute("y2", "100%");

        const stop1 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
        const stop2 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
        const stop3 = document.createElementNS("http://www.w3.org/2000/svg", "stop");

        if (verdict === "inconclusive") {
            stop1.setAttribute("offset", "0%"); stop1.setAttribute("stop-color", "#fbbf24");
            stop2.setAttribute("offset", "100%"); stop2.setAttribute("stop-color", "#968da1");
        } else if (level === "critical" || level === "high") {
            stop1.setAttribute("offset", "0%"); stop1.setAttribute("stop-color", "#ffb4ab");
            stop2.setAttribute("offset", "50%"); stop2.setAttribute("stop-color", "#93000a");
            stop3.setAttribute("offset", "100%"); stop3.setAttribute("stop-color", "#8e44ff");
        } else if (level === "moderate") {
            stop1.setAttribute("offset", "0%"); stop1.setAttribute("stop-color", "#fbbf24");
            stop2.setAttribute("offset", "100%"); stop2.setAttribute("stop-color", "#8e44ff");
        } else {
            stop1.setAttribute("offset", "0%"); stop1.setAttribute("stop-color", "#00eefc");
            stop2.setAttribute("offset", "50%"); stop2.setAttribute("stop-color", "#34d399");
            stop3.setAttribute("offset", "100%"); stop3.setAttribute("stop-color", "#8e44ff");
        }
        grad.appendChild(stop1);
        grad.appendChild(stop2);
        if (stop3.getAttribute("offset")) grad.appendChild(stop3);
        defs.appendChild(grad);
        svg.appendChild(defs);

        // Background Circle (r=66 -> circumference ≈ 414.69)
        const bgCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        bgCircle.setAttribute("cx", "80");
        bgCircle.setAttribute("cy", "80");
        bgCircle.setAttribute("r", "66");
        bgCircle.setAttribute("class", "gauge-bg-circle");
        svg.appendChild(bgCircle);

        // Value Circle
        const valCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        valCircle.setAttribute("cx", "80");
        valCircle.setAttribute("cy", "80");
        valCircle.setAttribute("r", "66");
        valCircle.setAttribute("class", "gauge-val-circle");
        valCircle.setAttribute("stroke", "url(#stitchRiskGradient)");

        const circumference = 2 * Math.PI * 66;
        valCircle.setAttribute("stroke-dasharray", String(circumference));
        if (!scoreIsUnknown) {
            const offset = circumference - (score / 100) * circumference;
            valCircle.setAttribute("stroke-dashoffset", String(offset));
        }
        svg.appendChild(valCircle);

        gaugeBox.appendChild(svg);

        // Metric Center Hub
        const centerHub = el("div", "absolute inset-0 flex flex-col items-center justify-center text-center");
        centerHub.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase tracking-wider", "HEURISTIC RISK SCORE"));

        const scoreRow = el("div", "flex items-baseline gap-0.5 mt-0.5");
        const scoreVal = el("span", "font-data-metric text-4xl font-extrabold text-on-surface", scoreIsUnknown ? "N/A" : String(score));
        if (verdict === "inconclusive") scoreVal.className += " text-warn";
        else if (level === "critical" || level === "high") scoreVal.className += " text-error";
        else if (level === "low") scoreVal.className += " text-secondary-container";
        scoreRow.appendChild(scoreVal);
        scoreRow.appendChild(el("span", "font-label-mono-lg text-sm text-outline", "/100"));
        centerHub.appendChild(scoreRow);

        let badgeText = `${level.toUpperCase()} THREAT`;
        let badgeClass = "font-label-mono-sm text-[10px] px-2 py-0.5 rounded uppercase font-bold mt-1";
        if (verdict === "inconclusive") {
            badgeText = "INCONCLUSIVE";
            badgeClass += " bg-warn/20 text-warn border border-warn/30";
        } else if (level === "critical") {
            badgeClass += " bg-error/20 text-error";
        } else if (level === "high") {
            badgeClass += " bg-error/15 text-error";
        } else if (level === "moderate") {
            badgeClass += " bg-warn/20 text-warn";
        } else {
            badgeClass += " bg-secondary-container/15 text-secondary-container";
        }
        const sevBadge = el("span", badgeClass, badgeText);
        centerHub.appendChild(sevBadge);

        gaugeBox.appendChild(centerHub);
        return gaugeBox;
    }

    // -----------------------------------------------------------------------
    // Helper: Render Single Evidence Card
    // -----------------------------------------------------------------------
    function renderEvidenceCard(title, icon, record) {
        const card = el("article", "bg-surface-container-low border border-outline-variant/30 p-5 rounded-xl shadow-md flex flex-col justify-between hover:border-primary-container/40 transition-colors");

        const topBar = el("div", "flex items-center justify-between pb-3 border-b border-outline-variant/20 mb-3");
        const titleGroup = el("div", "flex items-center gap-2");
        titleGroup.appendChild(el("span", "material-symbols-outlined text-[20px] text-primary", icon));
        titleGroup.appendChild(el("h4", "font-headline-sm text-sm font-bold text-on-surface", title));
        topBar.appendChild(titleGroup);

        const statusStr = record ? (record.status || "observed") : "not_run";
        const statusBadge = el("span", `status-badge status-${statusStr}`, statusStr.replaceAll("_", " "));
        topBar.appendChild(statusBadge);
        card.appendChild(topBar);

        const body = el("div", "flex-1");

        const obs = (record && record.observation) || {};
        const isUnavailableOrFailed = !record ||
            statusStr === "unavailable" ||
            statusStr === "error" ||
            statusStr === "not_run" ||
            statusStr === "destination_rejected" ||
            statusStr === "domain_absent" ||
            statusStr === "invalid_input" ||
            statusStr === "no_relationships";

        if (isUnavailableOrFailed && Object.keys(obs).length === 0) {
            const emptyMsg = el("p", "text-outline text-xs italic py-4 text-center");
            if (statusStr === "unavailable") {
                emptyMsg.textContent = "Telemetry source unavailable during scan.";
            } else if (statusStr === "error") {
                emptyMsg.textContent = "Telemetry error during collection.";
            } else if (statusStr === "destination_rejected") {
                emptyMsg.textContent = "Destination host rejected connection or was unreachable.";
            } else if (statusStr === "domain_absent") {
                emptyMsg.textContent = "Domain does not exist or has no DNS records.";
            } else if (statusStr === "invalid_input") {
                emptyMsg.textContent = "Domain name query invalid or could not be resolved.";
            } else if (statusStr === "no_relationships") {
                emptyMsg.textContent = "No infrastructure relationships identified.";
            } else {
                emptyMsg.textContent = "Telemetry module has not been executed.";
            }
            body.appendChild(emptyMsg);
        } else {
            const kvTable = el("div", "flex flex-col gap-1.5");
            const obs = record.observation || {};

            Object.entries(obs).forEach(([key, val]) => {
                const row = el("div", "flex items-center justify-between text-xs py-1 px-2 rounded bg-surface-container-lowest font-mono");
                row.appendChild(el("span", "text-outline capitalize", key.replaceAll("_", " ")));

                let displayVal = "";
                if (val === null || val === undefined) displayVal = "None";
                else if (typeof val === "boolean") displayVal = val ? "True" : "False";
                else if (typeof val === "object") {
                    displayVal = Array.isArray(val) ? (val.length === 0 ? "0 items" : `${val.length} items`) : `${Object.keys(val).length} fields`;
                } else displayVal = String(val);

                row.appendChild(el("span", "text-on-surface font-semibold truncate max-w-[200px]", displayVal));
                kvTable.appendChild(row);
            });

            body.appendChild(kvTable);
        }

        card.appendChild(body);

        if (record && record.uncertainty && record.uncertainty.length > 0) {
            const footer = el("div", "mt-3 pt-2 border-t border-outline-variant/20 font-mono text-[10px] text-outline italic");
            footer.textContent = `Uncertainty: ${record.uncertainty.join(" ")}`;
            card.appendChild(footer);
        }

        return card;
    }

    // -----------------------------------------------------------------------
    // Helper: Render Interactive SVG Domain Relationship Graph
    // -----------------------------------------------------------------------
    function renderRelationshipGraphSection(relationshipsRecord, targetHostname) {
        const deck = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl p-6 md:p-8 shadow-xl flex flex-col gap-4 relative overflow-hidden");

        const deckHeader = el("div", "flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-outline-variant/20");
        const titleWrap = el("div", "flex items-center gap-2");
        titleWrap.appendChild(el("span", "material-symbols-outlined text-secondary-container text-[24px]", "hub"));
        const titles = el("div");
        titles.appendChild(el("h3", "font-headline-sm text-headline-sm text-on-surface font-bold", "Domain Relationship & Threat Infrastructure Graph"));
        titles.appendChild(el("p", "font-body-sm text-xs text-outline", "Topological network correlation & brand resemblance connections"));
        titleWrap.appendChild(titles);
        deckHeader.appendChild(titleWrap);

        deckHeader.appendChild(el("span", "font-label-mono-sm text-xs text-secondary-container px-2.5 py-1 rounded bg-surface-container font-mono border border-outline-variant/30", "TOPOLOGY // VERIFIED"));
        deck.appendChild(deckHeader);

        const canvasBox = el("div", "bg-surface-container-lowest border border-outline-variant/30 rounded-xl min-h-[300px] flex items-center justify-center p-4 relative overflow-hidden");
        const obs = (relationshipsRecord && relationshipsRecord.observation) || {};
        const nodes = obs.nodes || [];
        const edges = obs.edges || [];

        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 600 280");
        svg.setAttribute("class", "w-full h-full min-h-[280px]");

        if (nodes.length === 0 && edges.length === 0) {
            // Clean uncalibrated baseline representation
            const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            circle.setAttribute("cx", "300"); circle.setAttribute("cy", "140"); circle.setAttribute("r", "38");
            circle.setAttribute("fill", "#1b1b23"); circle.setAttribute("stroke", "#00eefc"); circle.setAttribute("stroke-width", "2");
            svg.appendChild(circle);

            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            text.setAttribute("x", "300"); text.setAttribute("y", "145"); text.setAttribute("text-anchor", "middle");
            text.setAttribute("fill", "#e4e1ec"); text.setAttribute("font-size", "11"); text.setAttribute("font-family", "monospace");
            text.textContent = (targetHostname || "Target FQDN").slice(0, 16);
            svg.appendChild(text);

            const note = document.createElementNS("http://www.w3.org/2000/svg", "text");
            note.setAttribute("x", "300"); note.setAttribute("y", "210"); note.setAttribute("text-anchor", "middle");
            note.setAttribute("fill", "#968da1"); note.setAttribute("font-size", "11");
            note.textContent = "Isolated Target Host · Zero Brand Resemblance Links Detected";
            svg.appendChild(note);
        } else {
            const centerX = 300, centerY = 140;

            // Target Node
            const centerNode = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            centerNode.setAttribute("cx", String(centerX)); centerNode.setAttribute("cy", String(centerY)); centerNode.setAttribute("r", "34");
            centerNode.setAttribute("fill", "#1b1b23"); centerNode.setAttribute("stroke", "#00eefc"); centerNode.setAttribute("stroke-width", "3");
            svg.appendChild(centerNode);

            const centerText = document.createElementNS("http://www.w3.org/2000/svg", "text");
            centerText.setAttribute("x", String(centerX)); centerText.setAttribute("y", String(centerY + 4)); centerText.setAttribute("text-anchor", "middle");
            centerText.setAttribute("fill", "white"); centerText.setAttribute("font-size", "11"); centerText.setAttribute("font-weight", "bold");
            centerText.textContent = "TARGET";
            svg.appendChild(centerText);

            const radius = 100;
            const otherNodes = nodes.filter(n => n.id !== targetHostname);
            const total = Math.max(1, otherNodes.length);

            otherNodes.forEach((node, idx) => {
                const angle = (idx / total) * 2 * Math.PI - Math.PI / 2;
                const nx = centerX + radius * Math.cos(angle);
                const ny = centerY + radius * Math.sin(angle);

                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", String(centerX)); line.setAttribute("y1", String(centerY));
                line.setAttribute("x2", String(nx)); line.setAttribute("y2", String(ny));
                line.setAttribute("stroke", "#ffb4ab"); line.setAttribute("stroke-width", "2"); line.setAttribute("stroke-dasharray", "4,4");
                svg.appendChild(line);

                const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                c.setAttribute("cx", String(nx)); c.setAttribute("cy", String(ny)); c.setAttribute("r", "24");
                c.setAttribute("fill", "#1b1b23"); c.setAttribute("stroke", "#8e44ff"); c.setAttribute("stroke-width", "2");
                svg.appendChild(c);

                const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
                t.setAttribute("x", String(nx)); t.setAttribute("y", String(ny + 4)); t.setAttribute("text-anchor", "middle");
                t.setAttribute("fill", "#cdc2d8"); t.setAttribute("font-size", "10");
                t.textContent = (node.label || node.id || "Entity").slice(0, 10);
                svg.appendChild(t);
            });
        }

        canvasBox.appendChild(svg);
        deck.appendChild(canvasBox);

        // Legend & Transparency Note
        const legend = el("div", "flex items-center justify-center gap-6 flex-wrap font-label-mono-sm text-xs text-outline");
        legend.appendChild(el("span", "flex items-center gap-1.5", "● Analyzed Target FQDN"));
        legend.appendChild(el("span", "flex items-center gap-1.5", "● Brand / Candidate Entity"));
        legend.appendChild(el("span", "flex items-center gap-1.5", "- - Resemblance Linkage"));
        deck.appendChild(legend);

        const disc = el("p", "font-mono text-[11px] text-outline text-center italic",
            "Notice: Graph edges reflect structural and textual resemblance. They do not independently prove malicious intent or domain ownership.");
        deck.appendChild(disc);

        return deck;
    }

    // -----------------------------------------------------------------------
    // Helper: Generate Formatted Report Summary
    // -----------------------------------------------------------------------
    function generateReportSummary(url, riskAssessment, evidence) {
        const score = riskAssessment ? riskAssessment.risk_score : "N/A";
        const level = riskAssessment ? riskAssessment.risk_level.toUpperCase() : "N/A";
        const verdict = riskAssessment ? riskAssessment.verdict.toUpperCase().replace("_", " ") : "N/A";
        const sufficiency = riskAssessment ? riskAssessment.evidence_sufficiency : "N/A";

        let report = `=======================================================\n`;
        report += `MIMICTRACE AI — CYBERSECURITY FORENSIC DOSSIER\n`;
        report += `=======================================================\n`;
        report += `Target URL:       ${url}\n`;
        report += `Investigation:    ${new Date().toISOString()}\n`;
        report += `Risk Score:       ${score} / 100 (Heuristic Indicator Weight)\n`;
        report += `Classification:   ${level} RISK\n`;
        report += `Verdict:          ${verdict}\n`;
        report += `Sufficiency:      ${sufficiency}\n`;
        report += `-------------------------------------------------------\n\n`;

        if (riskAssessment && riskAssessment.contributing_indicators.length > 0) {
            report += `[!] SUSPICIOUS CONTRIBUTING INDICATORS (${riskAssessment.contributing_indicators.length}):\n`;
            riskAssessment.contributing_indicators.forEach(i => {
                report += `  - [${i.signal_id}] ${i.description}\n`;
            });
            report += `\n`;
        } else {
            report += `[*] SUSPICIOUS INDICATORS: None identified.\n\n`;
        }

        if (riskAssessment && riskAssessment.negative_indicators.length > 0) {
            report += `[+] REASSURING / NEGATIVE SIGNALS (${riskAssessment.negative_indicators.length}):\n`;
            riskAssessment.negative_indicators.forEach(i => {
                report += `  - [${i.signal_id}] ${i.description}\n`;
            });
            report += `\n`;
        }

        if (riskAssessment && riskAssessment.recommended_actions.length > 0) {
            report += `[>] RECOMMENDED ACTIONS:\n`;
            riskAssessment.recommended_actions.forEach((act, idx) => {
                report += `  ${idx + 1}. ${act}\n`;
            });
            report += `\n`;
        }

        if (riskAssessment && riskAssessment.limitations.length > 0) {
            report += `[i] DETECTION LIMITATIONS & SCOPE:\n`;
            riskAssessment.limitations.forEach(lim => {
                report += `  - ${lim}\n`;
            });
            report += `\n`;
        }

        report += `=======================================================\n`;
        report += `Generated by MimicTrace AI Defensive Telemetry Engine\n`;
        report += `Scores are heuristic weights, not statistical probabilities.\n`;
        report += `=======================================================\n`;

        return report;
    }

    // -----------------------------------------------------------------------
    // Deeper Analysis Handler
    // Invariants required by test_dashboard_contract.py:
    // - ["html", "dns", "domain", "tls", "brand", "visual", "relationships"]
    // - formData.append("logo_crop", selectedLogo)
    // - JSON.stringify({ url })
    // -----------------------------------------------------------------------
    deeperButton.addEventListener("click", async () => {
        const url = urlInput.value.trim();
        if (
            deeperRequestInFlight
            || !analyzedUrl
            || url !== analyzedUrl
            || completedDeeperUrl === url
        ) {
            return;
        }

        deeperRequestInFlight = true;
        deeperButton.disabled = true;

        const loadingBar = el("div", "radar-active");
        loadingBar.appendChild(el("span", "radar-spinner"));
        loadingBar.appendChild(el("span", null, "Fusing telemetry across HTML, DNS, TLS, WHOIS, Brand, and Graph intelligence..."));
        deeperStatus.replaceChildren(loadingBar);
        deeperResults.replaceChildren();

        try {
            const selectedLogo = logoCropInput.files[0];
            let requestOptions;
            if (selectedLogo) {
                const formData = new FormData();
                formData.append("url", url);
                formData.append("logo_crop", selectedLogo);
                requestOptions = {
                    method: "POST",
                    body: formData
                };
            } else {
                requestOptions = {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url })
                };
            }

            const response = await fetch("/api/analyze/deeper", requestOptions);
            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Deeper analysis failed.");
            }

            if (urlInput.value.trim() !== url || analyzedUrl !== url) return;

            completedDeeperUrl = url;
            deeperStatus.textContent = "Evidence collected. Results are observations, not a security verdict.";

            // Build Stitch Forensic Investigation Results Report
            const reportRoot = el("div", "flex flex-col gap-8");
            const riskAssessment = data.risk_assessment;
            const evidence = data.evidence || {};
            const hasValidAssessment =
                riskAssessment &&
                typeof riskAssessment === "object" &&
                typeof riskAssessment.verdict === "string";
            const score = hasValidAssessment ? riskAssessment.risk_score : null;
            const level = hasValidAssessment ? riskAssessment.risk_level : "inconclusive";
            const verdict = hasValidAssessment ? riskAssessment.verdict : "inconclusive";
            const sufficiency = hasValidAssessment
                ? riskAssessment.evidence_sufficiency
                : "limited";
            const assessmentState = hasValidAssessment
                ? riskAssessment.assessment_state
                : "inconclusive";

            // Action Ribbon
            const ribbon = el("div", "flex items-center justify-between p-4 rounded-xl bg-surface-container-low border border-outline-variant/30 flex-wrap gap-4");
            const ribbonLeft = el("div", "flex items-center gap-3");
            const breadcrumb = el("span", "font-mono text-xs text-primary font-bold", `TARGET // ${analyzedUrl}`);
            ribbonLeft.appendChild(breadcrumb);
            ribbon.appendChild(ribbonLeft);

            const ribbonRight = el("div", "flex items-center gap-2 flex-wrap");
            const copyReportBtn = el("button", "px-4 py-2 rounded-lg bg-primary-container hover:bg-primary text-on-primary-container font-label-mono-sm text-xs font-bold flex items-center gap-1.5 transition-all shadow-[0_0_16px_rgba(142,68,255,0.4)]");
            copyReportBtn.appendChild(el("span", "material-symbols-outlined text-[16px]", "content_copy"));
            copyReportBtn.appendChild(el("span", null, "Copy Forensic Report"));
            copyReportBtn.addEventListener("click", () => {
                const textReport = generateReportSummary(url, riskAssessment, evidence);
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(textReport).then(() => {
                        showToast("Forensic report copied to clipboard!");
                    }).catch(() => {
                        showToast("Could not copy automatically. Select from Technical Payload.");
                    });
                }
            });
            ribbonRight.appendChild(copyReportBtn);

            const newScanBtn = el("button", "px-4 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-mono-sm text-xs border border-outline-variant/30 flex items-center gap-1.5 transition-all");
            newScanBtn.appendChild(el("span", "material-symbols-outlined text-[16px]", "refresh"));
            newScanBtn.appendChild(el("span", null, "New Target"));
            newScanBtn.addEventListener("click", () => {
                urlInput.value = "";
                urlInput.focus();
                urlInput.dispatchEvent(new Event("input", { bubbles: true }));
            });
            ribbonRight.appendChild(newScanBtn);

            const payloadToggleBtn = el("button", "px-4 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-outline hover:text-on-surface font-label-mono-sm text-xs border border-outline-variant/30 flex items-center gap-1.5 transition-all");
            payloadToggleBtn.appendChild(el("span", "material-symbols-outlined text-[16px]", "code"));
            payloadToggleBtn.appendChild(el("span", null, "Technical Payload"));
            ribbonRight.appendChild(payloadToggleBtn);

            ribbon.appendChild(ribbonRight);
            reportRoot.appendChild(ribbon);

            // SECTION A: Risk Assessment Dossier
            const dossier = el("div", "relative bg-surface-container-lowest border border-outline-variant/40 rounded-2xl p-6 md:p-8 shadow-2xl overflow-hidden");
            const dossierAccent = el("div", "absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-error via-primary-container to-secondary-container");
            dossier.appendChild(dossierAccent);

            const dossierGrid = el("div", "grid grid-cols-1 xl:grid-cols-12 gap-8 items-center");

            // Gauge Col
            const gaugeCol = el("div", "xl:col-span-4 flex flex-col items-center justify-center p-6 bg-surface-container-low/70 rounded-2xl border border-outline-variant/30 relative");
            gaugeCol.appendChild(renderStitchGauge(score, level, verdict));
            dossierGrid.appendChild(gaugeCol);

            // Verdict & Summary Col
            const metaCol = el("div", "xl:col-span-8 flex flex-col justify-between gap-4");

            const verdictRow = el("div", "flex flex-wrap items-center gap-2");
            const isInconclusive = verdict === "inconclusive" || assessmentState === "inconclusive";
            const levelChipText = isInconclusive ? "INCONCLUSIVE" : `${level.toUpperCase()} RISK`;
            const levelChip = el("span", "px-3 py-1 rounded font-label-mono-sm text-xs font-bold uppercase tracking-wide", levelChipText);
            if (level === "critical" && !isInconclusive) levelChip.className += " bg-error/20 text-error";
            else if (level === "high" && !isInconclusive) levelChip.className += " bg-error/15 text-error";
            else if (level === "moderate" && !isInconclusive) levelChip.className += " bg-warn/20 text-warn";
            else if (isInconclusive) levelChip.className += " bg-warn/20 text-warn";
            else levelChip.className += " bg-secondary-container/20 text-secondary-container";
            verdictRow.appendChild(levelChip);

            const verdictChip = el("span", "bg-surface-container-high px-3 py-1 rounded font-label-mono-sm text-xs text-on-surface font-mono font-bold", `VERDICT: ${verdict.toUpperCase().replace("_", " ")}`);
            if (verdict === "inconclusive") {
                verdictChip.className += " border border-warn/40 text-warn";
            }
            verdictRow.appendChild(verdictChip);
            metaCol.appendChild(verdictRow);

            const headline = el("h2", "font-headline-md text-2xl text-on-surface font-bold");
            if (verdict === "inconclusive") {
                headline.textContent = "Inconclusive Assessment · Insufficient Telemetry";
            } else if (level === "critical" || level === "high") {
                headline.textContent = "High-Risk Impersonation Threat or Phishing Pattern";
            } else if (level === "moderate") {
                headline.textContent = "Moderate Suspicion · Anomalies Identified";
            } else {
                headline.textContent = "Likely Legitimate Identity · No Critical Impersonation Flags";
            }
            metaCol.appendChild(headline);

            const desc = el("p", "font-body-md text-sm text-on-surface-variant leading-relaxed");
            if (verdict === "inconclusive") {
                desc.textContent = "The destination host could not be verified because critical telemetry sources (e.g. DNS, TLS, or HTTP connection) were unreachable or unavailable. Absence of telemetry does not indicate safety.";
            } else {
                desc.textContent = "The target URL underwent comprehensive multi-signal telemetry fusion. Scores reflect heuristic indicator weights and should be evaluated in context with surrounding evidence.";
            }
            metaCol.appendChild(desc);

            // Coverage limitations (backend-reported, e.g. HTML unavailable)
            const limitations = hasValidAssessment && Array.isArray(riskAssessment.limitations)
                ? riskAssessment.limitations
                : [];
            if (limitations.length > 0) {
                const limitationsBox = el("div", "mt-4 p-3 rounded-lg bg-warn/10 border border-warn/30 text-xs text-warn leading-relaxed");
                const limitationsTitle = el("span", "font-mono text-[10px] text-warn font-bold uppercase mb-1 block", "Coverage Limitations");
                limitationsBox.appendChild(limitationsTitle);
                limitations.forEach((lim) => {
                    const limItem = el("p", "font-body-sm text-xs text-warn leading-relaxed", lim);
                    limitationsBox.appendChild(limItem);
                });
                metaCol.appendChild(limitationsBox);
            }

            // Metrics Strip
            const metricsStrip = el("div", "grid grid-cols-2 sm:grid-cols-4 gap-3 bg-surface-container-low p-4 rounded-xl border border-outline-variant/30");

            const m1 = el("div", "flex flex-col");
            m1.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase", "SUFFICIENCY"));
            m1.appendChild(el("span", "font-mono text-sm font-bold text-on-surface uppercase", sufficiency));
            metricsStrip.appendChild(m1);

            const m2 = el("div", "flex flex-col");
            m2.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase", "SUSPICIOUS SIGNALS"));
            m2.appendChild(el("span", "font-mono text-sm font-bold text-error", String(riskAssessment ? riskAssessment.contributing_indicators.length : 0)));
            metricsStrip.appendChild(m2);

            const m3 = el("div", "flex flex-col");
            m3.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase", "REASSURING SIGNALS"));
            m3.appendChild(el("span", "font-mono text-sm font-bold text-secondary-container", String(riskAssessment ? riskAssessment.negative_indicators.length : 0)));
            metricsStrip.appendChild(m3);

            const m4 = el("div", "flex flex-col");
            m4.appendChild(el("span", "font-label-mono-sm text-[10px] text-outline uppercase", "EVIDENCE SOURCES"));
            const sourceStatuses = hasValidAssessment && riskAssessment.evidence_summary
                ? riskAssessment.evidence_summary.source_statuses
                : {};
            const observedSourceCount = Object.values(sourceStatuses).filter(
                (status) => status === "observed"
            ).length;
            m4.appendChild(el("span", "font-mono text-sm font-bold text-primary", `${observedSourceCount} TELEMETRY`));
            metricsStrip.appendChild(m4);

            metaCol.appendChild(metricsStrip);

            // Non-probability advisory
            const advisory = el("div", "p-3 rounded-lg bg-surface-container border-l-2 border-primary text-xs text-outline leading-snug");
            advisory.appendChild(el("strong", "text-on-surface block mb-0.5", "⚠️ Methodological Note: Not a Statistical Probability"));
            advisory.appendChild(el("span", null, "The 0–100 risk score reflects the heuristic accumulation of detected threat indicators. Benign websites may exhibit isolated anomalies."));
            metaCol.appendChild(advisory);

            dossierGrid.appendChild(metaCol);
            dossier.appendChild(dossierGrid);
            reportRoot.appendChild(dossier);

            // SECTION B: Dual-Track Findings (Suspicious vs Reassuring)
            if (riskAssessment) {
                const findingsGrid = el("div", "grid grid-cols-1 lg:grid-cols-2 gap-6");

                // Suspicious Column
                const suspPanel = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl p-6 shadow-lg flex flex-col gap-4");
                const suspHeader = el("div", "flex items-center justify-between pb-3 border-b border-outline-variant/20");
                const suspTitle = el("div", "flex items-center gap-2");
                suspTitle.appendChild(el("span", "material-symbols-outlined text-error text-[20px]", "warning"));
                suspTitle.appendChild(el("h3", "font-headline-sm text-sm font-bold text-on-surface", `Suspicious Indicators (${riskAssessment.contributing_indicators.length})`));
                suspHeader.appendChild(suspTitle);
                suspHeader.appendChild(el("span", "font-mono text-xs px-2 py-0.5 rounded bg-error/20 text-error font-bold", "FLAGS"));
                suspPanel.appendChild(suspHeader);

                if (riskAssessment.contributing_indicators.length === 0) {
                    suspPanel.appendChild(el("p", "text-outline text-xs italic py-6 text-center", "No suspicious indicators were triggered for this website."));
                } else {
                    const list = el("div", "flex flex-col gap-2");
                    riskAssessment.contributing_indicators.forEach(item => {
                        const row = el("div", "p-3 rounded-xl bg-surface-container-lowest border-l-2 border-error border-t border-r border-b border-outline-variant/30 text-xs flex flex-col gap-1");
                        row.appendChild(el("span", "font-mono text-[10px] text-error font-bold", item.signal_id));
                        row.appendChild(el("span", "text-on-surface-variant", item.description));
                        list.appendChild(row);
                    });
                    suspPanel.appendChild(list);
                }
                findingsGrid.appendChild(suspPanel);

                // Reassuring Column
                const reassPanel = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl p-6 shadow-lg flex flex-col gap-4");
                const reassHeader = el("div", "flex items-center justify-between pb-3 border-b border-outline-variant/20");
                const reassTitle = el("div", "flex items-center gap-2");
                reassTitle.appendChild(el("span", "material-symbols-outlined text-secondary-container text-[20px]", "verified_user"));
                reassTitle.appendChild(el("h3", "font-headline-sm text-sm font-bold text-on-surface", `Reassuring Indicators (${riskAssessment.negative_indicators.length})`));
                reassHeader.appendChild(reassTitle);
                reassHeader.appendChild(el("span", "font-mono text-xs px-2 py-0.5 rounded bg-secondary-container/20 text-secondary-container font-bold", "CLEAN"));
                reassPanel.appendChild(reassHeader);

                if (riskAssessment.negative_indicators.length === 0) {
                    reassPanel.appendChild(el("p", "text-outline text-xs italic py-6 text-center", "No reassuring indicators identified."));
                } else {
                    const list = el("div", "flex flex-col gap-2");
                    riskAssessment.negative_indicators.forEach(item => {
                        const row = el("div", "p-3 rounded-xl bg-surface-container-lowest border-l-2 border-secondary-container border-t border-r border-b border-outline-variant/30 text-xs flex flex-col gap-1");
                        row.appendChild(el("span", "font-mono text-[10px] text-secondary-container font-bold", item.signal_id));
                        row.appendChild(el("span", "text-on-surface-variant", item.description));
                        list.appendChild(row);
                    });
                    reassPanel.appendChild(list);
                }
                findingsGrid.appendChild(reassPanel);

                reportRoot.appendChild(findingsGrid);

                // Guidance & Scope Cards
                const guideGrid = el("div", "grid grid-cols-1 lg:grid-cols-2 gap-6");

                const recCard = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl p-6 shadow-lg flex flex-col gap-3");
                recCard.appendChild(el("h4", "font-headline-sm text-sm font-bold text-on-surface", "Recommended Protective Actions"));
                const recList = el("ol", "list-decimal list-inside text-xs text-on-surface-variant flex flex-col gap-1.5");
                (riskAssessment.recommended_actions || []).forEach(act => {
                    recList.appendChild(el("li", null, act));
                });
                recCard.appendChild(recList);
                guideGrid.appendChild(recCard);

                const limCard = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl p-6 shadow-lg flex flex-col gap-3");
                limCard.appendChild(el("h4", "font-headline-sm text-sm font-bold text-on-surface", "Analysis Scope & Limitations"));
                const limList = el("ul", "list-disc list-inside text-xs text-outline flex flex-col gap-1.5");
                (riskAssessment.limitations || []).forEach(lim => {
                    limList.appendChild(el("li", null, lim));
                });
                limCard.appendChild(limList);
                guideGrid.appendChild(limCard);

                reportRoot.appendChild(guideGrid);
            }

            // SECTION C: Relationship Graph Intelligence
            const targetHostname = (lastAnalysisData && lastAnalysisData.analysis && lastAnalysisData.analysis.hostname) || url;
            const graphSection = renderRelationshipGraphSection(evidence.relationships, targetHostname);
            reportRoot.appendChild(graphSection);

            // SECTION D: Modular Telemetry Cards Grid
            // Preserving exact order for dashboard contract: ["html", "dns", "domain", "tls", "brand", "visual", "relationships"]
            const telemetrySec = el("div", "flex flex-col gap-4");
            telemetrySec.appendChild(el("h3", "font-headline-sm text-headline-sm text-on-surface font-bold", "Multi-Source Evidence Telemetry"));

            const telemetryGrid = el("div", "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4");

            const categoryOrder = ["html", "dns", "domain", "tls", "brand", "visual", "relationships"];
            const metaConfigs = {
                html: { title: "HTML & Page Structure", icon: "code" },
                dns: { title: "DNS Infrastructure", icon: "dns" },
                domain: { title: "WHOIS & Domain Age", icon: "calendar_today" },
                tls: { title: "TLS & Certificates", icon: "lock" },
                brand: { title: "Brand Impersonation", icon: "font_download" },
                visual: { title: "Visual Resemblance", icon: "image" },
                relationships: { title: "Graph Intelligence", icon: "hub" }
            };

            categoryOrder.forEach(secName => {
                const conf = metaConfigs[secName];
                if (!conf) return;

                const secEv = evidence[secName];
                if (secName === "dns" && secEv && typeof secEv === "object" && !secEv.status) {
                    const dnsCard = el("article", "bg-surface-container-low border border-outline-variant/30 p-5 rounded-xl shadow-md flex flex-col justify-between");
                    const topBar = el("div", "flex items-center justify-between pb-3 border-b border-outline-variant/20 mb-3");
                    const titleGrp = el("div", "flex items-center gap-2");
                    titleGrp.appendChild(el("span", "material-symbols-outlined text-[20px] text-primary", conf.icon));
                    titleGrp.appendChild(el("h4", "font-headline-sm text-sm font-bold text-on-surface", conf.title));
                    topBar.appendChild(titleGrp);

                    const anyObs = Object.values(secEv).some(r => r && r.status === "observed");
                    let dnsStatus = "unavailable";
                    let dnsText = "Unavailable";
                    if (anyObs) {
                        dnsStatus = "observed";
                        dnsText = "Observed";
                    } else {
                        const statuses = Object.values(secEv).map(r => r && r.status).filter(Boolean);
                        if (statuses.includes("domain_absent")) {
                            dnsStatus = "domain_absent";
                            dnsText = "Domain Absent";
                        } else if (statuses.includes("destination_rejected")) {
                            dnsStatus = "destination_rejected";
                            dnsText = "Rejected";
                        }
                    }
                    topBar.appendChild(el("span", `status-badge status-${dnsStatus}`, dnsText));
                    dnsCard.appendChild(topBar);

                    const body = el("div", "flex flex-col gap-1.5");
                    Object.entries(secEv).forEach(([recType, rec]) => {
                        const row = el("div", "flex items-center justify-between text-xs py-1 px-2 rounded bg-surface-container-lowest font-mono");
                        row.appendChild(el("span", "text-outline", `${recType} Record`));
                        let valText = "Not Returned";
                        if (rec && rec.status === "observed" && rec.observation) {
                            const ans = rec.observation.answers || rec.observation.records;
                            valText = Array.isArray(ans) && ans.length > 0 ? ans.slice(0, 2).join(", ") : "Present (Observed)";
                        } else if (rec && rec.status) {
                            valText = rec.status;
                        }
                        row.appendChild(el("span", "text-on-surface font-semibold truncate max-w-[180px]", valText));
                        body.appendChild(row);
                    });
                    dnsCard.appendChild(body);
                    telemetryGrid.appendChild(dnsCard);
                } else {
                    telemetryGrid.appendChild(renderEvidenceCard(conf.title, conf.icon, secEv));
                }
            });

            telemetrySec.appendChild(telemetryGrid);
            reportRoot.appendChild(telemetrySec);

            // SECTION E: Technical JSON Payload Drawer
            const payloadDrawer = el("div", "bg-surface-container-low border border-outline-variant/30 rounded-2xl overflow-hidden shadow-xl");
            payloadDrawer.style.display = "none";

            const payloadHeader = el("div", "p-4 bg-surface-container border-b border-outline-variant/20 flex items-center justify-between");
            payloadHeader.appendChild(el("span", "font-mono text-xs text-on-surface font-bold", "RAW TELEMETRY PAYLOAD // JSON"));
            const copyJson = el("button", "px-3 py-1 rounded bg-surface-container-highest text-secondary-container hover:underline text-xs font-mono", "Copy JSON");
            copyJson.addEventListener("click", () => {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => {
                        showToast("Raw JSON copied to clipboard!");
                    });
                }
            });
            payloadHeader.appendChild(copyJson);
            payloadDrawer.appendChild(payloadHeader);

            const codeBlock = el("pre", "p-4 max-h-[380px] overflow-y-auto font-mono text-xs text-outline-variant bg-surface-container-lowest", JSON.stringify(data, null, 2));
            payloadDrawer.appendChild(codeBlock);
            reportRoot.appendChild(payloadDrawer);

            payloadToggleBtn.addEventListener("click", () => {
                if (payloadDrawer.style.display === "none") {
                    payloadDrawer.style.display = "block";
                    payloadToggleBtn.textContent = "Hide Payload";
                } else {
                    payloadDrawer.style.display = "none";
                    payloadToggleBtn.textContent = "Technical Payload";
                }
            });

            deeperResults.replaceChildren(reportRoot);
            reportRoot.scrollIntoView({ behavior: "smooth" });

        } catch (error) {
            if (urlInput.value.trim() === url && analyzedUrl === url) {
                deeperStatus.textContent = `Deeper analysis error: ${error.message}`;
            }
        } finally {
            deeperRequestInFlight = false;
            if (
                analyzedUrl
                && urlInput.value.trim() === analyzedUrl
                && completedDeeperUrl !== analyzedUrl
            ) {
                deeperButton.disabled = false;
            }
        }
    });

    // -----------------------------------------------------------------------
    // Nav Tabs Active State & Smooth View Scrolling
    // -----------------------------------------------------------------------
    document.querySelectorAll(".nav-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
        });
    });
}
