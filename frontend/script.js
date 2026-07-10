/**
 * Advanced Threat & Integrity Intelligence - Main Frontend Controller
 * - 탭 전환, 파일 드래그 앤 드롭 인터랙션, 백엔드 API 통신 연동
 */

const API_BASE = "https://threat-intel-engine.onrender.com";

// 1. 전역 상태 관리 변수
let currentMode = 'integrity'; // 'integrity' 또는 'malware'
let selectedFiles = {
    orig: null,
    target: null,
    malware: null
};

window.addEventListener('DOMContentLoaded', () => {
    // 초기화 함수 실행
    initTabInterface();
    initDragAndDrop();
    initScanButton();
});

/**
 * [인터페이스] 무결성 검증 <-> AI 악성코드 스캔 탭 토글 및 UI 뷰 스위칭
 */
function initTabInterface() {
    const tabIntegrity = document.getElementById('tabIntegrity');
    const tabMalware = document.getElementById('tabMalware');

    if (tabIntegrity && tabMalware) {
        tabIntegrity.addEventListener('click', () => switchMode('integrity'));
        tabMalware.addEventListener('click', () => switchMode('malware'));
    }
}

function switchMode(mode) {
    currentMode = mode;

    // UI 요소 캐싱
    const tabIntegrity = document.getElementById('tabIntegrity');
    const tabMalware = document.getElementById('tabMalware');
    const integrityUpload = document.getElementById('integrityUploadContainer');
    const malwareUpload = document.getElementById('malwareUploadContainer');
    const uploadTitle = document.getElementById('uploadTitle');
    const uploadDesc = document.getElementById('uploadDesc');
    const scanBtn = document.getElementById('scanBtn');

    // 상태 리셋용 메인 패널 복구
    document.getElementById('introState').classList.remove('hidden');
    document.getElementById('loadingState').classList.add('hidden');
    document.getElementById('resultState').classList.add('hidden');

    if (mode === 'integrity') {
        tabIntegrity.classList.add('active');
        tabMalware.classList.remove('active');
        integrityUpload.classList.remove('hidden');
        malwareUpload.classList.add('hidden');
        uploadTitle.textContent = "Integrity Verification";
        uploadDesc.textContent = "Upload both the original base binary and the destination artifact to map cryptographic discrepancies.";
        scanBtn.textContent = "Run Forensic Matrix";
    } else {
        tabIntegrity.classList.remove('active');
        tabMalware.classList.add('active');
        integrityUpload.classList.add('hidden');
        malwareUpload.classList.remove('hidden');
        uploadTitle.textContent = "AI Malware Precision Scan";
        uploadDesc.textContent = "Drop a Portable Executable object (.exe, .dll) to evaluate security posture against AI neural engines.";
        scanBtn.textContent = "Execute AI Telemetry";
    }

    updateScanButtonState();
}

/**
 * [인터랙션] 드래그 앤 드롭 및 클릭 파일 업로드 바인딩
 */
function initDragAndDrop() {
    // 1) 오리지널 베이스라인 파일 바인딩
    setupFileInputEvent('fileOrig', 'dropAreaOrig', 'textOrig', 'orig');
    // 2) 타겟 검증 대상 파일 바인딩
    setupFileInputEvent('fileTarget', 'dropAreaTarget', 'textTarget', 'target');
    // 3) 악성코드 스캔 대상 파일 바인딩
    setupFileInputEvent('fileMal', 'dropAreaMal', 'fileMalName', 'malware');
}

function setupFileInputEvent(inputId, dropAreaId, textId, fileKey) {
    const fileInput = document.getElementById(inputId);
    const dropArea = document.getElementById(dropAreaId);
    const textDisplay = document.getElementById(textId);

    if (!fileInput || !dropArea) return;

    // 💡 무한 이중창 열림 완벽 해결 (클릭 리스너를 완전히 제거하여 HTML label에만 위임)
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelection(e.target.files[0], textDisplay, dropArea, fileKey);
        }
    });

    // 드래그 레이아웃 효과
    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropArea.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropArea.classList.remove('dragover');
        }, false);
    });

    dropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.remove('dragover');

        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files; // input 요소와 드롭된 파일 동기화
            handleFileSelection(files[0], textDisplay, dropArea, fileKey);
        }
    });
}

function handleFileSelection(file, textDisplay, dropArea, fileKey) {
    selectedFiles[fileKey] = file;

    // 시각적 피드백 제공
    if (fileKey === 'malware') {
        textDisplay.textContent = `Target Loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        textDisplay.style.color = "var(--accent)";
    } else {
        textDisplay.textContent = file.name;
        textDisplay.style.color = "var(--text-main)";
        dropArea.style.borderColor = "var(--success)";
    }

    updateScanButtonState();
}

/**
 * [유틸] 업로드 상태에 맞춰 하단 스캔 버튼 활성화 제어
 */
function updateScanButtonState() {
    const scanBtn = document.getElementById('scanBtn');
    if (!scanBtn) return;

    if (currentMode === 'integrity') {
        if (selectedFiles.orig && selectedFiles.target) {
            scanBtn.removeAttribute('disabled');
        } else {
            scanBtn.setAttribute('disabled', 'true');
        }
    } else {
        if (selectedFiles.malware) {
            scanBtn.removeAttribute('disabled');
        } else {
            scanBtn.setAttribute('disabled', 'true');
        }
    }
}

/**
 * [백엔드 API 통신] 백엔드 순정 주소(라우터)와 일대일 전송 체계 완전 롤백
 */
function initScanButton() {
    const scanBtn = document.getElementById('scanBtn');
    if (!scanBtn) return;

    scanBtn.addEventListener('click', async () => {
        // UI 상태를 대기 상태로 전환
        document.getElementById('introState').classList.add('hidden');
        document.getElementById('resultState').classList.add('hidden');
        document.getElementById('loadingState').classList.remove('hidden');

        const loadingText = document.getElementById('loadingText');
        loadingText.textContent = currentMode === 'integrity'
            ? "Executing Security Matrix Cryptographic Integrity Check..."
            : "Parsing PE Header Structures & Querying AI Neural Models...";

        const formData = new FormData();
        let apiEndpoint = "";

        // 💡 백엔드(server.py)가 원본 설계 상태에서 요구하는 파라미터 이름과 라우터 주소로 철저히 교체
        if (currentMode === 'integrity') {
            formData.append('file_orig', selectedFiles.orig);
            formData.append('file_target', selectedFiles.target);
            apiEndpoint = `${API_BASE}/verify-integrity`;
        } else {
            formData.append('file', selectedFiles.malware);
            apiEndpoint = `${API_BASE}/scan`;
        }

        try {
            const response = await fetch(apiEndpoint, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error("Security Engine 통신 장애 발생");

            const result = await response.json();

            // 전송 완료 시 렌더링 파이프라인 호출
            renderAnalysisResults(result);

        } catch (error) {
            console.error(error);
            alert("보안 인프라 구조 분석 중 에러가 발생했습니다. 백엔드(FastAPI) 서버 상태를 확인하세요.");
            switchMode(currentMode); // 인트로 상태 복구
        }
    });
}

/**
 * [출력 제어] 백엔드가 보내주는 오리지널 JSON 방 구조를 완전 매칭하여 출력 복구
 */
function renderAnalysisResults(data) {
    // 1) 로딩 창 숨기기 및 결과 패널 활성화
    document.getElementById('loadingState').classList.add('hidden');
    document.getElementById('resultState').classList.remove('hidden');

    const malHeader = document.getElementById('malwareHeaderBlock');
    const integrityHeader = document.getElementById('integrityHeaderBlock');
    const integrityCard = document.getElementById('integrityDetailCard');

    // 2) 모드 플래그별 헤더 블록 가시성 설정
    if (currentMode === 'integrity') {
        malHeader.classList.add('hidden');
        integrityHeader.classList.remove('hidden');
        integrityCard.style.display = "block"; // 무결성 해시 매트릭스 노출

        // 💡 [무결성 해시 매핑 복구] 무결성 검증 탭 리턴 데이터(orig_hash, target_hash) 정상 바인딩
        const hash1 = data.orig_hash || "-";
        const hash2 = data.target_hash || "-";

        document.getElementById('integrityHash1').textContent = hash1.toUpperCase();
        document.getElementById('integrityHash2').textContent = hash2.toUpperCase();
        document.getElementById('hashContainer2').classList.remove('hidden');
        document.getElementById('hashLabel1').textContent = "Original Baseline Signature";

        const badge = document.getElementById('comparisonBadge');
        const desc = document.getElementById('comparisonDesc');

        if (data.is_equal === true) {
            badge.textContent = "Verified Match";
            badge.className = "status-badge match";
            desc.textContent = "Cryptographic analysis proves the target evaluation payroll exactly pairs with the certified baseline binary. Structure is uncorrupted.";
        } else {
            badge.textContent = "Signature Mismatch";
            badge.className = "status-badge mismatch";
            desc.textContent = "CRITICAL WARNING: Base binary cryptographic arrays do not pair with the destination artifact. Mutation or injected indicators detected.";
        }

    } else {
        // AI 스캔 모드 리포트 가공
        malHeader.classList.remove('hidden');
        integrityHeader.classList.add('hidden');
        integrityCard.style.display = "none";

        // AI 스캔 해시 매핑
        const singleHash = data.integrity_check?.file_hash || "-";
        document.getElementById('hashLabel1').textContent = "Target Payload File SHA256 Signature";
        document.getElementById('integrityHash1').textContent = singleHash.toUpperCase();
        document.getElementById('hashContainer2').classList.add('hidden');

        // AI 스코어 세팅 및 Gemini 이유 출력 연동
        const aiScore = data.ai_scan?.score || 0;
        const aiReason = data.ai_scan?.reason || "No deep learning anomalies reported.";
        document.getElementById('resultReason').textContent = aiReason;

        // 상단 배지 핸들링
        const aiBadge = document.getElementById('aiBadge');
        if(aiScore >= 70) {
            aiBadge.textContent = "Critical Malicious Threat";
            aiBadge.className = "status-badge mismatch";
        } else if(aiScore >= 35) {
            aiBadge.textContent = "Suspicious Risk Status";
            aiBadge.className = "status-badge mismatch";
            aiBadge.style.background = "rgba(255,210,63,0.12)";
            aiBadge.style.color = "var(--warning)";
            aiBadge.style.borderColor = "rgba(255,210,63,0.25)";
        } else {
            aiBadge.textContent = "Secured Clean Element";
            aiBadge.className = "status-badge match";
        }

        // 원형 게이지 애니메이션 채우기 인터랙션 적용
        animateProgressCircle(aiScore);

        // 💡 백엔드(/scan)는 vt_result를 ai_scan 하위에 담아 반환하므로 해당 경로에서 읽어야 함 (data.virustotal_check는 존재하지 않아 항상 0/0으로 표시되던 버그 수정)
        const vt = data.ai_scan?.vt_result || {};
        const vtScoreEl = document.getElementById('vtScore');
        const vtLabelEl = document.getElementById('vtLabel');

        if (vt.positives !== undefined) {
            vtScoreEl.textContent = `${vt.positives}/${vt.total || 67}`;
            vtScoreEl.style.color = vt.positives > 0 ? 'var(--danger)' : 'var(--success)';
            vtLabelEl.textContent = `Global Engine Intelligence Verdict: ${vt.label || 'Clean Asset'}`;
        } else {
            vtScoreEl.textContent = "0/0";
            vtScoreEl.style.color = "var(--text-muted)";
            vtLabelEl.textContent = "No threats found in global intelligence stores.";
        }

        // 5) 침해지표 네트워크 IP / URL 데이터 리스트업 동적 바인딩
        const iocList = document.getElementById('iocList');
        iocList.innerHTML = '';
        const iocData = data.ai_scan?.ioc || {};
        const ips = iocData.ips || [], urls = iocData.urls || [];

        if (ips.length === 0 && urls.length === 0) {
            iocList.innerHTML = '<li style="color: var(--text-muted); font-size: 0.85rem;">No target external connections verified.</li>';
        } else {
            ips.forEach(ip => {
                iocList.innerHTML += `<li style="font-size:0.85rem; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center; width:100%;"><span style="font-family:'JetBrains Mono', monospace;">${ip}</span> <span class="badge" style="background:rgba(255,210,63,0.12); color:var(--warning); font-size:0.65rem; padding:2px 6px; border-radius:4px; font-weight:700;">IP</span></li>`;
            });
            urls.forEach(url => {
                iocList.innerHTML += `<li style="font-size:0.85rem; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center; width:100%;"><span style="font-family:'JetBrains Mono', monospace; word-break:break-all; max-width:85%;">${url}</span> <span class="badge" style="background:rgba(168,85,247,0.12); color:var(--accent); font-size:0.65rem; padding:2px 6px; border-radius:4px; font-weight:700;">URL</span></li>`;
            });
        }
    }
}

/**
 * [원형 프로그레스 매트릭스] conic-gradient 애니메이션 제어 틱 메커니즘
 */
function animateProgressCircle(targetScore) {
    const circle = document.getElementById('aiProgressCircle');
    const text = document.getElementById('aiProgressText');
    if (!circle || !text) return;

    let currentPercent = 0;
    if (window.circleInterval) clearInterval(window.circleInterval);

    let progressColor = '#4ade80';
    if (targetScore >= 70) progressColor = '#ff5c5c';
    else if (targetScore >= 35) progressColor = '#ffd23f';

    if (targetScore === 0) {
        circle.style.background = `conic-gradient(rgba(255, 255, 255, 0.05) 0deg, rgba(255, 255, 255, 0.05) 360deg)`;
        text.textContent = `0%`;
        text.style.color = 'var(--text-muted)';
        return;
    }

    window.circleInterval = setInterval(() => {
        currentPercent++;
        const degrees = (currentPercent / 100) * 360;

        circle.style.background = `conic-gradient(${progressColor} ${degrees}deg, rgba(255, 255, 255, 0.04) ${degrees}deg)`;
        text.textContent = `${currentPercent}%`;
        text.style.color = progressColor;

        if (currentPercent >= targetScore) {
            clearInterval(window.circleInterval);
        }
    }, 8);
}
