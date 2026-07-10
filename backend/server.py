from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import pefile
import requests
import json
import re
import os
import hashlib
import ipaddress

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

def load_malware_hashes(): #
    hash_file_path = os.path.join(os.path.dirname(__file__), "hashes.txt")
    if not os.path.exists(hash_file_path): return set()
    malware_set = set()
    try:
        with open(hash_file_path, "r", encoding="utf-8") as f:
            for line in f:
                clean_line = line.strip().lower()
                if not clean_line or clean_line.startswith("#"): continue
                malware_set.add(clean_line)
    except Exception: pass
    return malware_set

MALWARE_HASHES = load_malware_hashes() #

def extract_ioc_strings(file_bytes): #
    strings = re.findall(rb"[A-Za-z0-9/\-:.,_$%%@#~!?*()]{4,}", file_bytes)
    decoded_strings = []
    for s in strings:
        try:
            decoded_strings.append(s.decode('utf-8'))
        except:
            continue
            
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.-]*)*'
    
    found_ips = set()
    found_urls = set()
    
    joined_text = " ".join(decoded_strings)
    ips = re.findall(ip_pattern, joined_text)
    urls = re.findall(url_pattern, joined_text)
    
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            continue
        # PE 파일에 흔한 버전 정보(예: 6.0.0.0, 10.0.0.0)가 IP로 오인되는 것을 제외
        octets = ip.split(".")
        if octets[2] == "0" and octets[3] == "0":
            continue
        found_ips.add(ip)
            
    for url in urls:
        if "schemas.microsoft.com" not in url:
            found_urls.add(url)
            
    return {
        "ips": list(found_ips)[:5],
        "urls": list(found_urls)[:5]
    }

def query_virustotal(file_hash): #
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY" or not VT_API_KEY:
        return {"status": "not_configured"}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
            
            total = sum(stats.values()) if stats else 67
            if total == 0: total = 67
            
            meaningful_name = data['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'Clean')
            
            return {
                "status": "found",
                "positives": positives,
                "total": total,
                "label": meaningful_name
            }
        elif response.status_code == 404:
            return {"status": "not_found", "positives": 0, "total": 0, "label": "Clean"}
        else:
            return {"status": "error", "code": response.status_code}
    except:
        return {"status": "error", "msg": "Connection failed"}

def extract_pe_info_for_ai(file_bytes): #
    try:
        pe = pefile.PE(data=file_bytes)
        sections = [{"name": s.Name.decode('utf-8', 'ignore').strip('\x00'), "v_size": s.Misc_VirtualSize, "r_size": s.SizeOfRawData} for s in pe.sections]
        imports = [entry.dll.decode('utf-8', 'ignore') for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) if entry.dll]
        return {
            "is_exe": True,
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "sections": sections,
            "imported_dlls": imports[:15],
        }
    except pefile.PEFormatError:
        return {"is_exe": False}


# 🛠️ [상위 기능 1]: 2개의 파일을 사용자가 올렸을 때 서로 해시를 직접 비교 대조하는 전용 라우터
@app.post("/verify-integrity")
async def verify_integrity(file_orig: UploadFile = File(...), file_target: UploadFile = File(...)):
    try:
        orig_bytes = await file_orig.read()
        target_bytes = await file_target.read()
        
        orig_hash = hashlib.sha256(orig_bytes).hexdigest().lower()
        target_hash = hashlib.sha256(target_bytes).hexdigest().lower()
        
        return {
            "orig_hash": orig_hash,
            "target_hash": target_hash,
            "is_equal": orig_hash == target_hash
        }
    except Exception as e:
        return {"error": str(e)}


# 🌳 [상위 기능 2]: 1개 파일을 검사하며 하위 기능(로컬 DB, VT, AI)을 처리하는 기존 라우터 구조 보존
@app.post("/scan")
async def scan_malware(file: UploadFile = File(...)): #
    try:
        file_bytes = await file.read() #
        file_hash = hashlib.sha256(file_bytes).hexdigest().lower()
        
        is_matched_local = file_hash in MALWARE_HASHES #
        ioc_data = extract_ioc_strings(file_bytes) #
        pe_info = extract_pe_info_for_ai(file_bytes) #
        
        # [AI 스캔 하위] 로컬 데이터베이스 매핑 체크 처리
        if is_matched_local:
            return {
                "integrity_check": {"file_hash": file_hash},
                "ai_scan": {
                    "score": 100,
                    "reason": "[로컬 매핑 확인] 이 파일의 해시가 로컬 악성코드 블랙리스트(hashes.txt) DB와 정확히 일치합니다.",
                    "local_db_match": True,
                    "vt_result": {"status": "found", "positives": 70, "total": 70, "label": "Blacklisted"},
                    "ioc": ioc_data
                }
            }
        
        if not pe_info.get("is_exe"): #
            return {
                "integrity_check": {"file_hash": file_hash},
                "ai_scan": {
                    "score": 0,
                    "reason": "윈도우 실행 파일(PE) 구조가 아니므로 AI 악성코드 정밀 분석 대상에서 예외 처리되었습니다.",
                    "local_db_match": False,
                    "vt_result": {"status": "not_exe"},
                    "ioc": ioc_data
                }
            }

        # [AI 스캔 하위] VirusTotal API 조회 처리
        vt_result = query_virustotal(file_hash) #

        # [AI 스캔 하위] 제미나이 생성형 판정용 데이터 매핑
        ai_analysis_input = {
            "pe_metadata": pe_info,
            "extracted_network_ioc": ioc_data,
            "virustotal_summary": vt_result
        }

        prompt = f"""
        너는 숙련된 악성코드 분석가야. 아래 데이터를 바탕으로 위험 점수와 분석 이유를 도출해라.
        네트워크 IOC(IP, URL)에 의심스러운 외부 주소가 있거나, VirusTotal 탐지 건수가 있다면 적극 반영해라.
        
        데이터:
        {json.dumps(ai_analysis_input, indent=2)}
        
        [가이드라인]
        - 확실한 악성코드(VT 탐지 다수 혹은 명확한 악성 IOC)는 80~100점 점수를 줘라.
        - 마크다운 기호 쓰지마세요
        - VirtualBox나 대형 유틸리티처럼 안전한 외부 IP/URL과 일반적인 PE 구조를 가졌다면 오탐하지 말고 0~30점의 안전 점수를 줘라.

        반드시 아래 형식으로만 답변해 (마크다운 기호 섞지 말 것):
        점수: [숫자]
        이유: [분석한 구체적 근거를 바탕으로 설명]
        
        """

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}" #
        response = requests.post(url, headers={'Content-Type': 'application/json'}, json={"contents": [{"parts": [{"text": prompt}]}]}) #
        response_data = response.json() #
        
        if "error" in response_data: #
            raise ValueError(f"Gemini API 에러: {response_data['error']['message']}")
            
        if 'candidates' not in response_data or not response_data['candidates']: #
            raise ValueError("Gemini API가 유효한 분석 결과를 반환하지 않았습니다.")

        ai_text = response_data['candidates'][0]['content']['parts'][0]['text'] #

        score_match = re.search(r'점수:\s*\*?(\d+)\*?', ai_text) #
        score = int(score_match.group(1)) if score_match else 0 #
        
        reason = ai_text.replace(f"점수: {score}", "").replace("점수:", "").replace("이유:", "").strip() #
        reason = re.sub(r'^\s*[\-\*]\s*', '', reason) #

        return {
            "integrity_check": {"file_hash": file_hash},
            "ai_scan": {
                "score": score,
                "reason": reason,
                "local_db_match": False,
                "vt_result": vt_result,
                "ioc": ioc_data
            }
        }

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))