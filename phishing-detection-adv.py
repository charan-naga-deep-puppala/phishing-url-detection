

import re
import hashlib
import requests
import json
from datetime import datetime
import threading
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
with open('config.json') as f:
    config = json.load(f)

API_KEYS = config['api_keys']
THREAT_FEEDS = config['threat_feeds']
SIGNATURE_DB = config['signature_databases']

class ThreatIntelligence:
    
    def __init__(self):
        self.malicious_urls = set()
        self.malware_hashes = set()
        self.suspicious_ips = set()
        self.update_feeds()
        
    def update_feeds(self):
        for feed in THREAT_FEEDS['url_feeds']:
            response = requests.get(feed)
            self.malicious_urls.update(response.text.splitlines())
            
        for feed in THREAT_FEEDS['hash_feeds']:
            response = requests.get(feed)
            self.malware_hashes.update(response.text.splitlines())
            
        threading.Timer(21600, self.update_feeds).start()

class PhishingDetector:
    
    def __init__(self, ti):
        self.ti = ti
        self.patterns = [
            r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'@([^\s/:]+)',
            r'https?://([a-zA-Z0-9]+\.){2,}[a-zA-Z0-9]+/',
            r'(webscr|login|account|secure)\.\w+\.'
        ]
        
    def analyze_url(self, url):
        """Multi-layered URL analysis"""
        report = {
            'url': url,
            'threat_score': 0,
            'indicators': [],
            'verdict': 'clean'
        }
     
        if url in self.ti.malicious_urls:
            report['threat_score'] = 100
            report['verdict'] = 'malicious'
            return report
            

        for pattern in self.patterns:
            if re.search(pattern, url, re.IGNORECASE):
                report['threat_score'] += 20
                report['indicators'].append(f"Matched pattern: {pattern}")

        domain = self.extract_domain(url)
        if domain and self.check_domain_age(domain) < 30:
            report['threat_score'] += 30
            report['indicators'].append("New domain (<30 days)")

        vt_result = self.virustotal_check(url)
        if vt_result['positives'] > 2:
            report['threat_score'] += vt_result['positives'] * 5
            report['indicators'].append(f"VT detections: {vt_result['positives']}")
            
       
        if report['threat_score'] >= 65:
            report['verdict'] = 'phishing'
        elif report['threat_score'] >= 40:
            report['verdict'] = 'suspicious'
            
        return report
    
    def virustotal_check(self, url):
        """Query VirusTotal API"""
        headers = {'x-apikey': API_KEYS['virustotal']}
        params = {'url': url}
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data=params
        )
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        return {'positives': 0}

class MalwareAnalyzer:
    
    def __init__(self, ti):
        self.ti = ti
        self.malicious_signatures = self.load_signatures()
        
    def analyze_file(self, file_path):
        report = {
            'file': file_path,
            'hashes': {},
            'signatures': [],
            'verdict': 'clean'
        }
        
        
        report['hashes'] = self.calculate_hashes(file_path)
        
        
        if report['hashes']['sha256'] in self.ti.malware_hashes:
            report['verdict'] = 'malicious'
            return report
            
       
        with open(file_path, 'rb') as f:
            content = f.read()
            for sig in self.malicious_signatures:
                if sig.encode() in content:
                    report['signatures'].append(sig)
                    report['verdict'] = 'malicious'
                    
        
        if self.check_pe_header(file_path):
            report['indicators'].append('Malformed PE header')
            report['threat_score'] += 30
            
        return report
        
    def calculate_hashes(self, file_path):
        
        hashes = {}
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        return hashes

class LogMonitor(FileSystemEventHandler):
    
    
    def __init__(self, ti):
        self.ti = ti
        self.suspicious_patterns = [
            r'Failed password',
            r'Invalid user',
            r'POSSIBLE BREACH ATTEMPT',
            r'SQL injection attempt'
        ]
        self.log_queue = queue.Queue()
        
    def on_modified(self, event):
        if not event.is_directory:
            self.process_log(event.src_path)
            
    def analyze_entry(self, entry):
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, entry, re.IGNORECASE):
                return {
                    'entry': entry,
                    'pattern': pattern,
                    'severity': 'high'
                }
        return None

if __name__ == "__main__":
    
    ti = ThreatIntelligence()
    phishing_detector = PhishingDetector(ti)
    malware_analyzer = MalwareAnalyzer(ti)
    
    
    url_report = phishing_detector.analyze_url('http://login')
    print("Phishing Analysis Report:")
    print(json.dumps(url_report, indent=2))
    
    file_report = malware_analyzer.analyze_file('')
    print("\nMalware Analysis Report:")
    print(json.dumps(file_report, indent=2))
