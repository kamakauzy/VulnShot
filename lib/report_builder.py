"""Report builder for visual vulnerability evidence"""

import logging
from pathlib import Path
from typing import Dict, List
from datetime import datetime
from jinja2 import Template


class VulnReportBuilder:
    """Generate HTML reports with visual vulnerability evidence"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
    
    def generate(self, scan_data: Dict, screenshots: List[Dict]) -> Path:
        """Generate comprehensive HTML report"""
        
        # Organize data
        report_data = {
            'title': 'VulnShot - Visual Vulnerability Evidence Report',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': scan_data.get('url'),
            'wordpress_version': scan_data.get('wordpress_version'),
            'wordpress_vulns': scan_data.get('wordpress_vulns', []),
            'themes': scan_data.get('themes', []),
            'interesting_findings': scan_data.get('interesting_findings', []),
            'screenshots': self._organize_screenshots(screenshots),
            'stats': self._calculate_stats(scan_data, screenshots)
        }
        
        # Render HTML
        html = self._render_html(report_data)
        
        # Save report
        report_path = self.output_dir / 'vulnshot_report.html'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"Report generated: {report_path}")
        return report_path
    
    def _organize_screenshots(self, screenshots: List[Dict]) -> Dict:
        """Organize screenshots by type"""
        organized = {
            'version': [],
            'themes': [],
            'findings': []
        }
        
        for screenshot in screenshots:
            if screenshot.get('status') != 'success':
                continue
            
            if screenshot['type'] == 'wordpress_version':
                organized['version'].append(screenshot)
            elif screenshot['type'] == 'theme_version':
                organized['themes'].append(screenshot)
            elif screenshot['type'] == 'interesting_finding':
                organized['findings'].append(screenshot)
        
        return organized
    
    def _calculate_stats(self, scan_data: Dict, screenshots: List[Dict]) -> Dict:
        """Calculate statistics"""
        total_vulns = len(scan_data.get('wordpress_vulns', []))
        
        for theme in scan_data.get('themes', []):
            total_vulns += len(theme.get('vulnerabilities', []))
        
        successful_screenshots = len([s for s in screenshots if s.get('status') == 'success'])
        
        # Calculate severity breakdown
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for vuln in scan_data.get('wordpress_vulns', []):
            cvss = vuln.get('cvss')
            if cvss:
                try:
                    score = float(cvss)
                    if score >= 7.0:
                        high_risk += 1
                    elif score >= 4.0:
                        medium_risk += 1
                    else:
                        low_risk += 1
                except:
                    pass
        
        return {
            'total_vulnerabilities': total_vulns,
            'visual_evidence_captured': successful_screenshots,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk
        }
    
    def _render_html(self, data: Dict) -> str:
        """Render HTML report using PenDoc-inspired styling"""
        
        template_str = '''<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --bg-primary: #1e1e1e;
            --bg-secondary: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #b0b0b0;
            --border-color: #404040;
            --accent-color: #4da3ff;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #28a745;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: var(--bg-secondary);
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        h1 {
            color: var(--danger-color);
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.2em;
        }
        
        .target-url {
            color: var(--accent-color);
            font-size: 1.3em;
            margin: 15px 0;
        }
        
        .timestamp {
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        
        .severity-high { color: var(--danger-color); }
        .severity-medium { color: var(--warning-color); }
        .severity-low { color: var(--success-color); }
        
        .section {
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: var(--accent-color);
            margin-bottom: 20px;
            font-size: 2em;
        }
        
        .vuln-card {
            background: rgba(220, 53, 69, 0.1);
            border-left: 4px solid var(--danger-color);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .vuln-title {
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .vuln-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .badge-danger { background: var(--danger-color); color: white; }
        .badge-warning { background: var(--warning-color); color: black; }
        .badge-info { background: var(--accent-color); color: white; }
        
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(600px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .evidence-card {
            background: var(--bg-primary);
            border: 2px solid var(--danger-color);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .evidence-card img {
            width: 100%;
            height: auto;
            display: block;
        }
        
        .evidence-info {
            padding: 20px;
        }
        
        .evidence-type {
            color: var(--danger-color);
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .evidence-details {
            font-size: 0.95em;
            color: var(--text-secondary);
            line-height: 1.8;
        }
        
        .finding-card {
            background: rgba(255, 193, 7, 0.1);
            border-left: 4px solid var(--warning-color);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .theme-card {
            background: rgba(220, 53, 69, 0.15);
            border: 2px solid var(--danger-color);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        
        .theme-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .theme-name {
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .theme-version {
            background: var(--danger-color);
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .vuln-list {
            margin-top: 15px;
            padding-left: 0;
            list-style: none;
        }
        
        .vuln-list li {
            padding: 10px;
            margin-bottom: 8px;
            background: rgba(0,0,0,0.3);
            border-radius: 4px;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.95);
        }
        
        .modal-content {
            margin: 2% auto;
            display: block;
            max-width: 95%;
            max-height: 95%;
        }
        
        .close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔴 VulnShot</h1>
            <div class="subtitle">Visual Vulnerability Evidence Report</div>
            <div class="target-url">Target: {{ target_url }}</div>
            <div class="timestamp">Generated: {{ timestamp }}</div>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value severity-high">{{ stats.total_vulnerabilities }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Visual Evidence Captured</div>
                <div class="stat-value" style="color: var(--accent-color);">{{ stats.visual_evidence_captured }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Risk</div>
                <div class="stat-value severity-high">{{ stats.high_risk }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium Risk</div>
                <div class="stat-value severity-medium">{{ stats.medium_risk }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low Risk</div>
                <div class="stat-value severity-low">{{ stats.low_risk }}</div>
            </div>
        </div>
        
        {% if wordpress_version %}
        <div class="section">
            <h2>🔴 WordPress Core</h2>
            
            <div class="vuln-card">
                <div class="vuln-title">WordPress Version {{ wordpress_version.version }} Detected</div>
                <div class="vuln-meta">
                    <span class="badge badge-danger">VERSION DISCLOSURE</span>
                    <span>Found by: {{ wordpress_version.found_by }}</span>
                </div>
                
                {% if wordpress_vulns %}
                <div style="margin-top: 15px;">
                    <strong>{{ wordpress_vulns|length }} Known Vulnerabilities:</strong>
                    <ul class="vuln-list">
                    {% for vuln in wordpress_vulns %}
                        <li>
                            <strong>{{ vuln.title }}</strong><br>
                            {% if vuln.cvss %}<span class="badge badge-danger">CVSS {{ vuln.cvss }}</span>{% endif %}
                            {% if vuln.fixed_in %}<span class="badge badge-info">Fixed in {{ vuln.fixed_in }}</span>{% endif %}
                        </li>
                    {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            
            {% if screenshots.version %}
            <h3 style="margin-top: 30px; color: var(--danger-color);">📸 Visual Evidence</h3>
            <div class="evidence-grid">
            {% for evidence in screenshots.version %}
                <div class="evidence-card">
                    <img src="{{ evidence.screenshot }}" alt="WordPress Version Evidence" onclick="openModal(this.src)">
                    <div class="evidence-info">
                        <div class="evidence-type">🔴 Version Disclosure</div>
                        <div class="evidence-details">
                            <strong>Location:</strong> {{ evidence.element }}<br>
                            <strong>URL:</strong> {{ evidence.url }}<br>
                            <strong>Version:</strong> {{ evidence.version }}
                        </div>
                    </div>
                </div>
            {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if themes %}
        <div class="section">
            <h2>🎨 Vulnerable Themes</h2>
            
            {% for theme in themes %}
            <div class="theme-card">
                <div class="theme-header">
                    <div class="theme-name">{{ theme.name }}</div>
                    <div class="theme-version">Version {{ theme.version }}</div>
                </div>
                
                {% if theme.vulnerabilities %}
                <div>
                    <strong style="color: var(--danger-color);">⚠️ {{ theme.vulnerabilities|length }} Vulnerabilities Found:</strong>
                    <ul class="vuln-list">
                    {% for vuln in theme.vulnerabilities %}
                        <li>
                            <strong>{{ vuln.title }}</strong><br>
                            {% if vuln.cvss %}<span class="badge badge-danger">CVSS {{ vuln.cvss }}</span>{% endif %}
                            {% if vuln.fixed_in %}<span class="badge badge-info">Fixed in {{ vuln.fixed_in }}</span>{% endif %}
                        </li>
                    {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            
            {% if screenshots.themes %}
            <h3 style="margin-top: 30px; color: var(--danger-color);">📸 Visual Evidence</h3>
            <div class="evidence-grid">
            {% for evidence in screenshots.themes %}
                <div class="evidence-card">
                    <img src="{{ evidence.screenshot }}" alt="Theme Version Evidence" onclick="openModal(this.src)">
                    <div class="evidence-info">
                        <div class="evidence-type">🔴 Theme Version Disclosure</div>
                        <div class="evidence-details">
                            <strong>Theme:</strong> {{ evidence.theme_name }}<br>
                            <strong>Version:</strong> {{ evidence.version }}<br>
                            <strong>Vulnerabilities:</strong> {{ evidence.vulnerabilities|length }}
                        </div>
                    </div>
                </div>
            {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if interesting_findings %}
        <div class="section">
            <h2>ℹ️ Interesting Findings</h2>
            
            {% for finding in interesting_findings %}
            <div class="finding-card">
                <div class="vuln-title">{{ finding.type }}</div>
                <div class="vuln-meta">
                    <span class="badge badge-warning">INFO</span>
                    <span>{{ finding.url }}</span>
                </div>
                <div style="margin-top: 10px;">{{ finding.description }}</div>
            </div>
            {% endfor %}
            
            {% if screenshots.findings %}
            <h3 style="margin-top: 30px; color: var(--warning-color);">📸 Visual Evidence</h3>
            <div class="evidence-grid">
            {% for evidence in screenshots.findings %}
                <div class="evidence-card" style="border-color: var(--warning-color);">
                    <img src="{{ evidence.screenshot }}" alt="Finding Evidence" onclick="openModal(this.src)">
                    <div class="evidence-info">
                        <div class="evidence-type" style="color: var(--warning-color);">ℹ️ {{ evidence.finding_type }}</div>
                        <div class="evidence-details">
                            <strong>URL:</strong> {{ evidence.url }}<br>
                            {{ evidence.description }}
                        </div>
                    </div>
                </div>
            {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endif %}
        
    </div>
    
    <!-- Modal -->
    <div id="imageModal" class="modal" onclick="closeModal()">
        <span class="close">&times;</span>
        <img class="modal-content" id="modalImage">
    </div>
    
    <script>
        function openModal(src) {
            document.getElementById('imageModal').style.display = 'block';
            document.getElementById('modalImage').src = src;
        }
        
        function closeModal() {
            document.getElementById('imageModal').style.display = 'none';
        }
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });
    </script>
</body>
</html>'''
        
        template = Template(template_str)
        return template.render(**data)

