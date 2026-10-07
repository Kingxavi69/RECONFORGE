"""HTML report generation via Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ReconForge Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; color: #222; }
    section { margin-bottom: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }
    th { background: #f0f0f0; }
  </style>
</head>
<body>
  <h1>ReconForge Executive Summary</h1>
  <p><strong>Target:</strong> {{ target }}</p>
  <p><strong>Timestamp:</strong> {{ timestamp }}</p>
  <p><strong>Risk Level:</strong> {{ risk_level }}</p>
  <p><strong>Risk Score:</strong> {{ risk_score }}</p>

  <section>
    <h2>DNS</h2>
    <pre>{{ dns }}</pre>
  </section>

  <section>
    <h2>Ports</h2>
    <table>
      <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
      {% for port in ports %}
      <tr><td>{{ port.port }}</td><td>{{ port.state }}</td><td>{{ port.service }}</td><td>{{ port.version }}</td></tr>
      {% endfor %}
    </table>
  </section>

  <section>
    <h2>Technologies</h2>
    <ul>
      {% for tech in technologies %}
      <li>{{ tech }}</li>
      {% endfor %}
    </ul>
  </section>

  <section>
    <h2>Recommendations</h2>
    <ul>
      <li>Confirm the target is authorized before running active checks.</li>
      <li>Review TLS and web security headers.</li>
      <li>Document and compare future scan results.</li>
    </ul>
  </section>
</body>
</html>
"""


def render_html_report(payload: dict) -> str:
    """Render an HTML report using Jinja2."""
    template = Template(HTML_TEMPLATE)
    return template.render(**payload)


def save_html_report(payload: dict, path: str) -> str:
    output = render_html_report(payload)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output, encoding="utf-8")
    return str(destination)
