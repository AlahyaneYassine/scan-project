from __future__ import annotations

from html import escape
from io import BytesIO
import json
import re

from .nmap_service import calculate_risk_score, parse_nmap_output

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def _normalize_row(item: dict[str, object]) -> tuple[str, str, str, str, str]:
    port = str(item.get("port") or "-")
    protocol = str(item.get("protocol") or "-").upper()
    state = str(item.get("state") or "unknown").lower()
    service = str(item.get("service") or "unknown")
    risk = str(item.get("risk") or "LOW").upper()
    return (port, protocol, state, service, risk)


def _structured_rows(findings: list[dict[str, object]]) -> list[tuple[str, str, str, str, str]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    rows: list[tuple[str, str, str, str, str]] = []

    for item in findings:
        if item.get("port") is None:
            continue
        row = _normalize_row(item)
        if row in seen:
            continue
        seen.add(row)
        rows.append(row)

    rows.sort(key=lambda value: (value[0] == "-", int(value[0]) if value[0].isdigit() else 99999, value[1]))
    return rows


def _build_table_data(rows: list[tuple[str, str, str, str, str]]) -> list[list[str]]:
    header = ["Port", "Protocole", "Etat", "Service", "Risque"]
    if not rows:
        return [header, ["-", "-", "-", "Aucune donnee", "LOW"]]
    return [header, *[list(row) for row in rows]]


def _styled_table(data: list[list[str]], width_mm: float) -> Table:
    col_widths = [22 * mm, 28 * mm, 26 * mm, width_mm * mm - 115 * mm, 24 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("ALIGN", (0, 0), (2, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _build_fallback_pdf(scan_result, rows: list[tuple[str, str, str, str, str]]) -> bytes:
    # Minimal fallback if reportlab is unavailable: valid but plain PDF text.
    lines = [
        "Rapport Nmap",
        f"IP: {scan_result.ip}",
        f"Date: {scan_result.date.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Port | Protocole | Etat | Service | Risque",
    ]
    lines.extend(" | ".join(row) for row in rows or [("-", "-", "-", "Aucune donnee", "LOW")])
    escaped_lines = [
        line.encode("latin-1", errors="ignore").replace(b"(", b"\\(").replace(b")", b"\\)")
        for line in lines
    ]

    stream_parts = [b"BT", b"/F1 10 Tf", b"14 TL", b"40 780 Td"]
    for index, raw_line in enumerate(escaped_lines):
        if index == 0:
            stream_parts.append(b"(" + raw_line + b") Tj")
        else:
            stream_parts.append(b"T* (" + raw_line + b") Tj")
    stream_parts.append(b"ET")
    stream = b"\n".join(stream_parts)

    objects = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n")
    objects.append(f"4 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream\nendobj\n")
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    out = BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for obj in objects:
        offsets.append(out.tell())
        out.write(obj)
    xref = out.tell()
    out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets:
        out.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    out.write(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("latin-1"))
    return out.getvalue()


def build_scan_report_pdf(scan_result) -> bytes:
    try:
        from weasyprint import HTML
        # If the stored result is modular JSON, render the modular HTML instead
        try:
            parsed = json.loads(scan_result.result or "{}")
        except Exception:
            parsed = {}

        if isinstance(parsed, dict) and parsed.get("modules"):
            html_content = build_modular_network_report_html(scan_result)
        else:
            html_content = build_scan_audit_report_html(
                str(scan_result.ip),
                scan_result.result or "",
                scan_result.date.strftime("%Y-%m-%d %H:%M:%S"),
            )

        return HTML(string=html_content).write_pdf()
    except Exception:
        # Fall back to existing PDF pipeline when WeasyPrint is unavailable.
        pass

    findings = parse_nmap_output(scan_result.result or "")
    rows = _structured_rows(findings)

    if not REPORTLAB_AVAILABLE:
        return _build_fallback_pdf(scan_result, rows)

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=14 * mm,
        title=f"Rapport de scan {scan_result.ip}",
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    meta_style = ParagraphStyle(
        "MetaStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
    )

    vulnerable_rows = [row for row in rows if row[4] == "HIGH"]
    open_rows = [row for row in rows if row[2] == "open"]

    story = []
    story.append(Paragraph("Rapport Professionnel de Scan Nmap", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Adresse IP :</b> {scan_result.ip}", meta_style))
    story.append(Paragraph(f"<b>Date :</b> {scan_result.date.strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
    story.append(Paragraph(f"<b>Ports ouverts :</b> {len(open_rows)}", meta_style))
    story.append(Paragraph(f"<b>Vulnerabilites :</b> {len(vulnerable_rows)}", meta_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Ports, Services et Risques", heading_style))
    story.append(Spacer(1, 6))
    story.append(_styled_table(_build_table_data(rows), width_mm=178))
    story.append(Spacer(1, 14))

    story.append(Paragraph("2. Vulnerabilites Detectees", heading_style))
    story.append(Spacer(1, 6))
    story.append(_styled_table(_build_table_data(vulnerable_rows), width_mm=178))

    document.build(story)
    return buffer.getvalue()


SERVICE_IMPACT_MAP: dict[str, str] = {
    "ssh": "Vecteur d'administration distante: une mauvaise configuration peut permettre une prise de controle serveur.",
    "http": "Surface web exposee: risque d'exploitation applicative et de pivot vers le reseau interne.",
    "https": "Service web securise, mais une configuration TLS faible ou une application vulnerable reste exploitable.",
    "mysql": "Base de donnees exposee: risque d'exfiltration de donnees clients et de perte de confidentialite.",
    "mssql": "Base de donnees critique: exposition directe pouvant mener a vol ou alteration de donnees metier.",
    "postgresql": "Stockage metier sensible: un acces non autorise peut compromettre l'integrite des donnees.",
    "rdp": "Acces bureau distant: cible frequente de brute force et de compromission de comptes privilegies.",
    "smb": "Partage reseau: risque de mouvement lateral et d'acces non autorise aux fichiers internes.",
    "ftp": "Transfert de fichiers: protocole souvent mal durci, potentiellement exploitable pour depots malveillants.",
}


def _risk_label_from_score(score_total: int) -> str:
    if score_total >= 8:
        return "HIGH"
    if score_total >= 4:
        return "MEDIUM"
    return "LOW"


def _service_description(service: str, state: str) -> str:
    normalized_service = service.lower()
    if state != "open":
        return f"Service detecte en etat {state}: exposition partielle, a verifier selon la politique firewall."
    return SERVICE_IMPACT_MAP.get(
        normalized_service,
        "Service expose non catalogue: verifier l'utilite metier et durcir la configuration associee.",
    )


def build_scan_audit_report(ip: str, nmap_output: str) -> str:
    findings = parse_nmap_output(nmap_output or "")
    findings_with_port = [item for item in findings if isinstance(item.get("port"), int)]
    findings_with_port.sort(key=lambda item: int(item.get("port") or 0))

    if not findings_with_port:
        return "\n".join(
            [
                "=== EXECUTIVE SUMMARY ===",
                "Overall Risk Level: LOW",
                f"The host {ip} does not expose clearly open services in the provided scan output. Attack surface appears limited.",
                "",
                "=== TECHNICAL DETAILS ===",
                "No open ports or actionable service fingerprints were detected in this scan output.",
                "",
                "=== SECURITY RISKS ===",
                "With no exposed services detected, direct remote intrusion vectors are reduced. Risk remains tied to scan scope limitations (firewall filtering, host-based controls, segmented networks).",
                "",
                "=== RECOMMENDATIONS ===",
                "1. Keep host firewall default-deny and only allow explicitly required flows.",
                "2. Repeat scan from different network vantage points to validate true exposure.",
                "3. Maintain patching cadence and IDS alerting despite low external exposure.",
                "",
                "=== CONCLUSION ===",
                "Current visible posture is controlled with a reduced attack surface; maintain hardening and periodic verification.",
            ]
        )

    score = calculate_risk_score(findings_with_port)
    score_total = int(score.get("score_total") or 0)
    risk_level = _risk_label_from_score(score_total)

    detail_lines = []
    risk_lines = []
    for item in findings_with_port:
        port = item.get("port")
        protocol = str(item.get("protocol") or "tcp").lower()
        state = str(item.get("state") or "unknown").lower()
        service = str(item.get("service") or "unknown")
        description = _service_description(service, state)
        detail_lines.append(f"- {port}/{protocol} | {service} | {state} | {description}")

        item_risk = str(item.get("risk") or "LOW").upper()
        business_impact = (
            "Service exploitable depuis le reseau, avec risque d'intrusion et de propagation."
            if state == "open"
            else "Visibilite partielle; un mauvais filtrage peut laisser une voie d'acces inattendue."
        )
        risk_lines.append(f"- {port}/{protocol} ({service}) -> {item_risk}: {business_impact}")

    open_ports = [item for item in findings_with_port if str(item.get("state") or "").lower() == "open"]
    open_ports_text = ", ".join(f"{item['port']}/{item.get('protocol') or 'tcp'}" for item in open_ports[:8])
    if not open_ports_text:
        open_ports_text = "no clearly open ports"

    recommendation_lines = [
        "1. Close or filter non-essential exposed ports and restrict administrative access by source IP.",
        "2. Update detected services to supported versions and enforce hardening baselines.",
        "3. Activate continuous monitoring (IDS + log correlation) on exposed service ports.",
    ]

    return "\n".join(
        [
            "=== EXECUTIVE SUMMARY ===",
            f"Overall Risk Level: {risk_level}",
            f"Host {ip} exposes {len(open_ports)} open service(s) ({open_ports_text}) with a calculated risk score of {score_total}. This creates concrete intrusion paths that must be reduced by hardening and service minimization.",
            "",
            "=== TECHNICAL DETAILS ===",
            "Port | Service | State | Description",
            *detail_lines,
            "",
            "=== SECURITY RISKS ===",
            *risk_lines,
            "",
            "=== RECOMMENDATIONS ===",
            *recommendation_lines,
            "",
            "=== CONCLUSION ===",
            f"The current exposure level for {ip} is {risk_level}; remediation should prioritize externally reachable services and continuous detection coverage.",
        ]
    )


def _html_risk_class(level: str) -> str:
        normalized = (level or "LOW").upper()
        if normalized == "HIGH":
                return "risk-high"
        if normalized == "MEDIUM":
                return "risk-medium"
        return "risk-low"


def _risk_text(level: str) -> str:
        normalized = (level or "LOW").upper()
        if normalized == "HIGH":
                return "HIGH"
        if normalized == "MEDIUM":
                return "MEDIUM"
        return "LOW"


def _build_vulnerability_rows(findings: list[dict[str, object]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for item in findings:
        port = item.get("port")
        if not isinstance(port, int):
            continue

        protocol = str(item.get("protocol") or "tcp").lower()
        service = str(item.get("service") or "unknown").lower()
        state = str(item.get("state") or "unknown").lower()
        description = str(item.get("description") or "")
        level = _risk_text(str(item.get("risk") or "LOW"))
        target = f"{port}/{protocol} {service}"

        if state != "open":
            risk_text = "Service visible mais non ouvert: verifier les regles de filtrage et la reduction de surface d'exposition."
            risk_level = "LOW"
        elif service in {"mysql", "mssql", "postgresql"}:
            risk_text = "Service de base de donnees expose: risque eleve d'exfiltration et de compromission de donnees sensibles."
            risk_level = "HIGH"
        elif service in {"rdp", "ssh", "ftp", "smb", "telnet"}:
            risk_text = "Surface d'administration distante exposee: vecteur d'intrusion par brute force ou identifiants compromis."
            risk_level = "HIGH" if service in {"rdp", "telnet"} else "MEDIUM"
        elif service in {"http", "https"}:
            risk_text = "Surface web accessible: risque de failles applicatives et de pivot lateral selon le niveau de hardening."
            risk_level = "MEDIUM"
        else:
            risk_text = "Service expose a profil non standard: valider le besoin metier et renforcer la configuration de securite."
            risk_level = level

        key = (target, risk_text, risk_level)
        if key not in seen:
            seen.add(key)
            rows.append({"target": target, "risk": risk_text, "level": risk_level})

        if description and any(char.isdigit() for char in description):
            version_text = "Version detectee dans la banniere: verifier les CVE associees et planifier une mise a jour corrective."
            version_level = "MEDIUM" if risk_level == "LOW" else risk_level
            version_key = (target, version_text, version_level)
            if version_key not in seen:
                seen.add(version_key)
                rows.append({"target": target, "risk": version_text, "level": version_level})

    return rows[:12]


def build_scan_audit_report_html(ip: str, nmap_output: str, scan_date: str) -> str:
        findings = parse_nmap_output(nmap_output or "")
        findings_with_port = [item for item in findings if isinstance(item.get("port"), int)]
        findings_with_port.sort(key=lambda item: int(item.get("port") or 0))

        risk_summary = calculate_risk_score(findings_with_port)
        risk_level = _risk_text(str(risk_summary.get("global_level") or "LOW"))
        risk_score = int(risk_summary.get("score_total") or 0)
        risk_badge_class = _html_risk_class(risk_level)

        open_findings = [item for item in findings_with_port if str(item.get("state") or "").lower() == "open"]
        if not findings_with_port:
                summary = "Le scan ne montre aucun port exploitable dans la sortie fournie. La surface d'attaque visible est reduite, mais un controle croise depuis d'autres segments reseau reste recommande."
        elif len(open_findings) <= 2:
                summary = "La machine expose un nombre limite de services. Le risque est surtout lie au durcissement des ports ouverts identifies et a la mise a jour des versions detectees."
        else:
                summary = "La cible expose plusieurs services accessibles, ce qui augmente les vecteurs d'intrusion potentiels. Une reduction immediate de la surface d'attaque est prioritaire."

        structured_rows = _structured_rows(findings_with_port)

        rows_html = []
        if structured_rows:
            for port, protocol, state, service, _risk in structured_rows:
                description = escape(_service_description(service, state))
                state_class = "state-open" if state == "open" else "state-closed"
                rows_html.append(
                    "<tr>"
                    f"<td><span class='port-chip'>{escape(port)}/{escape(protocol.lower())}</span></td>"
                    f"<td>{escape(service)}</td>"
                    f"<td><span class='state-pill {state_class}'>{escape(state.upper())}</span></td>"
                    f"<td>{description}</td>"
                    "</tr>"
                )
        else:
            rows_html.append("<tr><td colspan='4'>Aucun service exploitable detecte dans la sortie analysee.</td></tr>")

        vulnerability_rows = _build_vulnerability_rows(findings_with_port)
        vulnerability_html = []
        if vulnerability_rows:
                for entry in vulnerability_rows:
                        level = _risk_text(entry["level"])
                        cls = _html_risk_class(level)
                        vulnerability_html.append(
                                "<tr>"
                                f"<td>{escape(entry['target'])}</td>"
                                f"<td>{escape(entry['risk'])}</td>"
                                f"<td><span class='badge {cls}'>{level}</span></td>"
                                "</tr>"
                        )
        else:
                vulnerability_html.append("<tr><td colspan='3'>Aucune vulnerabilite evidente basee sur ce scan. Maintenir le controle periodique.</td></tr>")

        cards = []
        if vulnerability_rows:
                for entry in vulnerability_rows[:3]:
                        level = _risk_text(entry["level"])
                        cls = _html_risk_class(level)
                        cards.append(
                                "<article class='risk-card'>"
                    f"<div class='card-head'><span class='badge {cls}'>{level}</span><strong>{escape(entry['target'])}</strong></div>"
                                f"<p>{escape(entry['risk'])}</p>"
                                "</article>"
                        )
        else:
                cards.append(
                        "<article class='risk-card'><div class='card-head'><span class='badge risk-low'>LOW</span><strong>Surface reduite</strong></div><p>Aucun service ouvert significatif observe dans la sortie de scan fournie.</p></article>"
                )

        recommendations = [
                "Priorite 1: Fermer ou filtrer les ports non indispensables et restreindre l'acces d'administration par IP source.",
                "Priorite 2: Mettre a jour les services detectes et verifier les CVE applicables aux versions visibles dans les bannieres.",
                "Priorite 3: Renforcer la supervision (journalisation, IDS, alertes) sur les services restes exposes.",
        ]

        return f"""<!DOCTYPE html>
<html lang='fr'>
<head>
    <meta charset='UTF-8' />
    <meta name='viewport' content='width=device-width, initial-scale=1.0' />
    <title>Rapport de Securite - {escape(ip)}</title>
    <style>
        :root {{
            --bg: #070b18;
            --bg-soft: #0a1124;
            --card: rgba(15, 23, 45, 0.96);
            --card-soft: rgba(12, 18, 37, 0.97);
            --ink: #ebf3ff;
            --muted: #9db0d9;
            --border: rgba(107, 132, 201, 0.35);
            --blue: #4ab2ff;
            --cyan: #49e2ff;
            --purple: #9a7bff;
            --green: #49db9f;
            --orange: #f4b455;
            --red: #ff728f;
            --green-bg: rgba(73, 219, 159, 0.18);
            --orange-bg: rgba(244, 180, 85, 0.2);
            --red-bg: rgba(255, 114, 143, 0.2);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: radial-gradient(circle at 8% 10%, rgba(74, 178, 255, 0.2), transparent 36%), radial-gradient(circle at 82% 20%, rgba(154, 123, 255, 0.2), transparent 40%), linear-gradient(145deg, #050915 0%, #070b18 45%, #0b1329 100%);
            color: var(--ink);
        }}
        .page {{ max-width: 980px; margin: 24px auto; padding: 0 18px 28px; }}
        .panel {{
            background: linear-gradient(155deg, var(--card), var(--card-soft));
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 16px;
            box-shadow: 0 12px 28px rgba(3, 8, 25, 0.45);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 16px;
            border: 1px solid rgba(74, 178, 255, 0.35);
            box-shadow: 0 0 24px rgba(74, 178, 255, 0.16);
        }}
        .title {{ font-size: 30px; margin: 0 0 6px; letter-spacing: 0.3px; color: #f6f9ff; }}
        .meta {{ color: var(--muted); font-size: 14px; margin: 3px 0; }}
        .meta strong {{ color: #d7e7ff; }}
        h2 {{ margin: 0 0 12px; font-size: 20px; color: #e8f2ff; letter-spacing: 0.2px; }}
        p {{ margin: 0 0 10px; line-height: 1.5; color: #e7f0ff; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        th, td {{ border: 1px solid rgba(107, 132, 201, 0.28); padding: 9px 10px; vertical-align: top; text-align: left; color: #e9f2ff; }}
        th {{ background: linear-gradient(120deg, rgba(74, 178, 255, 0.18), rgba(154, 123, 255, 0.16)); font-weight: 700; color: #e7f4ff; }}
        tbody tr:nth-child(even) td {{ background: rgba(10, 16, 34, 0.85); }}
        tbody tr:nth-child(odd) td {{ background: rgba(8, 13, 28, 0.82); }}
        .badge {{ display: inline-block; padding: 5px 10px; border-radius: 999px; font-weight: 800; font-size: 12px; border: 1px solid transparent; }}
        .risk-low {{ color: var(--green); background: var(--green-bg); }}
        .risk-medium {{ color: var(--orange); background: var(--orange-bg); }}
        .risk-high {{ color: var(--red); background: var(--red-bg); box-shadow: 0 0 18px rgba(255, 114, 143, 0.22); }}
        .port-chip {{ display: inline-block; border-radius: 999px; padding: 3px 9px; background: rgba(74, 178, 255, 0.14); border: 1px solid rgba(74, 178, 255, 0.4); color: #d7ecff; font-weight: 700; }}
        .state-pill {{ display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 11px; font-weight: 800; }}
        .state-open {{ background: rgba(73, 219, 159, 0.2); color: #8bf7cb; border: 1px solid rgba(73, 219, 159, 0.45); }}
        .state-closed {{ background: rgba(154, 123, 255, 0.2); color: #cfbcff; border: 1px solid rgba(154, 123, 255, 0.45); }}
        .risk-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }}
        .risk-card {{ border: 1px solid rgba(107, 132, 201, 0.3); border-radius: 12px; padding: 12px; background: linear-gradient(155deg, rgba(13, 20, 40, 0.94), rgba(9, 14, 31, 0.98)); box-shadow: 0 8px 22px rgba(3, 9, 24, 0.45); }}
        .card-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
        .card-head strong {{ font-size: 14px; color: #e8f1ff; }}
        .risk-card p {{ margin: 0; color: #cddcff; font-size: 13px; line-height: 1.45; }}
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin: 8px 0; line-height: 1.45; color: #e8f2ff; }}
        .priority-1 {{ color: #ff9eb2; font-weight: 700; }}
        .priority-2 {{ color: #ffd18a; font-weight: 700; }}
        .priority-3 {{ color: #96f1ca; font-weight: 700; }}
        .score {{ color: var(--cyan); font-weight: 700; }}
        footer {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 18px; }}
        @media print {{
            body {{ background: var(--bg); }}
            .page {{ margin: 0; max-width: none; padding: 0; }}
            .panel {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <main class='page'>
        <section class='panel header'>
            <div>
                <h1 class='title'>Rapport de Securite</h1>
                <p class='meta'><strong>IP analysee:</strong> {escape(ip)}</p>
                <p class='meta'><strong>Date du rapport:</strong> {escape(scan_date)}</p>
            </div>
            <span class='badge {risk_badge_class}'>Risque global: {risk_level}</span>
        </section>

        <section class='panel'>
            <h2>Executive Summary</h2>
            <p>{escape(summary)}</p>
            <p class='meta'>Score de risque calcule: <span class='score'>{risk_score}</span> | Niveau global: <span class='badge {risk_badge_class}'>{risk_level}</span></p>
        </section>

        <section class='panel'>
            <h2>Technical Analysis</h2>
            <table>
                <thead>
                    <tr><th>Port</th><th>Service</th><th>State</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {''.join(rows_html)}
                </tbody>
            </table>
        </section>

        <section class='panel'>
            <h2>Security Risks</h2>
            <div class='risk-grid'>
                {''.join(cards)}
            </div>
            <div style='height: 14px;'></div>
            <table>
                <thead>
                    <tr><th>Service / Port</th><th>Risque identifie</th><th>Niveau</th></tr>
                </thead>
                <tbody>
                    {''.join(vulnerability_html)}
                </tbody>
            </table>
        </section>

        <section class='panel'>
            <h2>Recommendations</h2>
            <ul>
                <li><span class='priority-1'>Priorite 1</span> - {escape(recommendations[0].split(': ', 1)[1] if ': ' in recommendations[0] else recommendations[0])}</li>
                <li><span class='priority-2'>Priorite 2</span> - {escape(recommendations[1].split(': ', 1)[1] if ': ' in recommendations[1] else recommendations[1])}</li>
                <li><span class='priority-3'>Priorite 3</span> - {escape(recommendations[2].split(': ', 1)[1] if ': ' in recommendations[2] else recommendations[2])}</li>
            </ul>
        </section>

        <section class='panel'>
            <h2>Conclusion</h2>
            <p>Le niveau de risque visible pour cette cible est <strong>{risk_level}</strong>. Les actions de hardening et de reduction de surface d'attaque doivent etre appliquees avant toute extension de service.</p>
        </section>

        <footer>Generated by Pentest Dashboard</footer>
    </main>
</body>
</html>
"""


MODULE_LABELS = {
    "host_discovery": "Host Discovery",
    "service_detection": "Service Detection",
    "vulnerability_scan": "Vulnerability Scan",
    "web_scan": "Web Scan",
    "custom_ports": "Custom Ports Scan",
    "network_audit": "Network Exposure Audit",
    "fast_scan": "Fast Scan",
}

HOST_LINE_PATTERN = re.compile(r"^Nmap scan report for (.+?)(?: \(([^)]+)\))?$", flags=re.IGNORECASE)
STATEFUL_PORT_LINE_PATTERN = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered)\s*(.*)$",
    flags=re.IGNORECASE,
)

SERVICE_DEVICE_CATEGORY = {
    "smb": "Windows Host",
    "microsoft-ds": "Windows Host",
    "netbios-ssn": "Windows Host",
    "rtsp": "Camera/IoT",
    "mysql": "Database Server",
    "postgresql": "Database Server",
    "postgres": "Database Server",
    "mssql": "Database Server",
    "ms-sql-s": "Database Server",
    "http": "Web Server",
    "https": "Web Server",
    "rdp": "Remote Access Host",
    "ms-wbt-server": "Remote Access Host",
}

SERVICE_RISK_SCORE = {
    "msrpc": 3,
    "netbios-ssn": 3,
    "microsoft-ds": 3,
    "smb": 3,
    "rdp": 3,
    "ms-wbt-server": 3,
    "telnet": 3,
    "mysql": 3,
    "postgresql": 3,
    "postgres": 3,
    "mssql": 3,
    "ms-sql-s": 3,
    "redis": 3,
    "mongodb": 3,
    "ssh": 2,
    "http": 2,
    "https": 2,
    "ftp": 2,
}


def _normalize_state(value: str) -> str:
    state = str(value or "").strip().lower()
    if state == "open|filtered":
        return "filtered"
    return state or "unknown"


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_version(service: str, details: str) -> str:
    details_text = str(details or "").strip()
    if not details_text:
        return ""
    parts = details_text.split()
    if not parts:
        return ""
    service_name = str(service or "").strip().lower()
    first_token = parts[0].strip().lower()
    if service_name and first_token == service_name and len(parts) > 1:
        return " ".join(parts[1:]).strip()
    return details_text


def _badge_for_risk(level: str) -> str:
    normalized = str(level or "LOW").upper()
    if normalized == "HIGH":
        return "risk-high"
    if normalized == "MEDIUM":
        return "risk-medium"
    return "risk-low"


def _parse_stateful_rows_from_output(module_name: str, output: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    current_host = ""
    current_hostname = ""

    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = HOST_LINE_PATTERN.match(line)
        if host_match:
            host_label = host_match.group(1).strip()
            host_ip = host_match.group(2).strip() if host_match.group(2) else host_label
            current_hostname = "" if host_label == host_ip else host_label
            current_host = host_ip
            continue

        port_match = STATEFUL_PORT_LINE_PATTERN.match(line)
        if not port_match:
            continue

        details = (port_match.group(4) or "").strip()
        service = details.split()[0] if details else "unknown"
        state = _normalize_state(port_match.group(3))
        rows.append(
            {
                "module": module_name,
                "host_ip": current_host,
                "hostname": current_hostname,
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2).lower(),
                "state": state,
                "service": service,
                "version": _extract_version(service, details),
            }
        )

    return rows


def _rows_from_parsed_results(module_name: str, parsed_results: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for host_entry in parsed_results or []:
        if not isinstance(host_entry, dict):
            continue

        host_ip = str(host_entry.get("host_ip") or host_entry.get("ip") or host_entry.get("address") or "").strip()
        hostname = str(host_entry.get("hostname") or "").strip()

        if module_name == "custom_ports":
            for port_entry in host_entry.get("ports", []) or []:
                if not isinstance(port_entry, dict):
                    continue
                port_value = _safe_int(port_entry.get("port"))
                if port_value is None:
                    continue
                details = str(port_entry.get("details") or "").strip()
                service = str(port_entry.get("service") or "unknown").strip() or "unknown"
                rows.append(
                    {
                        "module": module_name,
                        "host_ip": host_ip,
                        "hostname": hostname,
                        "port": port_value,
                        "protocol": str(port_entry.get("protocol") or "tcp").lower(),
                        "state": _normalize_state(str(port_entry.get("state") or "unknown")),
                        "service": service,
                        "version": _extract_version(service, details),
                    }
                )
            continue

        services = host_entry.get("services", []) or []
        if services:
            for service_entry in services:
                if not isinstance(service_entry, dict):
                    continue
                port_value = _safe_int(service_entry.get("port"))
                if port_value is None:
                    continue
                details = str(service_entry.get("details") or "").strip()
                service = str(service_entry.get("service") or "unknown").strip() or "unknown"
                rows.append(
                    {
                        "module": module_name,
                        "host_ip": host_ip,
                        "hostname": hostname,
                        "port": port_value,
                        "protocol": str(service_entry.get("protocol") or "tcp").lower(),
                        "state": _normalize_state(str(service_entry.get("state") or "open")),
                        "service": service,
                        "version": _extract_version(service, details),
                    }
                )
            continue

        for port_value in host_entry.get("open_ports", []) or []:
            port_int = _safe_int(port_value)
            if port_int is None:
                continue
            rows.append(
                {
                    "module": module_name,
                    "host_ip": host_ip,
                    "hostname": hostname,
                    "port": port_int,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "unknown",
                    "version": "",
                }
            )

    return rows


def _merge_unique_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    merged: dict[tuple[str, str, int, str, str], dict[str, object]] = {}
    for row in rows:
        port = _safe_int(row.get("port"))
        if port is None:
            continue
        module = str(row.get("module") or "").strip()
        host_ip = str(row.get("host_ip") or "").strip()
        protocol = str(row.get("protocol") or "tcp").lower()
        state = _normalize_state(str(row.get("state") or "unknown"))
        key = (module, host_ip, port, protocol, state)

        normalized_row = {
            "module": module,
            "host_ip": host_ip,
            "hostname": str(row.get("hostname") or "").strip(),
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": str(row.get("service") or "unknown").strip() or "unknown",
            "version": str(row.get("version") or "").strip(),
        }

        existing = merged.get(key)
        if existing is None:
            merged[key] = normalized_row
            continue

        if existing.get("service") in {"", "unknown"} and normalized_row["service"] not in {"", "unknown"}:
            existing["service"] = normalized_row["service"]
        if not existing.get("version") and normalized_row.get("version"):
            existing["version"] = normalized_row["version"]
        if not existing.get("hostname") and normalized_row.get("hostname"):
            existing["hostname"] = normalized_row["hostname"]

    return sorted(
        merged.values(),
        key=lambda item: (
            MODULE_LABELS.get(str(item.get("module") or ""), str(item.get("module") or "")),
            str(item.get("host_ip") or ""),
            int(item.get("port") or 0),
            str(item.get("protocol") or "tcp"),
        ),
    )


def _risk_from_open_rows(open_rows: list[dict[str, object]]) -> tuple[int, str]:
    score_total = 0
    for row in open_rows:
        service = str(row.get("service") or "unknown").lower()
        port = int(row.get("port") or 0)
        base = SERVICE_RISK_SCORE.get(service, 1)
        if port in {135, 139, 445, 3389, 23, 3306, 5432} and base < 3:
            base = 3
        score_total += base

    if score_total >= 12:
        level = "HIGH"
    elif score_total >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score_total, level


def _recommendations_from_rows(rows: list[dict[str, object]]) -> list[str]:
    open_rows = [row for row in rows if str(row.get("state") or "").lower() == "open"]
    filtered_rows = [row for row in rows if str(row.get("state") or "").lower() == "filtered"]
    recommendations: list[str] = []

    ports = {int(row.get("port") or 0) for row in open_rows}
    services = {str(row.get("service") or "unknown").lower() for row in open_rows}

    if 445 in ports or "smb" in services or "microsoft-ds" in services:
        recommendations.append("SMB exposure detected: restrict port 445 to trusted administration networks and disable SMBv1.")
    if 135 in ports or "msrpc" in services:
        recommendations.append("Windows RPC exposure detected on port 135: limit RPC reachability with host and network firewall rules.")
    if 139 in ports or "netbios-ssn" in services:
        recommendations.append("NetBIOS exposure detected on port 139: disable legacy NetBIOS where possible and enforce segmentation.")
    if 3389 in ports or "rdp" in services or "ms-wbt-server" in services:
        recommendations.append("Remote desktop exposure detected: enforce VPN-only access and MFA for RDP endpoints.")
    if "http" in services or "https" in services:
        recommendations.append("Web service exposure detected: verify patch level, disable unused virtual hosts, and harden TLS/cipher suites.")
    if {"mysql", "postgresql", "postgres", "mssql", "ms-sql-s"} & services:
        recommendations.append("Database service exposure detected: restrict database listener access to application tiers only.")
    if "rtsp" in services:
        recommendations.append("RTSP exposure detected: place camera/IoT devices in isolated VLANs and enforce credential rotation.")

    if not recommendations and filtered_rows and not open_rows:
        recommendations.append("Only filtered ports were observed: keep firewall policy in deny-by-default mode and verify ACL intent.")

    if not recommendations and not rows:
        recommendations.append("No actionable service findings were parsed from the executed scan output.")

    return recommendations


def _device_categories_from_host_rows(host_rows: list[dict[str, object]]) -> list[str]:
    categories: set[str] = set()
    for row in host_rows:
        if str(row.get("state") or "").lower() != "open":
            continue
        service = str(row.get("service") or "unknown").lower()
        mapped = SERVICE_DEVICE_CATEGORY.get(service)
        if mapped:
            categories.add(mapped)
        port = int(row.get("port") or 0)
        if port == 554:
            categories.add("Camera/IoT")
    return sorted(categories)


def _scan_type_label(module_names: list[str]) -> str:
    if len(module_names) == 1:
        return MODULE_LABELS.get(module_names[0], module_names[0].replace("_", " ").title())
    readable = [MODULE_LABELS.get(name, name.replace("_", " ").title()) for name in module_names]
    return ", ".join(readable)


def _module_section_table(module_name: str, module_data: dict[str, object], rows: list[dict[str, object]]) -> str:
    label = MODULE_LABELS.get(module_name, module_name.replace("_", " ").title())
    command_used = escape(str(module_data.get("command_used") or module_data.get("command") or ""))
    module_rows = [row for row in rows if str(row.get("module") or "") == module_name]

    if module_name == "host_discovery":
        host_entries = module_data.get("parsed_results", []) or []
        host_rows = []
        for entry in host_entries:
            if not isinstance(entry, dict):
                continue
            host_ip = escape(str(entry.get("host_ip") or entry.get("ip") or ""))
            hostname = escape(str(entry.get("hostname") or ""))
            state = escape(str(entry.get("state") or "unknown").upper())
            if host_ip:
                host_rows.append(f"<tr><td>{host_ip}</td><td>{hostname}</td><td>{state}</td></tr>")

        rows_html = "".join(host_rows) or "<tr><td colspan='3'>No host discovery findings parsed.</td></tr>"
        return (
            "<section class='panel'>"
            f"<h2>{escape(label)}</h2>"
            f"<p class='meta'><strong>Command:</strong> {command_used or 'N/A'}</p>"
            "<table><thead><tr><th>IP</th><th>Hostname</th><th>State</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
            "</section>"
        )

    no_http_message = str(module_data.get("message") or "").strip()
    if module_name == "web_scan" and (not module_rows) and no_http_message:
        return (
            "<section class='panel'>"
            f"<h2>{escape(label)}</h2>"
            f"<p class='meta'><strong>Command:</strong> {command_used or 'N/A'}</p>"
            f"<p><strong>{escape(no_http_message)}</strong></p>"
            "</section>"
        )

    if module_rows:
        rows_html = "".join(
            "<tr>"
            f"<td>{escape(str(row.get('host_ip') or ''))}</td>"
            f"<td>{escape(str(row.get('hostname') or ''))}</td>"
            f"<td>{escape(str(row.get('port') or ''))}/{escape(str(row.get('protocol') or 'tcp'))}</td>"
            f"<td>{escape(str(row.get('state') or 'unknown').upper())}</td>"
            f"<td>{escape(str(row.get('service') or 'unknown'))}</td>"
            f"<td>{escape(str(row.get('version') or '-'))}</td>"
            "</tr>"
            for row in module_rows
        )
    else:
        rows_html = "<tr><td colspan='6'>No parsed port/service findings for this executed module.</td></tr>"

    return (
        "<section class='panel'>"
        f"<h2>{escape(label)}</h2>"
        f"<p class='meta'><strong>Command:</strong> {command_used or 'N/A'}</p>"
        "<table><thead><tr><th>IP</th><th>Hostname</th><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>"
        f"<tbody>{rows_html}</tbody></table>"
        "</section>"
    )


def build_modular_network_report_html(scan_result) -> str:
    try:
        data = json.loads(scan_result.result or "{}")
    except Exception:
        data = {}

    modules = data.get("modules", {}) if isinstance(data, dict) else {}
    module_names = [str(name) for name in modules.keys()]
    target = str(data.get("target") or scan_result.ip)
    timestamp = scan_result.date.strftime("%Y-%m-%d %H:%M:%S")
    scan_type = _scan_type_label(module_names) if module_names else "Unknown Module"

    all_rows: list[dict[str, object]] = []
    host_inventory: dict[str, dict[str, str]] = {}
    for module_name, module_data in modules.items():
        parsed_results = module_data.get("parsed_results", []) or []
        for entry in parsed_results:
            if not isinstance(entry, dict):
                continue
            host_ip = str(entry.get("host_ip") or entry.get("ip") or entry.get("address") or "").strip()
            if host_ip:
                host_inventory.setdefault(host_ip, {"hostname": str(entry.get("hostname") or "").strip()})

        parsed_rows = _rows_from_parsed_results(module_name, parsed_results)
        raw_rows = _parse_stateful_rows_from_output(module_name, module_data.get("raw_output") or module_data.get("output") or "")
        all_rows.extend(parsed_rows)
        all_rows.extend(raw_rows)

    rows = _merge_unique_rows(all_rows)
    open_rows = [row for row in rows if str(row.get("state") or "").lower() == "open"]
    filtered_rows = [row for row in rows if str(row.get("state") or "").lower() == "filtered"]
    closed_rows = [row for row in rows if str(row.get("state") or "").lower() == "closed"]

    score_total, risk_level = _risk_from_open_rows(open_rows)
    risk_cls = _badge_for_risk(risk_level)

    open_summary = (
        "".join(
            f"<tr><td>{escape(str(row.get('host_ip') or ''))}</td><td>{escape(str(row.get('port') or ''))}/{escape(str(row.get('protocol') or 'tcp'))}</td><td>{escape(str(row.get('service') or 'unknown'))}</td><td>{escape(str(row.get('version') or '-'))}</td></tr>"
            for row in open_rows
        )
        or "<tr><td colspan='4'>No open ports found in executed module outputs.</td></tr>"
    )

    filtered_summary = (
        "".join(
            f"<tr><td>{escape(str(row.get('host_ip') or ''))}</td><td>{escape(str(row.get('port') or ''))}/{escape(str(row.get('protocol') or 'tcp'))}</td><td>{escape(str(row.get('service') or 'unknown'))}</td></tr>"
            for row in filtered_rows
        )
        or "<tr><td colspan='3'>No filtered ports detected.</td></tr>"
    )

    service_counts: dict[str, int] = {}
    for row in open_rows:
        service = str(row.get("service") or "unknown").lower()
        service_counts[service] = service_counts.get(service, 0) + 1
    detected_services_html = (
        "".join(f"<tr><td>{escape(service)}</td><td>{count}</td></tr>" for service, count in sorted(service_counts.items(), key=lambda item: (-item[1], item[0])))
        or "<tr><td colspan='2'>No open services detected.</td></tr>"
    )

    host_rows_html = []
    host_row_map: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        host_ip = str(row.get("host_ip") or "").strip()
        if not host_ip:
            continue
        host_row_map.setdefault(host_ip, []).append(row)

    for host_ip in sorted(set(list(host_inventory.keys()) + list(host_row_map.keys()))):
        hostname = host_inventory.get(host_ip, {}).get("hostname", "")
        categories = _device_categories_from_host_rows(host_row_map.get(host_ip, []))
        host_rows_html.append(
            f"<tr><td>{escape(host_ip)}</td><td>{escape(hostname)}</td><td>{escape(', '.join(categories) if categories else 'N/A')}</td></tr>"
        )
    attack_surface_html = "".join(host_rows_html) or "<tr><td colspan='3'>No host findings parsed.</td></tr>"

    recommendations = _recommendations_from_rows(rows)
    recommendations_html = "".join(f"<li>{escape(item)}</li>" for item in recommendations)

    module_sections_html = "".join(
        _module_section_table(module_name, modules[module_name], rows)
        for module_name in module_names
    ) or "<section class='panel'><h2>Executed Modules</h2><p>No module result payload was found.</p></section>"

    if "web_scan" in modules and not open_rows:
        web_message = str(modules["web_scan"].get("message") or "").strip()
        if web_message and "no http service" in web_message.lower():
            recommendations_html += f"<li>{escape(web_message)}</li>"

    return f"""<!doctype html>
<html lang='en'>
<head>
    <meta charset='utf-8'/>
    <meta name='viewport' content='width=device-width,initial-scale=1' />
    <title>Enterprise Report - {escape(target)} - {escape(scan_type)} - {escape(timestamp)}</title>
    <style>
        body {{ background:#071022; color:#e8f2ff; font-family: 'Segoe UI', Arial, sans-serif; margin:0; padding:18px; }}
        .page {{ max-width: 1020px; margin: 0 auto; }}
        .panel {{ background: linear-gradient(155deg, rgba(14,22,44,0.98), rgba(9,15,31,0.98)); border:1px solid rgba(102,130,196,0.25); border-radius:12px; padding:14px; margin-bottom:12px; }}
        h1,h2{{ margin:4px 0 10px 0; color:#f4f8ff; }}
        .meta {{ color:#b8caee; font-size:13px; margin:4px 0; }}
        table{{ width:100%; border-collapse:collapse; font-size:12px; }}
        th,td{{ border:1px solid rgba(102,130,196,0.2); padding:8px; text-align:left; vertical-align:top; }}
        th{{ background: rgba(75,145,255,0.15); }}
        .badge {{ display:inline-block; padding:4px 8px; border-radius:999px; font-size:12px; font-weight:700; }}
        .risk-high{{ background: rgba(255,114,143,0.16); color:#ff9ab0; border:1px solid rgba(255,114,143,0.35); }}
        .risk-medium{{ background: rgba(244,180,85,0.14); color:#ffd38d; border:1px solid rgba(244,180,85,0.35); }}
        .risk-low{{ background: rgba(73,219,159,0.14); color:#9ef4cc; border:1px solid rgba(73,219,159,0.35); }}
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin: 8px 0; }}
        footer{{ color:#a8bddf; font-size:12px; text-align:center; margin-top:18px; }}
    </style>
</head>
<body>
    <main class='page'>
        <section class='panel'>
            <h1>Enterprise Security Report</h1>
            <p class='meta'><strong>Target:</strong> {escape(target)}</p>
            <p class='meta'><strong>Scan Type:</strong> {escape(scan_type)}</p>
            <p class='meta'><strong>Execution Date:</strong> {escape(timestamp)}</p>
        </section>

        <section class='panel'>
            <h2>Open Ports Summary</h2>
            <table>
                <thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th></tr></thead>
                <tbody>{open_summary}</tbody>
            </table>
        </section>

        <section class='panel'>
            <h2>Filtered Ports Summary</h2>
            <table>
                <thead><tr><th>IP</th><th>Port</th><th>Service</th></tr></thead>
                <tbody>{filtered_summary}</tbody>
            </table>
            <p class='meta'><strong>Closed Ports Detected:</strong> {len(closed_rows)}</p>
        </section>

        <section class='panel'>
            <h2>Detected Services</h2>
            <table>
                <thead><tr><th>Service</th><th>Occurrences (open only)</th></tr></thead>
                <tbody>{detected_services_html}</tbody>
            </table>
        </section>

        <section class='panel'>
            <h2>Risk Evaluation</h2>
            <p>Risk is computed from real open services and exposed ports parsed from executed scan outputs only.</p>
            <p class='meta'><strong>Risk Score:</strong> {score_total} &nbsp; <strong>Risk Level:</strong> <span class='badge {risk_cls}'>{risk_level}</span></p>
        </section>

        <section class='panel'>
            <h2>Security Recommendations</h2>
            <ul>{recommendations_html}</ul>
        </section>

        <section class='panel'>
            <h2>Attack Surface Summary</h2>
            <p class='meta'><strong>Hosts:</strong> {len(set(list(host_inventory.keys()) + [str(r.get('host_ip') or '') for r in rows if str(r.get('host_ip') or '')]))} &nbsp; <strong>Open:</strong> {len(open_rows)} &nbsp; <strong>Filtered:</strong> {len(filtered_rows)} &nbsp; <strong>Closed:</strong> {len(closed_rows)}</p>
            <table>
                <thead><tr><th>IP</th><th>Hostname</th><th>Inferred Category</th></tr></thead>
                <tbody>{attack_surface_html}</tbody>
            </table>
        </section>

        {module_sections_html}

        <footer>Generated from executed module outputs only</footer>
    </main>
</body>
</html>
"""


def build_modular_network_report_pdf(scan_result) -> bytes:
    html_content = build_modular_network_report_html(scan_result)
    try:
        from weasyprint import HTML

        return HTML(string=html_content).write_pdf()
    except Exception:
        if REPORTLAB_AVAILABLE:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=18 * mm, bottomMargin=14 * mm)
            styles = getSampleStyleSheet()
            story = [
                Paragraph("Enterprise Security Report", styles["Title"]),
                Spacer(1, 6),
                Paragraph(f"Target: {escape(str(scan_result.ip))}", styles["Normal"]),
                Spacer(1, 6),
                Paragraph("Install WeasyPrint for full HTML-to-PDF rendering.", styles["Normal"]),
            ]
            doc.build(story)
            return buffer.getvalue()

    return html_content.encode("utf-8")
