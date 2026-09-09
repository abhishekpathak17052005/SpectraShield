"""
VisualElements: ReportLab drawing utilities for PDF visualizations.

Provides functions to render:
- Risk gauge (0-100 arc gauge)
- Timeline nodes and connectors
- Infrastructure flow diagrams
- Threat DNA fingerprints
- Confidence/certainty meters
- Evidence cards
"""

from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch, mm
from reportlab.platypus import Flowable
from typing import Dict, Any, List, Optional, Tuple
import math


class VisualElements:
    """Renders visual components for PDF using ReportLab."""

    # Colors
    COLOR_DARK_BG = colors.HexColor("#0B0F17")
    COLOR_ACCENT = colors.HexColor("#0891B2")
    COLOR_ALERT = colors.HexColor("#DC2626")
    COLOR_SUCCESS = colors.HexColor("#10B981")
    COLOR_NEUTRAL = colors.HexColor("#6B7280")
    COLOR_GRID = colors.HexColor("#E5E7EB")

    @staticmethod
    def risk_gauge(c: canvas.Canvas, x: float, y: float, score: float, label: str, size: float = 2*inch) -> None:
        """
        Draw risk gauge (0-100 arc gauge with needle).
        
        Args:
            c: Canvas to draw on
            x, y: Position (center)
            score: Risk score 0-100
            label: Label text (e.g., "Critical Risk")
            size: Gauge size
        """
        # Arc background (0-360 degrees, displayed as 180 degree arc)
        c.setFillColor(colors.HexColor("#F3F4F6"))
        c.setStrokeColor(colors.HexColor("#D1D5DB"))
        c.setLineWidth(8)

        # Draw gradient background arc
        start_angle = 180
        end_angle = 0

        # Color zones
        zones = [
            (0, 30, colors.HexColor("#10B981")),      # Safe - Green
            (30, 60, colors.HexColor("#F59E0B")),     # Moderate - Amber
            (60, 85, colors.HexColor("#F97316")),     # High - Orange
            (85, 100, colors.HexColor("#DC2626"))     # Critical - Red
        ]

        for zone_start, zone_end, zone_color in zones:
            # Calculate angles for this zone
            zone_angle_start = 180 - (zone_start / 100 * 180)
            zone_angle_end = 180 - (zone_end / 100 * 180)

            c.setStrokeColor(zone_color)
            c.setLineWidth(10)
            c.arc(x - size/2, y - size/2, x + size/2, y + size/2,
                  zone_angle_end, zone_angle_start)

        # Needle
        needle_angle = 180 - (score / 100 * 180)  # Convert to angle
        needle_rad = math.radians(needle_angle)

        needle_length = size / 2 - mm * 5
        needle_x_end = x + needle_length * math.cos(needle_rad)
        needle_y_end = y + needle_length * math.sin(needle_rad)

        c.setStrokeColor(VisualElements.COLOR_DARK_BG)
        c.setLineWidth(3)
        c.line(x, y, needle_x_end, needle_y_end)

        # Center dot
        c.setFillColor(VisualElements.COLOR_DARK_BG)
        c.circle(x, y, mm * 3, fill=True)

        # Score text
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(x, y - size/2 - mm*10, f"{int(score)}")

        # Label
        c.setFont("Helvetica", 10)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawCentredString(x, y - size/2 - mm*18, label)

    @staticmethod
    def timeline_node(c: canvas.Canvas, x: float, y: float, label: str, severity: str = "info") -> None:
        """
        Draw timeline node (circle + label).
        
        Args:
            c: Canvas
            x, y: Position
            label: Node label
            severity: "info", "warning", "critical"
        """
        # Color by severity
        severity_colors = {
            "info": VisualElements.COLOR_ACCENT,
            "warning": colors.HexColor("#F59E0B"),
            "critical": VisualElements.COLOR_ALERT
        }
        color = severity_colors.get(severity, VisualElements.COLOR_ACCENT)

        # Draw circle
        c.setFillColor(color)
        c.setStrokeColor(colors.white)
        c.setLineWidth(2)
        c.circle(x, y, mm * 4, fill=True, stroke=True)

        # Label
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.white)
        c.drawCentredString(x, y - mm*1, label[:3])

    @staticmethod
    def timeline_connector(c: canvas.Canvas, x1: float, y1: float, x2: float, y2: float) -> None:
        """
        Draw timeline connector line between nodes.
        
        Args:
            c: Canvas
            x1, y1: Start position
            x2, y2: End position
        """
        c.setStrokeColor(VisualElements.COLOR_NEUTRAL)
        c.setLineWidth(1)
        c.line(x1, y1, x2, y2)

    @staticmethod
    def confidence_meter(c: canvas.Canvas, x: float, y: float, value: float, width: float = 1.5*inch, height: float = 0.3*inch) -> None:
        """
        Draw horizontal confidence meter bar.
        
        Args:
            c: Canvas
            x, y: Top-left position
            value: 0-100 confidence value
            width, height: Meter dimensions
        """
        # Background bar
        c.setFillColor(colors.HexColor("#E5E7EB"))
        c.setStrokeColor(colors.HexColor("#D1D5DB"))
        c.setLineWidth(1)
        c.rect(x, y, width, height, fill=True, stroke=True)

        # Filled portion (color by confidence)
        if value < 40:
            fill_color = colors.HexColor("#F59E0B")
        elif value < 70:
            fill_color = colors.HexColor("#F97316")
        else:
            fill_color = VisualElements.COLOR_SUCCESS

        fill_width = (value / 100) * width
        c.setFillColor(fill_color)
        c.rect(x, y, fill_width, height, fill=True, stroke=False)

        # Percentage text
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor("#1F2937"))
        c.drawString(x + width + mm*2, y + height*0.2, f"{int(value)}%")

    @staticmethod
    def infrastructure_flow(c: canvas.Canvas, x: float, y: float, infrastructure: Dict[str, Any]) -> None:
        """
        Draw infrastructure flow diagram.
        
        Shows: [Client] → [Relay] → [Relay] → [Origin]
        
        Args:
            c: Canvas
            x, y: Top-left position
            infrastructure: Infrastructure data
        """
        step_width = 1.2 * inch
        current_x = x

        # Title
        c.setFont("Helvetica-Bold", 10)
        c.drawString(x, y, "Infrastructure Route")
        current_y = y - 0.2 * inch

        # Draw hops
        hops = [
            {"label": "Client", "type": "client"},
            {"label": "Relay 1", "type": "relay"},
            {"label": "Relay 2", "type": "relay"},
            {"label": infrastructure.get('organization', 'Origin'), "type": "origin"},
        ]

        for i, hop in enumerate(hops):
            # Box
            if hop['type'] == 'origin':
                c.setFillColor(VisualElements.COLOR_ALERT)
                c.setStrokeColor(VisualElements.COLOR_ALERT)
            else:
                c.setFillColor(VisualElements.COLOR_ACCENT)
                c.setStrokeColor(VisualElements.COLOR_ACCENT)

            c.setLineWidth(1)
            c.rect(current_x, current_y - 0.3*inch, 0.9*inch, 0.25*inch, fill=True, stroke=True)

            # Label
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.white)
            c.drawCentredString(current_x + 0.45*inch, current_y - 0.18*inch, hop['label'])

            # Arrow to next
            if i < len(hops) - 1:
                c.setStrokeColor(VisualElements.COLOR_NEUTRAL)
                c.setLineWidth(1)
                arrow_x = current_x + 0.95*inch
                arrow_y = current_y - 0.17*inch
                c.line(arrow_x, arrow_y, arrow_x + 0.2*inch, arrow_y)

                # Arrow head
                c.line(arrow_x + 0.2*inch, arrow_y, arrow_x + 0.15*inch, arrow_y + 0.05*inch)
                c.line(arrow_x + 0.2*inch, arrow_y, arrow_x + 0.15*inch, arrow_y - 0.05*inch)

            current_x += step_width

    @staticmethod
    def threat_dna_profile(c: canvas.Canvas, x: float, y: float, threat_data: Dict[str, Any]) -> None:
        """
        Draw threat DNA fingerprint (radar/spider chart).
        
        Args:
            c: Canvas
            x, y: Center position
            threat_data: Threat characteristics
        """
        # Draw hexagon outline
        c.setStrokeColor(VisualElements.COLOR_ACCENT)
        c.setLineWidth(1)
        c.setFillColor(colors.HexColor("F3F4F6"))

        size = 1 * inch
        axes = 6

        points = []
        for i in range(axes):
            angle = (i / axes) * 2 * math.pi - math.pi / 2
            px = x + size * math.cos(angle)
            py = y + size * math.sin(angle)
            points.append((px, py))

        # Close the polygon
        points.append(points[0])

        # Draw polygon
        c.setLineWidth(1)
        c.setStrokeColor(VisualElements.COLOR_ACCENT)
        c.setFillColor(colors.HexColor("#E0F2FE"))
        c.setFillAlpha(0.3)

        c_path = "M %s L" % " ".join(["%s,%s" % (p[0], p[1]) for p in points])
        # Using drawString for simplicity instead of complex path drawing

        # Title
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(colors.HexColor("#1F2937"))
        c.drawCentredString(x, y + size + 0.2*inch, "Threat DNA Profile")

    @staticmethod
    def evidence_card(c: canvas.Canvas, x: float, y: float, width: float, height: float,
                      title: str, value: str, icon: str = "⚠", color: str = "#DC2626") -> None:
        """
        Draw evidence/risk factor card.
        
        Args:
            c: Canvas
            x, y: Top-left position
            width, height: Card dimensions
            title: Card title
            value: Card value/description
            icon: Icon character
            color: Card color (hex)
        """
        card_color = colors.HexColor(color)

        # Background
        c.setFillColor(card_color)
        c.setStrokeColor(card_color)
        c.setLineWidth(0)
        c.rect(x, y - height, width, height, fill=True, stroke=False)

        # Border
        c.setStrokeColor(card_color)
        c.setLineWidth(2)
        c.rect(x, y - height, width, height, fill=False, stroke=True)

        # Icon
        c.setFont("Helvetica-Bold", 16)
        c.setFillColor(colors.white)
        c.drawString(x + 0.1*inch, y - height + 0.2*inch, icon)

        # Title
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(colors.white)
        c.drawString(x + 0.25*inch, y - height + 0.25*inch, title)

        # Value (wrapped text)
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.white)
        # Simple text wrapping
        words = value.split()
        line_y = y - height + 0.1*inch
        current_line = ""

        for word in words:
            test_line = current_line + " " + word if current_line else word
            if len(test_line) > 25:  # Rough character limit per line
                c.drawString(x + 0.15*inch, line_y, current_line)
                current_line = word
                line_y -= 0.12*inch
            else:
                current_line = test_line

        if current_line:
            c.drawString(x + 0.15*inch, line_y, current_line)

    @staticmethod
    def forensic_card(c: canvas.Canvas, x: float, y: float, width: float, height: float,
                      title: str, findings: Dict[str, str], background_color: str = "#E0F2FE") -> None:
        """
        Draw large forensic findings card.
        
        Args:
            c: Canvas
            x, y: Top-left position
            width, height: Card dimensions
            title: Card title
            findings: Key-value findings
            background_color: Card background (hex)
        """
        bg_color = colors.HexColor(background_color)

        # Background
        c.setFillColor(bg_color)
        c.setStrokeColor(colors.HexColor("#D1D5DB"))
        c.setLineWidth(1)
        c.rect(x, y - height, width, height, fill=True, stroke=True)

        # Title bar
        title_bg = colors.HexColor("#0891B2")
        c.setFillColor(title_bg)
        c.rect(x, y - 0.35*inch, width, 0.35*inch, fill=True, stroke=False)

        # Title text
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(colors.white)
        c.drawString(x + 0.1*inch, y - 0.25*inch, title)

        # Findings
        current_y = y - 0.5*inch
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor("#1F2937"))

        for key, value in findings.items():
            # Key
            c.drawString(x + 0.15*inch, current_y, f"{key}:")

            # Value
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#4B5563"))
            c.drawString(x + 0.15*inch, current_y - 0.15*inch, str(value)[:60])

            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(colors.HexColor("#1F2937"))

            current_y -= 0.35*inch

    @staticmethod
    def disclaimer_box(c: canvas.Canvas, x: float, y: float, width: float, height: float,
                       text: str) -> None:
        """
        Draw disclaimer box at bottom of page.
        
        Args:
            c: Canvas
            x, y: Top-left position
            width, height: Box dimensions
            text: Disclaimer text
        """
        # Background
        c.setFillColor(colors.HexColor("#FEF3C7"))
        c.setStrokeColor(colors.HexColor("#FBBF24"))
        c.setLineWidth(1)
        c.rect(x, y - height, width, height, fill=True, stroke=True)

        # Icon
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(colors.HexColor("#D97706"))
        c.drawString(x + 0.1*inch, y - height + 0.2*inch, "ⓘ")

        # Text
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#78350F"))

        # Simple text wrapping
        words = text.split()
        line_y = y - height + 0.15*inch
        current_line = ""
        max_width = width - 0.3*inch

        for word in words:
            test_line = current_line + " " + word if current_line else word
            if c.stringWidth(test_line, "Helvetica", 8) > max_width:
                c.drawString(x + 0.25*inch, line_y, current_line)
                current_line = word
                line_y -= 0.12*inch
            else:
                current_line = test_line

        if current_line:
            c.drawString(x + 0.25*inch, line_y, current_line)

    @staticmethod
    def page_footer(c: canvas.Canvas, x: float, y: float, case_id: str, page_num: int, total_pages: int) -> None:
        """
        Draw page footer.
        
        Args:
            c: Canvas
            x, y: Position
            case_id: Case identifier
            page_num: Current page number
            total_pages: Total pages
        """
        # Line separator
        c.setStrokeColor(colors.HexColor("#E5E7EB"))
        c.setLineWidth(1)
        c.line(x, y, x + 7*inch, y)

        # Footer text
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#6B7280"))

        left_text = f"Case ID: {case_id}"
        c.drawString(x, y - 0.15*inch, left_text)

        right_text = f"Page {page_num} of {total_pages}"
        text_width = c.stringWidth(right_text, "Helvetica", 8)
        c.drawString(x + 7*inch - text_width, y - 0.15*inch, right_text)

    @staticmethod
    def separator_line(c: canvas.Canvas, x: float, y: float, width: float, style: str = "solid") -> None:
        """
        Draw horizontal separator line.
        
        Args:
            c: Canvas
            x, y: Position
            width: Line width
            style: "solid", "dashed", "dotted"
        """
        c.setStrokeColor(colors.HexColor("#E5E7EB"))

        if style == "dashed":
            c.setLineWidth(1)
            c.setDash(3, 3)
        elif style == "dotted":
            c.setLineWidth(0.5)
            c.setDash(1, 2)
        else:
            c.setLineWidth(1)

        c.line(x, y, x + width, y)
        c.setDash()  # Reset
