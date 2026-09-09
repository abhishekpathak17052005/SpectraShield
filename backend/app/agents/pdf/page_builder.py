"""
PageBuilder: Orchestrates layout and rendering for individual PDF pages.

Manages:
- Page setup (margins, headers, footers)
- Component positioning and spacing
- Multi-column layouts
- Page breaks and overflow handling
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch, mm
from reportlab.pdfgen import canvas
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from typing import List, Dict, Any, Optional, Tuple


class PageBuilder:
    """
    Builds individual PDF pages with consistent layout and styling.
    
    Features:
    - Standard margins and page geometry
    - Header/footer templates
    - Component spacing and alignment
    - Multi-column support
    - Page break management
    """

    # Page geometry (letter size)
    PAGE_WIDTH = 8.5 * inch
    PAGE_HEIGHT = 11 * inch

    # Margins
    MARGIN_LEFT = 0.75 * inch
    MARGIN_RIGHT = 0.75 * inch
    MARGIN_TOP = 0.75 * inch
    MARGIN_BOTTOM = 0.75 * inch

    # Usable area
    CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
    CONTENT_HEIGHT = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM

    # Colors (from design spec)
    COLOR_DARK_BG = "#0B0F17"  # Dark navy background
    COLOR_ACCENT = "#0891B2"   # Electric cyan
    COLOR_ALERT = "#DC2626"    # Alert red
    COLOR_SUCCESS = "#10B981"  # Success green
    COLOR_NEUTRAL = "#6B7280"  # Neutral grey

    # Typography
    FONT_FAMILY = "Helvetica"
    FONT_TITLE = "Helvetica-Bold"
    FONT_MONO = "Courier"

    def __init__(self, page_number: int, total_pages: int, case_id: str):
        """Initialize page builder."""
        self.page_number = page_number
        self.total_pages = total_pages
        self.case_id = case_id
        self.current_y = self.PAGE_HEIGHT - self.MARGIN_TOP
        self.elements = []

    def add_header(self, title: str, subtitle: Optional[str] = None) -> None:
        """Add page header with title and optional subtitle."""
        # Title
        self.elements.append({
            'type': 'text',
            'content': title,
            'style': 'heading1',
            'y_offset': 0
        })

        # Subtitle
        if subtitle:
            self.elements.append({
                'type': 'text',
                'content': subtitle,
                'style': 'heading3',
                'y_offset': 0.2 * inch
            })

        # Horizontal rule
        self.elements.append({
            'type': 'line',
            'y_offset': 0.4 * inch
        })

        self.current_y -= 0.6 * inch

    def add_section_header(self, text: str) -> None:
        """Add section subheader."""
        self.elements.append({
            'type': 'text',
            'content': text,
            'style': 'heading2',
            'y_offset': 0
        })
        self.current_y -= 0.3 * inch

    def add_risk_gauge(self, risk_score: float, risk_label: str) -> None:
        """Add risk gauge visualization."""
        self.elements.append({
            'type': 'risk_gauge',
            'score': risk_score,
            'label': risk_label,
            'height': 2 * inch
        })
        self.current_y -= 2.2 * inch

    def add_evidence_cards(self, evidence_items: List[Dict[str, str]], columns: int = 3) -> None:
        """
        Add evidence cards in grid layout.
        
        Args:
            evidence_items: List of {title, value, icon, color} dicts
            columns: Number of columns in grid
        """
        self.elements.append({
            'type': 'evidence_cards',
            'items': evidence_items,
            'columns': columns
        })
        
        # Estimate height: ~1.5 inches per row
        rows = (len(evidence_items) + columns - 1) // columns
        height = rows * 1.5 * inch
        self.current_y -= height

    def add_timeline(self, events: List[Dict[str, Any]], layout: str = "vertical") -> None:
        """
        Add timeline visualization.
        
        Args:
            events: List of {timestamp, label, description, severity} dicts
            layout: "vertical" (default) or "horizontal"
        """
        self.elements.append({
            'type': 'timeline',
            'events': events,
            'layout': layout
        })
        
        # Estimate height: 0.5 inches per event
        height = len(events) * 0.5 * inch + 0.5 * inch
        self.current_y -= height

    def add_forensic_card(
        self,
        title: str,
        findings: Dict[str, Any],
        icon: Optional[str] = None,
        background_color: Optional[str] = None
    ) -> None:
        """
        Add large forensic findings card (for Authentication page).
        
        Args:
            title: Card title
            findings: Dict of key-value findings
            icon: Icon name
            background_color: Card background color
        """
        self.elements.append({
            'type': 'forensic_card',
            'title': title,
            'findings': findings,
            'icon': icon,
            'background_color': background_color
        })
        
        # Estimate height based on findings count
        height = 0.5 * inch + len(findings) * 0.25 * inch
        self.current_y -= height

    def add_infrastructure_diagram(self, infrastructure: Dict[str, Any]) -> None:
        """Add infrastructure profile visualization."""
        self.elements.append({
            'type': 'infrastructure_diagram',
            'data': infrastructure
        })
        self.current_y -= 3 * inch

    def add_threat_dna_profile(self, threat_data: Dict[str, Any]) -> None:
        """Add threat DNA fingerprint visualization."""
        self.elements.append({
            'type': 'threat_dna',
            'data': threat_data
        })
        self.current_y -= 2.5 * inch

    def add_attribution_flow(self, campaigns: List[Dict[str, Any]]) -> None:
        """Add campaign attribution flow diagram."""
        self.elements.append({
            'type': 'attribution_flow',
            'campaigns': campaigns
        })
        
        height = len(campaigns) * 0.75 * inch + 0.5 * inch
        self.current_y -= height

    def add_evidence_chain(self, evidence_records: List[Dict[str, Any]]) -> None:
        """Add evidence chain of custody visualization."""
        self.elements.append({
            'type': 'evidence_chain',
            'records': evidence_records
        })
        
        height = len(evidence_records) * 0.5 * inch + 0.5 * inch
        self.current_y -= height

    def add_paragraph(self, text: str, style: str = "normal", indent: float = 0) -> None:
        """
        Add paragraph of text.
        
        Args:
            text: Paragraph content
            style: "normal", "emphasis", "warning", "disclaimer"
            indent: Left indent in inches
        """
        self.elements.append({
            'type': 'paragraph',
            'content': text,
            'style': style,
            'indent': indent
        })
        
        # Rough estimate: ~0.1 inch per 10 words
        word_count = len(text.split())
        height = (word_count / 50) * inch
        self.current_y -= height

    def add_key_value_section(self, items: Dict[str, str]) -> None:
        """
        Add key-value pairs section.
        
        Args:
            items: Dict of {key: value}
        """
        self.elements.append({
            'type': 'key_value',
            'items': items
        })
        
        height = len(items) * 0.25 * inch + 0.2 * inch
        self.current_y -= height

    def add_table(
        self,
        data: List[List[str]],
        headers: List[str],
        col_widths: Optional[List[float]] = None
    ) -> None:
        """
        Add table with data.
        
        Args:
            data: List of rows
            headers: Column headers
            col_widths: Column widths in inches (optional)
        """
        self.elements.append({
            'type': 'table',
            'headers': headers,
            'data': data,
            'col_widths': col_widths
        })
        
        height = (len(data) + 1) * 0.3 * inch + 0.2 * inch
        self.current_y -= height

    def add_spacer(self, height: float = 0.2 * inch) -> None:
        """Add vertical spacing."""
        self.elements.append({
            'type': 'spacer',
            'height': height
        })
        self.current_y -= height

    def add_page_break(self) -> None:
        """Add page break."""
        self.elements.append({
            'type': 'page_break'
        })
        self.current_y = self.PAGE_HEIGHT - self.MARGIN_TOP

    def add_footer(self, text: Optional[str] = None) -> None:
        """
        Add page footer.
        
        Args:
            text: Custom footer text (optional)
        """
        if not text:
            text = f"Case ID: {self.case_id} | Page {self.page_number} of {self.total_pages}"

        self.elements.append({
            'type': 'footer',
            'content': text
        })

    def add_disclaimer(self, text: str) -> None:
        """Add disclaimer box (typically at bottom of page)."""
        self.elements.append({
            'type': 'disclaimer',
            'content': text
        })
        
        height = 0.8 * inch
        self.current_y -= height

    def add_confidence_meter(self, label: str, confidence: float) -> None:
        """
        Add confidence/certainty meter.
        
        Args:
            label: Meter label
            confidence: Confidence value 0-100
        """
        self.elements.append({
            'type': 'confidence_meter',
            'label': label,
            'value': confidence
        })
        self.current_y -= 0.6 * inch

    def needs_page_break(self) -> bool:
        """Check if next element would exceed page bounds."""
        return self.current_y < self.MARGIN_BOTTOM + 1 * inch

    def get_remaining_space(self) -> float:
        """Get remaining vertical space on current page in inches."""
        return (self.current_y - self.MARGIN_BOTTOM) / inch

    def get_elements(self) -> List[Dict[str, Any]]:
        """Get all elements added to this page."""
        return self.elements

    def reset(self) -> None:
        """Reset page for reuse."""
        self.elements = []
        self.current_y = self.PAGE_HEIGHT - self.MARGIN_TOP

    @staticmethod
    def create_style_sheet() -> Dict[str, ParagraphStyle]:
        """
        Create custom stylesheet for report typography.
        """
        styles = getSampleStyleSheet()
        
        # Override and add custom styles
        styles['heading1'] = ParagraphStyle(
            'heading1',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor(PageBuilder.COLOR_ACCENT),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )

        styles['heading2'] = ParagraphStyle(
            'heading2',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor(PageBuilder.COLOR_ACCENT),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        )

        styles['heading3'] = ParagraphStyle(
            'heading3',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor(PageBuilder.COLOR_NEUTRAL),
            spaceAfter=6,
            fontName='Helvetica'
        )

        styles['normal_text'] = ParagraphStyle(
            'normal_text',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor("#1F2937"),
            spaceAfter=6,
            leading=14
        )

        styles['emphasis'] = ParagraphStyle(
            'emphasis',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor(PageBuilder.COLOR_ACCENT),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        )

        styles['warning'] = ParagraphStyle(
            'warning',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor(PageBuilder.COLOR_ALERT),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        )

        styles['disclaimer'] = ParagraphStyle(
            'disclaimer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor(PageBuilder.COLOR_NEUTRAL),
            spaceAfter=4,
            leading=10,
            alignment=TA_CENTER
        )

        styles['mono'] = ParagraphStyle(
            'mono',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor("#1F2937"),
            fontName='Courier',
            spaceAfter=6,
            leading=12
        )

        return styles

    @staticmethod
    def rgb_to_hex(r: int, g: int, b: int) -> str:
        """Convert RGB to hex color."""
        return f"#{r:02x}{g:02x}{b:02x}"

    @staticmethod
    def get_threat_color(risk_score: float) -> str:
        """
        Get color based on risk score.
        
        0-30: Safe (green)
        31-60: Moderate (yellow)
        61-85: High (orange)
        86-100: Critical (red)
        """
        if risk_score < 30:
            return "#10B981"  # Green
        elif risk_score < 60:
            return "#F59E0B"  # Amber
        elif risk_score < 86:
            return "#F97316"  # Orange
        else:
            return "#DC2626"  # Red

    @staticmethod
    def get_auth_status_color(status: str) -> str:
        """Get color for authentication status."""
        status_lower = (status or "").lower()
        
        if "pass" in status_lower or "verified" in status_lower:
            return "#10B981"  # Green
        elif "fail" in status_lower or "invalid" in status_lower:
            return "#DC2626"  # Red
        elif "neutral" in status_lower or "none" in status_lower:
            return "#6B7280"  # Grey
        else:
            return "#6B7280"  # Grey
