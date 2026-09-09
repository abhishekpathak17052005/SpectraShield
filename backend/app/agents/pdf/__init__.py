"""
SpectraShield 2.0 Forensic Dossier PDF Generator

Modern investigation narrative with visual storytelling.
Transforms backend forensic analysis into 7-page professional report.

No data fabrication - backend is the single source of truth.

Module Architecture:
- data_transformer: Extract and normalize backend data into dataclasses
- validator: Validate data consistency before PDF generation
- translations: Convert technical terms to user-friendly language
- page_builder: Manage page layout and component positioning
- components: Page component implementations (7 page types)
- visual_elements: ReportLab drawing utilities
- report_builder: Orchestrate end-to-end PDF generation
"""

from .data_transformer import (
    DataTransformer,
    ThreatSnapshot,
    AttackStory,
    RelayHop,
    AuthenticationFindings,
    InfrastructureProfile,
    CampaignSignal,
    EvidenceRecord,
    ThreatDNAProfile,
)

from .validator import (
    DataValidator,
    ValidationWarning,
)

from .translations import (
    LanguageTranslator,
)

from .page_builder import (
    PageBuilder,
)

from .components import (
    PageComponent,
    ComponentRenderContext,
    RiskSnapshot,
    AttackStory as AttackStoryComponent,
    AuthenticationForensics,
    InfrastructureProfile as InfrastructureProfileComponent,
    CampaignIntelligence,
    EvidenceIntegrity,
    ThreatDNAFingerprint,
)

from .visual_elements import (
    VisualElements,
)

from .pii_redactor import (
    PIIRedactor,
    RedactionValidator,
)

from .report_builder import (
    PDFReportBuilder,
)

__all__ = [
    # Data transformation
    "DataTransformer",
    "ThreatSnapshot",
    "AttackStory",
    "RelayHop",
    "AuthenticationFindings",
    "InfrastructureProfile",
    "CampaignSignal",
    "EvidenceRecord",
    "ThreatDNAProfile",
    # Validation
    "DataValidator",
    "ValidationWarning",
    # Translations
    "LanguageTranslator",
    # Page building
    "PageBuilder",
    # Components
    "PageComponent",
    "ComponentRenderContext",
    "RiskSnapshot",
    "AttackStoryComponent",
    "AuthenticationForensics",
    "InfrastructureProfileComponent",
    "CampaignIntelligence",
    "EvidenceIntegrity",
    "ThreatDNAFingerprint",
    # Visual rendering
    "VisualElements",
    # PII Redaction
    "PIIRedactor",
    "RedactionValidator",
    # Report generation
    "PDFReportBuilder",
]
