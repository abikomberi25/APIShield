"""
APIShield — PowerPoint Presentation Generator
Creates APIShield_Technical_Presentation.pptx with 40 slides.
Run from the project root: python scripts/build_presentation.py
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Cm
import copy

# ─── Color palette ────────────────────────────────────────────────────────────
BG_DARK    = RGBColor(0x11, 0x11, 0x1B)   # #11111b  slide background
BG_CARD    = RGBColor(0x1E, 0x1E, 0x2E)   # #1e1e2e  card / header
ACCENT_B   = RGBColor(0x89, 0xB4, 0xFA)   # #89b4fa  blue accent
ACCENT_T   = RGBColor(0x94, 0xE2, 0xD5)   # #94e2d5  teal accent
ACCENT_G   = RGBColor(0xA6, 0xE3, 0xA1)   # #a6e3a1  green
ACCENT_R   = RGBColor(0xF3, 0x8B, 0xA8)   # #f38ba8  red
ACCENT_Y   = RGBColor(0xF9, 0xE2, 0xAF)   # #f9e2af  yellow
TEXT_MAIN  = RGBColor(0xCD, 0xD6, 0xF4)   # #cdd6f4
TEXT_SUB   = RGBColor(0xA6, 0xAD, 0xC8)   # #a6adc8
TEXT_MUTED = RGBColor(0x6C, 0x70, 0x86)   # #6c7086
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def set_slide_bg(slide, color: RGBColor):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_textbox(slide, text, left, top, width, height,
                font_size=14, bold=False, color=TEXT_MAIN,
                align=PP_ALIGN.LEFT, wrap=True, italic=False):
    txb = slide.shapes.add_textbox(
        Inches(left), Inches(top), Inches(width), Inches(height))
    tf = txb.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(font_size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    return txb


def add_rect(slide, left, top, width, height, fill_color, line_color=None):
    shape = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.RECTANGLE
        Inches(left), Inches(top), Inches(width), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if line_color:
        shape.line.color.rgb = line_color
    else:
        shape.line.fill.background()
    return shape


def add_header_bar(slide, title, subtitle=None):
    """Dark header bar across the top of the slide."""
    add_rect(slide, 0, 0, 13.33, 1.1, BG_CARD)
    add_textbox(slide, title, 0.3, 0.08, 12.5, 0.55,
                font_size=22, bold=True, color=ACCENT_B)
    if subtitle:
        add_textbox(slide, subtitle, 0.3, 0.62, 12.5, 0.35,
                    font_size=11, color=TEXT_SUB)


def add_bullet_box(slide, items, left, top, width, height,
                   title=None, font_size=12, bullet="•",
                   title_color=ACCENT_T, item_color=TEXT_MAIN):
    """Render a list of bullet items inside a card rect."""
    add_rect(slide, left, top, width, height, BG_CARD)
    y = top + 0.12
    if title:
        add_textbox(slide, title, left + 0.15, y, width - 0.25, 0.3,
                    font_size=11, bold=True, color=title_color)
        y += 0.33
    for item in items:
        add_textbox(slide, f"{bullet}  {item}", left + 0.15, y,
                    width - 0.3, 0.28, font_size=font_size, color=item_color)
        y += 0.3


def add_code_box(slide, code, left, top, width, height, font_size=9):
    """Monospaced code block on dark background."""
    add_rect(slide, left, top, width, height, RGBColor(0x18, 0x18, 0x25))
    add_textbox(slide, code, left + 0.1, top + 0.08, width - 0.2,
                height - 0.16, font_size=font_size,
                color=ACCENT_G, wrap=True)


def add_two_column_cards(slide, left_title, left_items, right_title, right_items,
                         top=1.25, height=4.5):
    add_bullet_box(slide, left_items, 0.2, top, 6.3, height,
                   title=left_title)
    add_bullet_box(slide, right_items, 6.8, top, 6.3, height,
                   title=right_title)


def add_attack_flow(slide, top=4.2):
    """Standard attack→detect→defend→verify flow diagram."""
    steps = ["ATTACK", "AUTHENTICATE", "ROUTE HANDLER", "DETECT", "DECIDE", "RESPOND", "VERIFY"]
    colors = [ACCENT_R, ACCENT_Y, ACCENT_B, ACCENT_T, ACCENT_B, ACCENT_G, ACCENT_T]
    w = 1.7
    gap = 0.05
    x = 0.2
    for i, (step, col) in enumerate(zip(steps, colors)):
        add_rect(slide, x, top, w, 0.45, col)
        add_textbox(slide, step, x, top, w, 0.45,
                    font_size=8, bold=True, color=BG_DARK, align=PP_ALIGN.CENTER)
        if i < len(steps) - 1:
            add_textbox(slide, "→", x + w, top, 0.05, 0.45,
                        font_size=10, color=TEXT_SUB, align=PP_ALIGN.CENTER)
        x += w + gap + 0.05


def slide_number(slide, n, total=40):
    add_textbox(slide, f"{n} / {total}", 12.6, 7.0, 0.65, 0.25,
                font_size=9, color=TEXT_MUTED, align=PP_ALIGN.RIGHT)


# ─── Build slides ─────────────────────────────────────────────────────────────

def build_prs() -> Presentation:
    prs = Presentation()
    prs.slide_width  = Inches(13.33)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]   # completely blank

    slides_data = []   # (slide_obj, number)

    def new_slide():
        sl = prs.slides.add_slide(blank_layout)
        set_slide_bg(sl, BG_DARK)
        return sl

    # ── SLIDE 1 — Title ──────────────────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 7.5, BG_DARK)
    add_rect(s, 0, 0, 13.33, 0.08, ACCENT_B)
    add_rect(s, 0, 7.42, 13.33, 0.08, ACCENT_B)
    add_textbox(s, "🛡  APIShield", 1.0, 1.6, 11.33, 1.1,
                font_size=46, bold=True, color=ACCENT_B, align=PP_ALIGN.CENTER)
    add_textbox(s,
                "A Controlled Platform for Evaluating Detection and Mitigation\n"
                "of OWASP API Security Risks",
                1.0, 2.85, 11.33, 0.9,
                font_size=16, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_textbox(s,
                "Attack, Detect, Defend, Verify: A Reproducible API Security Testing Framework",
                1.0, 3.85, 11.33, 0.5,
                font_size=12, italic=True, color=TEXT_SUB, align=PP_ALIGN.CENTER)
    add_rect(s, 4.5, 4.55, 4.33, 0.04, ACCENT_T)
    add_textbox(s,
                "Python 3.12 • FastAPI • SQLite • React • Vite • bcrypt • PyJWT",
                1.0, 4.8, 11.33, 0.4,
                font_size=11, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_textbox(s, "October 2026", 1.0, 5.45, 11.33, 0.35,
                font_size=11, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    slide_number(s, 1)

    # ── SLIDE 2 — The Problem ────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "The API Security Problem",
                   "APIs are now the #1 attack surface in modern applications")
    add_bullet_box(s, [
        "APIs exposed critical data in 83% of web traffic (Akamai, 2023)",
        "OWASP API Security Top 10 (2023) defines the most critical categories",
        "Developers build APIs with authentication but often skip authorization",
        "Lab environments for teaching API security are rare and hard to reproduce",
        "Testing real APIs is unsafe — production data exposure, legal risk",
        "Existing tools (OWASP WebGoat, DVWA) focus on web apps, not API-first architectures",
    ], 0.2, 1.2, 8.8, 4.5, title="Why API Security Needs a Dedicated Lab Platform")
    add_bullet_box(s, [
        "API1: Object-level access control broken",
        "API2: Brute-force / credential stuffing",
        "API3: Excessive property disclosure",
        "API4: Rate limiting absent or ineffective",
        "API5: Function-level authorization missing",
        "API9: Forgotten deprecated routes still active",
    ], 9.8, 1.2, 3.3, 4.5, title="OWASP Top 10 (2023) Scope")
    slide_number(s, 2)

    # ── SLIDE 3 — Objectives ─────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Project Objectives and Research Questions")
    add_bullet_box(s, [
        "RQ1: Can a controlled FastAPI application safely implement intentional OWASP vulnerabilities?",
        "RQ2: Can detection be verified by correlating HTTP responses with security event IDs?",
        "RQ3: Can a runtime defense toggle disable a vulnerability without code changes?",
        "RQ4: Is each experiment reproducible from a clean state?",
    ], 0.2, 1.25, 12.93, 1.8, title="Research Questions")
    add_two_column_cards(s,
        "Primary Objectives", [
            "Implement 6 OWASP API 2023 categories (API1–5, API9)",
            "Dual-mode safety: vulnerable behavior only in explicit lab mode",
            "Detection engine that logs auditable SecurityEvents",
            "Attack scripts with pre-flight allowlist validation",
            "156 automated tests covering all modules",
            "React dashboard for real-time inspection",
        ],
        "Non-objectives", [
            "Not a production-ready security product",
            "Not a comprehensive OWASP Top 10 scanner",
            "No multi-worker or distributed deployment",
            "No persistent authentication sessions",
            "API7 (SSRF) and API8 (Misconfiguration) not implemented",
        ],
        top=3.15, height=3.8)
    slide_number(s, 3)

    # ── SLIDE 4 — OWASP Scope ────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "OWASP API Security Top 10 (2023) — Project Scope")
    rows = [
        ("API1:2023", "BOLA",                    "GET /items/{id}",       "bola",                       "✅ Implemented"),
        ("API2:2023", "Broken Authentication",   "POST /auth/login",       "auth_hardening",             "✅ Implemented"),
        ("API3:2023", "BOPLA / Data Exposure",   "GET /items/{id}?include_internal=true", "schema_validation", "✅ Implemented"),
        ("API4:2023", "Rate Limiting",           "GET /items/{id} (burst)", "rate_limit",               "✅ Implemented"),
        ("API5:2023", "BFLA",                    "GET /admin/events",      "rbac",                       "✅ Implemented"),
        ("API6:2023", "Unrestricted Mass Assign","—",                       "—",                         "❌ Not in scope"),
        ("API7:2023", "SSRF",                    "—",                       "—",                         "❌ Not in scope"),
        ("API8:2023", "Security Misconfig",      "—",                       "—",                         "❌ Not in scope"),
        ("API9:2023", "Inventory Management",    "GET /api/v0/items/{id}", "deprecated_route_protection","✅ Implemented"),
        ("API10:2023","Unsafe API Consumption",  "—",                       "—",                         "❌ Not in scope"),
    ]
    col_w = [1.4, 2.4, 3.2, 2.5, 1.8]
    headers = ["OWASP ID", "Category", "Endpoint", "Defense Toggle", "Status"]
    header_colors = [ACCENT_B, ACCENT_B, ACCENT_B, ACCENT_B, ACCENT_B]
    y = 1.25
    x_starts = [0.15, 1.6, 4.05, 7.3, 9.85]
    for i, (h, c) in enumerate(zip(headers, header_colors)):
        add_rect(s, x_starts[i], y, col_w[i], 0.32, BG_CARD)
        add_textbox(s, h, x_starts[i]+0.05, y, col_w[i], 0.32,
                    font_size=10, bold=True, color=ACCENT_B)
    y += 0.32
    for j, row in enumerate(rows):
        bg = RGBColor(0x18,0x18,0x25) if j%2==0 else BG_CARD
        implemented = "✅" in row[4]
        for i, cell in enumerate(row):
            add_rect(s, x_starts[i], y, col_w[i], 0.3, bg)
            col = ACCENT_G if implemented else TEXT_MUTED
            if i == 4:
                col = ACCENT_G if implemented else ACCENT_R
            add_textbox(s, cell, x_starts[i]+0.05, y, col_w[i]-0.05, 0.3,
                        font_size=9, color=col)
        y += 0.3
    slide_number(s, 4)

    # ── SLIDE 5 — Motivation ────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Motivation — Why Controlled Experiments?",
                   "Security education requires safe, reproducible attack demonstrations")
    add_bullet_box(s, [
        "REAL-WORLD RISK: Production APIs cannot be deliberately broken for teaching",
        "REPRODUCIBILITY: Lab experiments must yield identical results across fresh installs",
        "VERIFIABILITY: Each experiment produces a traceable SecurityEvent with a unique ID",
        "SAFETY: Vulnerable behavior requires BOTH lab mode AND explicit defense-toggle OFF",
        "ISOLATION: In-memory SQLite, no network egress, localhost-only binding",
        "AUDITABILITY: All security events logged; no credentials or tokens ever persisted",
    ], 0.2, 1.25, 12.93, 3.3, title="Controlled Experiment Design Rationale")
    add_two_column_cards(s,
        "Dual-Mode Safety Gate", [
            "APISHIELD_LAB_MODE=false (default) → all attacks silently blocked",
            "APISHIELD_LAB_MODE=true → attack scripts can toggle defenses",
            "Lab mode is read-only after startup — cannot be changed via HTTP",
            "Each defense toggle is independently controlled",
            "Fail-closed: if event logging fails → request denied (HTTP 500)",
        ],
        "What Each Experiment Proves", [
            "Vulnerable run → HTTP success + restricted data + 'detected' event",
            "Defended run → HTTP 4xx + no data + 'blocked' event",
            "Event correlation by ID confirms the current run's event",
            "Does NOT prove production-readiness or scalability",
            "Does NOT prove all OWASP categories are covered",
        ],
        top=4.6, height=2.7)
    slide_number(s, 5)

    # ── SLIDE 6 — Milestones ─────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Development Methodology and Milestones")
    milestones = [
        ("M0", "m0-skeleton-complete",          "Project skeleton, .gitignore, requirements.txt"),
        ("M1-A/B/C/D", "m1-d-complete",         "Health endpoint → User model → bcrypt auth → JWT"),
        ("M2", "m2-security-gateway-complete",  "Security middleware, DefenseManager, admin routes"),
        ("M3", "m3-bola-complete",               "API1 BOLA: ownership check, detect_bola, attack script"),
        ("M4-A", "m4-a-bfla-complete",           "API5 BFLA: rbac detection on GET /admin/events"),
        ("M4-B", "m4-b-bopla-complete",          "API3 BOPLA: schema_validation, ItemInternalResponse"),
        ("M4-C + M5", "m4-c + m5",               "API2 Broken Auth + API4 Rate Limiting"),
        ("M6", "m6-dashboard-complete",          "React Vite dashboard: 4 tabs, dark theme"),
        ("M7", "m7-inventory-complete",          "API9 Inventory: deprecated route + protection toggle"),
        ("M8", "m8-evaluation-complete",         "evaluate.py, FINAL_REPORT.md, results README"),
        ("Docker", "—",                          "Dockerfile + docker-compose.yml, non-root user"),
    ]
    y = 1.3
    for tag, commit, desc in milestones:
        add_rect(s, 0.2, y, 1.5, 0.32, BG_CARD)
        add_textbox(s, tag, 0.25, y, 1.4, 0.32, font_size=10, bold=True, color=ACCENT_B)
        add_rect(s, 1.75, y, 3.0, 0.32, RGBColor(0x18,0x18,0x25))
        add_textbox(s, commit, 1.8, y, 2.9, 0.32, font_size=8, color=TEXT_MUTED)
        add_rect(s, 4.8, y, 8.35, 0.32, BG_CARD)
        add_textbox(s, desc, 4.85, y, 8.25, 0.32, font_size=10, color=TEXT_MAIN)
        y += 0.35
    add_textbox(s, "git log --oneline --decorate  →  16 commits, 14 milestone tags",
                0.2, y+0.1, 12.93, 0.3, font_size=9, color=TEXT_MUTED)
    slide_number(s, 6)

    # ── SLIDE 7 — Technology Stack ───────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Technology Stack — Choices and Rationale")
    stack = [
        ("Python 3.12",     "Runtime",       "Type hints, async, modern stdlib; version with best FastAPI support"),
        ("FastAPI 0.115",   "Web Framework", "ASGI, automatic OpenAPI docs, Pydantic v2 validation, Depends() injection"),
        ("SQLAlchemy 2.0",  "ORM",           "Declarative models, session management, PRAGMA foreign_keys enforcement"),
        ("SQLite",          "Database",      "File-local, no server process, ideal for reproducible lab environments"),
        ("bcrypt 4",        "Password Hash", "Adaptive cost (rounds=12); constant-time compare; resists offline brute-force"),
        ("PyJWT 2.8",       "JWT Auth",      "HS256 signing, claims validation, expiry enforcement"),
        ("python-dotenv",   "Config",        "Loads .env; JWT_SECRET sourced from environment, never hardcoded"),
        ("httpx",           "HTTP Client",   "Used by TestClient (sync) and attack scripts; connection reuse"),
        ("pytest 8",        "Testing",       "156 tests; in-memory SQLite fixture; autouse reset fixtures"),
        ("React 18 + Vite", "Frontend",      "Component-based dashboard; fast HMR; no SSR needed for local lab"),
        ("Docker",          "Container",     "Reproducible deployment; non-root user; health check; env-based secrets"),
    ]
    y = 1.25
    for tech, cat, reason in stack:
        add_rect(s, 0.15, y, 1.8, 0.29, BG_CARD)
        add_textbox(s, tech, 0.2, y, 1.7, 0.29, font_size=9, bold=True, color=ACCENT_B)
        add_rect(s, 2.0, y, 1.4, 0.29, RGBColor(0x18,0x18,0x25))
        add_textbox(s, cat, 2.05, y, 1.3, 0.29, font_size=9, color=ACCENT_T)
        add_rect(s, 3.45, y, 9.7, 0.29, BG_CARD)
        add_textbox(s, reason, 3.5, y, 9.6, 0.29, font_size=9, color=TEXT_MAIN)
        y += 0.32
    slide_number(s, 7)

    # ── SLIDE 8 — Architecture Overview ─────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "High-Level System Architecture")
    # Browser box
    add_rect(s, 0.2, 1.3, 2.2, 0.7, BG_CARD)
    add_textbox(s, "Browser\n(React Vite)", 0.2, 1.3, 2.2, 0.7,
                font_size=10, color=ACCENT_B, align=PP_ALIGN.CENTER)
    # Attack scripts box
    add_rect(s, 0.2, 2.3, 2.2, 0.7, BG_CARD)
    add_textbox(s, "Attack Scripts\n(attacks/*.py)", 0.2, 2.3, 2.2, 0.7,
                font_size=10, color=ACCENT_R, align=PP_ALIGN.CENTER)
    # Arrows
    add_textbox(s, "HTTP/JSON →", 2.45, 1.55, 1.2, 0.3, font_size=9, color=TEXT_MUTED)
    add_textbox(s, "HTTP/JSON →", 2.45, 2.55, 1.2, 0.3, font_size=9, color=TEXT_MUTED)
    # FastAPI block
    add_rect(s, 3.7, 1.1, 4.5, 2.2, RGBColor(0x18,0x18,0x25))
    add_textbox(s, "FastAPI Application (ASGI / Uvicorn)",
                3.75, 1.12, 4.4, 0.35, font_size=9, bold=True, color=ACCENT_B)
    add_rect(s, 3.8, 1.55, 4.3, 0.35, BG_CARD)
    add_textbox(s, "SecurityGatewayMiddleware (X-Response-Time-Ms)",
                3.85, 1.55, 4.2, 0.35, font_size=8, color=TEXT_SUB)
    add_rect(s, 3.8, 1.95, 1.3, 0.6, BG_CARD)
    add_textbox(s, "auth\nrouter", 3.85, 1.95, 1.2, 0.6, font_size=8, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_rect(s, 5.15, 1.95, 1.3, 0.6, BG_CARD)
    add_textbox(s, "items\nrouter", 5.2, 1.95, 1.2, 0.6, font_size=8, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_rect(s, 6.5, 1.95, 1.5, 0.6, BG_CARD)
    add_textbox(s, "admin +\ninventory", 6.55, 1.95, 1.4, 0.6, font_size=8, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    # Detection modules
    add_rect(s, 3.7, 3.45, 4.5, 0.45, BG_CARD)
    add_textbox(s, "detection/ : bola  bopla  rbac  auth  rate_limit  inventory",
                3.75, 3.45, 4.4, 0.45, font_size=8, color=ACCENT_T)
    # Security layer
    add_rect(s, 3.7, 4.0, 4.5, 0.45, BG_CARD)
    add_textbox(s, "backend/security/ : DefenseManager  LoginAttemptTracker  RateLimiter",
                3.75, 4.0, 4.4, 0.45, font_size=8, color=ACCENT_Y)
    # DB
    add_rect(s, 8.4, 1.5, 2.4, 1.5, BG_CARD)
    add_textbox(s, "SQLite DB\napishield.db\n\nusers | items\nsecurity_events",
                8.45, 1.5, 2.3, 1.5, font_size=9, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_textbox(s, "SQLAlchemy\n→", 8.0, 2.1, 0.35, 0.4, font_size=8, color=TEXT_MUTED)
    # Results
    add_rect(s, 8.4, 3.2, 2.4, 0.9, BG_CARD)
    add_textbox(s, "docs/results/\n*.json files\n(experiment output)",
                8.45, 3.2, 2.3, 0.9, font_size=8, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    # Frontend results
    add_rect(s, 0.2, 3.45, 2.2, 0.55, BG_CARD)
    add_textbox(s, "Dashboard reads\nresult JSON files",
                0.2, 3.45, 2.2, 0.55, font_size=8, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    slide_number(s, 8)

    # ── SLIDE 9 — Repository Structure ───────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Repository Structure and Module Responsibilities")
    tree = [
        ("apishield/",                "Project root"),
        ("  backend/",                "FastAPI application package"),
        ("    main.py",               "App factory, router mounting, lifespan"),
        ("    config.py",             "JWT_SECRET hardening, lab-mode gate"),
        ("    database.py",           "SQLAlchemy engine, get_db() dependency"),
        ("    auth/{security,deps}.py","bcrypt, JWT creation/validation, Bearer deps"),
        ("    routes/{auth,items,admin,inventory}.py", "HTTP route handlers"),
        ("    security/{defenses,events,lockout,rate_limiter,middleware}.py", "Runtime security"),
        ("    models/{user,item,event}.py", "SQLAlchemy ORM models"),
        ("    seed.py",               "Idempotent synthetic data seeder"),
        ("  detection/",              "OWASP detection engines (one per category)"),
        ("  attacks/",                "Controlled attack scripts (one per category)"),
        ("  tests/",                  "156 pytest tests; conftest.py with autouse fixtures"),
        ("  frontend/src/",           "React 18 dashboard (App.jsx, api.js)"),
        ("  scripts/evaluate.py",     "M8 multi-run evaluation framework"),
        ("  docs/",                   "Architecture, security model, final report, results"),
        ("  Dockerfile + docker-compose.yml", "Container support"),
    ]
    y = 1.25
    for path, desc in tree:
        indent = len(path) - len(path.lstrip())
        col = ACCENT_B if path.strip().endswith('/') else TEXT_MAIN
        if path.strip().startswith('#'):
            col = TEXT_MUTED
        add_textbox(s, path, 0.2 + indent*0.05, y, 5.5, 0.27, font_size=9, color=col)
        add_textbox(s, desc, 5.9, y, 7.2, 0.27, font_size=9, color=TEXT_SUB)
        y += 0.27
    slide_number(s, 9)

    # ── SLIDE 10 — Backend Init ──────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Backend Initialization and FastAPI Application Lifecycle",
                   "backend/main.py  •  backend/config.py  •  backend/database.py")
    add_code_box(s, (
        "# backend/main.py\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    Base.metadata.create_all(bind=engine)   # create tables if absent\n"
        "    yield                                    # app runs\n\n"
        "app = FastAPI(title='APIShield', lifespan=lifespan)\n"
        "app.add_middleware(SecurityGatewayMiddleware)\n"
        "app.include_router(auth_router,      prefix='/auth')\n"
        "app.include_router(items_router,     prefix='/items')\n"
        "app.include_router(admin_router,     prefix='/admin')\n"
        "app.include_router(inventory_router)  # owns its own prefixes"
    ), 0.2, 1.25, 7.5, 3.0)
    add_bullet_box(s, [
        "Uvicorn serves over ASGI (async gateway)",
        "lifespan() runs table creation on startup",
        "Router per domain: auth, items, admin, inventory",
        "Middleware wraps all routes for latency tracking",
        "config.py: JWT_SECRET from env or ephemeral random",
        "APISHIELD_LAB_MODE read once at startup — immutable",
        "HOST hardcoded to 127.0.0.1 (localhost-only binding)",
    ], 7.9, 1.25, 5.2, 5.5, title="Key Startup Decisions")
    slide_number(s, 10)

    # ── SLIDE 11 — Database Schema ───────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Database Schema and Entity Relationships",
                   "backend/models/{user.py, item.py, event.py}  •  SQLite  •  PRAGMA foreign_keys=ON")
    # Users table
    add_rect(s, 0.2, 1.3, 3.8, 2.5, BG_CARD)
    add_textbox(s, "users", 0.25, 1.32, 3.7, 0.35, font_size=12, bold=True, color=ACCENT_B)
    for field, typ, note in [
        ("id (PK)", "INTEGER", "auto-increment"),
        ("username", "TEXT UNIQUE", "indexed, not null"),
        ("hashed_password", "TEXT", "bcrypt, rounds=12"),
        ("role", "TEXT", "'user' | 'admin'"),
    ]:
        add_textbox(s, f"  {field}", 0.25, None, 1.5, 0.28, font_size=9, color=ACCENT_T)
        add_textbox(s, typ, 1.8, None, 1.2, 0.28, font_size=9, color=TEXT_MAIN)
        add_textbox(s, note, 3.05, None, 0.9, 0.28, font_size=8, color=TEXT_MUTED)
    # Items table
    add_rect(s, 4.3, 1.3, 4.5, 3.2, BG_CARD)
    add_textbox(s, "items", 4.35, 1.32, 4.4, 0.35, font_size=12, bold=True, color=ACCENT_B)
    item_fields = [
        ("id (PK)", "INTEGER", ""),
        ("title", "TEXT", "not null"),
        ("description", "TEXT", "nullable"),
        ("owner_id (FK)", "INTEGER", "→ users.id"),
        ("internal_notes", "TEXT", "BOPLA restricted"),
        ("is_confidential", "BOOLEAN", "BOPLA restricted"),
    ]
    y2 = 1.72
    for field, typ, note in item_fields:
        add_textbox(s, f"  {field}", 4.35, y2, 1.9, 0.28, font_size=9, color=ACCENT_T)
        add_textbox(s, typ, 6.3, y2, 1.3, 0.28, font_size=9, color=TEXT_MAIN)
        add_textbox(s, note, 7.65, y2, 1.1, 0.28, font_size=8, color=TEXT_MUTED)
        y2 += 0.3
    # Events table
    add_rect(s, 9.0, 1.3, 4.15, 5.5, BG_CARD)
    add_textbox(s, "security_events", 9.05, 1.32, 4.05, 0.35, font_size=12, bold=True, color=ACCENT_B)
    ev_fields = [
        ("id (PK)", "INTEGER"),
        ("timestamp", "DATETIME UTC"),
        ("user_id (FK)", "INTEGER → users"),
        ("endpoint", "TEXT"),
        ("method", "TEXT"),
        ("object_id", "TEXT nullable"),
        ("owasp_category", "TEXT"),
        ("severity", "LOW/MED/HIGH/CRIT"),
        ("rule_name", "TEXT"),
        ("action", "'detected'|'blocked'"),
    ]
    y3 = 1.72
    for f, t in ev_fields:
        add_textbox(s, f"  {f}", 9.05, y3, 2.1, 0.28, font_size=9, color=ACCENT_T)
        add_textbox(s, t, 11.2, y3, 1.9, 0.28, font_size=9, color=TEXT_MAIN)
        y3 += 0.3
    # Relationship
    add_textbox(s, "1:N", 4.1, 2.5, 0.18, 0.3, font_size=11, bold=True, color=ACCENT_Y)
    add_textbox(s, "1:N (optional)", 8.75, 2.5, 0.22, 0.3, font_size=8, color=ACCENT_Y)
    add_textbox(s,
        "Note: internal_notes and is_confidential are BOPLA experiment properties only — "
        "never returned in normal ItemResponse.",
        0.2, 6.9, 12.93, 0.35, font_size=9, color=TEXT_MUTED)
    slide_number(s, 11)

    # ── SLIDE 12 — Registration and Password Hashing ─────────────────────────
    s = new_slide()
    add_header_bar(s, "User Registration and bcrypt Password Hashing",
                   "backend/routes/auth.py  •  backend/auth/security.py")
    add_code_box(s, (
        "# backend/auth/security.py\n"
        "def hash_password(password: str) -> str:\n"
        "    salt = bcrypt.gensalt(rounds=12)   # 2^12 = 4096 KDF rounds\n"
        "    return bcrypt.hashpw(password.encode(), salt).decode()\n\n"
        "def verify_password(plain, hashed) -> bool:\n"
        "    # constant-time comparison — no timing side channel\n"
        "    return bcrypt.checkpw(plain.encode(), hashed.encode())\n\n"
        "# Registration endpoint rejects 'role' field (extra='forbid')\n"
        "class UserRegisterRequest(BaseModel):\n"
        "    model_config = ConfigDict(extra='forbid')\n"
        "    username: str = Field(..., min_length=3, max_length=50)\n"
        "    password: str = Field(..., min_length=8, max_length=72)"
    ), 0.2, 1.25, 7.3, 3.5)
    add_bullet_box(s, [
        "POST /auth/register → 201 Created",
        "Pydantic model with extra='forbid' — role injection rejected",
        "Role always assigned as 'user' by server — never from client",
        "bcrypt with 12 rounds: ~250ms hash time; GPU brute-force resistant",
        "Random salt per hash — identical passwords produce different hashes",
        "Stored hash: $2b$12$<22-char-salt><31-char-hash>",
        "verify_password uses constant-time comparison (timing-safe)",
        "Seeded users: alice, bob (user), admin — synthetic passwords only",
    ], 7.6, 1.25, 5.5, 5.0, title="Registration Security Properties")
    slide_number(s, 12)

    # ── SLIDE 13 — JWT ───────────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "JWT Generation, Validation and Bearer Authentication",
                   "backend/auth/security.py  •  backend/auth/deps.py  •  backend/config.py")
    add_code_box(s, (
        "# JWT token creation — backend/auth/security.py\n"
        "payload = {\n"
        "    'sub':      str(user.id),          # stable numeric identity\n"
        "    'username': user.username,          # informational only\n"
        "    'role':     user.role,              # 'user' | 'admin'\n"
        "    'iat':      int(now.timestamp()),\n"
        "    'exp':      int((now + timedelta(minutes=30)).timestamp()),\n"
        "}\n"
        "token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')\n\n"
        "# Validation — backend/auth/deps.py\n"
        "payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])\n"
        "# Raises jwt.ExpiredSignatureError or jwt.PyJWTError on failure"
    ), 0.2, 1.25, 7.3, 3.5)
    add_bullet_box(s, [
        "Algorithm: HS256 (HMAC-SHA256 — symmetric)",
        "Token lifetime: 30 minutes (ACCESS_TOKEN_EXPIRE_MINUTES)",
        "JWT_SECRET: ≥32 chars from env; else ephemeral random + WARNING",
        "Bearer scheme: Authorization: Bearer <token>",
        "get_current_user() dep: extracts + verifies on every protected route",
        "require_admin() dep: chains get_current_user + role=='admin' check",
        "Payload never contains password, hash, or Authorization header",
        "Token held in React component state only — not localStorage",
    ], 7.6, 1.25, 5.5, 5.0, title="JWT Security Properties")
    slide_number(s, 13)

    # ── SLIDE 14 — Request Lifecycle ─────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "HTTP Request Lifecycle — End to End",
                   "From client to response: middleware → auth → route → detection → event")
    steps_detail = [
        ("1", "Client", "Browser or attack script sends HTTP request to 127.0.0.1:8000"),
        ("2", "Uvicorn (ASGI)", "Accepts connection, hands to SecurityGatewayMiddleware"),
        ("3", "Middleware", "Records start time; calls next(); appends X-Response-Time-Ms"),
        ("4", "FastAPI Router", "Matches path+method; resolves Depends() chain"),
        ("5", "get_current_user()", "Extracts Bearer token; verifies JWT; loads User from DB"),
        ("6", "check_rate_limit()", "Keys by user ID; checks fixed window; optionally emits event"),
        ("7", "Route Handler", "Business logic: ownership check, BOLA, BOPLA, BFLA decisions"),
        ("8", "Detection Engine", "detect_*() logs SecurityEvent; action='detected'|'blocked'"),
        ("9", "Defense Decision", "If defense ON: raise HTTP 403/429. If OFF: allow (vulnerable)"),
        ("10", "Pydantic Response", "Validated response model — strips unrequested fields"),
        ("11", "Client receives", "JSON body + X-Response-Time-Ms header"),
    ]
    y = 1.3
    for num, stage, detail in steps_detail:
        add_rect(s, 0.15, y, 0.4, 0.29, ACCENT_B)
        add_textbox(s, num, 0.15, y, 0.4, 0.29, font_size=9, bold=True,
                    color=BG_DARK, align=PP_ALIGN.CENTER)
        add_rect(s, 0.6, y, 1.9, 0.29, BG_CARD)
        add_textbox(s, stage, 0.65, y, 1.85, 0.29, font_size=9, bold=True, color=ACCENT_T)
        add_rect(s, 2.55, y, 10.6, 0.29, RGBColor(0x18,0x18,0x25))
        add_textbox(s, detail, 2.6, y, 10.5, 0.29, font_size=9, color=TEXT_MAIN)
        y += 0.32
    slide_number(s, 14)

    # ── SLIDE 15 — Middleware ────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Security Gateway Middleware and Response Headers",
                   "backend/security/middleware.py  •  SecurityGatewayMiddleware")
    add_code_box(s, (
        "# backend/security/middleware.py\n"
        "class SecurityGatewayMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        start = time.perf_counter()\n"
        "        response = await call_next(request)\n"
        "        elapsed_ms = (time.perf_counter() - start) * 1000.0\n"
        "        response.headers['X-Response-Time-Ms'] = f'{elapsed_ms:.2f}'\n"
        "        return response"
    ), 0.2, 1.25, 7.0, 2.5)
    add_bullet_box(s, [
        "Added via app.add_middleware(SecurityGatewayMiddleware)",
        "Wraps ALL routes — zero auth, DB, or body inspection in middleware",
        "Latency measured with perf_counter() (monotonic, high-resolution)",
        "Header X-Response-Time-Ms visible in every HTTP response",
        "Auth, authorization, rate-limiting → route-level Depends() only",
        "Deliberate: avoids mixing concerns (OWASP recommendation)",
    ], 7.4, 1.25, 5.7, 3.8, title="Design Philosophy")
    add_bullet_box(s, [
        "test_middleware.py — 3 tests confirm header present on all routes",
        "Middleware does NOT block, filter, or inspect request body",
        "No CORS middleware currently configured (local lab only)",
        "No security headers (X-Frame-Options etc.) — documented limitation",
    ], 0.2, 3.9, 12.93, 1.8, title="Test Coverage and Limitations")
    slide_number(s, 15)

    # ── SLIDE 16 — Defense Manager ───────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Runtime Defense Manager and Administrator Endpoints",
                   "backend/security/defenses.py  •  backend/routes/admin.py")
    add_code_box(s, (
        "# backend/security/defenses.py\n"
        "DEFAULT_DEFENSES = {\n"
        "    'bola': False,  'auth_hardening': False,\n"
        "    'schema_validation': False,  'rate_limit': False,\n"
        "    'rbac': False,  'deprecated_route_protection': False,\n"
        "}\n\n"
        "class DefenseManager:\n"
        "    def update_defenses(self, updates):  # validates key + bool type\n"
        "    def reset(self):                     # test isolation\n\n"
        "defense_manager = DefenseManager()   # process-scope singleton"
    ), 0.2, 1.25, 6.8, 2.8)
    add_bullet_box(s, [
        "GET  /admin/defenses          → returns all toggle states",
        "PATCH /admin/defenses         → updates one or more toggles",
        "GET  /admin/lab-mode          → read-only lab mode status",
        "GET  /admin/events            → paginated security events (BFLA endpoint)",
        "GET  /admin/inventory         → full API route inventory",
        "POST /auth/login              → public (no auth required)",
        "POST /auth/register           → public",
        "GET  /items/{id}              → requires valid JWT",
        "GET  /api/v0/items/{id}       → deprecated route (lab mode only)",
    ], 7.15, 1.25, 6.0, 3.8, title="Key Admin Endpoints")
    add_bullet_box(s, [
        "All admin routes protected by require_admin() dependency",
        "DefenseUpdate model: extra='forbid'; unknown flags rejected 422",
        "All 6 toggles default to False — safe mode at startup",
        "State is in-memory only — lost on server restart",
        "Test conftest resets defense_manager.reset() before/after every test",
    ], 0.2, 4.15, 12.93, 2.05, title="Safety Properties")
    slide_number(s, 16)

    # ── SLIDE 17 — Safe vs Lab Mode ──────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Safe Mode vs. Experimental Lab Mode",
                   "backend/config.py  •  APISHIELD_LAB_MODE environment variable")
    add_two_column_cards(s,
        "SAFE MODE (default)", [
            "$env:APISHIELD_LAB_MODE = 'false'  (or unset)",
            "All vulnerabilities suppressed regardless of toggle states",
            "Cross-user item access → immediate HTTP 403",
            "include_internal=true → sanitized response, no event",
            "Deprecated route /api/v0/items/* → 404 Not Found",
            "Login brute-force tracked but no events emitted",
            "BFLA attempt (non-admin /admin/events) → 403",
        ],
        "LAB MODE (explicit opt-in)", [
            "$env:APISHIELD_LAB_MODE = 'true'  (before startup)",
            "Read once at import time — cannot be changed via HTTP",
            "Each defense toggle independently controls one vulnerability",
            "Toggle OFF = vulnerable run; Toggle ON = defended run",
            "Attack scripts verify lab mode before any experiment",
            "All events emitted (detected or blocked) and verified",
            "Lab mode status readable: GET /admin/lab-mode",
        ],
        top=1.25, height=3.8)
    add_bullet_box(s, [
        "SAFETY GATE: vulnerable behavior requires lab_mode=True AND defense toggle=False",
        "Two independent conditions must both be true — defense-in-depth design",
        "APISHIELD_LAB_MODE is read from os.getenv() at module import; set_lab_mode() for tests only",
        "Attack scripts call GET /admin/lab-mode and abort if disabled",
    ], 0.2, 5.15, 12.93, 2.05, title="Dual Condition Safety Gate")
    slide_number(s, 17)

    # ── SLIDE 18 — Detection Modules ────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Detection Modules and Security Event Logging",
                   "detection/*.py  •  backend/security/events.py  •  log_security_event()")
    add_code_box(s, (
        "# backend/security/events.py — log_security_event()\n"
        "event = SecurityEvent(\n"
        "    timestamp    = datetime.now(timezone.utc),\n"
        "    endpoint     = '/items/3',\n"
        "    method       = 'GET',\n"
        "    owasp_category = 'API1:2023',\n"
        "    severity     = 'HIGH',\n"
        "    rule_name    = 'bola_cross_tenant_access',\n"
        "    action       = 'detected',   # or 'blocked'\n"
        "    user_id      = 2,            # never username or password\n"
        "    object_id    = '3',          # item ID accessed\n"
        ")\n"
        "# Fail-closed: SQLAlchemyError → rollback → raise HTTP 500"
    ), 0.2, 1.25, 7.0, 3.3)
    det_modules = [
        ("detection/bola.py",      "detect_bola()",                   "API1:2023", "HIGH",   "bola_cross_tenant_access"),
        ("detection/rbac.py",      "detect_bfla()",                   "API5:2023", "HIGH",   "bfla_unauthorized_function_access"),
        ("detection/bopla.py",     "detect_bopla_read()",             "API3:2023", "MEDIUM", "bopla_excessive_data_exposure"),
        ("detection/auth.py",      "detect_brute_force()",            "API2:2023", "HIGH",   "auth_brute_force"),
        ("detection/rate_limit.py","detect_rate_limit_exceeded()",    "API4:2023", "MEDIUM", "rate_limit_exceeded"),
        ("detection/inventory.py", "detect_deprecated_route_access()","API9:2023", "MEDIUM", "deprecated_route_access"),
    ]
    y = 1.3
    add_rect(s, 7.25, y, 5.9, 0.3, ACCENT_B)
    for h, lbl in zip(["File", "Function", "Category", "Sev", "Rule"], [2.1,1.7,0.8,0.6,1.9]):
        pass  # just use text
    add_textbox(s, "File / Function / Category / Rule", 7.3, y, 5.8, 0.3,
                font_size=9, bold=True, color=BG_DARK)
    y += 0.32
    for f, fn, cat, sev, rule in det_modules:
        add_rect(s, 7.25, y, 5.9, 0.45, BG_CARD if det_modules.index((f,fn,cat,sev,rule))%2==0 else RGBColor(0x18,0x18,0x25))
        add_textbox(s, f, 7.3, y, 2.05, 0.22, font_size=8, color=TEXT_MUTED)
        add_textbox(s, fn, 7.3, y+0.22, 2.05, 0.22, font_size=8, color=ACCENT_T)
        add_textbox(s, cat, 9.4, y, 0.85, 0.45, font_size=8, color=ACCENT_Y)
        add_textbox(s, sev, 10.3, y, 0.6, 0.45, font_size=8, color=TEXT_MAIN)
        add_textbox(s, rule, 10.95, y, 2.15, 0.45, font_size=7, color=TEXT_MUTED)
        y += 0.48
    slide_number(s, 18)

    # ── SLIDE 19 — Dashboard Architecture ───────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Frontend Dashboard Architecture — Four Tabs",
                   "frontend/src/App.jsx  •  frontend/src/api.js  •  React 18 + Vite")
    add_bullet_box(s, [
        "Admin-only login: POST /auth/login; token in component state only (never localStorage)",
        "Password field cleared immediately after login attempt",
        "Non-admin login rejected in dashboard UI before any other request",
    ], 0.2, 1.25, 12.93, 1.3, title="LoginPanel")
    tabs = [
        ("Status", ACCENT_B, [
            "GET /health → server liveness (online/offline badge)",
            "GET /admin/lab-mode → lab mode ON/OFF indicator",
            "GET /admin/defenses → current toggle state display",
        ]),
        ("Defenses", ACCENT_T, [
            "GET /admin/defenses → reads all 6 toggle states",
            "PATCH /admin/defenses → ON/OFF buttons per toggle",
            "Server-confirmed state — no optimistic UI updates",
        ]),
        ("Events", ACCENT_Y, [
            "GET /admin/events?limit=50 → paginated security events table",
            "Action filter: all / detected / blocked",
            "Manual refresh button; auto-refresh not implemented",
        ]),
        ("Results", ACCENT_G, [
            "Reads /results/*.json from frontend/public/results/",
            "Shows vulnerable run vs defended run outcomes",
            "Dashboard does NOT launch attack scripts",
            "Missing result files shown with 'run the experiment' message",
        ]),
    ]
    y = 2.75
    for tab, col, items in tabs:
        add_rect(s, 0.2, y, 2.5, 1.3, BG_CARD)
        add_textbox(s, tab, 0.25, y, 2.4, 0.35, font_size=12, bold=True, color=col)
        for item in items:
            add_textbox(s, f"• {item}", 0.3, y+0.37 + items.index(item)*0.28, 2.3, 0.28, font_size=8, color=TEXT_MAIN)
        y += 1.4
    add_code_box(s, (
        "// frontend/src/api.js\n"
        "const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';\n"
        "// All auth via: { Authorization: `Bearer ${token}` }\n"
        "// Never logs tokens, passwords, or Authorization headers\n"
        "export async function patchDefenses(token, updates) {\n"
        "  return apiFetch('/admin/defenses', { method: 'PATCH',\n"
        "    body: JSON.stringify(updates) }, token);\n"
        "}"
    ), 2.9, 2.7, 10.2, 3.2)
    slide_number(s, 19)

    # ── SLIDE 20 — BOLA Overview ─────────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_R)
    add_header_bar(s, "API1:2023 — Broken Object Level Authorization (BOLA)",
                   "The most critical API vulnerability — 2023 OWASP #1")
    add_bullet_box(s, [
        "BOLA (also called IDOR) occurs when an API uses user-supplied object IDs",
        "without verifying whether the authenticated user owns or can access the object",
        "Example: Alice retrieves GET /items/3 — Item 3 belongs to Bob",
        "The server checks auth (valid token?) but not authorization (is this Alice's item?)",
    ], 0.2, 1.25, 12.93, 1.8, title="Vulnerability Definition")
    add_two_column_cards(s,
        "Vulnerable Scenario (bola=OFF, lab=ON)", [
            "Alice logs in → receives JWT",
            "Alice sends GET /items/3  (Bob's item)",
            "Server: valid JWT? ✓  →  lab mode? ✓  →  bola toggle? OFF",
            "detect_bola() runs → emits 'detected' SecurityEvent",
            "Vulnerable: returns ItemResponse for Bob's item — HTTP 200",
            "Attack result: attack_success=True, outcome='vulnerability_exploited'",
        ],
        "Defended Scenario (bola=ON, lab=ON)", [
            "Same request: Alice → GET /items/3",
            "Server: valid JWT? ✓  →  lab mode? ✓  →  bola toggle? ON",
            "detect_bola() runs → emits 'blocked' SecurityEvent",
            "Defense: raises HTTP 403 Forbidden",
            "No item data returned to Alice",
            "Attack result: attack_success=False, outcome='attack_blocked'",
        ],
        top=3.15, height=3.7)
    slide_number(s, 20)

    # ── SLIDE 21 — BOLA Technical Detail ─────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_R)
    add_header_bar(s, "BOLA — Attack Request, Detection and Defense Logic",
                   "backend/routes/items.py  •  detection/bola.py  •  attacks/bola.py")
    add_code_box(s, (
        "# backend/routes/items.py — GET /items/{item_id}\n"
        "if not is_owner and not is_admin:\n"
        "    if not is_lab_mode():\n"
        "        raise HTTPException(403, 'Not authorized')   # safe mode\n"
        "    bola_active = defense_manager.get_defenses()['bola']\n"
        "    detect_bola(db, current_user=user, item=item,\n"
        "                defense_active=bola_active)\n"
        "    if bola_active:\n"
        "        raise HTTPException(403, 'Not authorized')   # defended\n"
        "    return ItemResponse.model_validate(item)         # VULNERABLE"
    ), 0.2, 1.25, 7.0, 2.9)
    add_attack_flow(s, top=4.3)
    add_bullet_box(s, [
        "Attacker: alice (user), Target: Item 3 (owned by bob)",
        "attacks/bola.py: validates target URL before any request",
        "Vulnerable run: sets bola=False, requests /items/3 as alice",
        "Verified: HTTP 200 + detection event with rule='bola_cross_tenant_access'",
        "Defended run: sets bola=True, same request",
        "Verified: HTTP 403 + blocked event with same rule",
        "Result in: docs/results/bola_results.json",
        "Important: BOLA tests object-level auth, NOT property-level auth",
    ], 7.3, 1.25, 5.85, 4.9, title="Attack Script Verification")
    slide_number(s, 21)

    # ── SLIDE 22 — Broken Auth Overview ──────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_Y)
    add_header_bar(s, "API2:2023 — Broken Authentication",
                   "Brute-force / credential stuffing on POST /auth/login")
    add_two_column_cards(s,
        "Vulnerability Scenario", [
            "No lockout → attacker sends unlimited login attempts",
            "POST /auth/login with wrong password repeated N times",
            "Server returns 401 each time — no enforcement",
            "Attacker eventually guesses or stuffs correct credentials",
            "Source: backend/routes/auth.py + backend/security/lockout.py",
        ],
        "LoginAttemptTracker Design", [
            "Class: LoginAttemptTracker (thread-safe, in-memory)",
            "Threshold: 5 failed attempts in 5-minute rolling window",
            "Lockout duration: 5 minutes (LOCKOUT_DURATION_SECONDS=300)",
            "record_failure(username) → prunes old timestamps → appends",
            "record_success(username) → clears all state for username",
            "is_locked_out(username) → checks lockout_until vs now(UTC)",
            "Never stores passwords — only timestamps per username",
        ],
        top=1.25, height=3.2)
    add_bullet_box(s, [
        "auth_hardening=OFF (lab mode): failures tracked, 'detected' event emitted, lockout NOT enforced",
        "auth_hardening=ON  (lab mode): failures tracked, 'blocked' event emitted, HTTP 429 after threshold",
        "Outside lab mode: failures tracked silently — no events, no lockout (safe mode)",
        "Retry-After header included in HTTP 429 response",
        "detect_brute_force() stores object_id=username — never the password",
    ], 0.2, 4.55, 12.93, 2.7, title="Defense Behavior (auth_hardening toggle)")
    slide_number(s, 22)

    # ── SLIDE 23 — Broken Auth Technical ─────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_Y)
    add_header_bar(s, "Broken Authentication — Login Flow and Lockout Logic",
                   "backend/routes/auth.py  •  backend/security/lockout.py  •  detection/auth.py")
    add_code_box(s, (
        "# backend/routes/auth.py — login()\n"
        "defense_active = defense_manager.get_defenses()['auth_hardening']\n\n"
        "# Check lockout BEFORE revealing if account exists (BOLA-safe)\n"
        "if defense_active and login_tracker.is_locked_out(request.username):\n"
        "    detect_brute_force(..., action='blocked')\n"
        "    raise HTTPException(429, 'Account temporarily locked',\n"
        "                        headers={'Retry-After': str(remaining)})\n\n"
        "user = db.query(User).filter(username == ...).first()\n"
        "if not user or not verify_password(...):\n"
        "    login_tracker.record_failure(request.username)\n"
        "    if in_lab:\n"
        "        action = 'blocked' if defense_active else 'detected'\n"
        "        detect_brute_force(..., action=action)\n"
        "    raise HTTPException(401, 'Invalid username or password')\n\n"
        "login_tracker.record_success(request.username)   # clears counter"
    ), 0.2, 1.25, 7.5, 4.5)
    add_bullet_box(s, [
        "attacks/auth.py sends 6 invalid logins (threshold + 1)",
        "Vulnerable: all return 401, detected events emitted",
        "Defended: 5th+ attempt returns 429 with Retry-After",
        "Event rule: 'auth_brute_force', category: API2:2023",
        "Event object_id = username (never password)",
        "Lockout check before DB query — prevents user enumeration via timing",
        "Result: docs/results/auth_results.json (requires live server)",
    ], 7.7, 1.25, 5.4, 4.5, title="Experiment Verification")
    add_attack_flow(s, top=5.9)
    slide_number(s, 23)

    # ── SLIDE 24 — BOPLA Overview ─────────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_T)
    add_header_bar(s, "API3:2023 — Broken Object Property Level Authorization (BOPLA)",
                   "Excessive Data Exposure — GET /items/1?include_internal=true")
    add_bullet_box(s, [
        "BOLA vs BOPLA: BOLA = wrong object; BOPLA = right object, wrong properties",
        "Alice owns Item 1 — she has legitimate object-level access",
        "But internal_notes and is_confidential are admin-only restricted properties",
        "API allows Alice to request these via ?include_internal=true query parameter",
        "Without defense: ItemInternalResponse is returned — restricted fields disclosed",
        "With defense: HTTP 403, only public fields available via ItemResponse",
    ], 0.2, 1.25, 12.93, 2.2, title="Vulnerability Definition and Distinction from BOLA")
    add_code_box(s, (
        "# backend/routes/items.py — relevant excerpt\n"
        "# Alice owns Item 1, but requests restricted properties:\n"
        "# GET /items/1?include_internal=true\n\n"
        "if not include_internal:\n"
        "    return ItemResponse.model_validate(item)     # safe — always\n\n"
        "if not is_lab_mode():\n"
        "    return ItemResponse.model_validate(item)     # safe mode\n\n"
        "defense_active = defenses['schema_validation']\n"
        "detect_bopla_read(db, user, item, defense_active) # always runs\n"
        "if defense_active:\n"
        "    raise HTTPException(403, 'Restricted properties')  # defended\n"
        "return ItemInternalResponse.model_validate(item)  # VULNERABLE"
    ), 0.2, 3.55, 7.0, 3.7)
    add_bullet_box(s, [
        "ItemResponse: id, title, description, owner_id  (4 fields)",
        "ItemInternalResponse adds: internal_notes, is_confidential",
        "Restricted fields seeded: 'Internal audit: synthetic risk score 42/100'",
        "Attack confirms: disclosed_internal_notes=True in result JSON",
        "Defended: disclosed_internal_notes=False, HTTP 403",
        "Event: rule='bopla_excessive_data_exposure', severity='MEDIUM'",
        "Result: docs/results/bopla_read_results.json — VERIFIED",
    ], 7.3, 3.55, 5.8, 3.7, title="Verified Experiment Results")
    slide_number(s, 24)

    # ── SLIDE 25 — BOPLA Technical ───────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_T)
    add_header_bar(s, "BOPLA — Result Evidence and Detection Schema",
                   "docs/results/bopla_read_results.json  •  detection/bopla.py")
    add_code_box(s, (
        "// docs/results/bopla_read_results.json  (genuine run: 2026-10-15)\n"
        '{\n'
        '  "experiment": "OWASP API3:2023 BOPLA Excessive Data Exposure",\n'
        '  "timestamp": "2026-10-15T11:15:55.986560+00:00",\n'
        '  "vulnerable_run": {\n'
        '    "status_code": 200, "attack_success": true,\n'
        '    "disclosed_internal_notes": true,\n'
        '    "disclosed_is_confidential": true,\n'
        '    "detection_verified": true, "matched_event_id": 12,\n'
        '    "outcome": "vulnerability_exploited"\n'
        '  },\n'
        '  "defended_run": {\n'
        '    "status_code": 403, "attack_success": false,\n'
        '    "disclosed_internal_notes": false,\n'
        '    "detection_verified": true, "matched_event_id": 13,\n'
        '    "outcome": "attack_blocked"\n'
        '  }\n'
        '}'
    ), 0.2, 1.25, 7.5, 4.8)
    add_bullet_box(s, [
        "BOPLA is subtler than BOLA — user IS authorized at object level",
        "Authorization at property level is a separate check",
        "Even legitimate owners must not access admin-only fields",
        "Defense (schema_validation) prevents ItemInternalResponse from being returned",
        "Detection always runs: even if blocked, the attempt is logged",
        "Event matched by ID: verified it's from THIS experiment run",
        "attacks/bopla.py: dual-run orchestration with toggle restoration",
    ], 7.7, 1.25, 5.45, 4.8, title="Key Design Insights")
    add_attack_flow(s, top=6.2)
    slide_number(s, 25)

    # ── SLIDE 26 — Rate Limiting Overview ────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_G)
    add_header_bar(s, "API4:2023 — Unrestricted Resource Consumption (Rate Limiting)",
                   "backend/security/rate_limiter.py  •  backend/security/rate_limit_dep.py")
    add_two_column_cards(s,
        "RateLimiter Class (Fixed Window)", [
            "DEFAULT_REQUESTS_PER_WINDOW = 20",
            "DEFAULT_WINDOW_SECONDS = 60",
            "Keyed by: f'user:{current_user.id}'",
            "Thread-safe: threading.Lock()",
            "check_and_record() → (allowed: bool, remaining: int)",
            "Stale windows pruned on each call (bounded memory)",
            "Global singleton: rate_limiter = RateLimiter()",
        ],
        "Dependency: check_rate_limit()", [
            "FastAPI dependency injected in GET /items/{id}",
            "Runs AFTER authentication (needs user ID for key)",
            "rate_limit=OFF: detection runs, event emitted, request allowed",
            "rate_limit=ON: detection runs, event emitted, HTTP 429 raised",
            "Retry-After header: seconds until window reset",
            "Detection always runs — monitoring works even without blocking",
            "File: backend/security/rate_limit_dep.py",
        ],
        top=1.25, height=3.5)
    add_bullet_box(s, [
        "attacks/rate_limit.py: sends 25 requests in rapid succession (exceeds threshold of 20)",
        "Vulnerable run: all 25 allowed → 25 HTTP 200 responses, detected events emitted",
        "Defended run: first 20 allowed → requests 21-25 return HTTP 429",
        "Verified: block_rate, results_200_allowed, results_429_limited counted",
        "LIMITATION: In-memory, single-process — not suitable for multi-worker or distributed systems",
    ], 0.2, 4.85, 12.93, 2.35, title="Experiment Design and Limitations")
    slide_number(s, 26)

    # ── SLIDE 27 — Rate Limiting Technical ───────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_G)
    add_header_bar(s, "Rate Limiting — Fixed Window Algorithm",
                   "backend/security/rate_limiter.py  •  check_and_record()")
    add_code_box(s, (
        "# backend/security/rate_limiter.py\n"
        "def check_and_record(self, key: str) -> (bool, int):\n"
        "    now = datetime.now(timezone.utc)\n"
        "    with self._lock:\n"
        "        self._prune_stale(now)           # remove expired windows\n"
        "        if key not in self._windows:\n"
        "            self._windows[key] = (now, 1)\n"
        "            return True, self.requests_per_window - 1\n"
        "        window_start, count = self._windows[key]\n"
        "        elapsed = (now - window_start).total_seconds()\n"
        "        if elapsed >= self.window_seconds:   # window expired\n"
        "            self._windows[key] = (now, 1)\n"
        "            return True, self.requests_per_window - 1\n"
        "        if count >= self.requests_per_window:\n"
        "            return False, 0                  # RATE LIMITED\n"
        "        self._windows[key] = (window_start, count + 1)\n"
        "        return True, self.requests_per_window - count - 1"
    ), 0.2, 1.25, 7.3, 4.5)
    add_bullet_box(s, [
        "Fixed window: counter resets entirely when window_seconds elapsed",
        "Weakness: burst at window boundary → up to 2x requests in 2*window_seconds",
        "Alternative: sliding window (not implemented — documented limitation)",
        "Per-user keying prevents one user from throttling another",
        "reset_all() for test isolation; reset_key(key) for targeted resets",
        "Tests: tests/test_rate_limit.py — 13 tests",
        "Limitation: not shared across workers — single Uvicorn process only",
    ], 7.55, 1.25, 5.6, 4.5, title="Algorithm Properties and Limitations")
    add_attack_flow(s, top=5.9)
    slide_number(s, 27)

    # ── SLIDE 28 — BFLA Overview ─────────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_B)
    add_header_bar(s, "API5:2023 — Broken Function Level Authorization (BFLA)",
                   "GET /admin/events — non-admin access to admin function")
    add_bullet_box(s, [
        "BFLA: authenticated user calls a function/endpoint reserved for a higher-privilege role",
        "Distinct from BOLA (object access) and BOPLA (property access) — this is FUNCTION access",
        "Alice has a valid JWT (authentication passes) but role='user' (authorization fails)",
        "GET /admin/events lists all security events — an administrative function",
        "Without defense: non-admin users can read the full event log",
    ], 0.2, 1.25, 12.93, 2.0, title="Vulnerability Definition and Distinction")
    add_two_column_cards(s,
        "Vulnerable Run (rbac=OFF, lab=ON)", [
            "Alice: GET /admin/events with user JWT",
            "get_current_user() → valid token, role='user'",
            "require_admin() NOT used — get_current_user() only",
            "detect_bfla() runs → 'detected' event emitted",
            "rbac=OFF: events list returned to Alice — HTTP 200",
            "Verified: attack_success=True, matched_event_id=10",
        ],
        "Defended Run (rbac=ON, lab=ON)", [
            "Same request — Alice → GET /admin/events",
            "detect_bfla() runs → 'blocked' event emitted",
            "rbac=ON: HTTP 403 raised after detection",
            "No event data returned to Alice",
            "Verified: HTTP 403, matched_event_id=11",
            "Result: docs/results/rbac_results.json — VERIFIED",
        ],
        top=3.3, height=3.0)
    add_textbox(s,
        "Key: admin users (role='admin') always pass — detect_bfla() returns None for admins. "
        "Only non-admin authenticated users trigger the BFLA check.",
        0.2, 6.4, 12.93, 0.7, font_size=10, color=ACCENT_Y)
    slide_number(s, 28)

    # ── SLIDE 29 — BFLA Technical ─────────────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, ACCENT_B)
    add_header_bar(s, "BFLA — Source Evidence and Verified Results",
                   "backend/routes/admin.py  •  detection/rbac.py  •  docs/results/rbac_results.json")
    add_code_box(s, (
        "# backend/routes/admin.py — GET /admin/events\n"
        "if current_user.role == 'admin':\n"
        "    pass   # always allowed\n"
        "else:\n"
        "    if not is_lab_mode():\n"
        "        raise HTTPException(403)   # safe mode\n"
        "    defense_active = defenses['rbac']\n"
        "    detect_bfla(db, current_user=user, endpoint='/admin/events',\n"
        "                method='GET', defense_active=defense_active)\n"
        "    if defense_active:\n"
        "        raise HTTPException(403, 'Admin access required')\n"
        "    # VULNERABLE: returns events to non-admin\n\n"
        '# docs/results/rbac_results.json\n'
        '# vulnerable_run: status=200, detection_verified=true, event_id=10\n'
        '# defended_run:   status=403, detection_verified=true, event_id=11'
    ), 0.2, 1.25, 7.3, 4.5)
    add_bullet_box(s, [
        "attacks/rbac.py: alice accesses GET /admin/events",
        "Script verifies event ID is NEW (above baseline captured before run)",
        "rule_name: 'bfla_unauthorized_function_access'",
        "severity: HIGH (admin function exposure is high risk)",
        "Dual-run: toggle rbac off → on; original toggle restored in finally block",
        "Note: GET /admin/events uses get_current_user(), not require_admin()",
        "This is intentional: if it used require_admin(), there'd be no experiment to run",
    ], 7.55, 1.25, 5.6, 4.5, title="Attack Script and Event Evidence")
    add_attack_flow(s, top=5.9)
    slide_number(s, 29)

    # ── SLIDE 30 — Inventory Management ──────────────────────────────────────
    s = new_slide()
    add_rect(s, 0, 0, 13.33, 0.15, TEXT_MUTED)
    add_header_bar(s, "API9:2023 — Improper Inventory Management",
                   "GET /api/v0/items/{id} — synthetic deprecated route experiment")
    add_two_column_cards(s,
        "Vulnerability Scenario", [
            "APIs accumulate versions: /api/v0, /api/v1, /api/v2",
            "Old versions are forgotten but never decommissioned",
            "Deprecated routes bypass newer security controls",
            "Attackers discover and exploit undocumented routes",
            "GET /api/v0/items/{id} — still active in APIShield lab",
        ],
        "Implementation: backend/routes/inventory.py", [
            "Route: GET /api/v0/items/{item_id}",
            "Outside lab mode → 404 (effectively decommissioned)",
            "Lab + deprecated_route_protection=OFF → data returned + 'detected' event",
            "Lab + deprecated_route_protection=ON → 403 + 'blocked' event",
            "Detection: detect_deprecated_route_access() — API9:2023",
            "GET /admin/inventory → lists all routes incl. deprecated ones",
        ],
        top=1.25, height=3.4)
    add_code_box(s, (
        "# backend/routes/inventory.py\n"
        "if not is_lab_mode():\n"
        "    raise HTTPException(404, 'Not found')       # safe mode\n"
        "protection_active = defenses['deprecated_route_protection']\n"
        "detect_deprecated_route_access(db, path=f'/api/v0/items/{item_id}',\n"
        "    action='blocked' if protection_active else 'detected')\n"
        "if protection_active:\n"
        "    raise HTTPException(403, 'Deprecated route blocked')\n"
        "return {**item_data, '_deprecated': True,\n"
        "        '_warning': 'Use /items/{id} instead'}"
    ), 0.2, 4.75, 7.5, 2.55)
    add_bullet_box(s, [
        "Note: deprecated route IS authenticated (requires valid JWT)",
        "API9 is about inventory — knowing ALL your routes, not just active ones",
        "Result file: docs/results/inventory_results.json (requires live server)",
        "17 tests in tests/test_inventory.py",
    ], 7.9, 4.75, 5.2, 2.55, title="Evidence and Tests")
    slide_number(s, 30)

    # ── SLIDE 31 — Comparison Matrix ─────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Vulnerability and Defense Comparison Matrix")
    headers = ["OWASP", "Category", "Endpoint", "Toggle", "Vuln HTTP", "Def HTTP", "Event Rule", "Severity", "Tests"]
    rows_m = [
        ("API1", "BOLA",     "/items/{id}",           "bola",        "200","403","bola_cross_tenant_access",         "HIGH",   "18"),
        ("API2", "Brk Auth", "/auth/login",            "auth_hard.",  "401","429","auth_brute_force",                 "HIGH",   "20"),
        ("API3", "BOPLA",    "/items/{id}?inc_int",    "schema_val.", "200","403","bopla_excessive_data_exposure",    "MEDIUM", "34"),
        ("API4", "Rate Lim", "/items/{id} ×25",        "rate_limit",  "200","429","rate_limit_exceeded",              "MEDIUM", "13"),
        ("API5", "BFLA",     "/admin/events",          "rbac",        "200","403","bfla_unauthorized_func_access",    "HIGH",   "20"),
        ("API9", "Inventory","/api/v0/items/{id}",     "depr_route",  "200","403","deprecated_route_access",          "MEDIUM", "17"),
    ]
    col_w2 = [0.7, 1.1, 2.1, 1.2, 0.9, 0.9, 2.65, 0.85, 0.65]
    x_s = [0.15]
    for w in col_w2[:-1]:
        x_s.append(x_s[-1] + w + 0.04)
    y = 1.3
    for i, h in enumerate(headers):
        add_rect(s, x_s[i], y, col_w2[i], 0.32, ACCENT_B)
        add_textbox(s, h, x_s[i]+0.04, y, col_w2[i]-0.04, 0.32,
                    font_size=8, bold=True, color=BG_DARK)
    y += 0.32
    sev_colors = {"HIGH": ACCENT_R, "MEDIUM": ACCENT_Y, "LOW": ACCENT_G}
    for j, row in enumerate(rows_m):
        bg = BG_CARD if j%2==0 else RGBColor(0x18,0x18,0x25)
        for i, cell in enumerate(row):
            add_rect(s, x_s[i], y, col_w2[i], 0.42, bg)
            c = sev_colors.get(cell, TEXT_MAIN) if i==7 else TEXT_MAIN
            if i == 4: c = ACCENT_R
            if i == 5: c = ACCENT_G
            add_textbox(s, cell, x_s[i]+0.04, y, col_w2[i]-0.04, 0.42,
                        font_size=8, color=c)
        y += 0.45
    add_textbox(s, "Total verified tests: 156 passing (pytest -q, confirmed run 2026-10-23)",
                0.15, y+0.15, 12.9, 0.3, font_size=9, color=TEXT_MUTED)
    slide_number(s, 31)

    # ── SLIDE 32 — Prerequisites ─────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Prerequisites and Clean Installation",
                   "Windows 10/11 with PowerShell  •  Python 3.10+  •  Node.js 18+")
    add_two_column_cards(s,
        "Required Software", [
            "Python 3.10 or later (tested: 3.12.x, 3.14.6)",
            "pip (bundled with Python)",
            "Node.js 18+ (tested: v24.22.0) + npm 11+",
            "Git (for version history inspection)",
            "PowerShell 7 or Windows PowerShell 5.1",
            "Any terminal / code editor",
        ],
        "Python Dependencies (requirements.txt)", [
            "fastapi>=0.115.0     — web framework",
            "uvicorn[standard]>=0.30.0 — ASGI server",
            "sqlalchemy>=2.0.0    — ORM",
            "bcrypt>=4.0.0        — password hashing",
            "pyjwt>=2.8.0         — JWT tokens",
            "pytest>=8.0.0        — test framework",
            "httpx>=0.27.0        — HTTP client",
            "python-dotenv>=1.0.0 — .env loading",
        ],
        top=1.25, height=4.0)
    add_code_box(s, (
        "# Create and activate virtual environment\n"
        "python -m venv .venv\n"
        ".venv\\Scripts\\python.exe -m pip install -r requirements.txt\n\n"
        "# If PowerShell blocks .ps1 activation scripts:\n"
        "# Use .venv\\Scripts\\python.exe directly for all commands\n\n"
        "# Verify installation:\n"
        ".venv\\Scripts\\python.exe -m pytest --version"
    ), 0.2, 5.35, 12.93, 1.85)
    slide_number(s, 32)

    # ── SLIDE 33 — Backend Setup ──────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Backend Setup — Environment Variables and Database Seeding",
                   "backend/config.py  •  .env  •  backend/seed.py")
    add_code_box(s, (
        "# 1. Configure JWT_SECRET (REQUIRED)\n"
        "# Copy .env.example to .env and set a strong random secret:\n"
        "Copy-Item .env.example .env\n"
        "# Edit .env — replace JWT_SECRET with a strong value (≥32 chars)\n"
        "# NEVER use 'change-me' — config.py detects this and uses ephemeral key\n\n"
        "# Generate a strong secret (PowerShell):\n"
        "[System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))\n\n"
        "# 2. Seed the database with synthetic test data:\n"
        ".venv\\Scripts\\python.exe -m backend.seed\n"
        "# Output: Seeding complete: 3 users, 4 items in database.\n\n"
        "# Seeded users:  alice (user), bob (user), admin (admin)\n"
        "# Seeded items:  Items 1-2 owned by alice; Items 3-4 owned by bob\n"
        "# Seeding is idempotent — safe to run multiple times"
    ), 0.2, 1.25, 12.93, 4.8)
    add_bullet_box(s, [
        "JWT_SECRET < 32 chars or 'change-me' → ephemeral key + WARNING to stderr",
        "Database file: apishield.db (in project root) — excluded from git",
        "seed.py uses ensure_schema_compatibility() for safe ALTER TABLE",
        "Synthetic data ONLY — never use real user data in this lab",
    ], 0.2, 6.15, 12.93, 1.1, title="Important Security Notes")
    slide_number(s, 33)

    # ── SLIDE 34 — Safe Mode Startup ─────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Starting the Backend — Safe Mode",
                   "Vulnerable behaviors completely suppressed — suitable for general use")
    add_code_box(s, (
        "# Terminal 1 — Start APIShield in SAFE MODE (default)\n"
        "$env:APISHIELD_LAB_MODE = 'false'    # explicit; or simply leave unset\n"
        ".venv\\Scripts\\python.exe -m uvicorn backend.main:app `\n"
        "    --host 127.0.0.1 --port 8000\n\n"
        "# Verify health:\n"
        "Invoke-RestMethod http://127.0.0.1:8000/health\n"
        "# Expected: { status: 'ok' }\n\n"
        "# Interactive API docs (Swagger UI):\n"
        "Start-Process 'http://127.0.0.1:8000/docs'\n\n"
        "# In safe mode:\n"
        "#   GET /items/3 as alice → HTTP 403 (immediate, no event)\n"
        "#   GET /api/v0/items/1   → HTTP 404 (deprecated route hidden)\n"
        "#   include_internal=true → sanitized ItemResponse (no event)"
    ), 0.2, 1.25, 9.5, 4.5)
    add_bullet_box(s, [
        "Host 127.0.0.1: localhost-only — not reachable from external networks",
        "Port 8000: documented default; change with --port if needed",
        "Swagger UI at /docs: explore all endpoints interactively",
        "ReDoc at /redoc: alternative documentation view",
        "X-Response-Time-Ms present on every response",
        "Server log shows WARNING if JWT_SECRET is weak",
    ], 9.75, 1.25, 3.4, 4.5, title="Verification Checks")
    slide_number(s, 34)

    # ── SLIDE 35 — Lab Mode Startup ───────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Starting the Backend — Lab Mode (Experiments Only)",
                   "⚠  Lab mode enables intentional vulnerabilities — use for experiments only")
    add_rect(s, 0.2, 1.25, 12.93, 0.42, ACCENT_R)
    add_textbox(s,
        "⚠  WARNING: Never expose a lab-mode server to untrusted networks. Bind to 127.0.0.1 only.",
        0.3, 1.3, 12.7, 0.35, font_size=11, bold=True, color=BG_DARK)
    add_code_box(s, (
        "# Terminal 1 — Start APIShield in LAB MODE\n"
        "$env:APISHIELD_LAB_MODE = 'true'    # MUST be set BEFORE starting uvicorn\n"
        ".venv\\Scripts\\python.exe -m uvicorn backend.main:app `\n"
        "    --host 127.0.0.1 --port 8000\n\n"
        "# Verify lab mode (requires admin login first):\n"
        "$token = (Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/auth/login `\n"
        "    -ContentType 'application/json' `\n"
        "    -Body '{\"username\":\"admin\",\"password\":\"AdminSyntheticPass123!\"}').access_token\n"
        "Invoke-RestMethod http://127.0.0.1:8000/admin/lab-mode `\n"
        "    -Headers @{Authorization=\"Bearer $token\"}\n"
        "# Expected: { lab_mode: true }\n\n"
        "# All defenses remain OFF until explicitly toggled\n"
        "Invoke-RestMethod http://127.0.0.1:8000/admin/defenses `\n"
        "    -Headers @{Authorization=\"Bearer $token\"}"
    ), 0.2, 1.75, 12.93, 4.5)
    add_textbox(s,
        "Lab mode is READ from APISHIELD_LAB_MODE at startup. It cannot be changed via HTTP after startup.",
        0.2, 6.35, 12.93, 0.35, font_size=10, color=ACCENT_Y)
    slide_number(s, 35)

    # ── SLIDE 36 — Frontend ───────────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Frontend Installation, Dashboard Login and Navigation",
                   "frontend/  •  React 18  •  Vite  •  npm")
    add_code_box(s, (
        "# Terminal 2 — Start the React dashboard\n"
        "cd frontend\n"
        "cmd /c \"npm install\"    # first time only (on Windows if .ps1 blocked)\n"
        "cmd /c \"npm run dev\"    # starts Vite dev server\n\n"
        "# Vite prints: VITE v6.x.x  ready in 300ms\n"
        "#              Local: http://localhost:5173/\n\n"
        "# Open http://localhost:5173 in a browser\n\n"
        "# Login with: username=admin  password=AdminSyntheticPass123!\n"
        "# (password is cleared from the form immediately after submission)\n\n"
        "# If API base URL differs from http://127.0.0.1:8000:\n"
        "$env:VITE_API_URL = 'http://127.0.0.1:8000'\n"
        "cmd /c \"npm run dev\""
    ), 0.2, 1.25, 7.3, 4.0)
    add_bullet_box(s, [
        "Tab 1 — STATUS: health check + lab mode + defense states",
        "Tab 2 — DEFENSES: toggle each defense ON/OFF in real time",
        "Tab 3 — EVENTS: paginated security event log with action filter",
        "Tab 4 — RESULTS: reads JSON files from frontend/public/results/",
        "",
        "Dashboard READS experiment results — does NOT launch attacks",
        "Missing result file → 'run the experiment script' message shown",
        "Token stored in React component state (never localStorage/cookies)",
        "Logout clears token from memory immediately",
    ], 7.6, 1.25, 5.55, 5.5, title="Dashboard Navigation")
    slide_number(s, 36)

    # ── SLIDE 37 — Running Attacks ────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Running Attack Scripts and Inspecting Results",
                   "attacks/*.py  •  docs/results/*.json  •  Lab mode must be active")
    add_code_box(s, (
        "# From project root, with lab-mode server running:\n"
        ".venv\\Scripts\\python.exe attacks/bola.py `\n"
        "    --target http://127.0.0.1:8000\n"
        "# → docs/results/bola_results.json\n\n"
        ".venv\\Scripts\\python.exe attacks/bopla.py `\n"
        "    --target http://127.0.0.1:8000\n"
        "# → docs/results/bopla_read_results.json\n\n"
        ".venv\\Scripts\\python.exe attacks/rbac.py `\n"
        "    --target http://127.0.0.1:8000\n"
        "# → docs/results/rbac_results.json\n\n"
        ".venv\\Scripts\\python.exe attacks/auth.py `\n"
        "    --target http://127.0.0.1:8000\n"
        ".venv\\Scripts\\python.exe attacks/rate_limit.py `\n"
        "    --target http://127.0.0.1:8000\n"
        ".venv\\Scripts\\python.exe attacks/inventory.py\n"
        "# → docs/results/inventory_results.json"
    ), 0.2, 1.25, 7.3, 5.0)
    add_bullet_box(s, [
        "Each script: validates target URL BEFORE any network call",
        "Verifies lab mode is ON — aborts if disabled",
        "Captures original defense toggle state → restores in finally block",
        "Dual run: vulnerable (toggle OFF) → defended (toggle ON)",
        "Both outcomes must be verified before writing results JSON",
        "Result JSON: experiment, timestamp, target, runs, summary",
        "After running: copy results to frontend/public/results/ for dashboard",
        "attacks/inventory.py has no --target flag (hardcoded allowlist check)",
    ], 7.6, 1.25, 5.55, 5.0, title="Script Workflow")
    slide_number(s, 37)

    # ── SLIDE 38 — Tests and Evaluation ─────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Automated Tests, Evaluation Framework and Metrics",
                   "tests/  •  pytest  •  scripts/evaluate.py  •  156 tests verified")
    add_code_box(s, (
        "# Run all 156 tests:\n"
        ".venv\\Scripts\\python.exe -m pytest tests/ -v\n"
        "# Result: 156 passed, 1 warning in ~3 minutes (SQLite bcrypt timing)\n\n"
        "# Run specific module:\n"
        ".venv\\Scripts\\python.exe -m pytest tests/test_bopla.py -v\n\n"
        "# Multi-run evaluation (requires live lab-mode server):\n"
        ".venv\\Scripts\\python.exe scripts/evaluate.py --all --runs 10\n"
        "# → docs/results/evaluation_summary.json (real data)\n"
        "# → docs/results/evaluation_summary.csv\n\n"
        "# NOTE: evaluation_summary.json currently contains PLACEHOLDER data\n"
        "# Run evaluate.py against a live server to generate real metrics"
    ), 0.2, 1.25, 7.3, 3.8)
    test_counts = [
        ("test_auth.py",          "8",  "Registration, login, invalid credentials"),
        ("test_auth_hardening.py","20", "Lockout, detection events, lab mode gating"),
        ("test_bola.py",          "18", "Cross-user access, BOLA detection, defense"),
        ("test_bopla.py",         "34", "Property exposure, schema_validation toggle"),
        ("test_defenses.py",      "9",  "DefenseManager defaults, validation, reset"),
        ("test_events.py",        "10", "Event CRUD, pagination, action filter"),
        ("test_inventory.py",     "17", "Deprecated route, API9 detection, allowlist"),
        ("test_items.py",         "8",  "Item ownership, admin access"),
        ("test_middleware.py",    "3",  "X-Response-Time-Ms on all routes"),
        ("test_rate_limit.py",    "13", "Fixed-window algorithm, HTTP 429, events"),
        ("test_rbac.py",          "20", "BFLA detection, rbac toggle, event IDs"),
        ("test_seed.py",          "2",  "Idempotent seeding, user/item counts"),
    ]
    y = 1.28
    add_rect(s, 7.55, y, 5.6, 0.3, ACCENT_B)
    add_textbox(s, "Test File            | # Tests | Covers", 7.6, y, 5.5, 0.3,
                font_size=9, bold=True, color=BG_DARK)
    y += 0.32
    for f, n, c in test_counts:
        bg = BG_CARD if test_counts.index((f,n,c))%2==0 else RGBColor(0x18,0x18,0x25)
        add_rect(s, 7.55, y, 5.6, 0.3, bg)
        add_textbox(s, f, 7.6, y, 1.8, 0.3, font_size=8, color=TEXT_MAIN)
        add_textbox(s, n, 9.45, y, 0.45, 0.3, font_size=8, bold=True, color=ACCENT_G)
        add_textbox(s, c, 9.95, y, 3.15, 0.3, font_size=7, color=TEXT_SUB)
        y += 0.31
    slide_number(s, 38)

    # ── SLIDE 39 — Source Audit ───────────────────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Source Audit — Key Findings and Limitations")
    add_two_column_cards(s,
        "Verified Implementation Facts", [
            "✅ .env present but in .gitignore — secrets NOT in git history",
            "✅ 156/156 tests pass (confirmed live run 2026-10-23)",
            "✅ All attack scripts validate target before any network call",
            "✅ All attack scripts restore original defense state in finally block",
            "✅ Detection is fail-closed (SQLAlchemy error → HTTP 500)",
            "✅ JWT_SECRET hardened: ephemeral key if weak/missing",
            "✅ Dashboard does NOT launch attack scripts (reads JSON only)",
            "✅ evaluation_summary.json is clearly labeled as placeholder",
        ],
        "Issues Found", [
            "⚠  docker-compose publishes 0.0.0.0:8000 → external exposure",
            "⚠  Dockerfile CMD does not enforce --host 127.0.0.1",
            "⚠  No CORS middleware — dashboard works only on same host",
            "⚠  No security headers (X-Frame-Options, X-Content-Type-Options)",
            "⚠  Fixed-window rate limiter vulnerable to boundary bursts",
            "⚠  In-memory state lost on server restart — not production-safe",
            "⚠  frontend/public/results/ only has 3 of 6 result files",
            "⚠  evaluation_summary.json is placeholder — no real metrics yet",
        ],
        top=1.25, height=4.2)
    add_bullet_box(s, [
        "FIX Docker: add --host 127.0.0.1 to CMD; change ports to '127.0.0.1:8000:8000'",
        "FIX Rate limiter: switch to sliding window (token bucket) for production",
        "FIX Security headers: add CORS + security header middleware",
        "FIX Results: run all attack scripts and copy to frontend/public/results/",
        "API7, API8, API10 not implemented — clearly documented in FINAL_REPORT.md",
    ], 0.2, 5.55, 12.93, 1.65, title="Recommended Fixes")
    slide_number(s, 39)

    # ── SLIDE 40 — Conclusion and Viva Prep ──────────────────────────────────
    s = new_slide()
    add_header_bar(s, "Conclusion, Future Work and Viva Preparation")
    add_two_column_cards(s,
        "What Was Achieved", [
            "6 OWASP API Security (2023) categories implemented",
            "156 automated tests — all passing",
            "Dual-mode safety gate (lab mode + defense toggle)",
            "Verified experiment results for 3 categories",
            "React dashboard with 4 functional tabs",
            "Multi-run evaluation framework (scripts/evaluate.py)",
            "Full documentation suite + Docker support",
        ],
        "Future Work", [
            "API7: SSRF — local mock internal service",
            "API8: Security Misconfiguration — excess error detail, headers",
            "API10: Unsafe API Consumption — third-party API mock",
            "Sliding window rate limiter (replace fixed window)",
            "Persistent state via Redis for multi-worker support",
            "Generate real evaluation_summary.json via evaluate.py",
            "CORS middleware + security headers",
        ],
        top=1.25, height=3.5)
    add_bullet_box(s, [
        "Q: What is the difference between authentication and authorization? → Auth proves identity; authz determines access rights",
        "Q: Why does BOLA need lab mode AND defense toggle? → Two independent conditions prevent accidental exposure",
        "Q: Why bcrypt over SHA-256? → bcrypt is adaptive and slow; SHA-256 is fast and unsuitable for passwords",
        "Q: How does event correlation work? → Baseline event ID captured before run; matched event must have ID above baseline",
        "Q: Why is JWT_SECRET ephemeral when weak? → Prevents predictable tokens while not breaking tests; emits WARNING",
        "Q: What does 'fail-closed' mean? → If security event logging fails, the request is denied (HTTP 500) rather than allowed",
    ], 0.2, 4.85, 12.93, 2.35, title="Key Viva Questions — Quick Answers")
    slide_number(s, 40)

    return prs


def main():
    prs = build_prs()
    out = r"C:\Users\pcabi\OneDrive\Documents\apishield\APIShield_Technical_Presentation.pptx"
    prs.save(out)
    print(f"Saved: {out}")
    print(f"Slides: {len(prs.slides)}")


if __name__ == "__main__":
    main()
