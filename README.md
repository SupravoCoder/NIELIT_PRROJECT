---
title: VulnSense AI — Security Intelligence Platform
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8501
pinned: false
---

# VulnSense AI

An intelligent vulnerability assessment framework for automated network scanning, CVE matching, risk prioritization, LLM-based explanation, and report generation.


## Project Goal

VulnSense AI automates the core workflow of a security assessment:

1. Scan a target with Nmap.
2. Detect open ports, services, and software versions.
3. Normalize software names and versions.
4. Match results against NVD CVE data.
5. Prioritize findings by CVSS and business risk.
6. Explain findings in plain language with an LLM.
7. Generate executive and technical reports.
8. Present everything in a clean Streamlit dashboard.

## Initial Architecture

The project follows a clean, modular layout so the scanner, parser, CVE engine, risk engine, AI layer, reporting layer, and UI can evolve independently.

## Repository Layout

- `app/api` - FastAPI routes and request/response contracts.
- `app/scanner` - Nmap execution and scan orchestration.
- `app/parser` - Scan result normalization and enrichment.
- `app/cve_engine` - NVD lookup and CVE matching logic.
- `app/risk_engine` - CVSS-based scoring and prioritization.
- `app/ai` - LLM explanation and remediation generation.
- `app/reports` - Executive and technical report generation.
- `app/database` - SQLite persistence and repository helpers.
- `app/frontend` - Streamlit dashboard UI.
- `app/utils` - Shared helpers, logging, config, and validation.
- `tests` - Unit and integration tests.
- `docs` - Design notes, architecture, and future research material.

## Build Strategy

This repository will be built in small, reviewable modules:

1. Project structure
2. FastAPI backend
3. Streamlit frontend
4. Nmap scanner
5. Nmap output parser
6. NVD API integration
7. CVE matching engine
8. Risk prioritization
9. LLM integration
10. Report generator
11. Dashboard
12. Testing
13. Docker deployment

## Next Step

Step 2 will add the FastAPI application skeleton and backend entry points.
