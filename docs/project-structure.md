# Project Structure Notes

## Purpose

This document explains the modular boundaries for VulnSense AI so each capability can be developed, tested, and deployed independently.

## Design Principles

- Keep scanning, parsing, CVE lookup, risk analysis, AI explanation, and reporting separate.
- Use service classes instead of large procedural scripts.
- Keep FastAPI as the backend contract layer and Streamlit as the presentation layer.
- Persist scan history and normalized findings in SQLite for traceability and reproducibility.

## Folder Responsibilities

- `app/api`: HTTP routes, schemas, and orchestration endpoints.
- `app/scanner`: Nmap execution and scan job control.
- `app/parser`: Raw scan parsing, service normalization, and asset enrichment.
- `app/cve_engine`: NVD search, local cache lookup, and CVE matching.
- `app/risk_engine`: CVSS interpretation and custom prioritization logic.
- `app/ai`: LLM prompts, explanation generation, and remediation summaries.
- `app/reports`: PDF and HTML report rendering.
- `app/database`: SQLite schema and data access layer.
- `app/frontend`: Streamlit dashboard and user interactions.
- `app/utils`: Logging, configuration, validation, and common helpers.
- `tests`: Unit, integration, and regression tests.

## Roadmap Control

Each module will be introduced only after the previous one is reviewed and approved, which keeps the project manageable within a two-week build window.
