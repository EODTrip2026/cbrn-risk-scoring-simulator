# CBRN Simulation Project Guide

## Purpose
This project is a lightweight CBRN misuse detection prototype. It ingests unstructured reports, extracts intent and indicators (LLM + rules), applies deterministic risk scoring, and prioritizes reports for escalation.

## Architecture
- main.py → Backend analysis pipeline (LLM + rule-based logic + scoring)
- app.py → Streamlit UI for user interaction and display
- reports.csv → Synthetic input data
- reports.db → SQLite database storing analyzed reports
- cbrn_test_cases.xlsx → Manual regression test suite

## Core Design Principle
The LLM assists with interpretation, but final classification and risk scoring are controlled by deterministic, explainable logic.

## Coding Rules
- Keep code simple, readable, and modular
- Do NOT introduce unnecessary complexity, frameworks, or abstractions
- Do NOT create new files unless explicitly required
- Preserve separation between backend (main.py) and UI (app.py)
- All scoring logic must remain explainable and traceable
- Prefer rule-based adjustments over expanding LLM dependency
- Avoid duplicating logic across files

## Risk Model Expectations
- Clearly malicious intent → high risk score
- Benign technical/safety context → low risk score
- Dual-use or ambiguous → moderate to high with "suspicious" classification
- Evasion + precursor + delivery indicators should significantly increase risk

## Development Guidelines for Codex
- Make the smallest effective change
- Do not rewrite entire functions unless necessary
- Do not break existing functionality
- When updating scoring logic, do not modify unrelated components
- Ensure new logic generalizes to future reports (not hardcoded to one case)

## Testing Expectations
- Use cbrn_test_cases.xlsx for validation
- Avoid regressions on previously tested cases
- Similar inputs should produce consistent outputs

## Goal
Produce a clean, explainable prototype that demonstrates:
- Intent classification
- Indicator extraction
- Risk scoring
- Structured outputs

This is a demonstration tool for AI safety / CBRNE threat analysis roles.