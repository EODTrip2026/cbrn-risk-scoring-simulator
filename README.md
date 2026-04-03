# cbrn-risk-scoring-simulator
This project is a lightweight prototype for analyzing text-based inputs related to chemical, biological, radiological, and explosive (CBRN) topics and prioritizing them for escalation.

It combines:
structured signal detection, deterministic scoring logic, and controlled interpretation to evaluate risk in dual-use environments where intent is often ambiguous.

Why This Project Exists:
CBRN-related information presents a persistent challenge. Much of the knowledge is dual-use, malicious intent is rarely explicit, and traditional filtering approaches rely too heavily on language or keywords alone.

This project explores a different approach:
Model capability and escalation potential, not just stated intent.

Core Design Principle:
The system separates interpretation from decision-making: Interpretation (what is being asked), Scoring (what risk signals are present), and Classification (how it should be prioritized).

The final outcome is driven by deterministic, explainable logic, not opaque model behavior.

How It Works:
1. Signal Detection - Each input is evaluated for key indicators, including: Precursor chemicals, Delivery mechanisms, Target environments, Evasion or concealment language, Harm thresholds (concentration, exposure, enclosed effects), and Safety/responder context.

2. Risk Scoring - Signals are weighted and combined using rule-based logic: Higher-risk precursors receive greater weight, Combinations (e.g., precursor + delivery) trigger escalation, Evasion + delivery increases severity, Safety context reduces score when appropriate.

The system prioritizes operational feasibility, not just wording.

3. Classification - Final outputs fall into four categories: Benign, Dual-use, Suspicious, and Malicious.  Each output includes a risk score to support prioritization.

Key Features: Capability-based scoring (not keyword matching), Combination-driven escalation logic, Fiction / cover-story skepticism, Safety-context dampening, Research-to-harm drift detection, Explainable, rule-based architecture.

Example Behavior:
Input Type	- Outcome

-OSHA storage requirements	- Benign

-Industrial cyanide processes -	Dual-use

-Dispersal in enclosed space - Suspicious

-Water supply contamination + evasion -	Malicious

Validation & Testing: The model was iteratively refined through multiple validation cycles. Key improvements included:

-Capability-based weighting (v2)

-Context balancing and fiction handling (v3)

-Research-to-harm drift detection and score calibration (v4)

Results: Strong alignment with expected classifications, Improved separation of benign vs operationally dangerous queries, Reduced false positives in safety and responder contexts.

Detailed validation cases and iterative scoring results are available in: evaluation_cbrn_test_cases.xlsx.

How to Run: 

-pip install -r requirements.txt

-streamlit run app.py

Limitations: This is a prototype and has known limitations. Rule-based systems require ongoing tuning, Limited precursor chemicals, Edge cases still depend on calibration choices, Does not model real-world acquisition constraints, Not connected to live threat intelligence or external data.

Why This Matters
As AI systems become more capable, the risk is not just what they say—but what they enable.

This project demonstrates an approach to: Identify escalation pathways, Prioritize risk in ambiguous contexts, Maintain transparency in decision-making.

It is designed as a foundation for: AI safety systems, Trust & Safety workflows, CBRN threat analysis pipelines.

Author:
Matthew Tripoli, U.S. Navy EODC (Master Explosive Ordnance Disposal Technician), CBRNE / Risk Analysis / Operational Planning
