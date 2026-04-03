import argparse
import csv
import json
import os
import sqlite3
import sys
import textwrap
import typing
import urllib.error
import urllib.request

# Intent scoring
INTENT_SCORES = {"malicious": 3, "suspicious": 2, "dual_use": 1, "benign": 0}

# Hazard materials
PRECURSOR_CHEMICALS = ["chlorine", "cyanide", "phosgene", "ammonia", "hydrogen sulfide", "sarin"]
# Weights reflect relative hazardousness/capability of specific precursors
PRECURSOR_WEIGHTS = {
	"cyanide": 4,
	"phosgene": 4,
	"sarin": 5,
	"chlorine": 2,
	"ammonia": 1,
	"hydrogen sulfide": 2,
}
CHEMICAL_RISK_TERMS = tuple(PRECURSOR_CHEMICALS) + ("toxic", "poison")
TOXIC_NEAR_KEYWORDS = ["substance", "chemical", "material", "water", "supply"]

# Framing and acquisition
FRAMING_PHRASES = ("novel", "story", "fiction", "writing a book")
ACQUISITION_VERBS = ("acquir", "buy", "purchase", "obtain", "procure", "get")
SECRECY_TERMS = ("secret", "secretly", "without drawing attention", "avoid detection", "hide", "conceal", "discreetly")
EVASION_SYNONYMS = (
	"secret", "secretly", "avoid detection", "without drawing attention",
	"under the radar", "discreetly", "conceal", "hide"
)
EVASION_PHRASES = EVASION_SYNONYMS + (
	"without being detected", "avoid regulatory attention", "without attracting attention",
	"without attracting regulatory attention", "regulatory attention"
)

# Scale and delivery
LARGE_SCALE_TERMS = ("large", "mass", "widespread", "many", "industrial")
SMALL_SCALE_TERMS = ("small", "limited", "single", "few")
AEROSOL_SYNONYMS = ("disperse", "dispersal", "spread through air", "spray", "airborne", "fog")
INGESTION_SYNONYMS = ("water", "contaminate water", "water supply", "drinking water", "ingest", "food")
DEVICE_SYNONYMS = ("drone", "vehicle", "package", "grenade", "release from drone")
WATER_PHRASES = (
	"contaminat", "poison water", "poisoning water", "contaminate water",
	"water supply", "drinking water", "introduce into water", "introducing into water"
)
OPERATIONAL_HARMFUL_TERMS = ("disperse", "dispersal", "release", "contaminate")
OPERATIONAL_CONTEXT_TERMS = (
	"aerosol", "spray", "airborne", "fog", "drone", "device", "vehicle",
	"water supply", "drinking water", "through air", "into water"
)

# Safety and contextual qualifiers
SAFETY_CONTEXT_TERMS = (
	"osha", "ppe", "industrial accidents", "responders", "safely identify",
	"detection methods", "safety", "academic", "research", "study"
)
PROCESS_CONTEXT_TERMS = ("production", "process", "processes", "commonly used")
HARM_THRESHOLD_TERMS = (
	"threshold", "thresholds", "concentration", "concentrations",
	"dose", "dosage", "lethal", "cause harm", "harmful", "effects"
)
ENCLOSED_ENVIRONMENT_TERMS = ("enclosed environment", "enclosed space", "ventilation system", "indoors", "confined space")
PREVENTION_TERMS = ("prevent accidental release", "protect nearby populations", "safety measures", "protect", "prevention", "mitigate", "mitigation")
HIGH_HARM_INTENT_TERMS = ("maximize exposure", "most effective way", "crowded indoor space", "mass exposure")

RULE_BASED_MALICIOUS_TERMS = ("attack", "weapon", "poison", "sabotage", "release", "detonate")
RULE_BASED_SUSPICIOUS_TERMS = ("suspicious", "unknown", "unusual", "possible")
RULE_BASED_DUAL_USE_TERMS = ("dual use", "could be used", "maybe", "might be")
RULE_BASED_AEROSOL_TERMS = ("aerosol", "spray", "airborne", "fog", "disperse", "dispersing", "dispersal", "spread through air")
RULE_BASED_INGESTION_TERMS = ("ingest", "contaminate", "water", "food", "contaminate water")
RULE_BASED_DEVICE_TERMS = ("drone", "vehicle", "grenade", "package", "release from drone", "released from drone")
RULE_BASED_EVASION_TERMS = (
	"night", "cover", "conceal", "mask", "disguise", "hide", "hidden",
	"secret", "secretly", "without drawing attention", "avoid detection",
	"avoid being detected", "discreetly", "under the radar"
)


def format_report(row, wrap_width=80):
	report_id = row.get("report_id") or "<missing>"
	text = row.get("text") or "<no text>"
	timestamp = row.get("timestamp") or "<missing>"
	source = row.get("source") or "<missing>"

	wrapped_text = textwrap.fill(text, width=wrap_width)

	lines = [
		f"Report ID : {report_id}",
		f"Timestamp : {timestamp}",
		f"Source    : {source}",
		"Text      :",
		f"{wrapped_text}",
	]

	return "\n".join(lines)


def _print_indicator_list(indicators) -> None:
	if not indicators:
		print(" - <none>")
		return

	for item in indicators:
		print(f" - {item}")


def _fetch_all(db_path: str, query: str, params=()) -> list:
	conn = sqlite3.connect(db_path)
	try:
		cur = conn.cursor()
		cur.execute(query, params)
		return cur.fetchall()
	finally:
		conn.close()


def _set_intent(analysis: dict, intent: str) -> str:
	analysis["intent"] = intent
	return intent


def _add_precursor_indicators(text: str, indicators: list) -> bool:
	has_precursor = False
	for precursor in PRECURSOR_CHEMICALS:
		if precursor in text:
			has_precursor = True
			indicators.append(f"precursor: {precursor}")
	return has_precursor


def _has_strong_harmful_indicators(indicators) -> bool:
	return any(ind.startswith("evasion:") or ind.startswith("delivery:") for ind in indicators)


def load_and_print(csv_path, db_path="reports.db"):
	try:
		# ensure DB/table exists
		init_db(db_path)
		with open(csv_path, newline='', encoding='utf-8') as f:
			reader = csv.DictReader(f)
			if reader.fieldnames is None:
				print("No columns found in CSV.")
				return

			first = True
			for row in reader:
				# Skip entirely empty rows
				if not any((v and v.strip()) for v in row.values()):
					continue

				if not first:
					print("\n" + "-" * 80 + "\n")
				first = False

				print(format_report(row))

				analysis = analyze_report(row)

				print('\nAnalysis (JSON):')
				try:
					print(json.dumps(analysis, indent=2, ensure_ascii=False))
				except Exception:
					print(analysis)

				# Print structured fields and risk score
				risk = compute_risk_score(
					analysis.get("intent"),
					analysis.get("indicators"),
				)

				print('\nStructured Analysis:')
				print(f"Intent    : {analysis.get('intent')}")
				print("Indicators:")
				inds = analysis.get('indicators') or []
				_print_indicator_list(inds)
				print(f"Summary   : {analysis.get('summary')}")
				print(f"Risk Score: {risk}")

				# store into sqlite
				report_record = {
					"report_id": row.get("report_id"),
					"text": row.get("text"),
					"timestamp": row.get("timestamp"),
					"source": row.get("source"),
					"intent": analysis.get("intent"),
					"indicators": analysis.get("indicators") or [],
					"summary": analysis.get("summary"),
					"risk_score": risk,
				}

				try:
					insert_report(db_path, report_record)
				except Exception as e:
					print(f"Failed to write to DB: {e}", file=sys.stderr)

	except FileNotFoundError:
		print(f"File not found: {csv_path}", file=sys.stderr)
	except PermissionError:
		print(f"Permission denied: {csv_path}", file=sys.stderr)
	except Exception as e:
		print(f"Error reading CSV: {e}", file=sys.stderr)


def parse_args():
	p = argparse.ArgumentParser(description="Load and pretty-print reports from a CSV file.")
	p.add_argument("path", nargs="?", default="reports.csv", help="Path to CSV file (default: reports.csv)")
	p.add_argument("--db", dest="db", default="reports.db", help="Path to SQLite DB file (default: reports.db)")
	p.add_argument("--queries", dest="queries", action="store_true", help="Run summary SQLite queries after processing")
	return p.parse_args()


def main():
	args = parse_args()
	load_and_print(args.path, args.db)

	if getattr(args, "queries", False):
		run_queries(args.db)


def print_high_risk(db_path: str, threshold: int = 5):
	rows = _fetch_all(
		db_path,
		"""
		SELECT report_id, timestamp, source, intent, risk_score
		FROM reports
		WHERE risk_score >= ?
		ORDER BY risk_score DESC, timestamp
		""",
		(threshold,),
	)
	print('\nHigh-risk reports (risk_score >= {}):'.format(threshold))
	if not rows:
		print(' - None')
	else:
		for r in rows:
			print(f" - id={r[0]} | time={r[1]} | source={r[2]} | intent={r[3]} | risk={r[4]}")


def count_high_by_source(db_path: str, threshold: int = 5):
	rows = _fetch_all(
		db_path,
		"""
		SELECT source, COUNT(*)
		FROM reports
		WHERE risk_score >= ?
		GROUP BY source
		ORDER BY COUNT(*) DESC, source
		""",
		(threshold,),
	)
	print('\nHigh-risk report counts by source (risk_score >= {}):'.format(threshold))
	if not rows:
		print(' - None')
	else:
		for r in rows:
			print(f" - source={r[0]} | count={r[1]}")


def list_reports_by_risk(db_path: str):
	rows = _fetch_all(
		db_path,
		"SELECT report_id, timestamp, source, intent, risk_score FROM reports ORDER BY risk_score DESC, timestamp",
	)
	print('\nAll reports ordered by risk (highest first):')
	if not rows:
		print(' - None')
	else:
		for r in rows:
			print(f" - id={r[0]} | risk={r[4]} | time={r[1]} | source={r[2]} | intent={r[3]}")


def run_queries(db_path: str):
	print('\nRunning SQLite summary queries...')
	print_high_risk(db_path)
	count_high_by_source(db_path)
	list_reports_by_risk(db_path)


def init_db(db_path: str):
	conn = sqlite3.connect(db_path)
	try:
		cur = conn.cursor()
		cur.execute(
			"""
			CREATE TABLE IF NOT EXISTS reports (
				report_id TEXT,
				text TEXT,
				timestamp TEXT,
				source TEXT,
				intent TEXT,
				indicators TEXT,
				summary TEXT,
				risk_score INTEGER
			)
			"""
		)
		conn.commit()
	finally:
		conn.close()


def insert_report(db_path: str, record: dict):
	conn = sqlite3.connect(db_path)
	try:
		cur = conn.cursor()
		cur.execute(
			"INSERT INTO reports (report_id, text, timestamp, source, intent, indicators, summary, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			(
				record.get("report_id"),
				record.get("text"),
				record.get("timestamp"),
				record.get("source"),
				record.get("intent"),
				json.dumps(record.get("indicators") or [], ensure_ascii=False),
				record.get("summary"),
				record.get("risk_score"),
			),
		)
		conn.commit()
	finally:
		conn.close()


def _call_llm(text: str, api_key: str, model: str = None) -> typing.Optional[dict]:
	model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
	url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com") + "/v1/chat/completions"

	system = (
		"You are an assistant that classifies short incident reports.\n"
		"For each report, return JSON only with keys: intent, indicators, summary.\n"
		"- intent: one of [benign, dual_use, suspicious, malicious].\n"
		"- indicators: a list of short strings (e.g. 'precursor: chlorine', 'delivery: aerosol').\n"
		"- summary: a single short sentence summarizing the report.\n"
		"Do not add extra keys or commentary."
	)

	user_prompt = (
		"Report text:\n" + text + "\n\n"
		"Extract intent, indicators (precursor chemicals, scale, delivery method, evasion behavior), and a one-sentence summary."
	)

	payload = {
		"model": model,
		"messages": [
			{"role": "system", "content": system},
			{"role": "user", "content": user_prompt},
		],
		"max_tokens": 300,
		"temperature": 0.0,
	}

	data = json.dumps(payload).encode("utf-8")
	req = urllib.request.Request(url, data=data, method="POST")
	req.add_header("Content-Type", "application/json")
	req.add_header("Authorization", f"Bearer {api_key}")

	try:
		with urllib.request.urlopen(req, timeout=30) as resp:
			resp_data = resp.read().decode("utf-8")
			j = json.loads(resp_data)
			# Chat completions: choices[0].message.content
			content = None
			if "choices" in j and j["choices"]:
				message = j["choices"][0].get("message") or j["choices"][0].get("text")
				if isinstance(message, dict):
					content = message.get("content")
				else:
					content = message

			if not content:
				return None

			# Try to extract JSON from content
			return _extract_json_from_text(content)

	except urllib.error.HTTPError as e:
		try:
			body = e.read().decode('utf-8')
		except Exception:
			body = ''
		print(f"LLM HTTP error: {e.code} {e.reason}. Body: {body}", file=sys.stderr)
	except Exception as e:
		print(f"LLM request failed: {e}", file=sys.stderr)

	return None


def _extract_json_from_text(text: str) -> typing.Optional[dict]:
	text = text.strip()
	# Direct parse
	try:
		return json.loads(text)
	except Exception:
		pass

	# Try to find first { ... }
	start = text.find("{")
	end = text.rfind("}")
	if start != -1 and end != -1 and end > start:
		candidate = text[start : end + 1]
		try:
			return json.loads(candidate)
		except Exception:
			pass

	return None


def _find_all(text: str, sub: str) -> list:
	positions = []
	if not sub:
		return positions
	start = text.find(sub)
	while start != -1:
		positions.append(start)
		start = text.find(sub, start + 1)
	return positions


def _contains_any(text: str, terms) -> bool:
	return any(term in text for term in terms)


def _has_toxic_keyword_near_context(text: str) -> bool:
	if "toxi" not in text:
		return False

	for toxic_pos in _find_all(text, "toxi"):
		for keyword in TOXIC_NEAR_KEYWORDS:
			for keyword_pos in _find_all(text, keyword):
				if abs(toxic_pos - keyword_pos) <= 40:
					return True
	return False


def _short_summary(text: str, limit: int = 150) -> str:
	summary = text.strip().replace("\n", " ")
	if len(summary) <= limit:
		return summary
	return summary[: limit - 3].rsplit(" ", 1)[0] + "..."


def normalize_indicators(indicators) -> list:
	normalized = []
	seen = set()

	for raw in indicators or []:
		cleaned = (raw or "").strip().lower()
		if not cleaned:
			continue

		if cleaned in AEROSOL_SYNONYMS:
			label = "delivery: aerosol"
		elif cleaned in INGESTION_SYNONYMS:
			label = "delivery: ingestion/contamination"
		elif cleaned in DEVICE_SYNONYMS:
			label = "delivery: device/vehicle"
		elif cleaned in EVASION_SYNONYMS:
			label = "evasion: concealment/temporal"
		elif "precursor" in cleaned:
			label = cleaned
		elif "scale" in cleaned:
			if any(term in cleaned for term in LARGE_SCALE_TERMS):
				label = "scale: large"
			elif any(term in cleaned for term in SMALL_SCALE_TERMS):
				label = "scale: small"
			else:
				label = cleaned
		else:
			label = cleaned

		if label not in seen:
			seen.add(label)
			normalized.append(label)

	return normalized


def _apply_analysis_rules(text: str, analysis: dict) -> dict:
	if not text:
		analysis["indicators"] = normalize_indicators(analysis.get("indicators") or [])
		return analysis

	text = text.lower()
	indicators = list(analysis.get("indicators") or [])
	current_intent = analysis.get("intent") or "benign"
	has_fiction_framing = _contains_any(text, FRAMING_PHRASES)

	secret_chemical_acquisition = (
		_contains_any(text, ACQUISITION_VERBS)
		and _contains_any(text, CHEMICAL_RISK_TERMS)
		and _contains_any(text, SECRECY_TERMS)
	)
	if secret_chemical_acquisition and current_intent not in ("suspicious", "malicious"):
		current_intent = _set_intent(analysis, "suspicious")

	has_safety_context = _contains_any(text, SAFETY_CONTEXT_TERMS)
	has_operational_harmful_language = _contains_any(text, OPERATIONAL_HARMFUL_TERMS)
	has_prevention_context = _contains_any(text, PREVENTION_TERMS)
	has_high_harm_intent = _contains_any(text, HIGH_HARM_INTENT_TERMS)
	has_research_to_harm_drift = (
		has_safety_context
		and _contains_any(text, HARM_THRESHOLD_TERMS)
		and (
			_contains_any(text, OPERATIONAL_CONTEXT_TERMS)
			or _contains_any(text, ENCLOSED_ENVIRONMENT_TERMS)
			or _contains_any(text, ("cause harm", "effective", "effectiveness"))
		)
	)
	has_precursor = _add_precursor_indicators(text, indicators)

	precursor_with_evasion = has_precursor and _contains_any(text, EVASION_PHRASES)
	if precursor_with_evasion:
		indicators.append("evasion: concealment/temporal")
		if current_intent != "malicious":
			current_intent = _set_intent(analysis, "malicious")

	if has_precursor and _contains_any(text, PROCESS_CONTEXT_TERMS) and current_intent == "benign":
		current_intent = _set_intent(analysis, "dual_use")

	if has_high_harm_intent and _contains_any(text, CHEMICAL_RISK_TERMS) and _contains_any(text, OPERATIONAL_HARMFUL_TERMS):
		current_intent = _set_intent(analysis, "malicious")

	if has_operational_harmful_language and not has_safety_context and current_intent not in ("suspicious", "malicious"):
		current_intent = _set_intent(analysis, "suspicious")

	if has_research_to_harm_drift and current_intent == "benign":
		current_intent = _set_intent(analysis, "dual_use")
		if has_operational_harmful_language or _contains_any(text, EVASION_PHRASES) or _contains_any(text, ("cause harm", "effective", "effectiveness")):
			current_intent = _set_intent(analysis, "suspicious")

	if _contains_any(text, WATER_PHRASES):
		indicators.append("delivery: ingestion/contamination")
		if _contains_any(text, EVASION_PHRASES):
			indicators.append("evasion: concealment/temporal")
			current_intent = _set_intent(analysis, "suspicious" if has_fiction_framing else "malicious")
		elif current_intent not in ("suspicious", "malicious"):
			current_intent = _set_intent(analysis, "suspicious")

	if _has_toxic_keyword_near_context(text):
		indicators.append("precursor: toxic")

	normalized_indicators = normalize_indicators(indicators)
	has_strong_harmful_indicators = _has_strong_harmful_indicators(normalized_indicators)
	if has_prevention_context and has_safety_context and not has_strong_harmful_indicators:
		current_intent = _set_intent(analysis, "benign")
	if has_safety_context and current_intent in ("suspicious", "malicious") and not has_strong_harmful_indicators:
		_set_intent(analysis, "dual_use" if has_precursor else "benign")

	# Mark presence of safety context explicitly for scoring post-processing
	if has_safety_context and "context: safety" not in normalized_indicators:
		normalized_indicators.append("context: safety")
	if has_research_to_harm_drift and "context: research-to-harm" not in normalized_indicators:
		normalized_indicators.append("context: research-to-harm")

	analysis["indicators"] = normalized_indicators
	return analysis


def _rule_based_analysis(text: str) -> dict:
	t = text.lower()
	intent = "benign"
	has_fiction_framing = _contains_any(t, FRAMING_PHRASES)
	has_safety_context = _contains_any(t, SAFETY_CONTEXT_TERMS)

	# Simple intent heuristics
	if any(k in t for k in RULE_BASED_MALICIOUS_TERMS):
		intent = "malicious"
	elif any(k in t for k in RULE_BASED_SUSPICIOUS_TERMS):
		intent = "suspicious"
	elif any(k in t for k in RULE_BASED_DUAL_USE_TERMS):
		intent = "dual_use"

	# Fiction framing should not be treated as fully malicious on keywords alone.
	if has_fiction_framing and intent == "malicious":
		intent = "suspicious"

	indicators = []

	_add_precursor_indicators(t, indicators)

	if _has_toxic_keyword_near_context(t):
		indicators.append("precursor: toxic")

	if _contains_any(t, LARGE_SCALE_TERMS) and not has_safety_context:
		indicators.append("scale: large")
	elif _contains_any(t, SMALL_SCALE_TERMS):
		indicators.append("scale: small")

	if _contains_any(t, RULE_BASED_AEROSOL_TERMS) and not has_safety_context:
		indicators.append("delivery: aerosol")
	if _contains_any(t, RULE_BASED_INGESTION_TERMS):
		indicators.append("delivery: ingestion/contamination")
	if _contains_any(t, RULE_BASED_DEVICE_TERMS):
		indicators.append("delivery: device/vehicle")

	if _contains_any(t, RULE_BASED_EVASION_TERMS):
		indicators.append("evasion: concealment/temporal")

	if _contains_any(t, WATER_PHRASES):
		if "delivery: ingestion/contamination" not in indicators:
			indicators.append("delivery: ingestion/contamination")

	return {"intent": intent, "indicators": indicators, "summary": _short_summary(text)}


def analyze_report(row: dict) -> dict:
	text = (row.get("text") or "").strip()
	analysis = None

	api_key = os.environ.get("OPENAI_API_KEY")
	if api_key and text:
		result = _call_llm(text, api_key)
		if isinstance(result, dict):
			analysis = {
				"intent": result.get("intent", "benign"),
				"indicators": result.get("indicators") or [],
				"summary": result.get("summary", ""),
			}

	if analysis is None:
		analysis = _rule_based_analysis(text)

	# Detect fiction/cover-story framing in the raw text. If framing phrases
	# appear alongside harmful capability indicators (precursor or delivery),
	# add a `framing: fiction` indicator so scoring will not treat it as
	# automatically benign.
	try:
		low = text.lower()
		if any(p in low for p in FRAMING_PHRASES):
			inds = analysis.get("indicators") or []
			if any((i or "").lower().startswith(("precursor", "delivery")) for i in inds):
				inds.append("framing: fiction")
				analysis["indicators"] = inds
	except Exception:
		pass

	return _apply_analysis_rules(text, analysis)


def compute_risk_score(intent, indicators) -> int:
	# preserve normalization of indicators
	indicators = normalize_indicators(indicators)

	# Start with intent contribution (reduced dominance)
	score = INTENT_SCORES.get((intent or "benign"), 0)

	# Track presence of capability/behavior indicators for escalation rules
	has_precursor = False
	has_delivery = False
	has_evasion = False
	has_contamination = False

	for ind in indicators:
		il = (ind or "").lower()

		# Weighted precursor scoring: use PRECURSOR_WEIGHTS, default 1
		if il.startswith("precursor"):
			has_precursor = True
			# extract chemical part after 'precursor:' if present
			chem = ""
			parts = il.split(":", 1)
			if len(parts) > 1:
				chem = parts[1].strip()
			weight = PRECURSOR_WEIGHTS.get(chem, 1)
			score += weight

		# Delivery indicates capability to deliver — add fixed contribution
		elif il.startswith("delivery"):
			has_delivery = True
			score += 3

		# Scale increases risk modestly
		elif il.startswith("scale"):
			score += 1

		# Evasion increases risk and participates in escalation rules
		elif il.startswith("evasion"):
			has_evasion = True
			score += 2

		# Detect contamination/ingestion phrasing for minimum thresholds
		if "ingestion/contamination" in il or "contamination" in il:
			has_contamination = True

	# Post-processing boosts and adjustments
	# 1) Suspicious intent with delivery indicates operational capability → small boost
	if (intent or "").lower() == "suspicious" and has_delivery:
		score += 1
	if (intent or "").lower() == "dual_use" and "context: research-to-harm" in indicators:
		score += 1

	# 2) Malicious intent with precursor + delivery indicates high consequence capability → extra boost
	if (intent or "").lower() == "malicious" and has_precursor and has_delivery:
		score += 2

	# 3) Framing (fiction/cover-story) handling: if framing indicator present alongside
	#    precursor/delivery, ensure intent is at least suspicious for scoring purposes
	framing_present = any(((ind or "").lower().startswith("framing")) for ind in indicators)
	if framing_present and (has_precursor or has_delivery):
		# Ensure framing with harmful indicators is treated with caution:
		# - Raise local intent floor to at least 'suspicious' contribution
		# - Enforce a minimum score of 5 so fiction framing doesn't mask capability
		if (intent or "").lower() not in ("suspicious", "malicious"):
			if score < INTENT_SCORES.get("suspicious", 2):
				score = INTENT_SCORES.get("suspicious", 2)
		# Enforce minimum score for framing-with-harm cases
		if score < 5:
			score = 5

	# 4) Safety-context dampening: if explicit safety context and no evasion,
	#    cap clearly-benign cases at 3 to avoid over-scoring safety-oriented reports.
	if "context: safety" in indicators and not has_evasion:
		# Determine if strong harmful indicators exist (high-weight precursor, delivery, or evasion)
		has_strong_harm = False
		# consider a precursor strong if its weight >= 4
		for ind in indicators:
			il = (ind or "").lower()
			if il.startswith("precursor"):
				parts = il.split(":", 1)
				chem = parts[1].strip() if len(parts) > 1 else ""
				if PRECURSOR_WEIGHTS.get(chem, 1) >= 4:
					has_strong_harm = True
			if il.startswith("delivery") or il.startswith("evasion"):
				has_strong_harm = True

		# If intent is benign and no strong harmful indicators, cap score at 3
		if (intent or "").lower() == "benign" and not has_strong_harm and score > 3:
			score = 3

	# Combination escalation: precursor + delivery → additional capability escalation
	if has_precursor and has_delivery:
		# material + delivery method together significantly raise risk
		score += 3

	# Ensure minimums for dangerous combinations
	# precursor + evasion implies active concealment with dangerous material
	if has_precursor and has_evasion and score < 5:
		score = 5

	# precursor + delivery + evasion is the highest escalation we enforce
	if has_precursor and has_delivery and has_evasion and score < 8:
		score = 8

	# contamination (e.g., water/ingestion) enforces minimum serious risk
	if has_contamination and score < 5:
		score = 5

	# Soft-cap heavily stacked escalation paths so they stay high without ballooning.
	escalation_count = sum(1 for present in (has_precursor, has_delivery, has_evasion, has_contamination) if present)
	if escalation_count >= 3 and score > 12:
		score = 12 + (score - 12) // 2

	return score


def calculate_risk_score(intent, indicators) -> int:
	return compute_risk_score(intent, indicators)


if __name__ == "__main__":
	main()

