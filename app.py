import streamlit as st

from main import analyze_report, compute_risk_score


st.set_page_config(page_title="CBRN Report Analyzer", layout="centered")
st.title("CBRN Report Analyzer")
st.write("Paste a report and run the existing analysis pipeline.")

report_text = st.text_area("Report text", height=200, placeholder="Paste report text here...")

if st.button("Analyze"):
	if not report_text.strip():
		st.warning("Please enter report text before analyzing.")
	else:
		row = {"text": report_text}
		analysis = analyze_report(row)
		intent = analysis.get("intent", "benign")
		indicators = analysis.get("indicators") or []
		summary = analysis.get("summary", "")
		risk_score = compute_risk_score(intent, indicators)

		st.subheader("Results")
		st.write(f"Intent: {intent}")
		st.write("Indicators:")
		if indicators:
			for item in indicators:
				st.write(f"- {item}")
		else:
			st.write("- <none>")
		st.write(f"Summary: {summary}")
		st.write(f"Risk score: {risk_score}")
