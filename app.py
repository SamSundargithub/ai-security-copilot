# app.py
import streamlit as st
from rag_pipeline import process_query, index_data
from backend.cve_lookup import fetch_cve

st.set_page_config(page_title="🛡️ AI Security Copilot", layout="wide")

st.title("🛡️ AI Security Copilot")

# Sidebar
st.sidebar.title("Features")
feature = st.sidebar.radio("Select Feature", ["RAG Q&A", "Upload PDF", "CVE Lookup"])

# ----------------- Upload PDF -----------------
if feature == "Upload PDF":
    st.header("Upload Security Documents")
    uploaded_files = st.file_uploader("Upload PDFs", accept_multiple_files=True, type=["pdf"])
    
    if uploaded_files:
        st.success("✅ Files uploaded successfully!")
        st.info("⏳ Processing documents...")
        
        for file in uploaded_files:
            index_data(file)  # function: chunks → embeddings → FAISS
        st.success("✅ Knowledge base updated!")

# ----------------- RAG Q&A -----------------
elif feature == "RAG Q&A":
    st.header("Ask Security Question")
    question = st.text_input("Enter your question:")
    
    if st.button("Get Answer") and question:
        answer, _ = process_query(question)  # RAG returns answer + sources
        st.subheader("🧠 AI Output")

        # If no relevant answer exists in the uploaded documents, show a warning.
        if "No results found" in answer:
            st.warning(answer)
        else:
            st.write(answer)

# ----------------- CVE Lookup -----------------
elif feature == "CVE Lookup":
    st.header("CVE Lookup")
    keyword = st.text_input("Enter keyword (e.g., Apache Log4j)")
    
    if st.button("Search CVEs") and keyword:
        data = fetch_cve(keyword)  # fetch live CVEs from NVD

        # If the API request failed, show the error message.
        if data.get("error"):
            st.error(f"CVE lookup failed: {data['error']}")
            st.stop()

        results = data.get("results", [])
        if not results:
            st.warning("No CVEs found for that keyword. Try a different search term.")
            st.stop()

        st.subheader("🔎 CVE Results")
        for cve in results:
            risk = cve.get('risk_score', 'N/A') or 'N/A'
            severity = cve.get('severity', 'N/A') or 'N/A'
            threat = cve.get('threat', 'N/A') or 'N/A'
            vuln = cve.get('vulnerability', 'N/A') or 'N/A'
            mitigation = cve.get('mitigation')
            impact = cve.get('impact')

            st.markdown(f"**{cve['id']}** (Severity: {severity} / Risk Score: {risk}) - Threat: {threat} - Vulnerability: {vuln}\n\n{cve['description']}")
            if impact:
                st.markdown(f"**Impact:** {impact}")
            if mitigation:
                st.markdown(f"**Mitigation:** {mitigation}")