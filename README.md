# 🔐 AI Security Copilot

An AI-powered Cybersecurity Assistant that leverages **Semantic Search, Retrieval Augmented Generation (RAG), CVE Intelligence, and PDF Analysis** to help security analysts quickly retrieve insights and investigate vulnerabilities.

---

## 🚀 Features

* 🔍 **Semantic Search**

  * Uses embeddings to retrieve relevant cybersecurity knowledge
  * Powered by a custom vector database (Endee-inspired engine)

* 🧠 **RAG Pipeline**

  * Combines retrieval + AI reasoning for more accurate responses

* 🛡️ **CVE Lookup (NVD Integration)**

  * Fetch real-time vulnerability data using CVE IDs
  * Integrated with National Vulnerability Database (NVD)

* 📄 **PDF Analysis**

  * Upload security reports or documents
  * Extract and process text for insights

* 🖥️ **Streamlit UI**

  * Interactive and simple user interface

---

## 🧱 Project Architecture

```
User → Streamlit UI (app.py)
        ↓
   RAG Pipeline (rag_pipeline.py)
        ↓
 ┌───────────────┐
 │ Vector Engine │  (Custom Endee-style DB)
 └───────────────┘
        ↓
 Backend Services
 ├── CVE Lookup (NVD API)
 └── PDF Processing
```

---

## 📁 Project Structure

```
ai-security-copilot/
│
├── app.py                     # Streamlit UI
├── rag_pipeline.py            # Core AI logic
│
├── backend/
│   ├── __init__.py
│   ├── cve_lookup.py          # CVE API integration
│   
│
├── endee/
│   ├── __init__.py
│   └── engine.py              # Custom vector database
│
├── uploads/                   # Uploaded files
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository

```
git clone https://github.com/YOUR_USERNAME/ai-security-copilot.git
cd ai-security-copilot
```

---

### 2️⃣ Install dependencies

```
pip install -r requirements.txt
```

---

### 3️⃣ Run the application

```
python -m streamlit run app.py
```

---

## 🧪 Usage

* 🔍 Enter queries for semantic search
* 🛡️ Input CVE IDs (e.g., `CVE-2021-44228`)
* 📄 Upload PDF documents for analysis

---

## 🧠 Key Technologies

* Python
* Streamlit
* Sentence Transformers (Embeddings)
* NumPy
* REST APIs (NVD CVE API)

---

## 💡 How It Works

1. User submits a query
2. Query is converted into embeddings
3. Vector engine retrieves similar data
4. System enhances response using RAG
5. CVE or PDF input is processed if detected

---

## 📸 Demo 



## 🎯 Future Improvements

* 🤖 Chat-based UI
* ☁️ Cloud deployment (AWS)
* 📊 Advanced ranking & scoring system

---

## 👨‍💻 Author

**Sam Sundar N**
Cybersecurity Enthusiast | AI Developer

---

## ⭐ Acknowledgment

Inspired by modern vector database systems and built using a custom Endee-style engine.

---

## 📌 Note

This project is built for **educational and demonstration purposes** in cybersecurity and AI.

---
