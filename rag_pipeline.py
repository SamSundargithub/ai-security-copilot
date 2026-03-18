import numpy as np
from sentence_transformers import SentenceTransformer
from endee.engine import Engine
from backend.cve_lookup import fetch_cve

# SEMANTIC SEARCH CONFIGURATION
# This system uses sentence-transformers with cosine similarity for SEMANTIC search
# (understanding meaning), NOT keyword/regex matching.

# Load semantic embedding model: converts text to semantic vectors
# all-MiniLM-L6-v2 is optimized for semantic similarity and retrieval tasks
model = SentenceTransformer('all-MiniLM-L6-v2')

# Initialize vector store (in-memory, no external DB needed)
engine = Engine("cyber_db")

# Default docs used when no PDF is provided
_default_documents = [
    "SQL Injection vulnerability allows attackers to access database",
    "Cross Site Scripting affects web applications",
    "Brute force attack detected in login systems"
]

def _chunk_text(text, chunk_size=250, overlap=50):
    """Chunk text into overlapping windows for finer-grained retrieval."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i : i + chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


def index_data(uploaded_file=None):
    """Index either a default set of documents or an uploaded PDF.

    Args:
        uploaded_file: Optional streamlit uploaded file object (PDF).
    """

    documents = _default_documents

    if uploaded_file is not None:
        # Try to extract text from PDF; fall back to raw bytes if pdf parsing isn't available.
        try:
            import PyPDF2

            reader = PyPDF2.PdfReader(uploaded_file)
            documents = [page.extract_text() or "" for page in reader.pages]
            documents = [d for d in documents if d.strip()]

        except Exception:
            uploaded_file.seek(0)
            raw = uploaded_file.read()
            documents = [raw.decode("utf-8", errors="ignore")]

    # Chunk documents for more focused retrieval
    for i, doc in enumerate(documents):
        chunks = _chunk_text(doc, chunk_size=200, overlap=50)
        for j, chunk in enumerate(chunks):
            embedding = model.encode(chunk).tolist()
            engine.insert({
                "id": f"doc_{i}_chunk_{j}",  # unique ID per chunk
                "text": chunk,
                "vector": embedding,
            })


def _clean_text(text):
    """Remove unnecessary metadata like page numbers and chapter headers."""
    import re
    
    # Remove "Page | number" patterns
    text = re.sub(r'P\s*a\s*g\s*e\s*\|\s*\d+', '', text)
    text = re.sub(r'Page\s+\d+', '', text)
    
    # Remove "Chapter X:" patterns
    text = re.sub(r'Chapter\s+\d+.*?:', '', text)
    
    # Clean up extra whitespace
    text = ' '.join(text.split())
    
    return text.strip()


def _extract_best_sentence(text, query_vector, query_text):
    """Return the single sentence that best matches the query semantically.

    Avoid returning the query itself if the document includes it verbatim.
    """
    import re

    # Split into sentences (basic rule-based split)
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return text.strip()

    # Embed sentences and compare to query vector
    sent_embeddings = model.encode(sentences)
    query_vec = np.array(query_vector)

    # Compute scores for each sentence
    scored = []
    for sent, emb in zip(sentences, sent_embeddings):
        score = float(np.dot(query_vec, emb) / (np.linalg.norm(query_vec) * np.linalg.norm(emb) + 1e-9))
        scored.append((score, sent))

    # Sort by descending score
    scored.sort(key=lambda x: x[0], reverse=True)

    query_lower = query_text.strip().lower()

    for score, sent in scored:
        sent_lower = sent.lower()

        # Avoid returning the query itself if the document contains it verbatim
        if query_lower and query_lower in sent_lower:
            continue

        # Prefer statements/explanations over questions
        if sent.strip().endswith("?"):
            continue

        # Avoid extremely short fragments
        if len(sent) < 20:
            continue

        return sent

    # Fall back to the best scoring sentence (even if it's a question)
    return scored[0][1] if scored else sentences[0]


def search(query, top_k=1):
    """
    SEMANTIC SEARCH: Find documents by MEANING, not keywords.
    
    Flow:
    1. Encode query into semantic vector
    2. Compare against all indexed document vectors using cosine similarity
    3. Return best match if confidence > threshold
    4. Strip metadata for clean output
    5. Return a single best sentence to keep answers concise
    
    Args:
        query (str): Natural language question
        top_k (int): Number of candidates to evaluate (higher for better recall)
    
    Returns:
        tuple: (answer_text, source_ids)
    """
    
    # Step 1: Convert query to semantic vector (understanding meaning, not words)
    query_vector = model.encode(query).tolist()

    # Step 2: Search vector store using cosine similarity
    # Results include cosine similarity scores (0.0 to 1.0)
    results = engine.search({"vector": query_vector, "top_k": 5})
    
    if not results:
        return "No results found.", []

    # Step 3: Filter by semantic confidence threshold
    SEMANTIC_THRESHOLD = 0.2  # Cosine similarity threshold for semantic match
    relevant_results = [r for r in results if r.get("score", 0) > SEMANTIC_THRESHOLD]

    # If we found nothing above the threshold, return no results.
    if not relevant_results:
        return "No results found in the uploaded document.", []

    top_result = relevant_results[0]
    
    text = top_result.get("text") or top_result.get("payload", {}).get("text")
    if text:
        # Clean metadata for readability
        cleaned_text = _clean_text(text)
        if cleaned_text:
            # Extract a single best sentence that matches the query intent
            answer = _extract_best_sentence(cleaned_text, query_vector, query)
            source = top_result.get("id") or top_result.get("_id") or "unknown"
            return answer, [source]

    return "No semantically relevant documents found.", []


def process_query(query):
    """
    Route query to appropriate handler:
    - CVE lookups: use NVD live API (keyword-based)
    - Other queries: use SEMANTIC SEARCH on indexed documents
    """
    # Preserve the app's expectation that we return (answer, sources)
    if query.upper().startswith("CVE-"):
        results = fetch_cve(query)
        answer = "\n\n".join([f"{r['id']}: {r['description']}" for r in results])
        sources = [r.get("id") for r in results]
        return answer, sources

    # SEMANTIC SEARCH: Finds meaning by comparing vector embeddings, not keywords
    return search(query)