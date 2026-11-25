"""分析：按文档去重到底影响了什么。

回答两个问题：
1. 去重前，Top-3 里同一文档重复出现有多频繁？
2. 去重后，相关文档会被挤掉吗（文档级命中率是否下降）？
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langchain_core.embeddings import Embeddings  # noqa: E402
from langchain_chroma import Chroma  # noqa: E402
from sentence_transformers import SentenceTransformer  # noqa: E402

from core.rag.chunking import split_text  # noqa: E402
from core.rag.embeddings import BGE_ZH_QUERY_PREFIX  # noqa: E402

DATA = Path(__file__).resolve().parents[1] / "tests" / "data" / "rag_retrieval_large_v2.json"
MODEL = Path(__file__).resolve().parents[1] / "models" / "bge-large-zh-v1.5"


class Emb(Embeddings):
    def __init__(self):
        self.m = SentenceTransformer(str(MODEL), trust_remote_code=True)

    def embed_documents(self, texts):
        return self.m.encode(list(texts), normalize_embeddings=True).tolist()

    def embed_query(self, text):
        return self.m.encode(BGE_ZH_QUERY_PREFIX + text, normalize_embeddings=True).tolist()


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    documents, queries = data["documents"], data["queries"]

    texts, metas = [], []
    for doc in documents:
        for index, piece in enumerate(split_text(doc["text"], size=400, overlap=80)):
            texts.append(piece["text"])
            metas.append({"id": doc["id"], "chunk": index})

    store = Chroma.from_texts(texts, embedding=Emb(), metadatas=metas,
                              collection_name=f"an_{uuid.uuid4().hex}")

    dup_in_top3 = 0
    chunk_hit = doc_hit = 0
    total = 0
    examples = []

    for query in queries:
        hits = store.similarity_search(query["text"], k=10)
        chunk_ids = [(d.metadata or {}).get("id") for d in hits]
        top3_chunks = chunk_ids[:3]
        distinct = list(dict.fromkeys(chunk_ids))[:3]

        relevant = set(query["relevant_ids"])
        chunk_hit_ok = bool(relevant & set(top3_chunks))
        doc_hit_ok = bool(relevant & set(distinct))

        chunk_hit += chunk_hit_ok
        doc_hit += doc_hit_ok
        total += 1

        if len(set(top3_chunks)) < 3:
            dup_in_top3 += 1
            if len(examples) < 3:
                examples.append((query["id"], top3_chunks, distinct))

    store.delete_collection()

    print(f"问题数: {total}")
    print(f"Top-3 里出现重复文档的比例: {dup_in_top3}/{total} = {dup_in_top3 / total:.1%}")
    print(f"块级命中 (Top-3 任一块属于相关文档): {chunk_hit}/{total} = {chunk_hit / total:.1%}")
    print(f"文档级命中 (去重后 Top-3 含相关文档): {doc_hit}/{total} = {doc_hit / total:.1%}")
    print()
    print("重复样例（前 3 条）:")
    for qid, chunks, distinct in examples:
        print(f"  {qid}: 块级 {chunks} -> 文档级 {distinct}")


if __name__ == "__main__":
    main()
