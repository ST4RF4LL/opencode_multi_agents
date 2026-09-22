"""Bounded, read-only adapter for KnowledgeWorkFlow's own retrieval/quality code."""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SCHEMA = "audit-knowledge-query.v1"
MAX_BYTES = 128 * 1024


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_path(root, relative):
    path = (root / relative).resolve(strict=True)
    path.relative_to(root)
    return path


def source_ref(root, doc):
    path = checked_path(root, doc["path"])
    return {"path": path.relative_to(root).as_posix(), "sha256": sha(path)}


def summary(root, doc):
    result = {key: doc.get(key) for key in ("uid", "kind", "id", "title", "summary", "facets", "quality", "curation", "attributes")}
    result["source"] = source_ref(root, doc)
    if doc["kind"] == "mechanism":
        payload = doc.get("payload") or {}
        result["mechanism_status"] = {key: payload.get(key) for key in (
            "status", "evidence_status", "cross_project_status", "dynamic_verification", "automatic_vulnerability_verdict", "coverage")}
        result["detectors"] = payload.get("detectors", [])
    return result


def query_index(root, index, request):
    quality = index.quality
    warnings = list(index.errors) + list(quality.get("warnings", []))
    result = {"schema_version": SCHEMA, "status": "PARTIAL" if warnings else "READY",
              "read_only": True, "automatic_vulnerability_verdict": False,
              "root": str(root), "warnings": warnings[:20], "warning_count": len(warnings),
              "limits": ["知识条目仅作审查线索，不能替代当前源码证据或覆盖记录。",
                         "原案例差分、静态样本与跨项目验证是不同状态；保留原始质量标记。"]}
    if not index.docs or not any(doc["kind"] == "mechanism" for doc in index.docs):
        return {**result, "status": "UNAVAILABLE", "reason": "索引为空或缺少根因质量层，不能作为完整知识检索。"}
    command = request["command"]
    if command == "status":
        result.update(stats=index.stats(), quality_summary=quality.get("summary", {}))
    elif command == "search":
        filters = dict(request.get("filters", {}))
        if request.get("kind", "mechanism") != "any":
            filters["kind"] = [request.get("kind", "mechanism")]
        page = index.search(query=request.get("query", ""), filters=filters,
                            mode=request.get("mode", "auto"), limit=request.get("limit", 5),
                            offset=request.get("offset", 0))
        result.update(query=request.get("query", ""), total=page["total"],
                      offset=page["offset"], limit=page["limit"], results=[])
        for hit in page["results"]:
            doc = index.get(hit["uid"])
            result["results"].append({**summary(root, doc), "score": hit.get("score"), "snippet": hit.get("snippet")})
        if not page["total"]:
            result["reason"] = "本次检索无匹配；不代表该风险不存在，也不关闭覆盖项。"
    elif command == "show":
        doc = index.get(request["id"]) or index.resolve(request["id"])
        if doc is None:
            return {**result, "status": "NOT_FOUND", "reason": "未找到该条目，请使用检索返回的 uid 或规范 ID。"}
        # Keep the native quality-enriched payload, including counterexamples,
        # corrections and stale evidence flags; omit duplicate raw/body views.
        detail = summary(root, doc)
        detail["payload"] = doc.get("payload")
        if not detail["payload"]:
            detail.update(intro=doc.get("intro"), sections=doc.get("sections"))
        related = index.related(doc["uid"])
        offset, limit = request.get("offset", 0), request.get("limit", 5)
        detail.update(related=related[offset:offset + limit], related_total=len(related), related_offset=offset)
        result["document"] = detail
    else:
        raise ValueError("不支持的只读操作。")
    return result


def signature(root, paths):
    return sorted((path.relative_to(root).as_posix(), path.stat().st_size, path.stat().st_mtime_ns)
                  for path in paths)


def retrieve(root, request):
    # Only the selected knowledge checkout supplies the native index module.
    # Never invoke its CLI, workflow, scanners, agents, or web service.
    sys.path.insert(0, str(checked_path(root, "src")))
    from knowledge_factory.kb_index import build_index, iter_corpus_files
    before = signature(root, iter_corpus_files(root))
    index = build_index(root)
    result = query_index(root, index, request)
    provenance = []
    for relative in ("src/knowledge_factory/kb_index.py", "src/knowledge_factory/kb_quality.py",
                     "src/knowledge_factory/kb_mechanism_coverage.py", "knowledge/catalog/quality/corrections.yaml",
                     "knowledge/catalog/quality/mechanism-coverage.json", "knowledge/catalog/quality/evaluation.json",
                     "knowledge/detectors/evaluation.json"):
        path = root / relative
        if path.is_file():
            provenance.append(source_ref(root, {"path": relative}))
    after = signature(root, iter_corpus_files(root))
    if before != after:
        return {"schema_version": SCHEMA, "status": "STALE", "read_only": True,
                "automatic_vulnerability_verdict": False,
                "reason": "检索期间知识库文件发生变化，本次结果不采用；需要时重新查询。"}
    result["provenance"] = {"retrieval": "KnowledgeWorkFlow.kb_index", "quality_sources": provenance,
                            "metadata_revision": hashlib.sha256(json.dumps(after, ensure_ascii=False).encode()).hexdigest()}
    return result


def main():
    try:
        root = Path(sys.argv[1]).resolve(strict=True)
        request = json.loads(sys.argv[2])
        result = retrieve(root, request)
        rendered = json.dumps(result, ensure_ascii=False, default=str)
        if len(rendered.encode("utf-8")) > MAX_BYTES:
            raise ValueError("查询输出过大，请缩小集合、筛选条件或分页。")
    except Exception:
        rendered = json.dumps({"schema_version": SCHEMA, "status": "UNAVAILABLE", "read_only": True,
                               "automatic_vulnerability_verdict": False,
                               "reason": "知识库索引加载或查询失败；检查版本、依赖与文件完整性，继续源码审计并保留检索缺口。"}, ensure_ascii=False)
    sys.stdout.buffer.write((rendered + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
