import argparse
import os

import ChkApi


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="results 子目录（包含 results.db 的目录）")
    ap.add_argument("--query", required=True, help="全文检索关键词（将同时匹配 url 与 response 正文）")
    ap.add_argument("--dataset", default="response_log", choices=["response_log", "step5", "step5_xml_json", "step7"])
    ap.add_argument("--size", type=int, default=20)
    args = ap.parse_args()

    result_dir = os.path.abspath(args.dir)
    if not os.path.isdir(result_dir):
        raise SystemExit(f"dir not found: {result_dir}")

    q = args.query
    res = ChkApi.search_rr(
        result_dir,
        request_id="",
        url_kw=q,
        start="",
        end="",
        page=1,
        size=args.size,
        dataset=args.dataset,
        include_response=False,
        include_request=False,
        include_diff=False,
    )

    hits = res.get("response") or []
    print(f"dataset={args.dataset} query={q!r} hits={len(hits)} total={res.get('total')}")
    if not hits:
        return 2

    if args.dataset == "response_log":
        rid = hits[0].get("id") or ""
        det = ChkApi.search_rr(
            result_dir,
            request_id=rid,
            url_kw="",
            start="",
            end="",
            page=1,
            size=1,
            dataset="response_log",
            include_response=True,
            include_request=False,
            include_diff=False,
        )
        txt = ((det.get("response") or [{}])[0]).get("response") or ""
        ok = q.lower() in txt.lower()
        print(f"first_detail_contains_query={ok}")
        return 0 if ok else 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
