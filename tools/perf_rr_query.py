import argparse
import os
import time

import ChkApi


def run_once(result_dir: str, dataset: str, page: int, size: int, include_response: bool) -> float:
    t0 = time.perf_counter()
    ChkApi.search_rr(
        result_dir,
        request_id="",
        url_kw="",
        start="",
        end="",
        method="",
        res_code="",
        res_type="",
        min_length="",
        max_length="",
        sort="timestamp",
        order="desc",
        page=page,
        size=size,
        dataset=dataset,
        include_response=include_response,
        include_request=False,
        include_diff=False,
    )
    return time.perf_counter() - t0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="results 子目录（包含 results.db 的目录）")
    ap.add_argument("--dataset", default="response_log", choices=["response_log", "step5", "step5_xml_json", "step7"])
    ap.add_argument("--page", type=int, default=1)
    ap.add_argument("--size", type=int, default=50)
    ap.add_argument("--include-response", action="store_true")
    ap.add_argument("--rounds", type=int, default=5)
    args = ap.parse_args()

    result_dir = os.path.abspath(args.dir)
    if not os.path.isdir(result_dir):
        raise SystemExit(f"dir not found: {result_dir}")

    times = []
    for _ in range(max(1, args.rounds)):
        times.append(run_once(result_dir, args.dataset, args.page, args.size, args.include_response))

    ms = [t * 1000.0 for t in times]
    avg = sum(ms) / len(ms)
    p95 = sorted(ms)[max(0, int(len(ms) * 0.95) - 1)]
    print(f"dataset={args.dataset} size={args.size} include_response={args.include_response}")
    print(f"avg_ms={avg:.2f} p95_ms={p95:.2f} rounds={len(ms)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
