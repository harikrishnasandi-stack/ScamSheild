"""
ScamShield 2.0 - evaluation script
Runs the chain on every message in test_set.csv and reports accuracy,
a confusion matrix, false alarms and missed scams. Saves results_chain.csv.

Usage:
    python eval_chain.py        # all messages
    python eval_chain.py 5      # only the first 5 (quick test)
"""

import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor

LEVELS = ["Low", "Medium", "High"]


def predict_chain(text: str) -> dict:
    """Full 5-stage chain. Returns {'risk': ..., 'confidence': ...}."""
    from scamshield_chain import analyze_message

    last_error = None
    for attempt in range(3):
        try:
            result = analyze_message(text)
            return {"risk": result.get("risk_level"), "confidence": result.get("confidence")}
        except Exception as e:  # retry on API hiccups / bad JSON
            last_error = e
            time.sleep(2)
    return {"risk": "ERROR", "confidence": None, "error": str(last_error)}


# Add more pipelines here later (single prompt, few-shot, chain-of-thought...)
PIPELINES = {"chain": predict_chain}


def load_test_set(path="test_set.csv"):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def run_eval(name, predict_fn, rows):
    print(f"\nRunning '{name}' on {len(rows)} messages (this can take a few minutes)...")
    with ThreadPoolExecutor(max_workers=4) as pool:
        preds = list(pool.map(lambda r: predict_fn(r["message"]), rows))

    matrix = {t: {p: 0 for p in LEVELS + ["ERROR"]} for t in LEVELS}
    correct = 0
    out_rows = []
    for r, p in zip(rows, preds):
        true, pred = r["true_risk"], p["risk"]
        if pred not in matrix[true]:
            pred = "ERROR"
        matrix[true][pred] += 1
        ok = pred == true
        correct += ok
        out_rows.append({**r, "predicted": pred, "confidence": p.get("confidence"), "correct": ok})

    total = len(rows)
    print(f"\n=== Results: {name} ===")
    print(f"Exact-match accuracy: {correct}/{total} = {100 * correct / total:.1f}%")

    print("\nConfusion matrix (rows = true label, columns = predicted):")
    print(f"{'':10}" + "".join(f"{p:>9}" for p in LEVELS + ["ERROR"]))
    for t in LEVELS:
        print(f"{t:10}" + "".join(f"{matrix[t][p]:>9}" for p in LEVELS + ["ERROR"]))

    print("\nPer-class precision / recall:")
    for lvl in LEVELS:
        tp = matrix[lvl][lvl]
        fp = sum(matrix[t][lvl] for t in LEVELS if t != lvl)
        fn = sum(matrix[lvl][p] for p in LEVELS + ["ERROR"] if p != lvl)
        prec = tp / (tp + fp) if tp + fp else 0
        rec = tp / (tp + fn) if tp + fn else 0
        print(f"  {lvl:7} precision {prec:.2f}   recall {rec:.2f}")

    false_alarms = matrix["Low"]["High"] + matrix["Low"]["Medium"]
    missed = matrix["High"]["Low"]
    print(f"\nFalse alarms (genuine flagged Medium/High): {false_alarms}")
    print(f"Missed scams (High predicted as Low):        {missed}")

    print("\nWrong predictions:")
    for o in out_rows:
        if not o["correct"]:
            print(f"  #{o['id']} [{o['category']}] true={o['true_risk']} predicted={o['predicted']}")

    out_path = f"results_{name}.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    print(f"\nSaved per-message results to {out_path}")


if __name__ == "__main__":
    rows = load_test_set()
    if len(sys.argv) > 1:
        rows = rows[: int(sys.argv[1])]
    for pipeline_name, fn in PIPELINES.items():
        run_eval(pipeline_name, fn, rows)
