"""
ScamShield 2.0 - prompting technique comparison
Runs the same labelled test set (test_set.csv) through 5 approaches and compares them:
  1. zero_shot      - minimal instruction, no examples
  2. few_shot       - zero-shot + 6 labelled examples (not taken from the test set)
  3. chain_of_thought - asks for short evidence-based factors before the label
  4. single_detailed  - one all-in-one prompt with the same rules the chain uses
  5. chain          - the full 5-stage prompt chain (reuses results_chain.csv if present)

Outputs: comparison_results.csv, comparison_chart.png, and results_<name>.csv per approach.

Usage:
    pip install matplotlib
    python compare_prompts.py        # all 40 messages
    python compare_prompts.py 5      # quick test on the first 5
"""

import csv
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scamshield_chain import call_stage
from eval_chain import load_test_set, LEVELS

JSON_ONLY = "Reply with ONLY a JSON object, no explanation, no markdown formatting."

# ---------------------------------------------------------------------------
# Prompt variants
# ---------------------------------------------------------------------------

ZERO_SHOT = (
    "Classify the message below as Low, Medium, or High scam risk. "
    + JSON_ONLY
    + ' Format: {"risk_level": "Low|Medium|High"}'
)

FEW_SHOT_EXAMPLES = [
    ("Your Paytm KYC has expired. Click http://paytm-kyc-now.top and enter your card number and OTP to avoid account freeze.", "High"),
    ("Cashback of Rs 5,000 received. Scan this QR code and enter your UPI PIN to accept it.", "High"),
    ("Your free trial ends today. Upgrade now for 50% off: http://streamplus-offer.co", "Medium"),
    ("Join this app with my referral code and get a Rs 200 bonus: http://refer-earn-app.co", "Medium"),
    ("Your Airtel bill of Rs 499 is generated. Pay by 10-Oct via the Airtel Thanks app.", "Low"),
    ("Class is shifted to Lab 3 tomorrow at 10 am. - Prof. Meena", "Low"),
]
FEW_SHOT = (
    ZERO_SHOT
    + "\n\nExamples:\n"
    + "\n".join(f'Message: "{m}"\nOutput: {{"risk_level": "{r}"}}' for m, r in FEW_SHOT_EXAMPLES)
)

CHAIN_OF_THOUGHT = (
    "Classify the message below as Low, Medium, or High scam risk. "
    "First list the key observations that matter (for example urgency, threats, links, "
    "requests for OTP/PIN/money/personal details, who the sender claims to be), each as a "
    "short evidence-based point. Then give the final label. "
    + JSON_ONLY
    + ' Format: {"factors": ["short point", "..."], "risk_level": "Low|Medium|High"}'
)

SINGLE_DETAILED = (
    "You are a scam-detection assistant. Analyse the message: check for urgency or threats, "
    "requests for OTP/PIN/passwords/personal details, links that imitate a real organisation, "
    "demands to pay a fee or deposit, prizes or too-good-to-be-true offers, and remote-access "
    "app requests. Then classify the overall risk.\n"
    "- High: multiple high-severity signals, especially threats/urgency combined with a link "
    "or payment request.\n"
    "- Medium: one or two medium/low-severity signals, or a single high-severity signal with "
    "no other red flags.\n"
    "- Low: no signals, or only very weak/ambiguous ones.\n"
    + JSON_ONLY
    + ' Format: {"risk_level": "Low|Medium|High"}'
)


def make_predictor(system_prompt):
    def predict(text):
        last_error = None
        for _ in range(3):
            try:
                out = call_stage(system_prompt, f"Message:\n{text}")
                risk = str(out.get("risk_level", "")).strip().capitalize()
                return risk if risk in LEVELS else "ERROR"
            except Exception as e:
                last_error = e
                time.sleep(2)
        return "ERROR"

    return predict


VARIANTS = {
    "zero_shot": make_predictor(ZERO_SHOT),
    "few_shot": make_predictor(FEW_SHOT),
    "chain_of_thought": make_predictor(CHAIN_OF_THOUGHT),
    "single_detailed": make_predictor(SINGLE_DETAILED),
}


def score(rows, preds):
    correct = false_alarms = missed = errors = 0
    for r, p in zip(rows, preds):
        true = r["true_risk"]
        correct += p == true
        errors += p == "ERROR"
        false_alarms += true == "Low" and p in ("Medium", "High")
        missed += true == "High" and p == "Low"
    return {
        "accuracy": round(100 * correct / len(rows), 1),
        "correct": correct,
        "total": len(rows),
        "false_alarms": false_alarms,
        "missed_scams": missed,
        "errors": errors,
    }


def save_results(name, rows, preds):
    with open(f"results_{name}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "category", "true_risk", "predicted", "correct"])
        for r, p in zip(rows, preds):
            w.writerow([r["id"], r["category"], r["true_risk"], p, p == r["true_risk"]])


def load_chain_predictions(rows):
    """Reuse results_chain.csv from eval_chain.py so the chain is not re-run."""
    if not os.path.exists("results_chain.csv"):
        return None
    with open("results_chain.csv", newline="", encoding="utf-8-sig") as f:
        by_id = {r["id"]: r["predicted"] for r in csv.DictReader(f)}
    if not all(r["id"] in by_id for r in rows):
        return None
    return [by_id[r["id"]] for r in rows]


def main():
    rows = load_test_set()
    if len(sys.argv) > 1:
        rows = rows[: int(sys.argv[1])]

    summary = {}
    for name, predict in VARIANTS.items():
        print(f"Running {name} on {len(rows)} messages...")
        with ThreadPoolExecutor(max_workers=4) as pool:
            preds = list(pool.map(lambda r: predict(r["message"]), rows))
        save_results(name, rows, preds)
        summary[name] = score(rows, preds)

    chain_preds = load_chain_predictions(rows)
    if chain_preds is None:
        print("results_chain.csv not found - run python eval_chain.py first to include the full chain.")
    else:
        summary["chain"] = score(rows, chain_preds)

    print("\n=== Comparison ===")
    print(f"{'Approach':20}{'Accuracy':>10}{'False alarms':>14}{'Missed scams':>14}{'Errors':>8}")
    for name, s in summary.items():
        print(f"{name:20}{s['accuracy']:>9}%{s['false_alarms']:>14}{s['missed_scams']:>14}{s['errors']:>8}")

    with open("comparison_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["approach", "accuracy_pct", "correct", "total", "false_alarms", "missed_scams", "errors"])
        for name, s in summary.items():
            w.writerow([name, s["accuracy"], s["correct"], s["total"], s["false_alarms"], s["missed_scams"], s["errors"]])

    names = list(summary.keys())
    labels = [n.replace("_", "\n") for n in names]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    bars = ax1.bar(labels, [summary[n]["accuracy"] for n in names], color="#1C6E8C")
    ax1.set_ylim(0, 100)
    ax1.set_ylabel("Exact-match accuracy (%)")
    ax1.set_title("Accuracy by approach")
    for b in bars:
        ax1.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{b.get_height():.1f}", ha="center", fontsize=9)

    x = range(len(names))
    w = 0.38
    ax2.bar([i - w / 2 for i in x], [summary[n]["false_alarms"] for n in names], w, label="False alarms", color="#B8860B")
    ax2.bar([i + w / 2 for i in x], [summary[n]["missed_scams"] for n in names], w, label="Missed scams", color="#B23A2E")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels)
    ax2.set_ylabel("Number of messages")
    ax2.set_title("Costly mistakes (lower is better)")
    top = max([summary[n]["false_alarms"] for n in names] + [summary[n]["missed_scams"] for n in names] + [1])
    ax2.set_ylim(0, top * 1.35 + 1)
    ax2.legend(loc="upper left")

    fig.suptitle(f"ScamShield 2.0 - prompting techniques on {len(rows)} labelled messages")
    fig.tight_layout()
    fig.savefig("comparison_chart.png", dpi=150)
    print("\nSaved comparison_results.csv and comparison_chart.png")


if __name__ == "__main__":
    main()
