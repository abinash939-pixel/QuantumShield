"""Plain-Python math behind Shor's algorithm for N = 15 (no quantum libraries needed).
The quantum computer's only job is to find the period r. Everything here is the simple
arithmetic that happens before and after that step."""
import math

N = 15


def find_period(a, n=N):
    """Smallest r >= 1 with a**r = 1 (mod n), or None if a shares a factor with n."""
    if math.gcd(a, n) != 1:
        return None
    value = a % n
    r = 1
    while value != 1:
        value = (value * a) % n
        r += 1
    return r


def explain_factoring(a, n=N):
    """Step-by-step explanation for one choice of a.
    Returns a dict: table (rows for a DataFrame), steps (list of text), ok (bool), message."""
    r = find_period(a, n)
    if r is None:
        return {"table": [], "steps": [], "ok": False, "period": None,
                "message": f"{a} shares a factor with {n}, so it cannot be used."}

    table = []
    value = 1
    for k in range(0, r + 1):
        if k > 0:
            value = (value * a) % n
        note = ""
        if k == 0:
            note = "start"
        elif k == r:
            note = f"back to 1: the cycle length is r = {r}"
        table.append({"Step k": k, "Calculation": f"{a}^{k} mod {n}", "Result": value, "Note": note})

    steps = [f"The powers of {a} mod {n} return to 1 after r = {r} steps."]

    if r % 2 == 1:
        return {"table": table, "steps": steps, "ok": False, "period": r,
                "message": "The period is odd, so this a cannot be used. The attack picks another a."}

    x = pow(a, r // 2, n)
    steps.append(f"Half the period: {a}^{r // 2} mod {n} = {x}.")
    if x == n - 1:
        return {"table": table, "steps": steps, "ok": False, "period": r,
                "message": f"The result is {n} - 1, which gives no useful factor. The attack picks another a."}

    p, q = math.gcd(x - 1, n), math.gcd(x + 1, n)
    steps.append(f"Greatest common divisors: gcd({x} - 1, {n}) = {p} and gcd({x} + 1, {n}) = {q}.")
    if p in (1, n) or q in (1, n):
        return {"table": table, "steps": steps, "ok": False, "period": r,
                "message": "These give no useful factor. The attack picks another a."}

    lo, hi = min(p, q), max(p, q)
    steps.append(f"Check: {lo} x {hi} = {lo * hi}. The factors of {n} are {lo} and {hi}.")
    return {"table": table, "steps": steps, "ok": True, "period": r,
            "message": f"Success: {n} = {lo} x {hi}."}