import os, time, json, datetime, random, math
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
import jwt, bcrypt
from google.cloud import bigquery

load_dotenv()
app = Flask(__name__, static_folder="static")

JWT_SECRET = os.getenv("JWT_SECRET", "dev")
JWT_ALGO = "HS256"
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
RETAIL_DATASET = os.getenv("RETAIL_DATASET", "RetailData")
RETAIL_TABLE = os.getenv("RETAIL_TABLE", "Sales")
DP_EPSILON = float(os.getenv("DP_EPSILON", "1.0"))

ROLES = {
    "Data Analyst": {"expire": 30, "hours": (9, 17)},
    "Data Manager": {"expire": 600, "hours": (0, 24)},
    "Security Officer": {"expire": 600, "hours": (0, 24)},
}

# Permissions:
# - Analyst: analytics + meta
# - Manager: all analytics + logs + meta
# - Security Officer: logs + meta
PERMISSIONS = {
    "Data Analyst": ["top", "trend", "anomalies", "meta"],
    "Data Manager": ["top", "trend", "anomalies", "logs", "meta"],
    "Security Officer": ["logs", "meta"],
}

USERS = {
    "analyst@retail.local": {
        "pw": "$2b$12$B8UrSHwQAFtLXNIChYJ2Lee0TZagYTQ5aRwi9NDokuL/O1I7IcH82",  # Aida123
        "role": "Data Analyst",
    },
    "manager@retail.local": {
        "pw": "$2b$12$6LmVtRwk2.B040yM2eNIV./FnlIArTdsN5f8RrhiDleJsPVY659JG",  # Aida456
        "role": "Data Manager",
    },
    "security@retail.local": {
        "pw": "$2b$12$AYMpiTSjqF9oK/ZwypsuZeTU2RP6nLAxRoufrsJFkIu12UYXVpJ0K",  # Aida789
        "role": "Security Officer",
    },
}

_bq = None
def BQ():
    global _bq
    if _bq is None:
        _bq = bigquery.Client(project=GCP_PROJECT_ID)
    return _bq

def laplace_noise(scale):
    u = random.random() - 0.5
    return -scale * (1 if u >= 0 else -1) * math.log(1 - 2 * abs(u))

def dp_sum(v, eps):
    return v + (laplace_noise(1/eps) if eps > 0 else 0)

def audit(event, user, role, extra=None):
    os.makedirs("logs", exist_ok=True)
    with open("logs/audit.log", "a") as f:
        f.write(json.dumps({
            "t": int(time.time()),
            "e": event,
            "u": user,
            "r": role,
            "x": extra or {}
        }) + "\n")

def within_hours(role):
    now = datetime.datetime.now().hour
    s, e = ROLES[role]["hours"]
    return s <= now < e

def create_token(email, role):
    now = int(time.time())
    exp = now + ROLES[role]["expire"]
    return jwt.encode(
        {"sub": email, "role": role, "iat": now, "exp": exp},
        JWT_SECRET,
        algorithm=JWT_ALGO
    )

def require_roles(*allowed):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                audit("DENY_NO_TOKEN", "", "unknown", {"path": request.path})
                return jsonify({"error": "no token"}), 403
            try:
                tok = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGO])
            except jwt.ExpiredSignatureError:
                audit("DENY_EXPIRED", "", "unknown", {"path": request.path})
                return jsonify({"error": "expired"}), 403
            except Exception:
                audit("DENY_BAD_TOKEN", "", "unknown", {"path": request.path})
                return jsonify({"error": "bad token"}), 403

            role = tok.get("role", "")
            user = tok.get("sub", "")
            if role not in allowed or not within_hours(role):
                audit("DENY_ROLE_OR_TIME", user, role, {"path": request.path})
                return jsonify({"error": "denied"}), 403

            return fn(_claims=tok, *a, **kw)
        return wrapper
    return deco

@app.route("/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    email = d.get("email", "").lower()
    pw = d.get("password", "")
    u = USERS.get(email)

    if not u or not bcrypt.checkpw(pw.encode(), u["pw"].encode()):
        audit("LOGIN_FAIL", email, "unknown", {})
        return jsonify({"error": "bad creds"}), 403

    role = u["role"]
    token = create_token(email, role)

    now_dt = datetime.datetime.now()
    now_hour = now_dt.hour
    now_str = now_dt.strftime("%H:%M")

    start_h, end_h = ROLES[role]["hours"]
    duration = ROLES[role]["expire"]
    time_valid = start_h <= now_hour < end_h

    audit("LOGIN_OK", email, role, {"time_valid": time_valid})

    return jsonify({
        "token": token,
        "role": role,
        "msg": "Welcome!",
        "duration": duration,
        "hours": [start_h, end_h],
        "now": now_hour,
        "now_str": now_str,
        "time_valid": time_valid,
    })

@app.route("/dashboard")
def dash():
    return send_from_directory(app.static_folder, "dashboard.html")

@app.route("/analytics")
@require_roles("Data Analyst", "Data Manager", "Security Officer")
def analytics(_claims):
    role = _claims["role"]
    user = _claims["sub"]
    t = request.args.get("type")

    # DP only for numeric analytics, not for logs
    use_dp = (role == "Data Analyst") or (request.args.get("dp") == "true")

    audit("ANALYTICS", user, role, {
        "type": t,
        "params": request.args.to_dict()
    })

    if t not in PERMISSIONS.get(role, []):
        return jsonify({"error": "no access"}), 403

    # Logs view (Security Officer + Manager) – NO DP
    if t == "logs":
        try:
            entries = []
            os.makedirs("logs", exist_ok=True)
            if os.path.exists("logs/audit.log"):
                with open("logs/audit.log", "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entries.append(json.loads(line))
            entries = entries[-200:][::-1]
            return jsonify({"rows": entries})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    region = request.args.get("region") or None
    category = request.args.get("category") or None
    where, params = [], []
    if region:
        where.append("Region = @region")
        params.append(bigquery.ScalarQueryParameter("region", "STRING", region))
    if category:
        where.append("Category = @category")
        params.append(bigquery.ScalarQueryParameter("category", "STRING", category))
    W = ("WHERE " + " AND ".join(where)) if where else ""

    if t == "meta":
        try:
            sqlR = f"""
            SELECT DISTINCT Region AS v
            FROM `{GCP_PROJECT_ID}.{RETAIL_DATASET}.{RETAIL_TABLE}`
            ORDER BY v
            """
            sqlC = f"""
            SELECT DISTINCT Category AS v
            FROM `{GCP_PROJECT_ID}.{RETAIL_DATASET}.{RETAIL_TABLE}`
            ORDER BY v
            """
            regions = [r["v"] for r in BQ().query(sqlR).result()]
            cats = [r["v"] for r in BQ().query(sqlC).result()]
            return jsonify({"rows": {"regions": regions, "categories": cats}})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if t == "top":
        gdim = (request.args.get("gdim") or "region").lower()
        sdim = "category" if gdim == "region" else "region"
        sval = request.args.get("sval") or ""
        metric = (request.args.get("metric") or "profit").lower()
        n = int(request.args.get("n") or "10")

        if sval:
            params.append(bigquery.ScalarQueryParameter("sval", "STRING", sval))
            W2 = (W + (" AND " if W else "WHERE ") +
                  (("Category = @sval") if sdim == "category" else ("Region = @sval")))
        else:
            W2 = W

        if gdim == "region":
            col_g = "CONCAT(Market, ' | ', Region)"
        else:
            col_g = "Category"

        sql = f"""
        SELECT `Product Name` AS product,
               {col_g} AS g,
               SUM(Sales) AS s,
               SUM(Profit) AS p,
               COUNT(1) AS n
        FROM `{GCP_PROJECT_ID}.{RETAIL_DATASET}.{RETAIL_TABLE}` {W2}
        GROUP BY product, g
        """

        try:
            job = BQ().query(sql, job_config=bigquery.QueryJobConfig(query_parameters=params))
            rows = list(job.result())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        out = []
        for r in rows:
            s_raw = float(r["s"])
            p_raw = float(r["p"])
            s_val = dp_sum(s_raw, DP_EPSILON) if use_dp else s_raw
            p_val = dp_sum(p_raw, DP_EPSILON) if use_dp else p_raw
            mv = p_val
            out.append({
                "product": r["product"],
                "g": r["g"],
                "orders": int(r["n"]),
                "metric": mv
            })
        out.sort(key=lambda x: x["metric"], reverse=True)
        out = out[:max(1, min(50, n))]
        return jsonify({"rows": out})

    if t == "trend":
        gdim = (request.args.get("gdim") or "region").lower()
        if gdim == "region":
            col_g = "CONCAT(Market, ' | ', Region)"
        else:
            col_g = "Category"

        sql = f"""
        SELECT
          CONCAT(CAST(FLOOR(Discount*20)*5 AS INT64), '-', CAST(FLOOR(Discount*20)*5+5 AS INT64), '%') AS band,
          {col_g} AS g,
          SUM(Profit) AS sp,
          COUNT(1) AS n
        FROM `{GCP_PROJECT_ID}.{RETAIL_DATASET}.{RETAIL_TABLE}` {W}
        GROUP BY band, g
        ORDER BY band
        """

        try:
            job = BQ().query(sql, job_config=bigquery.QueryJobConfig(query_parameters=params))
            rows = list(job.result())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        out = {}
        for r in rows:
            sp = float(r["sp"])
            n = int(r["n"])
            sp_dp = dp_sum(sp, DP_EPSILON) if use_dp else sp
            avg_profit = (sp_dp / n) if n else 0.0
            band = r["band"]
            g = r["g"]
            out.setdefault(g, {})[band] = avg_profit

        bands = sorted({b for m in out.values() for b in m.keys()},
                       key=lambda x: int(x.split('-')[0]))
        series = []
        for g, m in out.items():
            series.append({"g": g, "values": [m.get(b, 0.0) for b in bands]})
        return jsonify({"bands": bands, "series": series})

    if t == "anomalies":
        gdim = (request.args.get("gdim") or "region").lower()
        if gdim == "region":
            col_g = "CONCAT(Market, ' | ', Region)"
        else:
            col_g = "Category"

        sql = f"""
        SELECT {col_g} AS g,
               SUM(CASE WHEN Profit < -100 OR Discount > 0.5 THEN 1 ELSE 0 END) AS cnt,
               SUM(CASE WHEN Profit < -100 OR Discount > 0.5 THEN Profit ELSE 0 END) AS sp
        FROM `{GCP_PROJECT_ID}.{RETAIL_DATASET}.{RETAIL_TABLE}` {W}
        GROUP BY g
        """

        try:
            job = BQ().query(sql, job_config=bigquery.QueryJobConfig(query_parameters=params))
            rows = list(job.result())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        total = sum(int(r["cnt"]) for r in rows)
        out = []
        for r in rows:
            cnt = int(r["cnt"])
            cnt_dp = max(0.0, dp_sum(float(cnt), DP_EPSILON) if use_dp else float(cnt))
            sp = float(r["sp"])
            sp_dp = dp_sum(sp, DP_EPSILON) if use_dp else sp
            avg_p = 0.0 if cnt == 0 else (sp_dp / cnt)
            pct = 0.0 if total == 0 else (cnt / total * 100.0)
            out.append({
                "g": r["g"],
                "count": cnt_dp,
                "pct": pct,
                "avg_profit": avg_p
            })
        out.sort(key=lambda x: x["count"], reverse=True)
        return jsonify({"rows": out})

    return jsonify({"error": "unknown type"}), 400


if __name__ == "__main__":
    print("Starting Flask app on http://localhost:5000 ...")
    app.run(host="0.0.0.0", port=5000, debug=True)
