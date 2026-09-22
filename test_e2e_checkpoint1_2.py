"""
End-to-End Live Integration Test for Checkpoints 1 & 2
Runs against the live running servers (Backend: 5001, Frontend: 3000)
"""
import urllib.request
import urllib.error
import json
import sys

BASE_BACKEND = "http://127.0.0.1:5001"
BASE_FRONTEND = "http://127.0.0.1:3000"

def get(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def put(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def check_frontend(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return resp.status

def run_tests():
    print("=== LIVE INTEGRATION TEST FOR CHECKPOINTS 1 & 2 ===\n")

    # 1. Test Public Catalog Exams
    print("[1] Checking Public Catalog Exams (http://localhost:5001/catalog/exams)...")
    public_exams = get(f"{BASE_BACKEND}/catalog/exams")
    exam_ids = [e["id"] for e in public_exams.get("exams", [])]
    print(f"    Public exams visible: {exam_ids}")
    assert exam_ids == ["qjPZtz"], f"Expected only UGC NET ('qjPZtz'), got: {exam_ids}"
    print("    --> PASS: Inactive exams (CUET PG, MPhil) are filtered out of public endpoints.")

    # 2. Test God-Mode All Exams Endpoint
    print("\n[2] Checking God-Mode All Exams Endpoint (http://localhost:5001/catalog/exams?all=true)...")
    all_exams = get(f"{BASE_BACKEND}/catalog/exams?all=true")
    exams_map = {e["id"]: e["active"] for e in all_exams.get("exams", [])}
    print(f"    Exams returned: {exams_map}")
    assert "g4mzja" in exams_map and exams_map["g4mzja"] is False, "CUET PG should be inactive"
    assert "t8ZB83" in exams_map and exams_map["t8ZB83"] is False, "MPhil should be inactive"
    assert "qjPZtz" in exams_map and exams_map["qjPZtz"] is True, "UGC NET should be active"
    print("    --> PASS: All exams returned with correct active/inactive statuses.")

    # 3. Test Toggle CUET PG to Active
    print("\n[3] Testing Toggle CUET PG to Active (PUT /admin/exams/g4mzja/toggle-status)...")
    res1 = put(f"{BASE_BACKEND}/admin/exams/g4mzja/toggle-status", {"is_active": True})
    print(f"    Toggle response: {res1.get('msg')} (is_active={res1.get('is_active')})")
    assert res1.get("is_active") is True

    # Confirm CUET PG now appears in public catalog
    public_after_enable = get(f"{BASE_BACKEND}/catalog/exams")
    public_ids_enabled = [e["id"] for e in public_after_enable.get("exams", [])]
    print(f"    Public exams visible after enable: {public_ids_enabled}")
    assert "g4mzja" in public_ids_enabled, "CUET PG should now be visible in public catalog"
    print("    --> PASS: CUET PG became publicly accessible immediately upon toggle.")

    # 4. Test Toggle CUET PG back to Inactive
    print("\n[4] Testing Toggle CUET PG back to Inactive...")
    res2 = put(f"{BASE_BACKEND}/admin/exams/g4mzja/toggle-status", {"is_active": False})
    print(f"    Toggle response: {res2.get('msg')} (is_active={res2.get('is_active')})")
    assert res2.get("is_active") is False

    # Confirm CUET PG is removed from public catalog
    public_after_disable = get(f"{BASE_BACKEND}/catalog/exams")
    public_ids_disabled = [e["id"] for e in public_after_disable.get("exams", [])]
    print(f"    Public exams visible after disable: {public_ids_disabled}")
    assert public_ids_disabled == ["qjPZtz"], f"Expected only UGC NET, got: {public_ids_disabled}"
    print("    --> PASS: CUET PG is once again hidden from public endpoints.")

    # 5. Check Frontend Pages
    print("\n[5] Checking Frontend Status (Next.js port 3000)...")
    status_catalog = check_frontend(f"{BASE_FRONTEND}/god-mode/lecture-catalog")
    print(f"    GET /god-mode/lecture-catalog -> HTTP {status_catalog}")
    assert status_catalog == 200

    status_godmode = check_frontend(f"{BASE_FRONTEND}/god-mode")
    print(f"    GET /god-mode -> HTTP {status_godmode}")
    assert status_godmode == 200
    print("    --> PASS: Frontend pages build and serve successfully.")

    print("\n=======================================================")
    print("🎉 ALL TESTS PASSED: CHECKPOINTS 1 & 2 VERIFIED LIVE! 🎉")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()
