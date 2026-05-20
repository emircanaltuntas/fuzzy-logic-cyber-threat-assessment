import sys
sys.path.insert(0, "..")
from fuzzy_engine import create_system, compute_threat, get_threat_label


def run_tests():
    simulation, _, _, _, _ = create_system()

    scenarios = [
        {"anomaly": 10, "login": 2, "cvss": 1.5, "expected": "Guvenli"},
        {"anomaly": 55, "login": 8, "cvss": 4.0, "expected": "Orta Risk"},
        {"anomaly": 30, "login": 45, "cvss": 7.5, "expected": "Yuksek Risk"},
        {"anomaly": 90, "login": 40, "cvss": 9.5, "expected": "Kritik"},
        {"anomaly": 20, "login": 5, "cvss": 3.0, "expected": "Dusuk Risk"},
        {"anomaly": 75, "login": 25, "cvss": 6.0, "expected": "Yuksek Risk"},
        {"anomaly": 5, "login": 1, "cvss": 0.5, "expected": "Guvenli"},
        {"anomaly": 95, "login": 48, "cvss": 9.8, "expected": "Kritik"},
    ]

    print(f"{'Senaryo':<10} {'Anomali':<10} {'Giris':<10} {'CVSS':<8} {'Sonuc':<10} {'Etiket':<15} {'Beklenen':<15} {'Durum':<8}")
    print("-" * 95)

    passed = 0
    for i, s in enumerate(scenarios, 1):
        try:
            result = compute_threat(simulation, s["anomaly"], s["login"], s["cvss"])
            label = get_threat_label(result)
            status = "OK" if label == s["expected"] else "FARKLI"
            if label == s["expected"]:
                passed += 1
            print(f"{i:<10} {s['anomaly']:<10} {s['login']:<10} {s['cvss']:<8} {result:<10.2f} {label:<15} {s['expected']:<15} {status:<8}")
        except Exception as e:
            print(f"{i:<10} {s['anomaly']:<10} {s['login']:<10} {s['cvss']:<8} {'HATA':<10} {str(e):<15}")

    print(f"\nToplam: {len(scenarios)} | Basarili: {passed} | Farkli: {len(scenarios) - passed}")


if __name__ == "__main__":
    run_tests()
