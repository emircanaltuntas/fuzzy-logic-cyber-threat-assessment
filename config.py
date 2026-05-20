ANOMALY_RANGE = [0, 100]
LOGIN_ATTEMPTS_RANGE = [0, 50]
CVSS_RANGE = [0, 10]
THREAT_RANGE = [0, 100]

ANOMALY_MF = {
    "dusuk": [0, 0, 15, 35],
    "orta": [25, 40, 60, 75],
    "yuksek": [60, 80, 100, 100]
}

LOGIN_MF = {
    "az": [0, 0, 5, 12],
    "orta": [8, 18, 30, 40],
    "cok": [30, 40, 50, 50]
}

CVSS_MF = {
    "dusuk": [0, 0, 1.5, 3.5],
    "orta": [2.5, 4, 5.5, 7],
    "yuksek": [6, 7.5, 8.5, 9],
    "kritik": [8, 9, 10, 10]
}

THREAT_MF = {
    "guvenli": [0, 0, 10, 20],
    "dusuk_risk": [15, 25, 35, 45],
    "orta_risk": [35, 45, 55, 65],
    "yuksek_risk": [55, 65, 75, 85],
    "kritik": [75, 85, 100, 100]
}

RULES = [
    (("dusuk", "az", "dusuk"), "guvenli"),
    (("orta", "az", "dusuk"), "dusuk_risk"),
    (("dusuk", "orta", "orta"), "orta_risk"),
    (("yuksek", "az", "dusuk"), "orta_risk"),
    (("yuksek", "orta", "orta"), "yuksek_risk"),
    (("yuksek", "cok", "yuksek"), "kritik"),
    (("orta", "cok", "kritik"), "kritik"),
    (("dusuk", "cok", "yuksek"), "yuksek_risk"),
    (("orta", "orta", "orta"), "orta_risk"),
    (("yuksek", "cok", "kritik"), "kritik"),
    (("dusuk", "az", "yuksek"), "orta_risk"),
    (("orta", "cok", "dusuk"), "orta_risk"),
    (("yuksek", "az", "kritik"), "yuksek_risk"),
    (("dusuk", "orta", "kritik"), "yuksek_risk"),
    (("orta", "orta", "yuksek"), "yuksek_risk"),
    (("yuksek", "orta", "kritik"), "kritik"),
    (("dusuk", "az", "orta"), "dusuk_risk"),
    (("orta", "az", "orta"), "orta_risk"),
    (("dusuk", "cok", "kritik"), "kritik"),
    (("yuksek", "cok", "dusuk"), "yuksek_risk"),
]
