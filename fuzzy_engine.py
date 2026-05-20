import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from config import (
    ANOMALY_RANGE, LOGIN_ATTEMPTS_RANGE, CVSS_RANGE, THREAT_RANGE,
    ANOMALY_MF, LOGIN_MF, CVSS_MF, THREAT_MF, RULES
)


def create_system():
    anomaly = ctrl.Antecedent(np.arange(ANOMALY_RANGE[0], ANOMALY_RANGE[1] + 1, 1), "anomaly")
    login = ctrl.Antecedent(np.arange(LOGIN_ATTEMPTS_RANGE[0], LOGIN_ATTEMPTS_RANGE[1] + 1, 1), "login")
    cvss = ctrl.Antecedent(np.arange(CVSS_RANGE[0], CVSS_RANGE[1] + 0.1, 0.1), "cvss")
    threat = ctrl.Consequent(np.arange(THREAT_RANGE[0], THREAT_RANGE[1] + 1, 1), "threat", defuzzify_method="centroid")

    for name, params in ANOMALY_MF.items():
        anomaly[name] = fuzz.trapmf(anomaly.universe, params)

    for name, params in LOGIN_MF.items():
        login[name] = fuzz.trapmf(login.universe, params)

    for name, params in CVSS_MF.items():
        cvss[name] = fuzz.trapmf(cvss.universe, params)

    for name, params in THREAT_MF.items():
        threat[name] = fuzz.trapmf(threat.universe, params)

    rule_list = []
    for (a, l, c), t in RULES:
        rule = ctrl.Rule(anomaly[a] & login[l] & cvss[c], threat[t])
        rule_list.append(rule)

    system = ctrl.ControlSystem(rule_list)
    simulation = ctrl.ControlSystemSimulation(system)

    return simulation, anomaly, login, cvss, threat


def compute_threat(simulation, anomaly_val, login_val, cvss_val):
    simulation.input["anomaly"] = anomaly_val
    simulation.input["login"] = login_val
    simulation.input["cvss"] = cvss_val
    simulation.compute()
    return simulation.output["threat"]


def get_threat_label(value):
    if value <= 20:
        return "Guvenli"
    elif value <= 40:
        return "Dusuk Risk"
    elif value <= 60:
        return "Orta Risk"
    elif value <= 80:
        return "Yuksek Risk"
    else:
        return "Kritik"
