import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
import skfuzzy as fuzz
from fuzzy_engine import create_system, compute_threat, get_threat_label
from config import (
    ANOMALY_RANGE, LOGIN_ATTEMPTS_RANGE, CVSS_RANGE, THREAT_RANGE,
    ANOMALY_MF, LOGIN_MF, CVSS_MF, THREAT_MF, RULES
)

st.set_page_config(page_title="Siber Guvenlik Tehdit Degerlendirme", layout="wide")
st.title("Bulanik Mantik Tabanli Siber Guvenlik Tehdit Degerlendirme Sistemi")

simulation, anomaly_var, login_var, cvss_var, threat_var = create_system()

st.sidebar.header("Giris Degerleri")
anomaly_val = st.sidebar.slider("Ag Trafigi Anomali Orani (%)", 0, 100, 50)
login_val = st.sidebar.slider("Basarisiz Giris Denemesi Sayisi", 0, 50, 10)
cvss_val = st.sidebar.slider("Guvenlik Acigi Skoru (CVSS)", 0.0, 10.0, 5.0, step=0.1)

if st.sidebar.button("Hesapla"):
    try:
        result = compute_threat(simulation, anomaly_val, login_val, cvss_val)
        label = get_threat_label(result)

        st.header("Sonuc")
        col1, col2 = st.columns(2)
        col1.metric("Tehdit Seviyesi (Sayisal)", f"{result:.2f}")
        col2.metric("Tehdit Seviyesi (Dilsel)", label)

        color_map = {
            "Guvenli": "green",
            "Dusuk Risk": "yellowgreen",
            "Orta Risk": "orange",
            "Yuksek Risk": "red",
            "Kritik": "darkred"
        }

        fig_result, ax_result = plt.subplots(figsize=(8, 2))
        ax_result.barh([0], [result], color=color_map.get(label, "gray"), height=0.5)
        ax_result.set_xlim(0, 100)
        ax_result.set_yticks([])
        ax_result.set_xlabel("Tehdit Seviyesi")
        ax_result.axvline(x=result, color="black", linestyle="--", linewidth=1.5)
        st.pyplot(fig_result)

        st.header("Uyelik Fonksiyonlari")
        fig, axes = plt.subplots(2, 2, figsize=(12, 8))

        ax = axes[0, 0]
        x_anomaly = np.arange(ANOMALY_RANGE[0], ANOMALY_RANGE[1] + 1, 1)
        for name, params in ANOMALY_MF.items():
            ax.plot(x_anomaly, fuzz.trapmf(x_anomaly, params), label=name)
        ax.axvline(x=anomaly_val, color="red", linestyle="--", label=f"Giris: {anomaly_val}")
        ax.set_title("Ag Trafigi Anomali Orani")
        ax.legend()

        ax = axes[0, 1]
        x_login = np.arange(LOGIN_ATTEMPTS_RANGE[0], LOGIN_ATTEMPTS_RANGE[1] + 1, 1)
        for name, params in LOGIN_MF.items():
            ax.plot(x_login, fuzz.trapmf(x_login, params), label=name)
        ax.axvline(x=login_val, color="red", linestyle="--", label=f"Giris: {login_val}")
        ax.set_title("Basarisiz Giris Denemesi")
        ax.legend()

        ax = axes[1, 0]
        x_cvss = np.arange(CVSS_RANGE[0], CVSS_RANGE[1] + 0.1, 0.1)
        for name, params in CVSS_MF.items():
            ax.plot(x_cvss, fuzz.trapmf(x_cvss, params), label=name)
        ax.axvline(x=cvss_val, color="red", linestyle="--", label=f"Giris: {cvss_val}")
        ax.set_title("CVSS Skoru")
        ax.legend()

        ax = axes[1, 1]
        x_threat = np.arange(THREAT_RANGE[0], THREAT_RANGE[1] + 1, 1)
        for name, params in THREAT_MF.items():
            ax.plot(x_threat, fuzz.trapmf(x_threat, params), label=name)
        ax.axvline(x=result, color="red", linestyle="--", label=f"Cikis: {result:.2f}")
        ax.set_title("Tehdit Seviyesi (Cikis)")
        ax.legend()

        plt.tight_layout()
        st.pyplot(fig)

        st.header("Aktif Kurallar")
        active_rules = []
        for (a, l, c), t in RULES:
            x_a = np.arange(ANOMALY_RANGE[0], ANOMALY_RANGE[1] + 1, 1)
            x_l = np.arange(LOGIN_ATTEMPTS_RANGE[0], LOGIN_ATTEMPTS_RANGE[1] + 1, 1)
            x_c = np.arange(CVSS_RANGE[0], CVSS_RANGE[1] + 0.1, 0.1)

            mf_a = fuzz.trapmf(x_a, ANOMALY_MF[a])
            mf_l = fuzz.trapmf(x_l, LOGIN_MF[l])
            mf_c = fuzz.trapmf(x_c, CVSS_MF[c])

            val_a = fuzz.interp_membership(x_a, mf_a, anomaly_val)
            val_l = fuzz.interp_membership(x_l, mf_l, login_val)
            val_c = fuzz.interp_membership(x_c, mf_c, cvss_val)

            activation = min(val_a, val_l, val_c)
            if activation > 0:
                active_rules.append({
                    "Kural": f"IF Anomali={a} AND Giris={l} AND CVSS={c} THEN Tehdit={t}",
                    "Aktivasyon": f"{activation:.3f}"
                })

        if active_rules:
            st.table(active_rules)
        else:
            st.warning("Aktif kural bulunamadi. Giris degerlerini degistirmeyi deneyin.")

    except Exception as e:
        st.error(f"Hesaplama hatasi: {str(e)}. Giris degerlerini degistirmeyi deneyin.")
