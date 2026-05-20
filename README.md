# Bulanik Mantik Tabanli Siber Guvenlik Tehdit Degerlendirme Sistemi

## Proje Hakkinda

Bu proje, bir ag ortamindaki anlik metriklere gore tehdit seviyesini bulanik mantik ile degerlendiren bir karar destek sistemidir. Guvenlik operasyon merkezlerinde (SOC) analistlere tehdit onceliklendirmesi konusunda yardimci olmayi amaclar.

Siber guvenlikte tehdit degerlendirmesi kesin esik degerleriyle yapilamaz. "Trafik biraz yuksek", "giris denemeleri oldukca fazla" gibi belirsiz ifadeler bulanik mantiga uygun problemlerdir. Klasik kural tabanli sistemler ya cok hassas (false positive) ya da cok gevsek (false negative) kalirken, bulanik mantik bu gri bolgeyi dogal sekilde modeller.

## Sistem Tasarimi

### Giris Degiskenleri

| Degisken | Aralik | Dilsel Terimler |
|----------|--------|-----------------|
| Ag Trafigi Anomali Orani (%) | 0-100 | Dusuk, Orta, Yuksek |
| Basarisiz Giris Denemesi Sayisi | 0-50 | Az, Orta, Cok |
| Guvenlik Acigi Skoru (CVSS) | 0-10 | Dusuk, Orta, Yuksek, Kritik |

### Cikis Degiskeni

| Degisken | Aralik | Dilsel Terimler |
|----------|--------|-----------------|
| Tehdit Seviyesi | 0-100 | Guvenli, Dusuk Risk, Orta Risk, Yuksek Risk, Kritik |

### Uyelik Fonksiyonlari

Tum degiskenler icin yamuk (trapezoidal) uyelik fonksiyonlari kullanilmistir. Parametreler config.py dosyasinda tanimlidir.

### Kural Tabani

Sistemde 20 adet IF-THEN kurali bulunmaktadir. Kurallar, uzman bilgisine dayali olarak olusturulmustur ve tum olasi tehdit senaryolarini kapsar.

### Cikarim ve Durulastirma

- Cikarim Yontemi: Mamdani
- Durulastirma Yontemi: Centroid (Agirlik Merkezi)

## Kurulum

```bash
git clone https://github.com/emircanaltuntas/fuzzy-logic-cyber-threat-assessment.git
cd fuzzy-logic-cyber-threat-assessment
pip install -r requirements.txt
```

## Calistirma

```bash
streamlit run app.py
```

Tarayicinizda http://localhost:8501 adresinde arayuz acilacaktir.

## Kullanim

1. Sol paneldeki slider'lar ile giris degerlerini ayarlayin
2. "Hesapla" butonuna basin
3. Sonuclari sayisal ve grafiksel olarak goruntuleyiniz
4. Uyelik fonksiyonlari grafiginde giris degerlerinizin konumunu inceleyin
5. Aktif kurallar tablosunda hangi kurallarin tetiklendigini gorun

## Test

```bash
cd tests
python test_scenarios.py
```

### Test Senaryolari

| Senaryo | Anomali | Giris | CVSS | Beklenen |
|---------|---------|-------|------|----------|
| Normal calisma | 10% | 2 | 1.5 | Guvenli |
| Port tarama suphesi | 55% | 8 | 4.0 | Orta Risk |
| Brute-force saldirisi | 30% | 45 | 7.5 | Yuksek Risk |
| Aktif exploit + DDoS | 90% | 40 | 9.5 | Kritik |
| Dusuk seviye aktivite | 20% | 5 | 3.0 | Dusuk Risk |
| Yogun saldiri gostergesi | 75% | 25 | 6.0 | Yuksek Risk |
| Tamamen normal | 5% | 1 | 0.5 | Guvenli |
| Maksimum tehdit | 95% | 48 | 9.8 | Kritik |

## Proje Yapisi

```
fuzzy-logic-cyber-threat-assessment/
├── README.md
├── requirements.txt
├── app.py                  # Streamlit arayuzu
├── fuzzy_engine.py         # Bulanik mantik motoru
├── config.py               # Sistem parametreleri ve kurallar
├── tests/
│   └── test_scenarios.py   # Test senaryolari
└── .gitignore
```

## Teknolojiler

- Python 3.x
- scikit-fuzzy (bulanik mantik kutuphanesi)
- NumPy (sayisal hesaplamalar)
- Matplotlib (grafik olusturma)
- Streamlit (web tabanli arayuz)

## Yazar

Emircan Altuntas - 22430070020 - Bulanik Mantik
