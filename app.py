
import streamlit as st
import pandas as pd
import joblib
import re
import ipaddress
from urllib.parse import urlparse

# ============================================================
# CONFIGURACIÓN DE LA PÁGINA
# ============================================================

st.set_page_config(
    page_title="SAFE URL Scan",
    page_icon="🛡️",
    layout="centered"
)

# ============================================================
# ESTILO
# ============================================================

st.markdown("""
<style>

.block-container {
    max-width: 760px;
    padding-top: 3rem;
    padding-bottom: 3rem;
}

.safe-title {
    font-size: 38px;
    font-weight: 700;
    margin-bottom: 0px;
}

.safe-subtitle {
    color: #8A8F98;
    font-size: 13px;
    margin-top: 0px;
    margin-bottom: 25px;
}

.safe-info {
    background-color: #E8F2FF;
    color: #005EB8;
    padding: 16px;
    border-radius: 8px;
    margin-top: 15px;
    margin-bottom: 20px;
}

.risk-low {
    background-color: #E4F7ED;
    color: #168A4B;
    padding: 16px;
    border-radius: 8px;
    margin-top: 15px;
    margin-bottom: 15px;
}

.risk-medium {
    background-color: #FFF4D6;
    color: #9A6700;
    padding: 16px;
    border-radius: 8px;
    margin-top: 15px;
    margin-bottom: 15px;
}

.risk-high {
    background-color: #FFE3E3;
    color: #D9363E;
    padding: 16px;
    border-radius: 8px;
    margin-top: 15px;
    margin-bottom: 15px;
}

.safe-footer {
    color: #8A8F98;
    font-size: 12px;
    margin-top: 30px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# CARGA DEL MODELO FINAL SAFE - 11 VARIABLES
# ============================================================

# IMPORTANTE:
# En Streamlit Cloud estos archivos estarán en la misma
# carpeta del repositorio que app.py.

RUTA_MODELO = "modelo_safe_v4_final_11.pkl"
RUTA_VARIABLES = "variables_safe_v4_final_11.pkl"

modelo = joblib.load(RUTA_MODELO)
variables_modelo = joblib.load(RUTA_VARIABLES)


# ============================================================
# EXTRACCIÓN DE CARACTERÍSTICAS
# ============================================================

def extraer_caracteristicas_safe_v3(url):

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    # Agregar esquema únicamente para poder procesar la URL
    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url_parseo = "http://" + url
    else:
        url_parseo = url

    parsed = urlparse(url_parseo)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    hostname_lower = hostname.lower()

    # 1. HTTPS
    safe_is_https = int(
        parsed.scheme.lower() == "https"
    )

    # 2. Longitud del hostname
    safe_hostname_length = len(hostname)

    # 3. Dominio expresado como IP
    try:
        ipaddress.ip_address(hostname)
        safe_is_domain_ip = 1
    except ValueError:
        safe_is_domain_ip = 0

    # 4. Número de puntos en hostname
    safe_hostname_dots = hostname.count(".")

    # 5. Número aproximado de subdominios
    safe_no_subdomains = max(
        safe_hostname_dots - 1,
        0
    )

    # 6. Proporción de dígitos en hostname
    if len(hostname) > 0:
        safe_hostname_digit_ratio = (
            sum(
                caracter.isdigit()
                for caracter in hostname
            )
            / len(hostname)
        )
    else:
        safe_hostname_digit_ratio = 0.0

    # 7. Guiones en hostname
    safe_hostname_hyphens = hostname.count("-")

    # 8. Presencia de Punycode
    safe_has_punycode = int(
        "xn--" in hostname_lower
    )

    # 9. Proporción de dígitos en el path
    if len(path) > 0:
        safe_path_digit_ratio = (
            sum(
                caracter.isdigit()
                for caracter in path
            )
            / len(path)
        )
    else:
        safe_path_digit_ratio = 0.0

    # 10 y 11. Codificación porcentual
    texto_url = path + query

    safe_percent_encoded_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            texto_url
        )
    )

    if len(texto_url) > 0:
        safe_percent_encoded_ratio = (
            safe_percent_encoded_count
            / len(texto_url)
        )
    else:
        safe_percent_encoded_ratio = 0.0

    return {
        "safe_is_https":
            safe_is_https,

        "safe_hostname_length":
            safe_hostname_length,

        "safe_is_domain_ip":
            safe_is_domain_ip,

        "safe_hostname_dots":
            safe_hostname_dots,

        "safe_no_subdomains":
            safe_no_subdomains,

        "safe_hostname_digit_ratio":
            safe_hostname_digit_ratio,

        "safe_hostname_hyphens":
            safe_hostname_hyphens,

        "safe_has_punycode":
            safe_has_punycode,

        "safe_path_digit_ratio":
            safe_path_digit_ratio,

        "safe_percent_encoded_count":
            safe_percent_encoded_count,

        "safe_percent_encoded_ratio":
            safe_percent_encoded_ratio
    }


# ============================================================
# CÁLCULO DEL RISK SCORE
# ============================================================

def calcular_risk_score(url):

    caracteristicas = (
        extraer_caracteristicas_safe_v3(url)
    )

    X_url = pd.DataFrame(
        [caracteristicas]
    )

    # Orden exacto de las 11 variables del modelo
    X_url = X_url[variables_modelo]

    probabilidades = modelo.predict_proba(
        X_url
    )[0]

    # En el dataset SAFE:
    # clase 0 = phishing
    # clase 1 = legítima

    indice_phishing = list(
        modelo.classes_
    ).index(0)

    probabilidad_phishing = (
        probabilidades[indice_phishing]
    )

    risk_score = (
        probabilidad_phishing * 100
    )

    return round(
        float(risk_score),
        2
    )


# ============================================================
# INTERFAZ
# ============================================================

st.markdown(
    '<div class="safe-title">'
    '🛡️ SAFE URL Scan'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="safe-subtitle">'
    'Smart AI Fraud Evaluation'
    '</div>',
    unsafe_allow_html=True
)

st.write(
    "Evaluación preliminar de riesgo estructural en URLs."
)

st.markdown(
    """
    <div class="safe-info">
    SAFE analiza patrones estructurales de una URL.
    El resultado no constituye una confirmación automática
    de phishing ni una garantía absoluta de seguridad.
    </div>
    """,
    unsafe_allow_html=True
)

url_usuario = st.text_input(
    "URL para analizar",
    placeholder="https://www.ejemplo.com/"
)

analizar = st.button(
    "🔎 Analizar URL",
    use_container_width=True
)


# ============================================================
# RESULTADO DEL ANÁLISIS
# ============================================================

if analizar:

    if not url_usuario.strip():

        st.warning(
            "Ingresa una URL para realizar el análisis."
        )

    else:

        try:

            risk_score = calcular_risk_score(
                url_usuario
            )

            st.divider()

            st.header(
                "Resultado del análisis"
            )

            st.caption(
                "Risk Score SAFE"
            )

            st.markdown(
                f"## {risk_score} / 100"
            )

            # =================================================
            # CLASIFICACIÓN DEL RIESGO
            # =================================================

            if risk_score < 30:

                st.markdown(
                    """
                    <div class="risk-low">
                    🟢 &nbsp; Riesgo estructural bajo
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.write(
                    "No se identifican patrones "
                    "estructurales relevantes de riesgo."
                )

            elif risk_score < 70:

                st.markdown(
                    """
                    <div class="risk-medium">
                    🟡 &nbsp; Riesgo estructural medio
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.write(
                    "La URL presenta algunos patrones "
                    "estructurales que requieren revisión."
                )

            else:

                st.markdown(
                    """
                    <div class="risk-high">
                    🔴 &nbsp; Riesgo estructural alto
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.write(
                    "La URL presenta patrones estructurales "
                    "asociados con mayor riesgo."
                )

            # =================================================
            # ACCIÓN RECOMENDADA
            # =================================================

            st.subheader(
                "Acción recomendada"
            )

            if risk_score < 30:

                st.write(
                    "El resultado estructural es bajo. "
                    "Aun así, verifica el dominio y el "
                    "contexto antes de compartir "
                    "información sensible."
                )

            elif risk_score < 70:

                st.write(
                    "Verifica cuidadosamente el dominio, "
                    "el origen del enlace y el contexto "
                    "antes de ingresar información sensible."
                )

            else:

                st.write(
                    "Realiza verificaciones adicionales "
                    "antes de ingresar credenciales, "
                    "efectuar pagos o continuar con "
                    "acciones sensibles."
                )

        except Exception as e:

            st.error(
                "No fue posible analizar la URL."
            )

            st.caption(
                f"Detalle técnico: {e}"
            )


# ============================================================
# PIE DE PÁGINA
# ============================================================

st.divider()

st.markdown(
    """
    <div class="safe-footer">
    SAFE URL Scan es un prototipo académico de apoyo para la
    evaluación preliminar de riesgo estructural. No sustituye
    herramientas especializadas de reputación de dominios,
    listas de amenazas, análisis de contenido ni mecanismos
    institucionales de ciberseguridad.
    </div>
    """,
    unsafe_allow_html=True
)
