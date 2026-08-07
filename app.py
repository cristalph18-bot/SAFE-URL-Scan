
import streamlit as st
import pandas as pd
import joblib
import ipaddress
import os

from urllib.parse import urlparse
from datetime import datetime


# ---------------------------------------------------------
# CONFIGURACIÓN GENERAL
# ---------------------------------------------------------

st.set_page_config(
    page_title="SAFE URL Scan",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# ESTILO VISUAL
# ---------------------------------------------------------

st.markdown("""
<style>

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
}

.safe-title {
    font-size: 42px;
    font-weight: 800;
    margin-bottom: 0px;
}

.safe-subtitle {
    color: #64748b;
    font-size: 18px;
    margin-bottom: 30px;
}

.safe-card {
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 25px;
    background-color: white;
    box-shadow: 0px 2px 8px rgba(0,0,0,0.04);
}

.score-low {
    color: #16a34a;
    font-size: 45px;
    font-weight: 800;
}

.score-medium {
    color: #d97706;
    font-size: 45px;
    font-weight: 800;
}

.score-high {
    color: #dc2626;
    font-size: 45px;
    font-weight: 800;
}

.small-text {
    color: #64748b;
    font-size: 14px;
}

</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# CARGA DEL MODELO
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ruta_modelo = os.path.join(
    BASE_DIR,
    "modelo_safe_funcional.pkl"
)

ruta_variables = os.path.join(
    BASE_DIR,
    "variables_safe_funcional.pkl"
)


@st.cache_resource
def cargar_modelo():

    modelo = joblib.load(ruta_modelo)
    variables = joblib.load(ruta_variables)

    return modelo, variables


modelo_safe, variables_safe = cargar_modelo()


# ---------------------------------------------------------
# EXTRACTOR SAFE
# ---------------------------------------------------------

def extraer_caracteristicas_safe(url):

    url = str(url).strip()

    url_parseo = url

    if not url_parseo.startswith(
        ("http://", "https://")
    ):
        url_parseo = "http://" + url_parseo

    parsed = urlparse(url_parseo)

    dominio = parsed.netloc.lower()

    tld = (
        dominio.split(".")[-1]
        if "." in dominio
        else ""
    )

    try:
        ipaddress.ip_address(
            dominio.split(":")[0]
        )
        es_ip = 1

    except ValueError:
        es_ip = 0


    letras = sum(
        c.isalpha()
        for c in url
    )

    digitos = sum(
        c.isdigit()
        for c in url
    )

    especiales = sum(
        not c.isalnum()
        for c in url
    )


    partes_dominio = dominio.split(".")


    if dominio.startswith("www."):

        partes_subdominio = (
            partes_dominio[1:-2]
        )

    else:

        partes_subdominio = (
            partes_dominio[:-2]
        )


    numero_subdominios = max(
        len(partes_subdominio),
        0
    )


    caracteristicas = {

        "safe_url_length": len(url),
        "safe_domain_length": len(dominio),
        "safe_tld_length": len(tld),

        "safe_is_https":
            1 if parsed.scheme.lower() == "https"
            else 0,

        "safe_is_domain_ip": es_ip,

        "safe_no_subdomains":
            numero_subdominios,

        "safe_no_letters": letras,

        "safe_letter_ratio":
            letras / len(url)
            if len(url) > 0
            else 0,

        "safe_no_digits": digitos,

        "safe_digit_ratio":
            digitos / len(url)
            if len(url) > 0
            else 0,

        "safe_no_equals": url.count("="),
        "safe_no_question": url.count("?"),
        "safe_no_ampersand": url.count("&"),

        "safe_no_special": especiales,

        "safe_special_ratio":
            especiales / len(url)
            if len(url) > 0
            else 0,

        "safe_has_at":
            1 if "@" in url
            else 0,

        "safe_has_hyphen":
            1 if "-" in dominio
            else 0
    }

    return caracteristicas


# ---------------------------------------------------------
# MOTOR SAFE
# ---------------------------------------------------------

def evaluar_url_safe(url):

    caracteristicas = (
        extraer_caracteristicas_safe(url)
    )

    entrada = pd.DataFrame(
        [caracteristicas]
    )

    entrada = entrada[
        variables_safe
    ]


    probabilidades = (
        modelo_safe.predict_proba(
            entrada
        )[0]
    )


    indice_phishing = list(
        modelo_safe.classes_
    ).index(0)


    indice_legitima = list(
        modelo_safe.classes_
    ).index(1)


    prob_phishing = (
        probabilidades[
            indice_phishing
        ]
    )


    prob_legitima = (
        probabilidades[
            indice_legitima
        ]
    )


    risk_score = (
        prob_phishing * 100
    )


    if risk_score < 30:

        nivel = "Bajo"
        accion = "Permitir navegación"
        clase_css = "score-low"
        icono = "🟢"

    elif risk_score < 70:

        nivel = "Medio"
        accion = "Advertir al usuario"
        clase_css = "score-medium"
        icono = "🟡"

    else:

        nivel = "Alto"
        accion = "Bloquear URL o escalar caso"
        clase_css = "score-high"
        icono = "🔴"


    return {

        "url": url,

        "risk_score":
            round(risk_score, 2),

        "nivel":
            nivel,

        "accion":
            accion,

        "prob_phishing":
            prob_phishing * 100,

        "prob_legitima":
            prob_legitima * 100,

        "caracteristicas":
            caracteristicas,

        "clase_css":
            clase_css,

        "icono":
            icono
    }


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

with st.sidebar:

    st.markdown("# 🛡️ SAFE")
    st.markdown("### URL Scan")

    st.divider()

    st.markdown(
        "**Smart AI Fraud Evaluation**"
    )

    st.write(
        "Sistema inteligente para la evaluación "
        "del riesgo de URLs potencialmente fraudulentas."
    )

    st.divider()

    st.markdown("**Modelo:** Random Forest")
    st.markdown("**Variables:** 17")
    st.markdown("**Versión:** 1.0")


# ---------------------------------------------------------
# ENCABEZADO
# ---------------------------------------------------------

st.markdown(
    '<div class="safe-title">'
    'Análisis de URL'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="safe-subtitle">'
    'Ingresa una URL para analizar su nivel de riesgo mediante SAFE.'
    '</div>',
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# INPUT
# ---------------------------------------------------------

url_usuario = st.text_input(
    "URL para analizar",
    placeholder="https://www.ejemplo.com"
)


analizar = st.button(
    "🔎 Analizar URL",
    type="primary",
    use_container_width=True
)


# ---------------------------------------------------------
# RESULTADO
# ---------------------------------------------------------

if analizar:

    if not url_usuario.strip():

        st.warning(
            "Ingresa una URL para realizar el análisis."
        )

    else:

        resultado = evaluar_url_safe(
            url_usuario
        )

        st.divider()

        st.markdown(
            "## Resultado del análisis"
        )


        col1, col2 = st.columns(
            [1, 2]
        )


        with col1:

            st.markdown(
                f"""
                <div class="safe-card">
                    <div class="{resultado['clase_css']}">
                        {resultado['risk_score']}
                    </div>

                    <div class="small-text">
                        RISK SCORE / 100
                    </div>

                    <br>

                    <h2>
                    {resultado['icono']}
                    Riesgo {resultado['nivel']}
                    </h2>

                </div>
                """,
                unsafe_allow_html=True
            )


        with col2:

            st.markdown(
                f"""
                <div class="safe-card">

                <h3>
                Acción recomendada
                </h3>

                <h2>
                {resultado['accion']}
                </h2>

                <br>

                <b>URL analizada:</b><br>

                {resultado['url']}

                </div>
                """,
                unsafe_allow_html=True
            )


        st.write("")


        c1, c2, c3 = st.columns(3)


        with c1:

            st.metric(
                "Probabilidad de phishing",
                f"{resultado['prob_phishing']:.2f}%"
            )


        with c2:

            st.metric(
                "Probabilidad de legitimidad",
                f"{resultado['prob_legitima']:.2f}%"
            )


        with c3:

            st.metric(
                "Modelo",
                "SAFE Funcional"
            )


        st.caption(
            "Fecha del análisis: "
            + datetime.now().strftime(
                "%d/%m/%Y %H:%M:%S"
            )
        )


        with st.expander(
            "🔍 Ver características analizadas"
        ):

            tabla_caracteristicas = (
                pd.DataFrame(
                    resultado[
                        "caracteristicas"
                    ].items(),
                    columns=[
                        "Característica",
                        "Valor"
                    ]
                )
            )

            st.dataframe(
                tabla_caracteristicas,
                use_container_width=True,
                hide_index=True
            )


        st.info(
            "SAFE constituye un prototipo académico "
            "de apoyo a la evaluación del riesgo de URLs. "
            "El resultado no sustituye los mecanismos "
            "oficiales de seguridad de una entidad financiera."
        )
