
import streamlit as st
import pandas as pd
import joblib
import re

from urllib.parse import urlparse, parse_qs

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

st.markdown(
    """
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
        padding: 18px;
        border-radius: 8px;
        margin-bottom: 20px;
    }

    .risk-low {
        background-color: #E4F7EC;
        color: #148447;
        padding: 16px;
        border-radius: 8px;
        margin-top: 15px;
        margin-bottom: 15px;
    }

    .risk-medium {
        background-color: #FFF4D8;
        color: #9A6700;
        padding: 16px;
        border-radius: 8px;
        margin-top: 15px;
        margin-bottom: 15px;
    }

    .risk-high {
        background-color: #FFE5E5;
        color: #D9363E;
        padding: 16px;
        border-radius: 8px;
        margin-top: 15px;
        margin-bottom: 15px;
    }

    .footer {
        color: #9298A1;
        font-size: 12px;
        line-height: 1.7;
        margin-top: 30px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# ARCHIVOS DEL MODELO DEFINITIVO
# ============================================================

MODELO_PATH = "modelo_safe_v3_final_13.pkl"
VARIABLES_PATH = "variables_safe_v3_final_13.pkl"


# ============================================================
# CARGA DEL MODELO
# ============================================================

@st.cache_resource
def cargar_modelo():

    modelo = joblib.load(
        MODELO_PATH
    )

    variables = joblib.load(
        VARIABLES_PATH
    )

    # Verificación crítica
    if modelo.n_features_in_ != len(variables):

        raise ValueError(
            "El modelo y la lista de variables "
            "no tienen el mismo número de características."
        )

    if len(variables) != 13:

        raise ValueError(
            f"SAFE esperaba 13 variables, "
            f"pero se cargaron {len(variables)}."
        )

    return modelo, variables


try:

    modelo, variables = cargar_modelo()

except Exception as e:

    st.error(
        "No fue posible cargar correctamente "
        "los artefactos del modelo SAFE."
    )

    st.write(
        "Detalle técnico:",
        str(e)
    )

    st.stop()


# ============================================================
# EXTRACCIÓN DE CARACTERÍSTICAS SAFE V3
# ============================================================

def extraer_caracteristicas_safe_v3(url):

    url = str(url).strip()
    url_lower = url.lower()

    # --------------------------------------------------------
    # PARSEO
    # --------------------------------------------------------

    try:

        parsed = urlparse(url)

        if not parsed.netloc:
            parsed = urlparse(
                "//" + url
            )

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:

        hostname = ""
        path = ""
        query = ""

    hostname = hostname.lower()


    # --------------------------------------------------------
    # 1. HTTPS
    # --------------------------------------------------------

    safe_is_https = int(
        url_lower.startswith(
            "https://"
        )
    )


    # --------------------------------------------------------
    # 2. LONGITUD DEL HOSTNAME
    # --------------------------------------------------------

    safe_hostname_length = len(
        hostname
    )


    # --------------------------------------------------------
    # 3. DOMINIO COMO IP
    # --------------------------------------------------------

    patron_ip = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    safe_is_domain_ip = int(
        bool(
            re.fullmatch(
                patron_ip,
                hostname
            )
        )
    )


    # --------------------------------------------------------
    # 4. PUNTOS DEL HOSTNAME
    # --------------------------------------------------------

    safe_hostname_dots = (
        hostname.count(".")
    )


    # --------------------------------------------------------
    # 5. SUBDOMINIOS
    # --------------------------------------------------------

    safe_no_subdomains = max(
        safe_hostname_dots - 1,
        0
    )


    # --------------------------------------------------------
    # 6. RATIO DE DÍGITOS EN HOSTNAME
    # --------------------------------------------------------

    hostname_digits = sum(
        c.isdigit()
        for c in hostname
    )

    safe_hostname_digit_ratio = (
        hostname_digits
        / len(hostname)
        if len(hostname) > 0
        else 0
    )


    # --------------------------------------------------------
    # 7. GUIONES EN HOSTNAME
    # --------------------------------------------------------

    safe_hostname_hyphens = (
        hostname.count("-")
    )


    # --------------------------------------------------------
    # 8. PUNYCODE
    # --------------------------------------------------------

    safe_has_punycode = int(
        "xn--" in hostname
    )


    # --------------------------------------------------------
    # 9. RATIO DE DÍGITOS EN PATH
    # --------------------------------------------------------

    path_digits = sum(
        c.isdigit()
        for c in path
    )

    safe_path_digit_ratio = (
        path_digits
        / len(path)
        if len(path) > 0
        else 0
    )


    # --------------------------------------------------------
    # 10. LONGITUD DEL QUERY
    # --------------------------------------------------------

    safe_query_length = len(
        query
    )


    # --------------------------------------------------------
    # 11. NÚMERO DE PARÁMETROS
    # --------------------------------------------------------

    try:

        parametros = parse_qs(
            query,
            keep_blank_values=True
        )

        safe_no_query_params = len(
            parametros
        )

    except Exception:

        safe_no_query_params = 0


    # --------------------------------------------------------
    # 12 Y 13. CODIFICACIÓN PORCENTUAL
    # --------------------------------------------------------

    secuencias_codificadas = re.findall(
        r"%[0-9A-Fa-f]{2}",
        url
    )

    safe_percent_encoded_count = len(
        secuencias_codificadas
    )

    safe_percent_encoded_ratio = (
        (
            safe_percent_encoded_count
            * 3
        )
        / len(url)
        if len(url) > 0
        else 0
    )


    # --------------------------------------------------------
    # RESULTADO
    # --------------------------------------------------------

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

        "safe_query_length":
            safe_query_length,

        "safe_no_query_params":
            safe_no_query_params,

        "safe_percent_encoded_count":
            safe_percent_encoded_count,

        "safe_percent_encoded_ratio":
            safe_percent_encoded_ratio
    }


# ============================================================
# FUNCIÓN DE ANÁLISIS
# ============================================================

def analizar_url(url):

    caracteristicas = (
        extraer_caracteristicas_safe_v3(
            url
        )
    )


    # --------------------------------------------------------
    # VERIFICACIÓN AUTOMÁTICA
    # --------------------------------------------------------

    faltantes = [
        variable
        for variable in variables
        if variable not in caracteristicas
    ]

    if faltantes:

        raise ValueError(
            "Faltan variables en la extracción: "
            + ", ".join(faltantes)
        )


    # --------------------------------------------------------
    # CREAR DATAFRAME EN EL ORDEN EXACTO DEL MODELO
    # --------------------------------------------------------

    X_url = pd.DataFrame(
        [caracteristicas]
    )

    X_url = X_url[
        variables
    ]


    # --------------------------------------------------------
    # PROBABILIDAD DE PHISHING
    # label 0 = phishing
    # --------------------------------------------------------

    probabilidades = (
        modelo.predict_proba(
            X_url
        )[0]
    )

    indice_phishing = list(
        modelo.classes_
    ).index(0)

    risk_score = (
        probabilidades[
            indice_phishing
        ]
        * 100
    )


    # --------------------------------------------------------
    # NIVEL DE RIESGO
    # --------------------------------------------------------

    if risk_score < 30:

        nivel = (
            "Riesgo estructural bajo"
        )

        descripcion = (
            "No se identifican patrones "
            "estructurales relevantes de riesgo."
        )

        accion = (
            "Continuar con los controles "
            "habituales de navegación."
        )

        clase_css = "risk-low"

        icono = "🟢"


    elif risk_score < 70:

        nivel = (
            "Riesgo estructural medio"
        )

        descripcion = (
            "La URL presenta algunos patrones "
            "que requieren verificación adicional."
        )

        accion = (
            "Verificar el dominio, la fuente del "
            "enlace y el contexto antes de ingresar "
            "información sensible."
        )

        clase_css = "risk-medium"

        icono = "🟡"


    else:

        nivel = (
            "Riesgo estructural alto"
        )

        descripcion = (
            "La URL presenta patrones estructurales "
            "asociados con mayor riesgo."
        )

        accion = (
            "Realizar verificaciones adicionales "
            "antes de ingresar credenciales, "
            "efectuar pagos, permitir la navegación "
            "o bloquear el acceso."
        )

        clase_css = "risk-high"

        icono = "🔴"


    return {

        "risk_score":
            round(
                risk_score,
                2
            ),

        "nivel":
            nivel,

        "descripcion":
            descripcion,

        "accion":
            accion,

        "clase_css":
            clase_css,

        "icono":
            icono
    }


# ============================================================
# INTERFAZ
# ============================================================

st.markdown(
    """
    <div class="safe-title">
        🛡️ SAFE URL Scan
    </div>

    <div class="safe-subtitle">
        Smart AI Fraud Evaluation
    </div>
    """,
    unsafe_allow_html=True
)


st.write(
    "Evaluación preliminar de riesgo "
    "estructural en URLs."
)


st.markdown(
    """
    <div class="safe-info">
        SAFE analiza patrones estructurales de una URL.
        El resultado no constituye una confirmación
        automática de phishing ni una garantía absoluta
        de seguridad.
    </div>
    """,
    unsafe_allow_html=True
)


url_usuario = st.text_input(
    "URL para analizar",
    placeholder=(
        "https://www.ejemplo.com"
    )
)


analizar = st.button(
    "🔎 Analizar URL",
    use_container_width=True
)


# ============================================================
# RESULTADO
# ============================================================

if analizar:

    if not url_usuario.strip():

        st.warning(
            "Ingresa una URL para realizar "
            "el análisis."
        )

    else:

        try:

            resultado = analizar_url(
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
                f"""
                <div style="
                    font-size:32px;
                    margin-bottom:10px;
                ">
                    {resultado["risk_score"]} / 100
                </div>
                """,
                unsafe_allow_html=True
            )


            st.markdown(
                f"""
                <div class="{resultado['clase_css']}">
                    {resultado['icono']}
                    &nbsp;
                    {resultado['nivel']}
                </div>
                """,
                unsafe_allow_html=True
            )


            st.write(
                resultado[
                    "descripcion"
                ]
            )


            st.subheader(
                "Acción recomendada"
            )

            st.write(
                resultado[
                    "accion"
                ]
            )


            with st.expander(
                "ℹ️ ¿Qué significa este resultado?"
            ):

                st.write(
                    """
                    El Risk Score SAFE representa una
                    estimación de riesgo estructural
                    basada en patrones observables de
                    la URL.

                    No constituye por sí solo una
                    confirmación de phishing.

                    Una decisión definitiva debe
                    complementarse con mecanismos
                    como reputación del dominio,
                    listas de amenazas, análisis de
                    contenido y controles
                    institucionales de ciberseguridad.
                    """
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
    <div class="footer">
        SAFE URL Scan es un prototipo académico de apoyo
        para la evaluación preliminar de riesgo estructural.
        No sustituye herramientas especializadas de
        reputación de dominios, listas de amenazas,
        análisis de contenido ni mecanismos institucionales
        de ciberseguridad.
    </div>
    """,
    unsafe_allow_html=True
)
