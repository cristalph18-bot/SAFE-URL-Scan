
import streamlit as st
import pandas as pd
import joblib
import ipaddress

from urllib.parse import (
    urlparse,
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode
)

# ============================================================
# CONFIGURACIÓN DE LA APLICACIÓN
# ============================================================

st.set_page_config(
    page_title="SAFE URL Scan",
    page_icon="🛡️",
    layout="centered"
)

# ============================================================
# CARGA DE ARTEFACTOS FINALES
# ============================================================

# Los archivos estarán en la misma carpeta que app.py
# dentro del repositorio de GitHub.

MODELO_PATH = "modelo_safe_final.pkl"
VARIABLES_PATH = "variables_safe_final.pkl"

modelo = joblib.load(MODELO_PATH)
variables = joblib.load(VARIABLES_PATH)

# ============================================================
# NORMALIZACIÓN SAFE
# ============================================================

def normalizar_url_safe(url):

    url = str(url).strip()

    try:
        partes = urlsplit(url)

        esquema = partes.scheme.lower()
        dominio = partes.netloc.lower()
        ruta = partes.path

        # "/" únicamente en la raíz se considera equivalente
        # a una ruta vacía.
        if ruta == "/":
            ruta = ""

        # Parámetros conocidos de seguimiento
        parametros_tracking = {
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "utm_id",
            "gclid",
            "gbraid",
            "wbraid",
            "fbclid"
        }

        parametros = parse_qsl(
            partes.query,
            keep_blank_values=True
        )

        parametros_limpios = [
            (clave, valor)
            for clave, valor in parametros
            if clave.lower() not in parametros_tracking
        ]

        query_limpia = urlencode(
            parametros_limpios,
            doseq=True
        )

        # Se eliminan fragmentos
        return urlunsplit(
            (
                esquema,
                dominio,
                ruta,
                query_limpia,
                ""
            )
        )

    except Exception:
        return url


# ============================================================
# EXTRACCIÓN DE LAS 17 CARACTERÍSTICAS SAFE
# ============================================================

def extraer_caracteristicas_safe(url):

    url = str(url).strip()

    # Agregar esquema temporal si la URL no lo contiene,
    # únicamente para facilitar el parseo.
    url_parseo = url

    if not url_parseo.startswith(
        ("http://", "https://")
    ):
        url_parseo = "http://" + url_parseo

    parsed = urlparse(url_parseo)

    dominio = parsed.netloc.lower()

    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    tld = (
        dominio.split(".")[-1]
        if "." in dominio
        else ""
    )

    # --------------------------------------------------------
    # Verificar si el dominio es una IP
    # --------------------------------------------------------

    try:
        ipaddress.ip_address(
            dominio.split(":")[0]
        )
        es_ip = 1

    except ValueError:
        es_ip = 0

    # --------------------------------------------------------
    # Conteo de caracteres
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Número de subdominios
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Las 17 características SAFE
    # --------------------------------------------------------

    return {

        "safe_url_length":
            len(url),

        "safe_domain_length":
            len(dominio),

        "safe_tld_length":
            len(tld),

        "safe_is_https":
            1 if parsed.scheme.lower() == "https"
            else 0,

        "safe_is_domain_ip":
            es_ip,

        "safe_no_subdomains":
            numero_subdominios,

        "safe_no_letters":
            letras,

        "safe_letter_ratio":
            letras / len(url)
            if len(url) > 0
            else 0,

        "safe_no_digits":
            digitos,

        "safe_digit_ratio":
            digitos / len(url)
            if len(url) > 0
            else 0,

        "safe_no_equals":
            url.count("="),

        "safe_no_question":
            url.count("?"),

        "safe_no_ampersand":
            url.count("&"),

        "safe_no_special":
            especiales,

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


# ============================================================
# MOTOR DE EVALUACIÓN SAFE
# ============================================================

def evaluar_url(url):

    # --------------------------------------------------------
    # 1. Normalización
    # --------------------------------------------------------

    url_normalizada = normalizar_url_safe(
        url
    )

    # --------------------------------------------------------
    # 2. Extracción de características
    # --------------------------------------------------------

    caracteristicas = extraer_caracteristicas_safe(
        url_normalizada
    )

    # --------------------------------------------------------
    # 3. Orden de variables esperado por el modelo
    # --------------------------------------------------------

    X_url = pd.DataFrame(
        [
            [
                caracteristicas[var]
                for var in variables
            ]
        ],
        columns=variables
    )

    # --------------------------------------------------------
    # 4. Predicción del modelo
    # --------------------------------------------------------

    probabilidades = modelo.predict_proba(
        X_url
    )[0]

    # Clase 0 = phishing / maliciosa
    # dentro del dataset de entrenamiento.
    indice_riesgo = list(
        modelo.classes_
    ).index(0)

    prob_riesgo = probabilidades[
        indice_riesgo
    ]

    # --------------------------------------------------------
    # 5. Risk Score SAFE
    # --------------------------------------------------------

    risk_score = float(
        round(
            prob_riesgo * 100,
            2
        )
    )

    # --------------------------------------------------------
    # 6. Interpretación del resultado
    # --------------------------------------------------------

    if risk_score < 30:

        nivel = (
            "Riesgo estructural bajo"
        )

        mensaje = (
            "No se identifican patrones estructurales "
            "relevantes de riesgo."
        )

        accion = (
            "Continuar con los controles habituales "
            "de navegación."
        )

    elif risk_score < 70:

        nivel = (
            "Riesgo estructural medio"
        )

        mensaje = (
            "Se identifican algunos patrones estructurales "
            "que requieren revisión."
        )

        accion = (
            "Validar el dominio, la fuente y el contexto "
            "antes de realizar acciones sensibles."
        )

    else:

        nivel = (
            "Riesgo estructural alto"
        )

        mensaje = (
            "La URL presenta patrones estructurales "
            "asociados con mayor riesgo."
        )

        accion = (
            "Realizar verificaciones adicionales antes de "
            "ingresar credenciales, efectuar pagos, permitir "
            "la navegación o bloquear el acceso."
        )

    return {

        "url_original":
            url,

        "url_normalizada":
            url_normalizada,

        "risk_score":
            risk_score,

        "nivel":
            nivel,

        "mensaje":
            mensaje,

        "accion":
            accion
    }


# ============================================================
# INTERFAZ SAFE URL SCAN
# ============================================================

st.title(
    "🛡️ SAFE URL Scan"
)

st.caption(
    "Smart AI Fraud Evaluation"
)

st.write(
    "Evaluación preliminar de riesgo estructural en URLs."
)

st.info(
    "SAFE analiza patrones estructurales de una URL. "
    "El resultado no constituye una confirmación automática "
    "de phishing ni una garantía absoluta de seguridad."
)

# ------------------------------------------------------------
# INPUT
# ------------------------------------------------------------

url_usuario = st.text_input(
    "URL para analizar",
    placeholder="https://www.ejemplo.com"
)

# ------------------------------------------------------------
# BOTÓN DE ANÁLISIS
# ------------------------------------------------------------

if st.button(
    "🔎 Analizar URL",
    type="primary",
    use_container_width=True
):

    if not url_usuario.strip():

        st.warning(
            "Ingresa una URL para realizar el análisis."
        )

    else:

        try:

            resultado = evaluar_url(
                url_usuario
            )

            score = resultado[
                "risk_score"
            ]

            st.divider()

            # =================================================
            # RESULTADO
            # =================================================

            st.subheader(
                "Resultado del análisis"
            )

            st.metric(
                label="Risk Score SAFE",
                value=f"{score:.2f} / 100"
            )

            # -------------------------------------------------
            # NIVEL DE RIESGO
            # -------------------------------------------------

            if score < 30:

                st.success(
                    f"🟢 {resultado['nivel']}"
                )

            elif score < 70:

                st.warning(
                    f"🟡 {resultado['nivel']}"
                )

            else:

                st.error(
                    f"🔴 {resultado['nivel']}"
                )

            st.write(
                resultado["mensaje"]
            )

            # =================================================
            # ACCIÓN RECOMENDADA
            # =================================================

            st.subheader(
                "Acción recomendada"
            )

            st.write(
                resultado["accion"]
            )

            # =================================================
            # EXPLICACIÓN
            # =================================================

            with st.expander(
                "ℹ️ ¿Qué significa este resultado?"
            ):

                st.markdown(
                    """
SAFE analiza características **estructurales y léxicas**
de la URL, como:

- longitud de la dirección;
- longitud del dominio;
- cantidad de subdominios;
- caracteres especiales;
- números y letras;
- presencia de `@` o guiones;
- uso de HTTPS;
- estructura general de la URL.

Un **Risk Score elevado** significa que la estructura
analizada presenta similitudes con patrones asociados
a URLs de riesgo dentro del conjunto utilizado para
entrenar el modelo.

**Un puntaje alto no confirma que el sitio sea phishing.**

De igual forma, un puntaje bajo no constituye una
garantía absoluta de seguridad.

SAFE debe utilizarse como una **señal de apoyo** para
determinar si son necesarias validaciones adicionales.
                    """
                )

            # =================================================
            # RECOMENDACIONES SEGÚN CONTEXTO
            # =================================================

            with st.expander(
                "🧭 ¿Qué puedo verificar adicionalmente?"
            ):

                st.markdown(
                    """
Antes de realizar una acción sensible puedes revisar:

- Que el dominio corresponda realmente a la organización;
- Que la URL provenga de una fuente confiable;
- Que no hayas llegado al sitio mediante un enlace sospechoso;
- Que la página utilice HTTPS;
- Que no existan cambios extraños en el dominio;
- Que no te estén solicitando credenciales o pagos
  de forma inesperada;
- Mecanismos institucionales de ciberseguridad o
  reputación del dominio cuando estén disponibles.
                    """
                )

            # =================================================
            # INFORMACIÓN TÉCNICA
            # =================================================

            with st.expander(
                "🔬 Información técnica"
            ):

                st.write(
                    "**URL ingresada:**",
                    resultado[
                        "url_original"
                    ]
                )

                st.write(
                    "**URL normalizada:**",
                    resultado[
                        "url_normalizada"
                    ]
                )

                st.write(
                    "**Características analizadas:**",
                    len(variables)
                )

                st.write(
                    "**Modelo:** Random Forest"
                )

                st.write(
                    "**Tipo de resultado:** "
                    "Risk Score de riesgo estructural"
                )

        except Exception as error:

            st.error(
                "No fue posible analizar la URL."
            )

            st.caption(
                f"Detalle técnico: {error}"
            )


# ============================================================
# NOTA METODOLÓGICA
# ============================================================

st.divider()

st.caption(
    "SAFE URL Scan es un prototipo académico de apoyo para "
    "la evaluación preliminar de riesgo estructural. "
    "No sustituye herramientas especializadas de reputación "
    "de dominios, listas de amenazas, análisis de contenido "
    "ni mecanismos institucionales de ciberseguridad."
)
