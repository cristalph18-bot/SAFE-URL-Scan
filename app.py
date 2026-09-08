
import streamlit as st
import pandas as pd
import joblib
import re
import ipaddress
from urllib.parse import urlparse

# ============================================================
# CONFIGURACIÓN
# ============================================================

st.set_page_config(
    page_title="SAFE URL Scan",
    page_icon="🛡️",
    layout="wide"
)

RUTA_MODELO = "modelo_safe_v4_final_11.pkl"
RUTA_VARIABLES = "variables_safe_v4_final_11.pkl"

modelo = joblib.load(RUTA_MODELO)
variables_modelo = joblib.load(RUTA_VARIABLES)


# ============================================================
# ESTILOS
# ============================================================

st.markdown("""
<style>

.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

.safe-header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 6px;
}

.safe-logo {
    font-size: 46px;
}

.safe-title {
    font-size: 38px;
    font-weight: 750;
    color: #17365D;
    margin: 0;
}

.safe-subtitle {
    font-size: 16px;
    color: #64748B;
    margin-top: 2px;
}

.safe-card {
    background: #FFFFFF;
    border: 1px solid #DCE5F0;
    border-radius: 14px;
    padding: 22px;
    box-shadow: 0 2px 8px rgba(20, 50, 90, 0.04);
    margin-bottom: 18px;
}

.safe-info {
    background: #EDF5FF;
    border: 1px solid #D7E8FF;
    padding: 15px 18px;
    border-radius: 10px;
    color: #185A9D;
    margin-bottom: 18px;
}

.risk-low {
    background: #E8F7EE;
    color: #167A45;
    border-radius: 10px;
    padding: 14px 16px;
    font-weight: 600;
}

.risk-medium {
    background: #FFF4D6;
    color: #8A6200;
    border-radius: 10px;
    padding: 14px 16px;
    font-weight: 600;
}

.risk-high {
    background: #FDE7E7;
    color: #C7353E;
    border-radius: 10px;
    padding: 14px 16px;
    font-weight: 600;
}

.metric-label {
    font-size: 14px;
    color: #7B8794;
    margin-bottom: 0px;
}

.metric-value {
    font-size: 52px;
    font-weight: 750;
    color: #17365D;
    margin-top: -5px;
}

.reco-item {
    border-bottom: 1px solid #E9EEF5;
    padding: 10px 0px;
}

.reco-title {
    font-weight: 650;
    color: #17365D;
}

.feature-chip {
    display: inline-block;
    background: #F4F7FB;
    border: 1px solid #E1E7EF;
    border-radius: 10px;
    padding: 10px 12px;
    margin: 6px;
    font-size: 13px;
    color: #334155;
}

.footer {
    color: #8A8F98;
    font-size: 12px;
    margin-top: 25px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# EXTRACCIÓN DE CARACTERÍSTICAS
# ============================================================

def extraer_caracteristicas_safe_v3(url):

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

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

    safe_is_https = int(
        parsed.scheme.lower() == "https"
    )

    safe_hostname_length = len(hostname)

    try:
        ipaddress.ip_address(hostname)
        safe_is_domain_ip = 1
    except ValueError:
        safe_is_domain_ip = 0

    safe_hostname_dots = hostname.count(".")

    safe_no_subdomains = max(
        safe_hostname_dots - 1,
        0
    )

    safe_hostname_digit_ratio = (
        sum(c.isdigit() for c in hostname)
        / len(hostname)
        if len(hostname) > 0
        else 0.0
    )

    safe_hostname_hyphens = hostname.count("-")

    safe_has_punycode = int(
        "xn--" in hostname_lower
    )

    safe_path_digit_ratio = (
        sum(c.isdigit() for c in path)
        / len(path)
        if len(path) > 0
        else 0.0
    )

    texto_url = path + query

    safe_percent_encoded_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            texto_url
        )
    )

    safe_percent_encoded_ratio = (
        safe_percent_encoded_count
        / len(texto_url)
        if len(texto_url) > 0
        else 0.0
    )

    return {
        "safe_is_https": safe_is_https,
        "safe_hostname_length": safe_hostname_length,
        "safe_is_domain_ip": safe_is_domain_ip,
        "safe_hostname_dots": safe_hostname_dots,
        "safe_no_subdomains": safe_no_subdomains,
        "safe_hostname_digit_ratio": safe_hostname_digit_ratio,
        "safe_hostname_hyphens": safe_hostname_hyphens,
        "safe_has_punycode": safe_has_punycode,
        "safe_path_digit_ratio": safe_path_digit_ratio,
        "safe_percent_encoded_count": safe_percent_encoded_count,
        "safe_percent_encoded_ratio": safe_percent_encoded_ratio
    }


# ============================================================
# CÁLCULO DE RIESGO
# ============================================================

def analizar_url(url):

    caracteristicas = extraer_caracteristicas_safe_v3(url)

    X_url = pd.DataFrame(
        [caracteristicas]
    )[variables_modelo]

    probabilidades = modelo.predict_proba(
        X_url
    )[0]

    indice_phishing = list(
        modelo.classes_
    ).index(0)

    risk_score = float(
        probabilidades[indice_phishing] * 100
    )

    return round(risk_score, 2), caracteristicas


# ============================================================
# INTERPRETACIÓN HUMANA DE VARIABLES
# ============================================================

def generar_hallazgos(c):

    hallazgos = []

    if c["safe_is_https"] == 1:
        hallazgos.append(
            ("HTTPS presente", "La URL utiliza protocolo HTTPS.")
        )
    else:
        hallazgos.append(
            ("Sin HTTPS", "La URL no utiliza HTTPS.")
        )

    if c["safe_is_domain_ip"] == 1:
        hallazgos.append(
            ("Dominio en formato IP",
             "El sitio usa una dirección IP en lugar de un nombre de dominio.")
        )

    if c["safe_no_subdomains"] >= 3:
        hallazgos.append(
            ("Varios subdominios",
             "El dominio presenta una estructura con varios niveles.")
        )

    if c["safe_hostname_digit_ratio"] > 0.20:
        hallazgos.append(
            ("Alta presencia de números",
             "El dominio contiene una proporción relevante de dígitos.")
        )

    if c["safe_hostname_hyphens"] >= 2:
        hallazgos.append(
            ("Varios guiones",
             "El dominio contiene varios guiones.")
        )

    if c["safe_has_punycode"] == 1:
        hallazgos.append(
            ("Punycode detectado",
             "El dominio utiliza codificación Punycode.")
        )

    if c["safe_path_digit_ratio"] > 0.20:
        hallazgos.append(
            ("Números en la ruta",
             "La ruta de la URL contiene una proporción relevante de dígitos.")
        )

    if c["safe_percent_encoded_count"] > 0:
        hallazgos.append(
            ("Caracteres codificados",
             "La URL contiene secuencias codificadas con %.") 
        )

    if not hallazgos:
        hallazgos.append(
            ("Sin señales destacadas",
             "No se identificaron patrones estructurales especialmente llamativos.")
        )

    return hallazgos


# ============================================================
# RECOMENDACIONES
# ============================================================

def recomendaciones_por_riesgo(score):

    if score < 30:
        return [
            ("Verifica el dominio",
             "Confirma que el dominio corresponda al sitio que esperas visitar."),
            ("Confirma la fuente del enlace",
             "Asegúrate de que el enlace provenga de un canal confiable."),
            ("Mantén controles habituales",
             "Aunque el riesgo estructural sea bajo, evita compartir información sensible sin validar el contexto.")
        ]

    elif score < 70:
        return [
            ("Revisa cuidadosamente el dominio",
             "Busca variaciones sospechosas en el nombre del sitio."),
            ("Confirma el origen del enlace",
             "Verifica quién te envió la URL y por qué."),
            ("No ingreses credenciales todavía",
             "Valida primero que la página corresponda al servicio oficial."),
            ("Accede desde el sitio oficial",
             "Si es posible, escribe la dirección oficial directamente en el navegador.")
        ]

    else:
        return [
            ("No ingreses credenciales",
             "Evita suministrar usuario, contraseña o códigos de autenticación."),
            ("No realices pagos",
             "No efectúes transacciones hasta validar la legitimidad del sitio."),
            ("Verifica el dominio",
             "Revisa que el dominio corresponda exactamente a la entidad esperada."),
            ("Confirma la fuente del enlace",
             "Valida el mensaje, correo o canal desde el cual recibiste la URL."),
            ("Accede al sitio oficial",
             "Ingresa directamente desde la aplicación oficial o escribe la URL conocida en el navegador.")
        ]


# ============================================================
# ENCABEZADO
# ============================================================

st.markdown("""
<div class="safe-header">
    <div class="safe-logo">🛡️</div>
    <div>
        <div class="safe-title">SAFE URL Scan</div>
        <div class="safe-subtitle">
            Smart AI Fraud Evaluation · Análisis estructural de URLs
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="safe-info">
SAFE realiza una evaluación preliminar de patrones estructurales de una URL.
El resultado no constituye una confirmación automática de phishing ni una
garantía absoluta de seguridad.
</div>
""", unsafe_allow_html=True)


# ============================================================
# ENTRADA
# ============================================================

st.markdown("### 🔗 Ingresa la URL a analizar")

col_url, col_btn = st.columns([5, 1])

with col_url:
    url_usuario = st.text_input(
        "URL",
        label_visibility="collapsed",
        placeholder="https://www.ejemplo.com/"
    )

with col_btn:
    analizar = st.button(
        "🔎 Analizar",
        use_container_width=True
    )


# ============================================================
# RESULTADO
# ============================================================

if analizar:

    if not url_usuario.strip():
        st.warning(
            "Ingresa una URL para realizar el análisis."
        )

    else:

        try:

            risk_score, caracteristicas = analizar_url(
                url_usuario
            )

            hallazgos = generar_hallazgos(
                caracteristicas
            )

            recomendaciones = recomendaciones_por_riesgo(
                risk_score
            )

            col_resultado, col_reco = st.columns(
                [1.05, 1.35]
            )
            # ============================================================
            # COLUMNA IZQUIERDA: RESULTADO PRINCIPAL
            # ============================================================

            with col_resultado:

                st.markdown(
                    '<div class="safe-card">',
                    unsafe_allow_html=True
                )

                st.markdown(
                    "### 📋 Resultado del análisis"
                )

                st.markdown(
                    '<div class="metric-label">SAFE Risk Score</div>',
                    unsafe_allow_html=True
                )

                st.markdown(
                    f'<div class="metric-value">{risk_score:.0f}/100</div>',
                    unsafe_allow_html=True
                )

                # --------------------------------------------------------
                # NIVEL DE RIESGO
                # --------------------------------------------------------

                if risk_score < 30:

                    st.markdown(
                        '<div class="risk-low">'
                        '🟢 Riesgo estructural bajo'
                        '</div>',
                        unsafe_allow_html=True
                    )

                    st.markdown("#### ¿Cómo interpretar este resultado?")

                    st.write(
                        "SAFE identificó una baja similitud entre la estructura "
                        "de esta URL y los patrones asociados con URLs de mayor "
                        "riesgo aprendidos durante el entrenamiento del modelo."
                    )

                    st.info(
                        "Un puntaje bajo no garantiza que el sitio sea legítimo "
                        "o completamente seguro. SAFE realiza una evaluación "
                        "estructural de la URL y debe utilizarse como una señal "
                        "de apoyo."
                    )

                elif risk_score < 70:

                    st.markdown(
                        '<div class="risk-medium">'
                        '🟡 Riesgo estructural medio'
                        '</div>',
                        unsafe_allow_html=True
                    )

                    st.markdown("#### ¿Cómo interpretar este resultado?")

                    st.write(
                        "SAFE identificó algunos patrones estructurales que "
                        "merecen una revisión adicional. El resultado se "
                        "encuentra en una zona intermedia de riesgo."
                    )

                    st.warning(
                        "Este resultado no permite concluir por sí solo que la "
                        "URL sea fraudulenta. Antes de ingresar información "
                        "sensible, conviene verificar el dominio, el origen del "
                        "enlace y el contexto en el que fue recibido."
                    )

                else:

                    st.markdown(
                        '<div class="risk-high">'
                        '🔴 Riesgo estructural alto'
                        '</div>',
                        unsafe_allow_html=True
                    )

                    st.markdown("#### ¿Cómo interpretar este resultado?")

                    st.write(
                        "SAFE identificó una combinación de características "
                        "estructurales con alta similitud frente a los patrones "
                        "asociados con URLs de mayor riesgo aprendidos durante "
                        "el entrenamiento del modelo."
                    )

                    st.error(
                        "Este resultado funciona como una señal de alerta. "
                        "No significa por sí solo que la URL sea definitivamente "
                        "phishing o fraudulenta, pero sí indica que deberían "
                        "realizarse verificaciones adicionales antes de continuar."
                    )

                st.markdown(
                    '</div>',
                    unsafe_allow_html=True
                )


            # ============================================================
            # COLUMNA DERECHA: RECOMENDACIONES
            # ============================================================

            with col_reco:

                st.markdown(
                    '<div class="safe-card">',
                    unsafe_allow_html=True
                )

                st.markdown(
                    "### 💡 Recomendaciones de verificación"
                )

                for numero, (titulo, descripcion) in enumerate(
                    recomendaciones,
                    start=1
                ):

                    st.markdown(
                        f"""
                        <div class="reco-item">
                            <div class="reco-title">
                                {numero}. {titulo}
                            </div>
                            <div style="
                                color:#64748B;
                                font-size:14px;
                                margin-top:4px;
                            ">
                                {descripcion}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                st.markdown(
                    '</div>',
                    unsafe_allow_html=True
                )


            # ============================================================
            # QUÉ ENCONTRÓ SAFE
            # ============================================================

            st.markdown("### 🔎 ¿Qué encontró SAFE?")

            st.write(
                "SAFE analiza diferentes características estructurales de la "
                "URL. Estas señales se evalúan de manera conjunta mediante el "
                "modelo Random Forest para obtener el Risk Score."
            )

            columnas_hallazgos = st.columns(2)

            for i, (titulo, descripcion) in enumerate(hallazgos):

                columna = columnas_hallazgos[i % 2]

                with columna:

                    st.markdown(
                        f"""
                        <div class="safe-card">
                            <div style="
                                font-weight:650;
                                color:#17365D;
                                margin-bottom:5px;
                            ">
                                {titulo}
                            </div>
                            <div style="
                                color:#64748B;
                                font-size:14px;
                            ">
                                {descripcion}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )


            # ============================================================
            # CARACTERÍSTICAS ANALIZADAS
            # ============================================================

            st.markdown("### 🧩 Características analizadas (11)")

            st.write(
                "El modelo utiliza las siguientes once características "
                "estructurales para evaluar cada URL:"
            )

            nombres_variables = {
                "safe_is_https":
                    "Uso de HTTPS",

                "safe_hostname_length":
                    "Longitud del dominio",

                "safe_is_domain_ip":
                    "Dominio expresado como IP",

                "safe_hostname_dots":
                    "Puntos en el dominio",

                "safe_no_subdomains":
                    "Número de subdominios",

                "safe_hostname_digit_ratio":
                    "Proporción de números en el dominio",

                "safe_hostname_hyphens":
                    "Guiones en el dominio",

                "safe_has_punycode":
                    "Presencia de Punycode",

                "safe_path_digit_ratio":
                    "Proporción de números en la ruta",

                "safe_percent_encoded_count":
                    "Caracteres codificados",

                "safe_percent_encoded_ratio":
                    "Proporción de caracteres codificados"
            }

            chips = ""

            for variable in variables_modelo:

                nombre = nombres_variables.get(
                    variable,
                    variable
                )

                chips += (
                    f'<span class="feature-chip">'
                    f'{nombre}'
                    f'</span>'
                )

            st.markdown(
                chips,
                unsafe_allow_html=True
            )


            # ============================================================
            # DETALLE TÉCNICO
            # ============================================================

            with st.expander(
                "⚙️ Ver detalles técnicos del análisis"
            ):

                datos_detalle = []

                for variable in variables_modelo:

                    valor = caracteristicas[
                        variable
                    ]

                    if variable in [
                        "safe_hostname_digit_ratio",
                        "safe_path_digit_ratio",
                        "safe_percent_encoded_ratio"
                    ]:

                        valor_mostrar = f"{valor * 100:.2f}%"

                    elif variable in [
                        "safe_is_https",
                        "safe_is_domain_ip",
                        "safe_has_punycode"
                    ]:

                        valor_mostrar = (
                            "Sí"
                            if valor == 1
                            else "No"
                        )

                    else:

                        valor_mostrar = valor

                    datos_detalle.append(
                        {
                            "Característica":
                                nombres_variables.get(
                                    variable,
                                    variable
                                ),

                            "Variable técnica":
                                variable,

                            "Valor observado":
                                valor_mostrar
                        }
                    )

                df_detalle = pd.DataFrame(
                    datos_detalle
                )

                st.dataframe(
                    df_detalle,
                    use_container_width=True,
                    hide_index=True
                )

                st.caption(
                    "Estas características no deben interpretarse de manera "
                    "individual como evidencia de fraude. SAFE analiza su "
                    "combinación mediante el modelo para calcular el Risk Score."
                )


            # ============================================================
            # SIGNIFICADO DEL RISK SCORE
            # ============================================================

            with st.expander(
                "ℹ️ ¿Qué significa el SAFE Risk Score?"
            ):

                st.markdown(
                    """
                    **🟢 0 a menos de 30 · Riesgo estructural bajo**

                    La estructura de la URL presenta una baja similitud con
                    los patrones asociados con URLs de mayor riesgo aprendidos
                    por el modelo.

                    **🟡 30 a menos de 70 · Riesgo estructural medio**

                    La URL presenta una combinación de características que
                    justifica realizar verificaciones adicionales.

                    **🔴 70 a 100 · Riesgo estructural alto**

                    La estructura de la URL presenta una mayor similitud con
                    patrones asociados con URLs de riesgo identificados durante
                    el entrenamiento.

                    El SAFE Risk Score debe entenderse como una señal de apoyo
                    para la evaluación preliminar. No constituye una confirmación
                    definitiva de que una página sea legítima o fraudulenta.
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

st.markdown(
    """
    <div class="footer">
        SAFE URL Scan · Smart AI Fraud Evaluation<br>
        Prototipo académico para evaluación preliminar del riesgo
        estructural de URLs.
    </div>
    """,
    unsafe_allow_html=True
)
            
