# -*- coding: utf-8 -*-
"""
UD2 — Firmas digitales y sellado de tiempo (Streamlit)
Incluye:
 - Analizador X.509 (cert individual y bundle PKCS#7)
 - Analizador de sello de tiempo (RFC 3161 / PKCS#7)
 - Validación didáctica por Policy OID + EKU timeStamping
 - Parche de parsing PKCS#7 tolerante a BER con asn1crypto (sin warnings)
"""
import io
import binascii
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd
import streamlit as st

# X.509 y PKCS#7 (extractor de certificados de bundles .p7b/.p7s)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID as EKUOID

# RFC 3161 (TSR/TST) y CMS con asn1crypto
from asn1crypto import tsp, cms, x509 as a_x509, pem  # añadimos pem para detectar PEM

# ================= Configuración =================
st.set_page_config(
    page_title="UD2 — Firmas digitales y sellado de tiempo",
    page_icon="🔐",
    layout="wide"
)

# ================= Utilidades =================
def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def dt_iso_utc(dt) -> str:
    """Convierte cualquier datetime a ISO-8601 en UTC (tolerando naive/aware)."""
    try:
        if getattr(dt, "tzinfo", None) is None:
            return dt.replace(tzinfo=timezone.utc).isoformat()
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(dt)

def cert_validity_iso(cert: x509.Certificate) -> Tuple[str, str]:
    """
    Devuelve (not_before_iso, not_after_iso) en UTC con compatibilidad
    entre cryptography >=42 (propiedades *_utc) y <42 (naive).
    """
    try:
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
    except AttributeError:
        # Fallback para versiones antiguas: pueden devolver naive
        nvb = getattr(cert, "not_valid_before", None)
        nva = getattr(cert, "not_valid_after", None)
        if nvb is not None and nvb.tzinfo is None:
            nvb = nvb.replace(tzinfo=timezone.utc)
        if nva is not None and nva.tzinfo is None:
            nva = nva.replace(tzinfo=timezone.utc)
    return (
        nvb.isoformat() if nvb is not None else "—",
        nva.isoformat() if nva is not None else "—",
    )

def _try_load_x509_cert(cert_bytes: bytes) -> Optional[x509.Certificate]:
    """Carga un certificado X.509 desde PEM o DER."""
    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(cert_bytes)
    except Exception:
        return None

def _name_to_dict(name: x509.Name) -> Dict[str, str]:
    """Convierte un x509.Name en dict legible."""
    out: Dict[str, str] = {}
    for rdn in name.rdns:
        for attr in rdn:
            out[attr.oid._name or attr.oid.dotted_string] = attr.value
    return out

def _bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def _safe_get_native(asn1_obj, path: List[str], default=None):
    """Acceso seguro a rutas en estructuras ASN.1 de asn1crypto."""
    try:
        cur = asn1_obj
        for p in path:
            cur = cur[p]
        return getattr(cur, "native", cur)
    except Exception:
        return default

def _asn1_certs_to_cryptography_list(certs_seq) -> List[x509.Certificate]:
    """
    Convierte una secuencia asn1crypto de CertificateChoices a objetos cryptography.x509.Certificate.
    Ignora entradas que no sean 'certificate'.
    """
    out: List[x509.Certificate] = []
    if certs_seq is None:
        return out
    try:
        for c in certs_seq:
            if c.name == "certificate":
                der = c.chosen.dump()
                out.append(x509.load_der_x509_certificate(der))
    except Exception:
        pass
    return out

def _has_eku_time_stamping(pycert: x509.Certificate) -> bool:
    """Devuelve True si el certificado tiene EKU timeStamping (1.3.6.1.5.5.7.3.8)."""
    try:
        eku = pycert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        for oid in eku:
            if oid.dotted_string == EKUOID.TIME_STAMPING.dotted_string:
                return True
    except Exception:
        return False
    return False

# --------- Parche PKCS#7 tolerante a BER (evita el warning de cryptography) ---------
def _pkcs7_extract_certs_asn1(p7_bytes: bytes) -> List[x509.Certificate]:
    """
    Lee un PKCS#7 (.p7b/.p7s) en BER o DER con asn1crypto (tolerante),
    extrae certificados como DER y los carga con cryptography.x509.
    """
    certs: List[x509.Certificate] = []
    try:
        # Si viene en PEM, lo pasamos a DER
        if pem.detect(p7_bytes):
            _type, _headers, der = pem.unarmor(p7_bytes)
        else:
            der = p7_bytes

        ci = cms.ContentInfo.load(der)  # asn1crypto soporta BER/DER
        if ci["content_type"].native != "signed_data":
            return []

        sd = ci["content"]
        cert_seq = sd["certificates"]
        if cert_seq is None:
            return []

        for c in cert_seq:
            if c.name == "certificate":
                der_cert = c.chosen.dump()  # DER limpio
                certs.append(x509.load_der_x509_certificate(der_cert))
    except Exception:
        return []
    return certs

def _try_load_pkcs7_bundle(bundle_bytes: bytes) -> List[x509.Certificate]:
    """
    Intenta extraer certificados de un PKCS#7 (BER/DER/PEM).
    1) asn1crypto (BER/DER, sin warnings)
    2) cryptography pkcs7 DER
    3) cryptography pkcs7 PEM
    """
    # Paso 1: asn1crypto (preferido; evita el warning)
    certs = _pkcs7_extract_certs_asn1(bundle_bytes)
    if certs:
        return certs

    # Paso 2–3: fallbacks clásicos
    try:
        certs = pkcs7.load_der_pkcs7_certificates(bundle_bytes)
        if certs:
            return certs
    except Exception:
        pass
    try:
        certs = pkcs7.load_pem_pkcs7_certificates(bundle_bytes)
        return certs or []
    except Exception:
        return []

# ================= Contenido didáctico =================
st.title("UD2 — Firmas digitales y sellado de tiempo")
st.caption("Certificado digital, clave pública, PKI · Lecturas: ETSI EN 319 411-1; AEPD (2018) · Actividad: análisis de firma X.509")

tabs = st.tabs([
    "📚 Teoría guiada",
    "📖 Lecturas y normativa",
    "🧪 Analizador X.509",
    "⏱️ Analizador de sello de tiempo (TSR/PKCS#7)",
    "✅ Autoevaluación",
    "📦 Descargas & Glosario"
])

# --------- Teoría ---------
with tabs[0]:
    c1, c2 = st.columns([1.2, 1])
    with c1:
        st.subheader("Objetivos de la unidad")
        st.write(
            "- Entender la **PKI**: CA, RA, políticas e identificadores.\n"
            "- Leer un certificado **X.509**: Sujeto, Emisor, **KeyUsage**, **EKU**, **SAN**, **BasicConstraints**, AIA/CRL.\n"
            "- Comprender **RFC 3161**: sello de tiempo (TSA), *message imprint*, *genTime*, política.\n"
            "- Aterrizarlo en el uso jurídico: firma, sellado, custodia y verificación."
        )

        st.subheader("Mapa de conceptos (rápido)")
        df = pd.DataFrame({
            "Concepto": [
                "Certificado X.509",
                "Clave pública/privada",
                "Key Usage / EKU",
                "SAN (Subject Alt Name)",
                "AIA/CRL/OCSP",
                "TSA (RFC 3161)",
                "Imprint (hash)",
            ],
            "¿Para qué sirve?": [
                "Vincula identidad ↔ clave pública bajo una CA.",
                "Cifrado, firma, intercambio de claves.",
                "Restringe usos (firma, cifrado, OCSP, etc.).",
                "Aliases/dominios/UID del sujeto.",
                "Puntos de información del emisor y revocación.",
                "Datación electrónica con evidencia firmada.",
                "Huella del dato que se sella/firmó."
            ]
        })
        st.dataframe(df, width="stretch")
    with c2:
        st.info(
            "La firma X.509 prueba **integridad + autoría criptográfica**; el sello de tiempo prueba **existencia en un momento**. "
            "La validez jurídica depende de políticas, **PSC/TSA cualificados** y contexto normativo."
        )

# --------- Lecturas ---------
with tabs[1]:
    st.subheader("Lecturas recomendadas (para clase)")
    st.markdown("""
- **ETSI EN 319 411-1** (resumen técnico): requisitos para la emisión de certificados de confianza.
- **AEPD (2018)**: *Sellado de tiempo y custodia digital*.
- **Reglamento eIDAS** y **Ley 6/2020**: marco legal de firmas/sellos cualificados.
    """)
    st.caption("Estas referencias ayudan a separar valor técnico vs. valor jurídico y responsabilidades del prestador.")

# --------- Analizador X.509 ---------
with tabs[2]:
    st.subheader("Analizador de certificados X.509")
    st.caption("Sube un certificado `.cer/.crt/.pem/.der` o un bundle `.p7b` (PKCS#7). No se valida cadena ni revocación.")

    left, right = st.columns([1.1, 1])
    with left:
        cert_file = st.file_uploader("Certificado individual (.cer/.crt/.pem/.der)", type=["cer", "crt", "pem", "der"], key="x509_single")
        bundle_file = st.file_uploader("Bundle PKCS#7 (.p7b/.p7s) — opcional", type=["p7b", "p7s"], key="x509_bundle")

    with right:
        st.markdown("**Huella de archivo (si subes un certificado individual):**")
        if cert_file:
            b = cert_file.read()
            st.code(f"SHA-256 (archivo): {sha256_hex(b)}", language="text")

    # Cert individual
    if cert_file:
        cert = _try_load_x509_cert(b)
        if cert is None:
            st.error("No se pudo cargar el certificado. ¿Es un PEM/DER válido?")
        else:
            st.markdown("### Metadatos principales")
            colA, colB = st.columns(2)
            with colA:
                st.write("**Sujeto (Subject)**")
                st.json(_name_to_dict(cert.subject), expanded=False)
                st.write("**Emisor (Issuer)**")
                st.json(_name_to_dict(cert.issuer), expanded=False)
                st.write("**Número de serie**")
                st.code(hex(cert.serial_number), language="text")

            with colB:
                st.write("**Validez (UTC)**")
                nb_iso, na_iso = cert_validity_iso(cert)
                st.json({
                    "not_before_utc": nb_iso,
                    "not_after_utc":  na_iso
                }, expanded=False)
                st.write("**Algoritmo de firma**")
                try:
                    algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "—"
                except Exception:
                    algo = "—"
                st.code(algo, language="text")
                st.write("**Huellas del certificado (DER)**")
                st.code(f"SHA-256: {cert.fingerprint(hashes.SHA256()).hex()}", language="text")
                st.code(f"SHA-1  : {cert.fingerprint(hashes.SHA1()).hex()}", language="text")

            st.markdown("### Clave pública")
            pub = cert.public_key()
            try:
                if hasattr(pub, "key_size"):
                    st.write(f"**Tipo/Longitud:** {pub.__class__.__name__} · {pub.key_size} bits")
                else:
                    st.write(f"**Tipo:** {pub.__class__.__name__}")
            except Exception:
                st.write("No disponible")

            # Extensiones útiles
            st.markdown("### Extensiones relevantes")
            rows = []

            def add_row(name, value):
                rows.append({"Extensión": name, "Valor": value})

            # Basic Constraints
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                add_row("BasicConstraints", f"CA={bc.ca}, path_len={bc.path_length}")
            except Exception:
                add_row("BasicConstraints", "—")

            # Key Usage
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                add_row("KeyUsage", f"digital_signature={ku.digital_signature}, key_encipherment={ku.key_encipherment}, "
                                    f"content_commitment={ku.content_commitment}, key_cert_sign={ku.key_cert_sign}, "
                                    f"crl_sign={ku.crl_sign}")
            except Exception:
                add_row("KeyUsage", "—")

            # Extended Key Usage
            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                add_row("ExtendedKeyUsage", ", ".join([oid._name or oid.dotted_string for oid in eku]))
            except Exception:
                add_row("ExtendedKeyUsage", "—")

            # Subject Alt Name
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                add_row("SubjectAltName", ", ".join([getattr(g, "value", str(g)) for g in san]))
            except Exception:
                add_row("SubjectAltName", "—")

            # AIA
            try:
                aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
                desc = []
                for ad in aia:
                    method = ad.access_method._name or ad.access_method.dotted_string
                    loc = getattr(ad.access_location, "value", str(ad.access_location))
                    desc.append(f"{method}: {loc}")
                add_row("AIA", " | ".join(desc) if desc else "—")
            except Exception:
                add_row("AIA", "—")

            # CRL Dist Points
            try:
                crl = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
                urls = []
                for dp in crl:
                    if dp.full_name:
                        urls += [getattr(g, "value", str(g)) for g in dp.full_name]
                add_row("CRL Distribution Points", ", ".join(urls) if urls else "—")
            except Exception:
                add_row("CRL Distribution Points", "—")

            df_ext = pd.DataFrame(rows)
            st.dataframe(df_ext, width="stretch")

    # Bundle PKCS#7
    if bundle_file:
        st.markdown("### Certificados incluidos en el bundle PKCS#7")
        bundle_bytes = bundle_file.read()
        certs = _try_load_pkcs7_bundle(bundle_bytes)
        if not certs:
            st.error("No se pudieron extraer certificados del bundle (¿formato correcto?).")
        else:
            data = []
            for idx, c in enumerate(certs, start=1):
                # BasicConstraints.ca puede no estar; tratamos con cuidado
                ca_flag = False
                try:
                    ca_flag = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                except Exception:
                    ca_flag = False
                nb_iso, na_iso = cert_validity_iso(c)
                data.append({
                    "idx": idx,
                    "Subject CN": _name_to_dict(c.subject).get("commonName", "—"),
                    "Issuer CN": _name_to_dict(c.issuer).get("commonName", "—"),
                    "Válido desde": nb_iso,
                    "Válido hasta": na_iso,
                    "SHA-256": c.fingerprint(hashes.SHA256()).hex()[:32] + "…",
                    "CA?": ca_flag
                })
            st.dataframe(pd.DataFrame(data), width="stretch")
            st.caption("Nota: no se valida cadena ni estado de revocación (CRL/OCSP). Es lectura didáctica.")

# --------- Analizador de sello de tiempo ---------
with tabs[3]:
    st.subheader("Analizador de sello de tiempo (RFC 3161 / PKCS#7)")
    st.caption("Sube un token `.tsr/.tsp` (RFC 3161) o un `.p7s` con TST. Puedes subir también el documento original para comprobar el imprint.")

    colL, colR = st.columns([1.05, 1])
    with colL:
        token_file = st.file_uploader("Token de sello de tiempo (.tsr/.tsp/.p7s)", type=["tsr", "tsp", "p7s"], key="tsp_token")
        src_doc = st.file_uploader("Documento original (opcional)", type=None, key="tsp_doc")
    with colR:
        st.markdown("**Acciones**")
        go = st.button("Analizar token")

    # ---- Validación opcional (docente) ----
    st.markdown("### Validación opcional (docente)")
    with st.expander("Configurar política y requisitos", expanded=False):
        wl_default = "1.2.3.4.1.2345.1"  # Ejemplo de OID demo
        wl_str = st.text_input(
            "Lista blanca de Policy OIDs (separados por comas)",
            value=wl_default,
            help="Introduce OIDs de políticas de sello que aceptas como 'válidas' a efectos didácticos."
        )
        require_eku = st.checkbox(
            "Exigir EKU timeStamping en el certificado firmante del token",
            value=True,
            help="Comprueba que el certificado firmante declara Extended Key Usage 'timeStamping' (1.3.6.1.5.5.7.3.8)."
        )
        label_qualified = st.checkbox(
            "Marcar como «cualificado (didáctico)» si política/ekus cumplen",
            value=True
        )

    def _parse_tsr(tsr_bytes: bytes) -> Dict[str, Any]:
        """Devuelve un dict con campos clave de un TimeStampResp (RFC 3161)."""
        out: Dict[str, Any] = {}
        resp = tsp.TimeStampResp.load(tsr_bytes)
        out["status"] = resp["status"]["status"].native
        out["status_string"] = _safe_get_native(resp, ["status", "status_string"], default=None)
        token = resp["time_stamp_token"]
        if token is None:
            out["error"] = "No incluye time_stamp_token"
            return out

        # token es cms.ContentInfo
        ci = cms.ContentInfo.load(token.dump())
        if ci["content_type"].native != "signed_data":
            out["error"] = "El token no es SignedData"
            return out

        sd = ci["content"]
        eci = sd["encap_content_info"]
        # TSTInfo va encapsulado como content; asn1crypto lo parsea automáticamente
        tst_info = eci["content"].parsed

        # Campos clave de TSTInfo
        mi = tst_info["message_imprint"]
        out["hash_algorithm"] = mi["hash_algorithm"]["algorithm"].native
        out["message_imprint"] = _bytes_to_hex(mi["hashed_message"].native)
        gen_time = _safe_get_native(tst_info, ["gen_time"])
        out["gen_time_utc"] = dt_iso_utc(gen_time) if gen_time else "—"
        out["serial_number"] = tst_info["serial_number"].native
        out["policy_oid"] = tst_info["policy"].dotted
        out["ordering"] = _safe_get_native(tst_info, ["ordering"], False)
        out["nonce"] = _safe_get_native(tst_info, ["nonce"])
        # Nombre de la TSA (si está)
        tsa_gn = _safe_get_native(tst_info, ["tsa"])
        out["tsa_name"] = str(tsa_gn) if tsa_gn is not None else "—"

        # Certificados del SignedData (si están embebidos)
        certs_seq = _safe_get_native(sd, ["certificates"], None)
        out["signer_subjects"] = []
        out["embedded_certs_count"] = 0
        out["eku_time_stamping_present"] = None

        try:
            # Extrae 'subject' legible con asn1crypto
            if certs_seq is not None:
                for c in sd["certificates"]:
                    if c.name == "certificate":
                        out["signer_subjects"].append(c.chosen.subject.human_friendly)
                out["embedded_certs_count"] = len(out["signer_subjects"])
        except Exception:
            pass

        # EKU check con cryptography (más simple y robusto)
        pycerts = _asn1_certs_to_cryptography_list(sd["certificates"] if "certificates" in sd.native else None)
        if pycerts:
            out["eku_time_stamping_present"] = any(_has_eku_time_stamping(pc) for pc in pycerts)

        return out

    if go:
        if not token_file:
            st.warning("Sube un token primero.")
        else:
            tb = token_file.read()
            parsed = None
            ok = False
            error = None

            # Intento 1: parsear como TimeStampResp (tsr/tsp)
            try:
                parsed = _parse_tsr(tb)
                ok = True
            except Exception as e:
                error = f"TSR parse error: {e}"

            # Intento 2: si falla, mirar si es PKCS#7 SignedData directamente
            if not ok and token_file.name.lower().endswith(".p7s"):
                try:
                    ci = cms.ContentInfo.load(tb)
                    if ci["content_type"].native == "signed_data":
                        sd = ci["content"]
                        eci = sd["encap_content_info"]
                        parsed = {"status": "granted", "note": "PKCS#7 con SignedData"}
                        if eci["content_type"].native in ("tst_info", "data"):
                            try:
                                ti = eci["content"].parsed
                                if ti.name == "TSTInfo":
                                    mi = ti["message_imprint"]
                                    parsed["hash_algorithm"] = mi["hash_algorithm"]["algorithm"].native
                                    parsed["message_imprint"] = _bytes_to_hex(mi["hashed_message"].native)
                                    g = _safe_get_native(ti, ["gen_time"])
                                    parsed["gen_time_utc"] = dt_iso_utc(g) if g else "—"
                                    parsed["policy_oid"] = ti["policy"].dotted
                            except Exception:
                                pass
                        # EKU (si el P7S trae certificados)
                        try:
                            pycerts = _asn1_certs_to_cryptography_list(sd["certificates"])
                            if pycerts:
                                parsed["eku_time_stamping_present"] = any(_has_eku_time_stamping(pc) for pc in pycerts)
                                parsed["signer_subjects"] = []
                                for c in sd["certificates"]:
                                    if c.name == "certificate":
                                        parsed.setdefault("signer_subjects", []).append(c.chosen.subject.human_friendly)
                        except Exception:
                            pass
                        ok = True
                except Exception as e:
                    error = f"PKCS#7 parse error: {e}"

            if not ok and error:
                st.error(error)
            elif parsed:
                # --- Validaciones didácticas ---
                whitelist = [o.strip() for o in wl_str.split(",") if o.strip()]
                policy_ok = None
                if "policy_oid" in parsed and parsed["policy_oid"]:
                    policy_ok = parsed["policy_oid"] in whitelist if whitelist else None

                eku_ok = parsed.get("eku_time_stamping_present", None)
                qualifies = False
                if label_qualified:
                    # Etiquetamos como "cualificado (didáctico)" si:
                    #  - la policy está en lista blanca (si se definió)
                    #  - y, si se exige, el certificado trae EKU timeStamping
                    cond_policy = (policy_ok is True) if whitelist else True  # si no hay WL, no bloquea
                    cond_eku = (eku_ok is True) if require_eku else True
                    qualifies = cond_policy and cond_eku

                st.markdown("### Resultado del token")
                st.json(parsed, expanded=False)

                # Resumen de validación (docente)
                with st.container():
                    st.markdown("### Validación (docente)")
                    cols = st.columns(3)
                    with cols[0]:
                        if whitelist:
                            if policy_ok is True:
                                st.success(f"Policy OID aceptada ✅\n\n`{parsed.get('policy_oid','—')}`")
                            elif policy_ok is False:
                                st.error(f"Policy OID fuera de lista ❌\n\n`{parsed.get('policy_oid','—')}`")
                            else:
                                st.info("Sin Policy OID o no detectable")
                        else:
                            st.caption("Sin lista blanca de políticas: no se filtra por Policy OID.")

                    with cols[1]:
                        if require_eku:
                            if eku_ok is True:
                                st.success("EKU timeStamping presente ✅")
                            elif eku_ok is False:
                                st.error("EKU timeStamping ausente ❌")
                            else:
                                st.info("No se pudo determinar EKU")
                        else:
                            st.caption("EKU no exigido.")

                    with cols[2]:
                        if label_qualified:
                            if qualifies:
                                st.success("Etiqueta: **cualificado (didáctico)** ✅")
                            else:
                                st.warning("Etiqueta: **no cualificado (didáctico)**")
                        else:
                            st.caption("Etiquetado didáctico desactivado.")

                # Verificación contra documento (si se subió)
                if src_doc and parsed.get("message_imprint"):
                    doc_bytes = src_doc.read()
                    alg = (parsed.get("hash_algorithm") or "sha256").lower()
                    # Normalizamos a los más comunes
                    if alg in ("sha256", "2.16.840.1.101.3.4.2.1"):
                        calc = hashlib.sha256(doc_bytes).hexdigest()
                    elif alg in ("sha1", "1.3.14.3.2.26"):
                        calc = hashlib.sha1(doc_bytes).hexdigest()
                    elif alg in ("sha512", "2.16.840.1.101.3.4.2.3"):
                        calc = hashlib.sha512(doc_bytes).hexdigest()
                    else:
                        calc = hashlib.sha256(doc_bytes).hexdigest()

                    st.markdown("### Verificación de imprint")
                    st.code(f"Imprint del token: {parsed['message_imprint']}", language="text")
                    st.code(f"Imprint del documento: {calc}", language="text")
                    if parsed["message_imprint"].lower() == calc.lower():
                        st.success("✅ Coincide el imprint: el token sella este documento.")
                    else:
                        st.error("❌ No coincide el imprint: el token no sella este documento.")

                st.caption(
                    "Aviso docente: no se valida cadena de confianza (CA), identidad de TSA, ni estado de revocación. "
                    "La lista blanca y el EKU son filtros **didácticos** para discutir políticas y perfiles."
                )

# --------- Autoevaluación ---------
with tabs[4]:
    st.subheader("Autoevaluación rápida")
    preguntas = [
        {
            "q": "¿Qué garantiza el sello de tiempo cualificado (RFC 3161) emitido por una TSA?",
            "opts": ["Identidad del autor", "Existencia e integridad a una hora determinada", "Capacidad jurídica", "Validez de un contrato"],
            "ok": "Existencia e integridad a una hora determinada"
        },
        {
            "q": "En un certificado X.509, ¿qué extensión indica si el certificado puede firmar otros certificados?",
            "opts": ["KeyUsage", "BasicConstraints", "ExtendedKeyUsage", "SubjectAltName"],
            "ok": "BasicConstraints"
        },
        {
            "q": "¿Qué campo relaciona el certificado con puntos de descarga de CRL u OCSP?",
            "opts": ["AIA/CRL Distribution Points", "SAN", "KeyUsage", "Policy OID"],
            "ok": "AIA/CRL Distribution Points"
        }
    ]
    aciertos = 0
    res = []
    for i, p in enumerate(preguntas, start=1):
        st.markdown(f"**{i}. {p['q']}**")
        sel = st.radio("Elige una:", p["opts"], key=f"ud2q{i}", index=0)
        res.append((sel, p["ok"]))
    if st.button("Corregir", key="ud2_corr"):
        for i, (sel, ok) in enumerate(res, start=1):
            if sel == ok:
                st.success(f"{i}) Correcto ✅")
                aciertos += 1
            else:
                st.error(f"{i}) Incorrecto ❌ → Correcta: {ok}")
        st.info(f"Puntuación: **{aciertos}/{len(preguntas)}**")

# --------- Descargas & Glosario ---------
with tabs[5]:
    st.subheader("Materiales/Descargas")
    st.markdown("""
- Exporta informes desde los propios visores (copiar/pegar resultados).
- Si dispones de un token `.tsr` y el documento sellado, aquí puedes verificar el **imprint**.
    """)

    st.subheader("Glosario breve")
    glos = pd.DataFrame({
        "Término": [
            "PKI", "X.509", "KeyUsage", "EKU", "AIA/CRL/OCSP", "TSA", "RFC 3161", "Imprint", "Policy OID"
        ],
        "Definición": [
            "Infraestructura de Clave Pública: CA/RA/políticas y dispositivos.",
            "Formato estándar de certificados digitales.",
            "Extensión que limita usos de la clave.",
            "Usos extendidos: serverAuth, emailProtection, timeStamping, etc.",
            "Servicios de información y revocación del emisor.",
            "Autoridad de Sellado de Tiempo.",
            "Especificación técnica del sellado de tiempo.",
            "Huella hash del objeto que se sella.",
            "Identificador de política aplicable al sello/certificado."
        ]
    })
    st.dataframe(glos, width="stretch")

    st.caption("Herramienta **docente**: no sustituye validaciones cualificadas, políticas de confianza ni verificaciones de revocación.")


