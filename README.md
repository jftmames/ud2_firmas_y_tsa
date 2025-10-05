# UD2 — Firmas digitales y sellado de tiempo (Streamlit)

App didáctica autónoma para la asignatura **Blockchain: fundamentos técnicos y problemática jurídica**.

Incluye:
- Teoría (PKI, X.509, TSA/RFC 3161)
- Analizador de certificados **X.509** (PEM/DER y bundle **PKCS#7** `.p7b/.p7s`)
- Analizador de **sello de tiempo**: carga `.tsr/.tsp` (RFC 3161) o `.p7s` con TST y compara el *message imprint* contra el documento
- Autoevaluación y glosario

## Ejecutar localmente
1) Python 3.10+  
2) `pip install -r requirements.txt`  
3) `streamlit run app.py`

## Despliegue (sin terminal)
- **Streamlit Community Cloud** → New app → sube esta carpeta (o conéctala a GitHub) → elige `app.py` → Deploy.

> Aviso docente: la herramienta **no** valida cadena de confianza ni revocación. Es material pedagógico, no asesoramiento jurídico.
