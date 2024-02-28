import streamlit as st
import nmap

def escanear_Puertos(IP):
    st.subheader(f"Escaneando la dirección IP: {IP}")
    st.info("Por favor, espera mientras se realiza el escaneo...")

    scanner = nmap.PortScanner()
    scanner.scan(IP, '1-1024', '-v -sS -sV -sC -A -O') # O = SO A = Agresivo C = scripts V = versiones

    st.success("Escaneo completado. Mostrando resultados:")

    for host in scanner.all_hosts():
        st.subheader(f"Resultados para {host}")
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in lport:
                st.write("   - **Puerto:**", port)
                st.write("     - **Nombre:**", scanner[host][proto][port]['name'])
                st.write("     - **Estado:**", scanner[host][proto][port]['state'])
                st.write("     - **Versión:**", scanner[host][proto][port]['version'])
                if 'product' in scanner[host][proto][port]:
                    st.write("     - **Producto:**", scanner[host][proto][port]['product'])
                if 'extrainfo' in scanner[host][proto][port]:
                    st.write("     - **Información Adicional:**", scanner[host][proto][port]['extrainfo'])

def main():
    st.title("Escáner de Puertos")
    st.image("img/BG.jpg", width=600)
    

    # Recoger la dirección IP desde el usuario
    IP = st.text_input("Por favor, introduce la dirección IP que deseas escanear (formato xxx.xxx.xxx.xxx): ")

    # Verificar si se proporcionó una dirección IP
    if not IP:
        st.warning("Por favor, introduce una dirección IP válida.")
    else:
        # Botón de escaneo
        if st.button("Escanear"):
            escanear_Puertos(IP)

if __name__ == "__main__":
    main()