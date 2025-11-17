import os
import shutil
import sys

def copiar_fase(source_dir, target_dir, phase_name):
    """Copia todos los archivos de una fase específica"""
    source_path = os.path.join(source_dir, phase_name)
    target_path = os.path.join(target_dir, phase_name)

    print(f"Copiando fase: {phase_name}")

    # Crear directorio si no existe
    os.makedirs(target_path, exist_ok=True)

    # Copiar archivos si el directorio origen existe
    if os.path.exists(source_path):
        try:
            for item in os.listdir(source_path):
                source_item = os.path.join(source_path, item)
                target_item = os.path.join(target_path, item)

                if os.path.isdir(source_item):
                    shutil.copytree(source_item, target_item, dirs_exist_ok=True)
                    print(f"      OK {item}/")
                else:
                    shutil.copy2(source_item, target_item)
                    print(f"      OK {item}")
        except Exception as e:
            print(f"      ERROR: {e}")
    else:
        print(f"      No existe: {source_path}")

    print()

def main():
    # Rutas absolutas
    source_root = "C:/Users/FUENTES/OneDrive/Desktop/WSTG GITHUB/wstg/checklists/testing_frameworks"
    target_root = "C:/Users/FUENTES/OneDrive/Desktop/OWASP/owasp-wstg-framework"

    # Asegurar directorio destino
    os.makedirs(target_root, exist_ok=True)

    # Fases del WSTG
    fases = [
        "01-Information_Gathering",
        "02-Configuration_and_Deployment_Management",
        "03-Identity_Management",
        "04-Authentication_Testing",
        "05-Authorization_Testing",
        "06-Session_Management",
        "07-Input_Validation",
        "08-Error_Handling",
        "09-Cryptography",
        "10-Business_Logic",
        "11-Client_Side",
        "12-API_Testing",
        "core"
    ]

    print("Copiando WSTG Framework completo...")

    # Copiar cada fase
    for fase in fases:
        copiar_fase(source_root, target_root, fase)

    # Copiar archivos principales
    archivos_principales = [
        "wstg_framework.py",
        "complete_wstg_framework.py",
        "setup_kali.sh",
        "requirements.txt",
        "README.md",
        ".gitignore",
        "LICENSE"
    ]

    print("Copiando archivos principales...")
    for archivo in archivos_principales:
        source_file = os.path.join(source_root, archivo)
        if os.path.exists(source_file):
            try:
                shutil.copy2(source_file, os.path.join(target_root, archivo))
                print(f"      OK {archivo}")
            except Exception as e:
                print(f"      ERROR {archivo}: {e}")
        else:
            print(f"      No encontrado: {archivo}")

    print("\nCopia completada!")
    print(f"Framework listo en: {target_root}")

if __name__ == "__main__":
    main()