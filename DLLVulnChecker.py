#!/usr/bin/env python3

import requests
import re
import time
from datetime import datetime
import sys, signal
import os

#Clase Vulnerabilidad

class Vulnerabilidad:
        def __init__(self, nombre="", criticidad="", componente="", versiones="", descarga="", fecha_publicacion=""):
                self._nombre = nombre
                self._criticidad = criticidad
                self._componente = componente
                self._versiones = versiones
                self._descarga = descarga
                self._fecha_publicacion = fecha_publicacion

        def get_nombre(self):
                return self._nombre

        def get_criticidad(self):
                return self._criticidad

        def get_componente(self):
                return self._componente

        def get_versiones(self):
                return self._versiones

        def get_descarga(self):
                return self._descarga

        def get_fecha(self):
                return self._fecha_publicacion

        def set_nombre(self, nombre):
                self._nombre = nombre

        def set_criticidad(self, criticidad):
                self._criticidad = criticidad

        def set_componente(self, componente):
                self._componente = componente

        def set_versiones(self, versiones):
                self._versiones = versiones

        def set_descarga(self, descarga):
                self._descarga = descarga

        def set_fecha(self, fecha_publicacion):
                self._fecha_publicacion = fecha_publicacion



#Colores

RED_DARK = '\033[38;5;1m'
RED = '\033[91m'
ORANGE = '\033[38;5;208m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

#Variables globales

url = 'https://security.snyk.io/vuln?search='

banner = """
██▄   █    █             ▄     ▄   █        ▄          ▄▄▄▄▄   ▄███▄   ██   █▄▄▄▄ ▄█▄     ▄  █ ▄███▄   █▄▄▄▄
█  █  █    █              █     █  █         █        █     ▀▄ █▀   ▀  █ █  █  ▄▀ █▀ ▀▄  █   █ █▀   ▀  █  ▄▀
█   █ █    █         █     █ █   █ █     ██   █     ▄  ▀▀▀▀▄   ██▄▄    █▄▄█ █▀▀▌  █   ▀  ██▀▀█ ██▄▄    █▀▀▌
█  █  ███▄ ███▄       █    █ █   █ ███▄  █ █  █      ▀▄▄▄▄▀    █▄   ▄▀ █  █ █  █  █▄  ▄▀ █   █ █▄   ▄▀ █  █
███▀      ▀    ▀       █  █  █▄ ▄█     ▀ █  █ █                ▀███▀      █   █   ▀███▀     █  ▀███▀     █
                        █▐    ▀▀▀        █   ██                          █   ▀             ▀            ▀
                        ▐                                               ▀
"""

#Funcion para imprimir usando colores sin que se vuelva loca la consola despues
#       Por eso hay que meterle el RESET
def print_colores(text, color):
        print(f"{color}{text}{RESET}")

#Ctrl+C

def signal_handler(sig, frame):
        print_colores("\n\n[!] Saliendo...", RED)
        sys.exit(1)

#Funcion que ordena las vulnerabilidades de mas reciente a menos
def ordenar_vulns_fecha(vulnerabilidades):

    def obtener_fecha_datetime(vuln):
        return datetime.strptime(vuln.get_fecha(), "%d %b %Y")

    vulnerabilidades_ordenadas = sorted(vulnerabilidades, key=obtener_fecha_datetime, reverse=True)

    return vulnerabilidades_ordenadas

#Funcion que aplica la regex a la respuesta de la peticion para sacar solamente las criticidades de las vulnerabilidades encontradas
def criticidades(peticion):
        regexCrit = re.compile(r'(?<=data-v-87993300>).*?(?=<)', re.DOTALL)

        crits = regexCrit.findall(peticion)

        filtered_matches = [
                match.strip() for match in crits
                if match.strip() and not re.fullmatch(r'<!---->', match.strip())
        ]

        return filtered_matches

#Funcion que crea la lista de objetos vulnerabilidad y la devuelve por parametro
def formatear_respuesta(datos, criticidades):

        i = 0
        j = 0

        vulns = []

        crits = {
                'C': 'Critica',
                'H': 'Alta',
                'M': 'Media',
                'L': 'Baja'
        }

        if(len(datos) % 5 == 0):
                while i < len(datos):

                        vulnerabilidad = Vulnerabilidad()

                        vulnerabilidad.set_nombre(str(datos[i].strip()))
                        vulnerabilidad.set_criticidad(str(crits[str(criticidades[j])]))
                        vulnerabilidad.set_componente(str(datos[i+1].strip()))
                        vulnerabilidad.set_versiones(str(datos[i+2].strip()))
                        vulnerabilidad.set_descarga(str(datos[i+3].strip()))
                        vulnerabilidad.set_fecha(str(datos[i+4].strip()))

                        vulns.append(vulnerabilidad)
                        i += 5
                        j += 1

        else:
                while i < len(datos):

                        vulnerabilidad = Vulnerabilidad()
                        masV = 0

                        vulnerabilidad.set_nombre(str(datos[i].strip()))
                        vulnerabilidad.set_criticidad(str(crits[str(criticidades[j])]))
                        vulnerabilidad.set_componente(str(datos[i+1].strip()))

                        versiones = ''

                        if(datos[i+3].strip().startswith('(') or datos[i+3].strip().startswith('[')):
                                while(datos[i+2+masV].strip().startswith('(') or datos[i+2+masV].strip().startswith('[')):
                                        if not versiones:
                                                versiones = datos[i+2+masV].strip()
                                                masV += 1
                                        else:
                                                versiones += ', ' + datos[i+2+masV].strip()
                                                masV += 1

                                vulnerabilidad.set_versiones(versiones)

                                vulnerabilidad.set_descarga(str(datos[i+2+masV].strip()))
                                vulnerabilidad.set_fecha(str(datos[i+3+masV].strip()))

                                vulns.append(vulnerabilidad)

                                i += (4+masV)
                                j += 1
                        else:

                                vulnerabilidad.set_descarga(str(datos[i+3].strip()))
                                vulnerabilidad.set_fecha(str(datos[i+4].strip()))

                                vulns.append(vulnerabilidad)
                                i += 5
                                j += 1
        return vulns

#Funcion que hace la peticion y luego recibe la lista y la imprime
def hacer_peticion():
        try:
                while True:
                        nombre_archivo = input("Introduce el nombre de donde se van a importar los datos (unicamente extension .txt): ")
                        if(nombre_archivo.lower().endswith('.txt')):
                                if(os.path.isfile(nombre_archivo)):
                                        break
                                else:
                                        print_colores("\n[!] No se encuentra el archivo, introduce uno valido", ORANGE)
                        else:
                                print_colores("\n[!] La extension del archivo no coincide con la esperada:", ORANGE)

                with open(nombre_archivo, 'r') as f:
                        for linea in f:
                                urlFinal = url + linea

                                respuesta = requests.get(urlFinal)
                                contenido = respuesta.text.splitlines()

                                crit = criticidades(respuesta.text)

                                regex = re.compile(r'<\!---|<\/span|<\/body|<\/html|Snyk|Disclosed|Policies|Sell|Report|Next')

                                filtrado1 = [linea for linea in contenido if not regex.search(linea)]

                                filtrado2 = next((i for i, linea in enumerate(filtrado1) if 'PUBLISHED' in linea), None)

                                if filtrado2 is not None:
                                        contenido_relevante = filtrado1[filtrado2 + 1:filtrado2 + 1001]
                                else:
                                        contenido_relevante = []

                                contenido_final = [linea for linea in contenido_relevante if 'PUBLISHED' not in linea]
                                contenido_final = [linea.replace('&lt;', '<') for linea in contenido_final]

                                respuesta_formateada = formatear_respuesta(contenido_final, crit)
                                print(f"\t\t{linea}")

                                ordenada = ordenar_vulns_fecha(respuesta_formateada)

                                for vuln in ordenada:
                                        if((datetime.now().year-3) >= datetime.strptime(vuln.get_fecha(), "%d %b %Y").year):
                                                continue
                                        if(vuln.get_criticidad()=='Critica'):
                                                print_colores("Nombre de la vulnerabilidad: " + vuln.get_nombre(), RED_DARK)
                                                print_colores(f"\tCriticidad: " + vuln.get_criticidad(), RED_DARK)
                                                print_colores(f"\tComponente afectado: " + vuln.get_componente(), RED_DARK)
                                                print_colores(f"\tVersiones afectadas: " + vuln.get_versiones(), RED_DARK)
                                                print_colores(f"\tDescarga: " + vuln.get_descarga(), RED_DARK)
                                                print_colores(f"\tFecha de publicacion: " + vuln.get_fecha(), RED_DARK)
                                        elif(vuln.get_criticidad()=='Alta'):
                                                print_colores("Nombre de la vulnerabilidad: " + vuln.get_nombre(), RED)
                                                print_colores(f"\tCriticidad: " + vuln.get_criticidad(), RED)
                                                print_colores(f"\tComponente afectado: " + vuln.get_componente(), RED)
                                                print_colores(f"\tVersiones afectadas: " + vuln.get_versiones(), RED)
                                                print_colores(f"\tDescarga: " + vuln.get_descarga(), RED)
                                                print_colores(f"\tFecha de publicacion: " + vuln.get_fecha(), RED)
                                        elif(vuln.get_criticidad()=='Media'):
                                                print_colores("Nombre de la vulnerabilidad: " + vuln.get_nombre(), ORANGE)
                                                print_colores(f"\tCriticidad: " + vuln.get_criticidad(), ORANGE)
                                                print_colores(f"\tComponente afectado: " + vuln.get_componente(), ORANGE)
                                                print_colores(f"\tVersiones afectadas: " + vuln.get_versiones(), ORANGE)
                                                print_colores(f"\tDescarga: " + vuln.get_descarga(), ORANGE)
                                                print_colores(f"\tFecha de publicacion: " + vuln.get_fecha(), ORANGE)
                                        elif(vuln.get_criticidad()=='Baja'):
                                                print_colores("Nombre de la vulnerabilidad: " + vuln.get_nombre(), YELLOW)
                                                print_colores(f"\tCriticidad: " + vuln.get_criticidad(), YELLOW)
                                                print_colores(f"\tComponente afectado: " + vuln.get_componente(), YELLOW)
                                                print_colores(f"\tVersiones afectadas: " + vuln.get_versiones(), YELLOW)
                                                print_colores(f"\tDescarga: " + vuln.get_descarga(), YELLOW)
                                                print_colores(f"\tFecha de publicacion: " + vuln.get_fecha(), YELLOW)
                                print("\n")

        except FileNotFoundError:
                return "Error: El fichero no existe."
        except IOError:
                return "Error: No se puede leer."

#Main funtion
if __name__ == "__main__":
        signal.signal(signal.SIGINT, signal_handler)

        print(banner)
        print("Herramienta hecha con muxo amor por m4t1. <3\n")
        time.sleep(3)
        hacer_peticion()
