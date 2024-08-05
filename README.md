# 🚀 DLL Vuln Searcher 🛡️

Bienvenido a **DLL Vuln Searcher**, un script de Python que utiliza técnicas de web scraping para buscar vulnerabilidades en las dependencias de diferentes vendors desde la web de [security.snyk.io](https://security.snyk.io).

## 🌟 Características

- **Web Scraping**: Utiliza web scraping para extraer información detallada sobre vulnerabilidades.
- **Soporte para Múltiples Vendors**: Diseñado para buscar vulnerabilidades en dependencias de diversos vendors, incluyendo NuGet.
- **Entrada Flexible**: Lee las dependencias desde un archivo de texto proporcionado por el usuario.

## 🚀 Cómo Empezar

### 1. Requisitos Previos

- Python 3.x instalado en tu máquina.
- Las siguientes librerías de Python:
  - `requests`
  - `re`
  - `time`
  - `datetime`
  - 

Puedes instalarlas usando pip:

```bash
pip install requests re time datetime
```

### 2. Uso del Script

1. **Prepara tu Archivo de Dependencias**:
   - Crea un archivo `.txt` que contenga las dependencias que deseas verificar, cada una en una línea diferente. Ejemplo:
     ```
     Newtonsoft.Json
     NUnit
     ```

2. **Ejecuta el Script**:
   - Al ejecutar el script, te pedirá que ingreses el nombre del archivo de texto que contiene las dependencias.
   
   ```bash
   python3 DLLVulnSearcher.py
   ```

3. **Proporciona el Nombre del Archivo**:
   - Ingresa el nombre del archivo de texto cuando el script lo solicite. Asegúrate de que el archivo esté en el mismo directorio que el script o proporciona la ruta completa.

### 3. Ejemplo de Ejecución

```plaintext
Ingrese el nombre del archivo de dependencias: example.txt

		RazorEngine

Nombre de la vulnerabilidad: Arbitrary Code Execution
	Criticidad: Alta
	Componente afectado: razorengine
	Versiones afectadas: [0,]
	Descarga: NuGet
	Fecha de publicacion: 6 Mar 2022


		Microsoft.Owin

Nombre de la vulnerabilidad: Denial of Service (DoS)
	Criticidad: Alta
	Componente afectado: microsoft.owin
	Versiones afectadas: [,4.2.2)
	Descarga: NuGet
	Fecha de publicacion: 31 Aug 2022
Nombre de la vulnerabilidad: Denial of Service (DoS)
	Criticidad: Alta
	Componente afectado: microsoft.owin.security.cookies
	Versiones afectadas: [,4.2.2)
	Descarga: NuGet
	Fecha de publicacion: 31 Aug 2022

```

## 🔧 Personalización

Puedes modificar el script para ajustar los vendors o la forma en que se manejan las dependencias. Este es solo un punto de partida, y las posibilidades son infinitas.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Puedes obtener más detalles en el archivo LICENSE.

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si tienes alguna mejora o sugerencia, por favor abre un issue o crea un pull request.

## 📬 Contacto

Para cualquier consulta, no dudes en contactarme a través de mi perfil de GitHub.

---

¡Gracias por usar **DLL Vuln Searcher**! Juntos, hagamos que nuestras dependencias sean más seguras. 🛡️

---

Hecho con ❤️ por m4t1
---

**Nota**: Este proyecto no está afiliado ni respaldado por Snyk. Es una herramienta creada independientemente para ayudar en la búsqueda de vulnerabilidades.
