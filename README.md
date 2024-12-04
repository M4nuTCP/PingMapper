# PingMapper

**PingMapper** realiza un escaneo sistemático de subredes privadas comunes para detectar dispositivos activos. También genera un informe detallado en formato HTML con un diseño visual que incluye:

- Tramas de red detectadas.
- Hosts encontrados en cada trama.
- Gráficos de representación (número de hosts y porcentaje).

## ¿Cómo funciona?

1. **Escaneo de subredes**: 
   La herramienta escanea las subredes privadas más comunes (10.0.0.0/8, 172.16.0.0/12 y 192.168.0.0/16).
   
2. **Detección de hosts activos**:
   Envía pings a cada IP dentro de las subredes para identificar dispositivos activos.

3. **Generación de informe**:
   Al finalizar el escaneo, se genera un archivo HTML que contiene:
   - Tramas de red activas detectadas.
   - Hosts activos en cada trama.
   - Gráficos para visualizar la cantidad y proporción de hosts.

El informe es visualmente atractivo y organizado para facilitar el análisis.

![Captura de pantalla 2024-12-04 174647](https://github.com/user-attachments/assets/7191b565-8eb9-4834-88ba-a31a99bd73bb)

![Captura de pantalla 2024-12-04 174735](https://github.com/user-attachments/assets/825da324-8cdd-4f3f-88ac-685386d22d76)

![Captura de pantalla 2024-12-04 182939](https://github.com/user-attachments/assets/b525cc3f-5c9a-4c3c-88d4-04fa9c34eec1)

## Instalación

  ```bash
  git clone https://github.com/M4nuTCP/PingMapper.git
  cd PingMapper
  pip3 install -r requirements.txt
  sudo python3 pingmapper.py
  ```
