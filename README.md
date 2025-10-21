# PingMapper

PingMapper escanea todas las tramas de una red privada y detecta los hosts activos en cada una. Con esta información, genera un informe en HTML que puede visualizarse fácilmente iniciando un servidor con Python:

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

## Ejemplos de uso según la sensibilidad de la red

### Redes extremadamente sensibles

- **Comando:**
  ```bash
  sudo python3 pingmapper.py --mode subnets --subnet-threads 1 --ping-timeout 2
  ```
- **Repeticiones y ritmo:** hasta 6 pings secuenciales por trama candidata (hosts 1, 254, 100, 50, 10 y 200) con un tiempo máximo de 2 s por intento, es decir, un barrido de aproximadamente 12 s por trama.

### Redes sensibles

- **Comando:**
  ```bash
  sudo python3 pingmapper.py --mode full --subnet-threads 2 --host-threads 4 --ping-timeout 1.5 --delay 1.0
  ```
- **Repeticiones y ritmo:** descubrimiento de tramas con hasta 6 pings por trama en dos hilos y exploración de hosts con un único ping por dirección, aplicando 1 s de espera entre resultados; en la práctica se generan unas 60 solicitudes por minuto repartidas entre los 4 hilos de hosts.

### Redes normales

- **Comando:**
  ```bash
  sudo python3 pingmapper.py --mode full --subnet-threads 10 --host-threads 10 --ping-timeout 1.0 --delay 0.2
  ```
- **Repeticiones y ritmo:** escaneo simultáneo de hasta 10 tramas y 10 hosts por tanda, manteniendo el retraso total en torno a 0.2 s entre pings; se alcanzan aproximadamente 300 solicitudes por minuto sin saturar redes de uso general.

### Redes buenas

- **Comando:**
  ```bash
  sudo python3 pingmapper.py --mode full --subnet-threads 30 --host-threads 20 --ping-timeout 0.7
  ```
- **Repeticiones y ritmo:** paralelismo completo tanto en la detección de tramas (30 hilos) como en el escaneo de hosts (20 hilos), enviando un único ping por host sin demoras adicionales; pueden emitirse varios cientos de solicitudes por minuto sin afectar redes robustas.
