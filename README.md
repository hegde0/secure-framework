# Securing V2X Communication

## Overview
This project focuses on the development of a secure vehicle-to-everything (V2X) communication system, aimed at ensuring data integrity, authenticity, and confidentiality within connected vehicle environments. By utilizing Elliptic Curve Cryptography (ECC) and advanced encryption mechanisms, this system secures data transmission between vehicles, infrastructure, and other V2X entities, supporting intelligent transportation systems and autonomous driving.

## Key Features
- **Elliptic Curve Cryptography (ECC)**: Provides efficient and secure public key management.
- **Symmetric Key Encryption**: AES-GCM is used for fast, secure data exchange.
- **Digital Signatures**: ECDSA for message authentication ensures data authenticity.
- **Optimized Communication Protocols**: Reduces latency and computational load, suitable for real-time V2X environments.

## Project Structure
- **System Design**: Contains functional block diagrams and detailed designs outlining the communication flow and security architecture.
- **Implementation**: Built on Raspberry Pi with NodeMCU ESP8266 modules and MPU6050 sensors for motion tracking. Data transmission is secured over a WLAN.
- **Optimization**: Minimizes message size and latency by removing redundant certificate exchanges after the initial trust establishment.
- **Security Protocols**: Uses initialization vectors, authentication tags, and certificate-based key exchanges to establish a reliable V2X communication environment.

## Results
- The project achieves secure, real-time data communication across V2X nodes, verified through time and memory profiling.
- Optimized packet size significantly improves performance, enabling real-time operation even in resource-constrained environments.

## Future Scope
- **Quantum-resistant encryption** for future-proof security.
- **Integration with smart city infrastructure** and autonomous vehicles to expand the system’s reach and capabilities.

## Alignment with SDG
This project contributes to **Sustainable Development Goal 11.2** by enhancing the safety and efficiency of urban and rural transportation networks.

