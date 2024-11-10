#Overview
This project addresses the development of a secure vehicle-to-everything (V2X) communication system aimed at ensuring the integrity, authenticity, and confidentiality of data exchanged in connected vehicle environments. Utilizing elliptic curve cryptography (ECC) and advanced encryption mechanisms, this system helps secure data transmission between vehicles, infrastructure, and other V2X entities, which is crucial for intelligent transportation systems and autonomous driving.

#Key Features
Elliptic Curve Cryptography (ECC) for efficient and secure public key management.
Symmetric Key Encryption through AES-GCM for fast, secure data exchange.
Digital Signatures with ECDSA for message authentication.
Optimized Communication Protocols to minimize latency and computational load.
#Project Structure
System Design: Functional block diagrams and detailed designs outline the communication flow and security architecture.
Implementation: Built on Raspberry Pi with NodeMCU ESP8266 modules and MPU6050 sensors for motion tracking. Data transmission is securely handled over a WLAN.
Optimization: Reduces message size and latency by eliminating redundant certificate exchanges after initial trust establishment.
Security Protocols: Initialization vectors, authentication tags, and certificate-based key exchanges establish a reliable V2X communication environment.
#Results
The project successfully establishes secure, real-time data communication across V2X nodes, verified through time and memory profiling.
Optimized packet size leads to significant performance improvements, enabling real-time operation in constrained environments.
#Future Scope
Integration with quantum-resistant encryption for long-term security.
Extension to support seamless interaction with smart city infrastructure and autonomous vehicles.
#Alignment with SDG
Contributes to Sustainable Development Goal 11.2 by enhancing the safety and efficiency of urban and rural transport networks.
