# SmartWaterMeter

SmartWaterMeter is an implementation of an Advanced Metering Infrastructure. This aims to provide proper monitoring and controlling water consumption in contemporary smart water systems.

### Introduction

#### Core Concepts

Communities depend on water delivery systems as essential infrastructure because they guarantee the availability of clean water for many uses, including drinking, sanitation, and industrial use. Like its electrical counterparts, Advanced Metering Infrastructure (AMI) is essential to properly monitoring and controlling water consumption in contemporary smart water systems. The Internet of Things (IoT) is used in these smart water grids, which include data management systems, communication networks, and smart meters deployed at each customer's location.

Smart water networks are vulnerable to data integrity threats, which jeopardize the precision and dependability of usage data, just like electrical grids. Both utilities and customers are seriously at risk from these kinds of attacks. Similar to deductive assaults in electrical systems, data falsification in smart water grids frequently takes the form of water theft, when reported consumption figures are lower than the real usage. Additive attacks, on the other hand, entail manipulating reported consumption figures, which may result in increased expenses and improper use of resources. Additionally, more subtle threats come in the form of camouflage attacks, which combine additive and deductive attacks to maintain the mean consumption while secretly changing individual consumption records.

#### Data Integrity

Ensuring the integrity, dependability, and effectiveness of smart water grids requires the detection and mitigation of various data integrity assaults. Conventional anomaly detection systems present a promising defense against these kinds of attacks since they can detect departures from typical usage patterns. Deploying such systems, however, raises privacy concerns over user data, as providing detecting systems with individual consumption information may breach privacy laws and damage customer confidence.


#### Development Approach

Driven by the necessity to balance privacy concerns with security requirements, researchers have investigated a range of privacy-preserving methods for anomaly detection in smart water grids. While approaches like Secure Multiparty Computation (SMC) and Differential Privacy (DP) provide theoretical guarantees of privacy, they frequently have scalability or accuracy issues. Fully Homomorphic Encryption (FHE), in particular, offers a strong substitute by allowing calculations to be performed on encrypted data without the requirement for decryption. The problem lies in striking a balance between processing overhead and detection accuracy when including FHE into anomaly detection frameworks.

Using a Look-Up Table (LUT) based FHE approach combined with Private Information Retrieval (PIR), we provide a privacy-preserving anomaly detection system inspired by the privacy-preserving anomaly detection system in smart energy grids designed for smart water grids in this research. By employing LUTs and PIR, our method addresses the key challenges of integrating FHE into anomaly detection frameworks, providing an accurate solution that maintains user confidentiality. Early findings suggest that this innovative approach can enhance the integrity, dependability, and effectiveness of smart water grids. The following sections will detail the technology behind our method, explore implementation challenges, and present evidence of its impact on improving water management systems.


### Getting Started

Download this zip file and ensure you have the correct versions of the required software before running. When building manually, you might run into an issue of CMake not identifying the software installed on your computer. In that case, navigate to `src/1hour` and open `CMakeLists.txt`. Under the comment `# Import OpenMP`, you can set the specific install path of the required software. Ensure you correct every path.

### Requirements
- Microsoft SEAL 4.1.2 (exact version)
- OpenMP 18.1.8 (exact version)
- CMake 3.10 (minimum version)

### Optional Dependencies
For testing Microsoft SEAL yourself, you may use these optional dependencies:
- GoogleTest 1.12.1
- GoogleBenchmark 1.7.1


### Authors
Ben Antonellis, Alex Nguyen, Gabe Smith

### Sponsors
- Department of Computer Science, Western Michigan University, Kalamazoo, USA
- Professor Shameek Bhattacharjee

## Faculy Advisors
- Halil Dursunoglu
- Dr. Wuwei Shen
