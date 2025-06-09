# Network Security IDS Simulator

![Normal Traffic](https://drive.google.com/uc?export=view&id=1sBK_6YwB-mp8neKlGljJKV0zCCtNkR8M)

## 🛡️ Overview

In today's interconnected digital world, every online system – from websites to mobile apps – is constantly exposed to threats. Just like you secure your home with locks and an alarm system, businesses and organizations need robust digital security to protect their valuable data and services.

This **Network Security IDS Simulator** is a visual, interactive tool designed to demystify complex cybersecurity concepts. It allows anyone, regardless of their technical background, to **see how cyberattacks unfold in a simplified network environment** and, crucially, **how an Intrusion Detection System (IDS) acts as a vigilant digital alarm** to spot and alert on these threats in real-time.

It's an ideal project for:
* Students learning about network security fundamentals.
* Professionals demonstrating IDS concepts.
* Anyone curious about the unseen digital battles happening online.

## ✨ Features

This simulator brings key network security concepts to life through compelling visualizations:

* **Customizable Network Topology:** Simulates a basic network infrastructure including a Firewall, Web Server, Database, User PC, and an Attacker.
background coloring and labels.
    * **Firewall Prominence:** The central Firewall node is visibly larger and uniquely colored, emphasizing its critical role as a security gateway.
* **Dynamic Packet Visualization:**
    * **Normal Traffic:** Green, circular packets represent legitimate data flow between network nodes, showing everyday operations.
    * **Attack Traffic:** Red, diamond-shaped packets clearly indicate malicious activity.
    * **Packet Trails:** Each packet leaves a fading trail, making its direction and path instantly clear and visually engaging.
    * **Attack Impact Visuals:** Brief, striking visual effects (e.g., flashes, temporary color changes, "OVERLOADED!" text, subtle shaking) on target nodes to show the immediate effect of attacks like Brute-Force and DoS.
* **Simulated Cyberattacks:** Launch common attack types at the press of a key:
    * **Port Scan:** Simulates an attacker probing various "digital doors" (ports) on a target server to find vulnerabilities.
    * **Brute Force Attack:** Visualizes repeated, automated attempts to guess login credentials on a service (e.g., SSH).
    * **Denial of Service (DoS) Attack:** Shows a flood of malicious traffic overwhelming a target server, making it unavailable for legitimate users.
* **Real-time Intrusion Detection System (IDS):**
    * **Threat Monitoring:** The IDS constantly monitors network traffic for suspicious patterns characteristic of known attacks.
    * **Prominent Alerts:** When an attack is detected, a highly visible, semi-transparent alert banner pops up with clear messages, distinct colors for different alert types (yellow for Port Scan, orange for Brute Force, red for DoS), and fade-out effects.
    * **IDS Status Indicator:** A dynamic "IDS" text display changes color (Green: Normal, Yellow: Attack Active, Red: Alert Triggered) to provide an immediate status overview.
* **Intuitive User Interface (UI):**
    * **On-screen Controls Guide:** A dedicated panel displays clear keybindings for launching attacks and controlling the simulation.
    * **Dynamic Status Message:** A prominent message at the top of the screen provides high-level status updates (e.g., "Network Status: Normal Traffic" or "Attack Active: Port Scan").
    * **Node Highlighting:** Attacker and target nodes pulsate with a glow during an active attack, drawing immediate attention to the threat actors.

## 🚀 How to Run

To get this simulator up and running on your local machine, follow these simple steps:

1.  **Prerequisites:**
    * Python 3.x installed (preferably 3.8 or newer).
    * `pip` (Python package installer) installed.

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/sammyifelse/IDS-Env.git](https://github.com/sammyifelse/IDS-Env.git)
    cd IDS-ENV
    ```

3.  **Install Dependencies:**
    This project uses `pygame` for graphics.
    ```bash
    pip install pygame
    ```

4.  **Run the Simulator:**
    ```bash
    python main.py
    ```

## 🕹️ How to Use & Demo

Once the simulator window appears:

1.  **Observe Normal Traffic:** You'll see green packets (normal traffic) moving between nodes. The "Network Status" will display "Normal Traffic."
2.  **Launch Attacks (using keyboard keys):**
    * Press **`A`** to launch a **Port Scan** from the Attacker to the Web Server. Watch the red, diamond-shaped packets probe the Web Server.
    * Press **`B`** to launch a **Brute Force Attack** from the Attacker to the Web Server.
    * Press **`D`** to launch a **Denial of Service (DoS) Attack** from the Attacker to the Web Server. Observe the target node becoming "OVERLOADED!".
3.  **Watch for IDS Alerts:** Pay attention to the top-left corner of the screen for the semi-transparent alert banners and the "IDS" status indicator changing colors.
4.  **Exit:** Press **`ESC`** to close the simulator window.

For a guided walkthrough and to see the simulator in action, check out the demo video:

[**Watch the Network Security IDS Simulator Demo Video **](https://drive.google.com/file/d/1nTwWBzkDf4o9krusTIcS8-Pvj36v0V0n/view?usp=sharing)

## 📸 Screenshots

*(Ensure these Google Drive images are set to "Anyone with the link can view" for them to display correctly.)*

![Normal Traffic](https://drive.google.com/uc?export=view&id=1sBK_6YwB-mp8neKlGljJKV0zCCtNkR8M)
![Port Scan Alert](https://drive.google.com/uc?export=view&id=1aBrJm-zviyQZ5wZaihHB2_ppiKrju40m)
![BruteForce Impact](https://drive.google.com/uc?export=view&id=1d5JYUbuwuwZTEQBYGZWybrcwPztVEO0Z)

## 💻 Technical Details & Implementation Highlights

* **Pygame:** Used for all graphics rendering and event handling.
* **Object-Oriented Design:** Nodes, Packets, and the IDS are implemented as separate classes for modularity and maintainability.
* **IDS Logic:** The IDS employs rule-based detection for Port Scans (port threshold over time), Brute Force (failed attempts over time on a specific port), and DoS (packet rate threshold).
* **Packet Generation:** Uses Python generator functions for controlled attack packet release.
* **Dynamic UI:** On-the-fly rendering of alerts, status messages, and node highlights provides a responsive user experience.

## 🗺️ Future Enhancements

This project is a strong foundation and can be expanded further. Here are some ideas for future development:

* **Network Routing & Pathfinding:** Implement more complex routing algorithms for packets to traverse multiple hops.
* **Advanced IDS Rules:** Allow customizable IDS rules or explore basic anomaly detection for unknown threats.
* **Firewall Functionality:** Add active packet filtering and blocking capabilities to the Firewall.
* **Event Logging & Replay:** Implement logging of all events and a feature to replay past attack scenarios.
* **Multi-Attacker / DDoS Simulation:** Introduce multiple attacker nodes to simulate distributed attacks.
* **Network Health Metrics:** Visually represent node load, latency, or bandwidth usage to show real-time impact.

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements or new features, feel free to:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/AmazingFeature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
5.  Push to the branch (`git push origin feature/AmazingFeature`).
6.  Open a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
