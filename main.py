# Import required libraries
import pygame
import sys
import random
import math
from collections import defaultdict

# Initialize Pygame
pygame.init()

# Constants
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700
FPS = 60
NODE_RADIUS = 30
LINE_THICKNESS = 2
PACKET_RADIUS = 5
PACKET_SPEED = 5
PORT_SCAN_DELAY = 50  # Milliseconds between port scan packets
ALERT_DURATION = 5000  # How long alerts stay visible (ms)

# Colors
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (0, 0, 255)
RED = (255, 0, 0)
GREEN = (0, 255, 0)  # For normal traffic
YELLOW = (255, 255, 0)  # For alerts

class Node:
    def __init__(self, node_id, x, y):
        self.node_id = node_id
        self.x = x
        self.y = y
        self.connected_nodes = []
    
    def connect_to(self, other_node):
        # Prevent duplicate connections
        if other_node not in self.connected_nodes:
            self.connected_nodes.append(other_node)
            # Ensure bidirectional connection
            if self not in other_node.connected_nodes:
                other_node.connected_nodes.append(self)
    
    def draw(self, screen, font):
        # Draw the node circle
        pygame.draw.circle(screen, BLUE, (self.x, self.y), NODE_RADIUS)
        
        # Draw the node ID text
        text = font.render(self.node_id, True, WHITE)
        text_rect = text.get_rect(center=(self.x, self.y - NODE_RADIUS - 10))
        screen.blit(text, text_rect)
        
        # Draw connections to other nodes
        for connected_node in self.connected_nodes:
            pygame.draw.line(screen, WHITE, 
                           (self.x, self.y),
                           (connected_node.x, connected_node.y),
                           LINE_THICKNESS)

class Packet:
    def __init__(self, source_node, destination_node, protocol="TCP", port=80, is_attack=False, payload=""):
        self.source_node = source_node
        self.destination_node = destination_node
        self.protocol = protocol
        self.port = port
        self.is_attack = is_attack
        self.payload = payload  # New: Added payload for attack data
        self.current_pos = [source_node.x, source_node.y]
        self.color = RED if is_attack else GREEN
        self.speed = PACKET_SPEED
        self.path_nodes = [source_node, destination_node]
        self.current_path_index = 0
    
    def move(self):
        if self.current_path_index >= len(self.path_nodes) - 1:
            return True
        
        next_node = self.path_nodes[self.current_path_index + 1]
        dx = next_node.x - self.current_pos[0]
        dy = next_node.y - self.current_pos[1]
        distance = math.sqrt(dx**2 + dy**2)
        
        if distance <= self.speed:
            self.current_pos = [next_node.x, next_node.y]
            self.current_path_index += 1
            return self.current_path_index >= len(self.path_nodes) - 1
        else:
            move_x = (dx / distance) * self.speed
            move_y = (dy / distance) * self.speed
            self.current_pos[0] += move_x
            self.current_pos[1] += move_y
            return False
    
    def draw(self, screen):
        pygame.draw.circle(screen, self.color, 
                         (int(self.current_pos[0]), int(self.current_pos[1])), 
                         PACKET_RADIUS)

class IDS:
    def __init__(self):
        self.alerts = []  # List of (timestamp, message, attack_type) tuples
        # Port scan tracking
        self.scan_tracker = defaultdict(lambda: defaultdict(lambda: {'ports_hit': set(), 'start_time': 0}))
        self.port_scan_threshold = 10
        self.port_scan_time_window = 3000
        
        # Brute force tracking
        self.brute_force_tracker = defaultdict(lambda: {'attempts': 0, 'start_time': 0})
        self.brute_force_threshold = 5  # Number of attempts to trigger alert
        self.brute_force_time_window = 10000  # 10 seconds in milliseconds
        
        # DoS tracking
        self.dos_tracker = defaultdict(lambda: {'packet_count': 0, 'start_time': 0})
        self.dos_threshold = 50  # Packets per second to trigger alert
        self.dos_time_window = 1000  # 1 second in milliseconds
        
        # Alert cooldown tracking
        self.alert_cooldown = {}
        
    def inspect_packet(self, packet, current_time):
        source_id = packet.source_node.node_id
        target_id = packet.destination_node.node_id
        
        # Skip if this source-target pair is in cooldown
        cooldown_key = f"{source_id}->{target_id}"
        if cooldown_key in self.alert_cooldown:
            if current_time - self.alert_cooldown[cooldown_key] < 3000:  # 3 second cooldown
                return
            else:
                del self.alert_cooldown[cooldown_key]
        
        # Check for port scan
        self._check_port_scan(source_id, target_id, packet.port, current_time)
        
        # Check for brute force
        self._check_brute_force(source_id, target_id, packet, current_time)
        
        # Check for DoS
        self._check_dos(source_id, target_id, current_time)
    
    def _check_port_scan(self, source_id, target_id, port, current_time):
        # Initialize start time if this is first packet
        if not self.scan_tracker[target_id][source_id]['start_time']:
            self.scan_tracker[target_id][source_id]['start_time'] = current_time
        
        # Add port to the set of ports hit
        self.scan_tracker[target_id][source_id]['ports_hit'].add(port)
        
        # Check time window
        time_elapsed = current_time - self.scan_tracker[target_id][source_id]['start_time']
        
        if (len(self.scan_tracker[target_id][source_id]['ports_hit']) >= self.port_scan_threshold and
            time_elapsed <= self.port_scan_time_window):
            self._add_alert(current_time, f"Port Scan Detected! {source_id} -> {target_id}", "Port Scan")
            self._set_cooldown(f"{source_id}->{target_id}", current_time)
            self.scan_tracker[target_id][source_id] = {'ports_hit': set(), 'start_time': 0}
        elif time_elapsed > self.port_scan_time_window:
            self.scan_tracker[target_id][source_id] = {'ports_hit': set(), 'start_time': 0}
    
    def _check_brute_force(self, source_id, target_id, packet, current_time):
        key = (source_id, target_id, packet.port)
        
        # Initialize start time if this is first attempt
        if not self.brute_force_tracker[key]['start_time']:
            self.brute_force_tracker[key]['start_time'] = current_time
        
        # Increment attempt counter
        self.brute_force_tracker[key]['attempts'] += 1
        
        # Check time window
        time_elapsed = current_time - self.brute_force_tracker[key]['start_time']
        
        if (self.brute_force_tracker[key]['attempts'] >= self.brute_force_threshold and
            time_elapsed <= self.brute_force_time_window):
            self._add_alert(current_time, 
                          f"Brute Force Attack Detected! {source_id} -> {target_id} (Port {packet.port})",
                          "Brute Force")
            self._set_cooldown(f"{source_id}->{target_id}", current_time)
            self.brute_force_tracker[key] = {'attempts': 0, 'start_time': 0}
        elif time_elapsed > self.brute_force_time_window:
            self.brute_force_tracker[key] = {'attempts': 0, 'start_time': 0}
    
    def _check_dos(self, source_id, target_id, current_time):
        key = (source_id, target_id)
        
        # Initialize start time if this is first packet
        if not self.dos_tracker[key]['start_time']:
            self.dos_tracker[key]['start_time'] = current_time
        
        # Increment packet counter
        self.dos_tracker[key]['packet_count'] += 1
        
        # Check time window
        time_elapsed = current_time - self.dos_tracker[key]['start_time']
        
        if time_elapsed >= self.dos_time_window:
            # Calculate packets per second
            packets_per_second = (self.dos_tracker[key]['packet_count'] * 1000) / time_elapsed
            
            if packets_per_second >= self.dos_threshold:
                self._add_alert(current_time,
                              f"DoS Attack Detected! {source_id} -> {target_id} ({packets_per_second:.1f} packets/sec)",
                              "DoS")
                self._set_cooldown(f"{source_id}->{target_id}", current_time)
            
            # Reset counter for next window
            self.dos_tracker[key] = {'packet_count': 0, 'start_time': current_time}
    
    def _add_alert(self, timestamp, message, attack_type):
        self.alerts.append((timestamp, message, attack_type))
    
    def _set_cooldown(self, key, current_time):
        self.alert_cooldown[key] = current_time
    
    def draw_alerts(self, screen, font):
        current_time = pygame.time.get_ticks()
        y_offset = 10
        
        # Filter and sort alerts
        active_alerts = [(t, msg, type) for t, msg, type in self.alerts 
                        if current_time - t < ALERT_DURATION]
        self.alerts = active_alerts  # Remove expired alerts
        
        # Draw each active alert
        for timestamp, message, attack_type in active_alerts:
            # Calculate alert opacity based on age
            age = current_time - timestamp
            opacity = max(0, min(255, int(255 * (1 - age / ALERT_DURATION))))
            
            # Choose color based on attack type
            color = {
                "Port Scan": YELLOW,
                "Brute Force": (255, 165, 0),  # Orange
                "DoS": RED
            }.get(attack_type, YELLOW)
            
            # Create color with opacity
            alert_color = (*color[:3], opacity)
            
            # Render alert text
            text = font.render(message, True, alert_color)
            text_rect = text.get_rect(topleft=(10, y_offset))
            screen.blit(text, text_rect)
            
            y_offset += 30

def initiate_port_scan(source_node, target_node, num_ports=100, start_port=1):
    """
    Generator function that yields port scan packets over time.
    """
    for port in range(start_port, start_port + num_ports):
        # Create a new attack packet targeting the next port
        packet = Packet(
            source_node=source_node,
            destination_node=target_node,
            protocol="TCP",
            port=port,
            is_attack=True
        )
        yield packet

def initiate_brute_force(source_node, target_node, target_port=22, num_attempts=50, delay_ms=100):
    """Generator function that yields brute force attack packets over time."""
    common_passwords = ["password", "123456", "admin", "root", "letmein", "qwerty"]
    usernames = ["admin", "root", "user", "administrator"]
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(common_passwords) + str(i)
        payload = f"{username}:{password}"
        
        packet = Packet(
            source_node=source_node,
            destination_node=target_node,
            protocol="TCP",
            port=target_port,
            is_attack=True,
            payload=payload
        )
        yield packet

def initiate_dos_attack(source_node, target_node, duration_ms=5000, packets_per_second=10):
    """Generator function that yields DoS attack packets over time."""
    start_time = pygame.time.get_ticks()
    end_time = start_time + duration_ms
    
    while pygame.time.get_ticks() < end_time:
        # Create packets with random properties to simulate flood
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        port = random.randint(1, 65535)
        payload = "X" * random.randint(32, 128)  # Random garbage data
        
        packet = Packet(
            source_node=source_node,
            destination_node=target_node,
            protocol=protocol,
            port=port,
            is_attack=True,
            payload=payload
        )
        yield packet

# Set up the display
screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
pygame.display.set_caption("Network Security IDS Simulator")

# Create a font for node labels and alerts
font = pygame.font.Font(None, 36)

# Create a clock object to control frame rate
clock = pygame.time.Clock()

# Create network nodes
nodes = [
    Node("Firewall", WINDOW_WIDTH // 2, WINDOW_HEIGHT // 2),
    Node("Web Server", WINDOW_WIDTH // 2 - 200, WINDOW_HEIGHT // 2 - 150),
    Node("Database", WINDOW_WIDTH // 2 + 200, WINDOW_HEIGHT // 2 - 150),
    Node("User PC", WINDOW_WIDTH // 2 - 200, WINDOW_HEIGHT // 2 + 150),
    Node("Attacker", WINDOW_WIDTH // 2 + 200, WINDOW_HEIGHT // 2 + 150)
]

# Establish network connections
firewall = nodes[0]  # Firewall is at index 0
web_server = nodes[1]
database = nodes[2]
user_pc = nodes[3]
attacker = nodes[4]

# Connect nodes to create network topology
firewall.connect_to(web_server)
firewall.connect_to(database)
firewall.connect_to(user_pc)
web_server.connect_to(database)
attacker.connect_to(firewall)

# List to store active packets
active_packets = []

# Protocols and ports for random packet generation
protocols = ["TCP", "HTTP", "UDP", "HTTPS"]
ports = [80, 443, 22, 21, 3306]

# Port scan attack variables
current_attack_generator = None
last_attack_packet_time = 0
dos_end_time = 0  # New: Track DoS attack duration

# Initialize IDS
ids = IDS()

# Main game loop
running = True
while running:
    current_time = pygame.time.get_ticks()
    
    # Event handling
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        elif event.type == pygame.KEYDOWN:
            if current_attack_generator is None:  # Only start new attack if none is running
                if event.key == pygame.K_a:
                    # Port scan attack
                    current_attack_generator = initiate_port_scan(attacker, web_server)
                    last_attack_packet_time = current_time
                elif event.key == pygame.K_b:
                    # Brute force attack (targeting SSH port 22)
                    current_attack_generator = initiate_brute_force(attacker, web_server)
                    last_attack_packet_time = current_time
                elif event.key == pygame.K_d:
                    # DoS attack
                    current_attack_generator = initiate_dos_attack(attacker, web_server)
                    last_attack_packet_time = current_time
                    dos_end_time = current_time + 5000  # 5 seconds duration

    # Random packet generation (1% chance per frame)
    if random.randint(1, 100) == 1:
        source_node = random.choice(nodes)
        if source_node.connected_nodes:  # Only create packet if node has connections
            destination_node = random.choice(source_node.connected_nodes)
            protocol = random.choice(protocols)
            port = random.choice(ports)
            is_attack = False  # Normal traffic
            
            new_packet = Packet(source_node, destination_node, protocol, port, is_attack)
            active_packets.append(new_packet)

    # Generate attack packets if an attack is in progress
    if current_attack_generator is not None:
        if current_time - last_attack_packet_time >= PORT_SCAN_DELAY:
            try:
                new_attack_packet = next(current_attack_generator)
                active_packets.append(new_attack_packet)
                last_attack_packet_time = current_time
                
                # Check if DoS attack should end
                if dos_end_time > 0 and current_time >= dos_end_time:
                    current_attack_generator = None
                    dos_end_time = 0
            except StopIteration:
                # Attack is complete
                current_attack_generator = None
                dos_end_time = 0

    # Fill the background
    screen.fill(BLACK)
    
    # Draw all nodes and their connections
    for node in nodes:
        node.draw(screen, font)
    
    # Update and draw packets
    packets_to_remove = []
    for packet in active_packets:
        packet.draw(screen)
        if packet.move():  # Returns True if packet reached destination
            # Inspect packet when it reaches its destination
            ids.inspect_packet(packet, current_time)
            packets_to_remove.append(packet)
    
    # Remove completed packets
    for packet in packets_to_remove:
        active_packets.remove(packet)
    
    # Draw IDS alerts
    ids.draw_alerts(screen, font)

    # Update the display
    pygame.display.flip()

    # Control the frame rate
    clock.tick(FPS)

# Quit Pygame
pygame.quit()
sys.exit()