import pandas as pd
import numpy as np
import os
import random

def generate_sample_dataset(filename, num_rows=1000):
    data = []
    for _ in range(num_rows):
        is_attack = random.random() > 0.7
        
        row = {
            'Destination Port': random.choice([80, 443, 53, 22, 8080]),
            'Flow Duration': random.uniform(100000, 2000000) if is_attack else random.uniform(1000000, 60000000),
            'Total Fwd Packets': random.randint(1000, 10000) if is_attack else random.randint(10, 500),
            'Total Backward Packets': random.randint(500, 5000) if is_attack else random.randint(5, 250),
            'Total Length of Fwd Packets': random.uniform(100000, 500000) if is_attack else random.uniform(1000, 10000),
            'Total Length of Bwd Packets': random.uniform(50000, 250000) if is_attack else random.uniform(500, 5000),
            'Fwd Packet Length Max': random.uniform(100, 1500),
            'Fwd Packet Length Min': random.uniform(0, 100),
            'Fwd Packet Length Mean': random.uniform(100, 500) if is_attack else random.uniform(200, 800),
            'Bwd Packet Length Max': random.uniform(100, 1500),
            'Bwd Packet Length Min': random.uniform(0, 100),
            'Bwd Packet Length Mean': random.uniform(50, 200) if is_attack else random.uniform(100, 400),
            'Flow Bytes/s': random.uniform(100000, 500000) if is_attack else random.uniform(1000, 10000),
            'Flow Packets/s': random.uniform(10000, 50000) if is_attack else random.uniform(100, 1000),
            'Flow IAT Mean': random.uniform(0.1, 10.0),
            'Flow IAT Std': random.uniform(0.1, 5.0),
            'Flow IAT Max': random.uniform(10.0, 100.0),
            'Flow IAT Min': random.uniform(0.01, 1.0),
            'Fwd IAT Total': random.uniform(100000, 1000000),
            'Bwd IAT Total': random.uniform(50000, 500000),
            'SYN Flag Count': random.randint(100, 500) if is_attack else random.randint(0, 20),
            'ACK Flag Count': random.randint(50, 200) if is_attack else random.randint(5, 50),
            'Label': 'DDoS' if is_attack else 'BENIGN'
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Created {filename} with {num_rows} rows.")

if __name__ == "__main__":
    output_dir = 'sample_datasets'
    os.makedirs(output_dir, exist_ok=True)
    
    dataset_types = [
        "syn_flood", "udp_flood", "http_flood", "icmp_flood", 
        "slowloris", "dns_amplification", "ntp_amplification", 
        "smurf_attack", "fraggle_attack", "land_attack"
    ]
    
    for i, attack_name in enumerate(dataset_types):
        filename = os.path.join(output_dir, f"ddos_sample_{i+1}_{attack_name}.csv")
        generate_sample_dataset(filename, num_rows=random.randint(500, 2000))
