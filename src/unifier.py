import pandas as pd
import os
from logger import logging

# Path to the folder containing the CSV files
input_folder = "D:\\DDOS_Detection\\ddos_ds\\"
output_file = "D:\\DDOS_Detection\\ddos_ds\\combined_dataset.csv"

# List of the CSV files to process
csv_files = [
    "DrDoS_DNS.csv",
    "Syn.csv",
    "UDPLag.csv",
    "DrDoS_NTP.csv",
    "DrDoS_UDP.csv"
]

# Fraction of data to sample from each file (adjust as needed)
sample_fraction = 0.4  # 10% of each file

# Open the output file in write mode
with open(output_file, "w") as output_csv:
    for i, file_name in enumerate(csv_files):
        file_path = os.path.join(input_folder, file_name)
        print(f"Processing file: {file_path}")

        # Read the file in chunks
        for chunk in pd.read_csv(file_path, chunksize=100000, low_memory=False):
            # Take a random sample of the chunk
            sampled_chunk = chunk.sample(frac=sample_fraction, random_state=42)

            # Unify the labels: rename attack types to "DDOS" and benign to "Normal"
            sampled_chunk[" Label"] = sampled_chunk[" Label"].apply(lambda x: "Normal" if x == "BENIGN" else "DDOS")

            # Write to output file
            if i == 0 and chunk.index[0] == 0:  # Write header only for the first chunk of the first file
                sampled_chunk.to_csv(output_csv, index=False, mode='a')
            else:
                sampled_chunk.to_csv(output_csv, index=False, mode='a', header=False)

logging.info(f"Sampled combined dataset saved to {output_file}")
