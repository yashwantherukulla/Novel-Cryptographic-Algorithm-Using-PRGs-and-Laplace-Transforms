import random
import string
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
from scipy.stats import entropy
from Encryptor import Encryptor 

def generate_random_text(max_length=100):
    """Generate a random piece of text with a maximum length."""
    length = random.randint(10, max_length)
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation + ' ', k=length))

def generate_text_files(num_files, output_dir='distribution/plain_texts'):
    """Generate a specified number of random text files."""
    os.makedirs(output_dir, exist_ok=True)
    file_paths = []
    for i in range(num_files):
        file_path = os.path.join(output_dir, f'plain_{i}.txt')
        with open(file_path, 'w') as f:
            f.write(generate_random_text())
        file_paths.append(file_path)
    return file_paths

def encrypt_files(file_paths, output_dir='distribution/encrypted_texts'):
    """Encrypt the given files and store them in the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    encrypted_paths = []
    for file_path in file_paths:
        r = 2
        fn = f"x*exp({r}*x)"
        encryptor = Encryptor(file_path, fn, (157, 173, 833))
        cipher_text, keys = encryptor.encrypt(False)
        
        output_path = os.path.join(output_dir, f'encrypted_{os.path.basename(file_path)}')
        with open(output_path, 'w') as f: 
            f.write(cipher_text)
        encrypted_paths.append(output_path)
    return encrypted_paths

def analyze_letter_distribution(file_paths):
    """Analyze the letter distribution of the given files."""
    all_text = ''
    for file_path in file_paths:
        with open(file_path, 'r') as f:
            all_text += f.read()
    return Counter(all_text)

def plot_letter_distribution(plain_dist, cipher_dist):
    """Plot the letter distribution of plain text vs cipher text."""
    plt.figure(figsize=(15, 10))
    
    labels = list(string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation)
    plain_freq = [plain_dist[label] for label in labels]
    cipher_freq = [cipher_dist[label] for label in labels]
    
    x = np.arange(len(labels))
    width = 0.35
    
    plt.bar(x - width/2, plain_freq, width, label='Plain Text')
    plt.bar(x + width/2, cipher_freq, width, label='Cipher Text')
    
    plt.xlabel('Characters')
    plt.ylabel('Frequency')
    plt.title('Character Distribution: Plain Text vs Cipher Text')
    plt.xticks(x, labels, rotation='vertical')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('distribution/letter_distribution.png')
    plt.close()

def calculate_entropy(distribution):
    """Calculate the Shannon entropy of the given distribution."""
    total = sum(distribution.values())
    probabilities = [count / total for count in distribution.values()]
    return entropy(probabilities, base=2)

def main():
    if (os.path.exists('distribution')):
        os.system('rmdir /s /q distribution')
    num_files = 100
    plain_files = generate_text_files(num_files)
    encrypted_files = encrypt_files(plain_files)
    
    plain_dist = analyze_letter_distribution(plain_files)
    cipher_dist = analyze_letter_distribution(encrypted_files)
    
    plot_letter_distribution(plain_dist, cipher_dist)
    
    plain_entropy = calculate_entropy(plain_dist)
    cipher_entropy = calculate_entropy(cipher_dist)
    
    print(f"Plain text entropy: {plain_entropy:.2f} bits")
    print(f"Cipher text entropy: {cipher_entropy:.2f} bits")
    #save to file
    with open('distribution/entropy.txt', 'w') as file:
        file.write(f"Plain text entropy: {plain_entropy:.5f} bits\n")
        file.write(f"Cipher text entropy: {cipher_entropy:.5f} bits\n")

if __name__ == "__main__":
    main()