import cv2
import numpy as np
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC2
import sys
import os
import matplotlib.pyplot as plt
import time
import csv
from datetime import datetime
from collections import Counter
from scipy import stats


# The function `image_to_intarray` reads an image file and converts it into a grayscale integer array
# using OpenCV.
def image_to_intarray(img_path):
  return cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)


# The function `intarray_to_image` saves an integer array as an image file using OpenCV.
def intarray_to_image(new_img_path, int_arr):
  return cv2.imwrite(new_img_path, int_arr)


# The function `intarray_to_bytes` converts a 2D integer array representing an image into a bytearray.
def intarray_to_bytes(row, col, img_int):

  img_bytes = bytearray()

  leng = 0

  for i in range(row):
    for j in range(col):

      img_bytes.append(img_int[i][j])
      leng += 1

  return img_bytes


# The function `bytes_to_intarray` converts a byte array representing an image into a 2D integer
# array.
def bytes_to_intarray(row, col, img_bytes):

  img_int = np.zeros((row, col))

  r = 0
  c = 0

  for byte in img_bytes:
    img_int[r][c] = byte

    if c < col: c += 1
    if c == col:
      c = 0
      r += 1

  img = img_int.astype(np.uint8)

  return img


# The function `key_gen` generates a random key of a specific length based on the algorithm provided
# as input.
def key_gen(algo):

  if algo == "DES":
    key_len = 8
  elif algo == "DES3":
    key_len = 16
  else:
    key_len = 32

  return os.urandom(key_len)


# The function `iv_gen` generates a random initialization vector (IV) of a specific length based on
# the specified encryption algorithm.
def iv_gen(algo):

  if algo == "AES":
    iv_len = 16
  elif algo == "DES" or algo == "DES3" or algo == "Blowfish" or algo == "ARC2":
    iv_len = 8

  return os.urandom(iv_len)


# The function `nonce_gen` generates a random nonce of a specific length based on the provided
# encryption algorithm.
def nonce_gen(algo):

  if algo == "AES":
    nonce_len = 8
  elif algo == "DES" or algo == "DES3" or algo == "Blowfish" or algo == "ARC2":
    nonce_len = 4

  return os.urandom(nonce_len)


# The function `create_cipher` generates a cipher object based on the specified algorithm, mode, key,
# and optional initialization vector or nonce.
def create_cipher(algo, mode, key, iv=None, nonce=None):

  mode_dic = {
    "AES-ECB": AES.MODE_ECB,
    "AES-CBC": AES.MODE_CBC,
    "AES-CTR": AES.MODE_CTR,
    "AES-CFB": AES.MODE_CFB,
    "AES-OFB": AES.MODE_OFB,

    "DES-ECB": DES.MODE_ECB,
    "DES-CBC": DES.MODE_CBC,
    "DES-CFB": DES.MODE_CFB,
    "DES-OFB": DES.MODE_OFB,
    "DES-CTR": DES.MODE_CTR,

    "DES3-ECB": DES3.MODE_ECB,
    "DES3-CBC": DES3.MODE_CBC,
    "DES3-CFB": DES3.MODE_CFB,
    "DES3-OFB": DES3.MODE_OFB,
    "DES3-CTR": DES3.MODE_CTR,

    "Blowfish-ECB": Blowfish.MODE_ECB,
    "Blowfish-CBC": Blowfish.MODE_CBC,
    "Blowfish-CFB": Blowfish.MODE_CFB,
    "Blowfish-OFB": Blowfish.MODE_OFB,
    "Blowfish-CTR": Blowfish.MODE_CTR,

    "ARC2-ECB": ARC2.MODE_ECB,
    "ARC2-CBC": ARC2.MODE_CBC,
    "ARC2-CFB": ARC2.MODE_CFB,
    "ARC2-OFB": ARC2.MODE_OFB,
    "ARC2-CTR": ARC2.MODE_CTR,
  }

  try:
    if mode in ["CBC", "CFB", "OFB"]:
      if algo == "AES":
        return AES.new(key, mode_dic[algo+'-'+mode], iv = iv)
      elif algo == "DES":
        return DES.new(key, mode_dic[algo+'-'+mode], iv = iv)
      elif algo == "DES3":
        return DES3.new(key, mode_dic[algo+'-'+mode], iv = iv)
      elif algo == "Blowfish":
        return Blowfish.new(key, mode_dic[algo+'-'+mode], iv = iv)
      elif algo == "ARC2":
        return ARC2.new(key, mode_dic[algo+'-'+mode], iv = iv)
      
    elif mode == "CTR":
      if algo == "AES":
        return AES.new(key, mode_dic[algo+'-'+mode], nonce = nonce)
      elif algo == "DES":
        return DES.new(key, mode_dic[algo+'-'+mode], nonce = nonce)
      elif algo == "DES3":
        return DES3.new(key, mode_dic[algo+'-'+mode], nonce = nonce)
      elif algo == "Blowfish":
        return Blowfish.new(key, mode_dic[algo+'-'+mode], nonce = nonce)
      elif algo == "ARC2":
        return ARC2.new(key, mode_dic[algo+'-'+mode], nonce = nonce)
      
    else:
      if algo == "AES":
        return AES.new(key, mode_dic[algo+'-'+mode])
      elif algo == "DES":
        return DES.new(key, mode_dic[algo+'-'+mode])
      elif algo == "DES3":
        return DES3.new(key, mode_dic[algo+'-'+mode])
      elif algo == "Blowfish":
        return Blowfish.new(key, mode_dic[algo+'-'+mode])
      elif algo == "ARC2":
        return ARC2.new(key, mode_dic[algo+'-'+mode])

  except Exception as e:
    print(e)
    raise ValueError("Unsupported mode: " + mode)


# The function `enc` takes image bytes and a cipher as input, encrypts the image bytes using the
# cipher, measures the execution time, and returns the encrypted bytes.
def enc(img_bytes, cipher):

  start_time = datetime.now()
  encrypted_bytes = cipher.encrypt(img_bytes)
  end_time = datetime.now()
  
  execution_time = (end_time - start_time).total_seconds()

  return encrypted_bytes, execution_time


# The function `dec` takes in encrypted image bytes and a cipher object, decrypts the image bytes
# using the cipher, and returns the decrypted bytes.
def dec(img_bytes, cipher):

  startd_time = datetime.now()
  decrypted_bytes = cipher.decrypt(img_bytes)
  endd_time = datetime.now()

  execution_time = (endd_time - startd_time).total_seconds()

  return decrypted_bytes, execution_time



# The function calculates the Shannon entropy of an image based on the pixel values.
def shannon_entropy(img):

  pixel_counts = Counter(img.flatten())
  total_pixels = len(img.flatten())

  probabilities = [count / total_pixels for count in pixel_counts.values()]
  entropy = -np.sum([p * np.log2(p) for p in probabilities if p != 0])
  return entropy

# The function 'horizontal_correlation' calculates the adjacent horzontal x,y pairs
def horizontal_correlation(image):
    x = image[:,:-1]
    y = image[:,1:]
    return x, y

# The function 'vertical_correlation' calculates the adjacent vertical x,y pairs
def vertical_correlation(image):
    x = image[:-1,:]
    y = image[1:,:]
    return x, y

# The function 'diagonal_correlation' calculates the adjacent diagonal x,y pairs
def diagonal_correlation(image):
    x = image[:-1,:-1]
    y = image[1:,1:]
    return x, y

# The function calculates and visualizes horizontal, vertical, and diagonal correlations of original,
# encrypted, and decrypted images, saving the plots with a specified prefix.
def correlation(org_image, enc_img, dec_img, prefix):

  x,y = horizontal_correlation(org_image)
  org_r_horizontal, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = vertical_correlation(org_image)
  org_r_vertical, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = diagonal_correlation(org_image)
  org_r_diagonal, _ = stats.pearsonr(x.flatten(), y.flatten())

  x,y = horizontal_correlation(enc_img)
  enc_r_horizontal, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = vertical_correlation(enc_img)
  enc_r_vertical, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = diagonal_correlation(enc_img)
  enc_r_diagonal, _ = stats.pearsonr(x.flatten(), y.flatten())

  x,y = horizontal_correlation(dec_img)
  dec_r_horizontal, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = vertical_correlation(dec_img)
  dec_r_vertical, _ = stats.pearsonr(x.flatten(), y.flatten())
  x,y = diagonal_correlation(dec_img)
  dec_r_diagonal, _ = stats.pearsonr(x.flatten(), y.flatten())

  fig, axs = plt.subplots(3, 3, figsize=(24, 24))

  # Horizontal Correlation
  x_horizontal, y_horizontal = horizontal_correlation(org_image)
  axs[0, 0].scatter(x_horizontal, y_horizontal, s=1, color='blue', label='Data Points')
  axs[0, 0].set_xlabel('Pixel value at location (x,y)')
  axs[0, 0].set_ylabel('Pixel value at location (x,y+1)')
  axs[0, 0].set_title('Horizontal Correlation of original image (a)')

  x_horizontal, y_horizontal = horizontal_correlation(enc_img)
  axs[1, 0].scatter(x_horizontal, y_horizontal, s=1, color='blue', label='Data Points')
  axs[1, 0].set_xlabel('Pixel value at location (x,y)')
  axs[1, 0].set_ylabel('Pixel value at location (x,y+1)')
  axs[1, 0].set_title('Horizontal Correlation of encrypted image (d)')

  x_horizontal, y_horizontal = horizontal_correlation(dec_img)
  axs[2, 0].scatter(x_horizontal, y_horizontal, s=1, color='blue', label='Data Points')
  axs[2, 0].set_xlabel('Pixel value at location (x,y)')
  axs[2, 0].set_ylabel('Pixel value at location (x,y+1)')
  axs[2, 0].set_title('Horizontal Correlation of decrypted image (g)')

  # Vertical Correlation=
  x_vertical, y_vertical = vertical_correlation(org_image)
  axs[0, 1].scatter(x_vertical, y_vertical, s=1, color='blue', label='Data Points')
  axs[0, 1].set_xlabel('Pixel value at location (x,y)')
  axs[0, 1].set_ylabel('Pixel value at location (x+1,y)')
  axs[0, 1].set_title('Vertical Correlation of original image (b)')

  x_vertical, y_vertical = vertical_correlation(enc_img)
  axs[1, 1].scatter(x_vertical, y_vertical, s=1, color='blue', label='Data Points')
  axs[1, 1].set_xlabel('Pixel value at location (x,y)')
  axs[1, 1].set_ylabel('Pixel value at location (x+1,y)')
  axs[1, 1].set_title('Vertical Correlation of encrypted image (e)')

  x_vertical, y_vertical = vertical_correlation(dec_img)
  axs[2, 1].scatter(x_vertical, y_vertical, s=1, color='blue', label='Data Points')
  axs[2, 1].set_xlabel('Pixel value at location (x,y)')
  axs[2, 1].set_ylabel('Pixel value at location (x+1,y)')
  axs[2, 1].set_title('Vertical Correlation of decrypted image (h)')

  # Diagonal Correlation
  x_diagonal, y_diagonal = diagonal_correlation(org_image)
  axs[0, 2].scatter(x_diagonal, y_diagonal, s=1, color='blue', label='Data Points')
  axs[0, 2].set_xlabel('Pixel value at location (x,y)')
  axs[0, 2].set_ylabel('Pixel value at location (x+1,y+1)')
  axs[0, 2].set_title('Diagonal Correlation of original image (c)')

  x_diagonal, y_diagonal = diagonal_correlation(enc_img)
  axs[1, 2].scatter(x_diagonal, y_diagonal, s=1, color='blue', label='Data Points')
  axs[1, 2].set_xlabel('Pixel value at location (x,y)')
  axs[1, 2].set_ylabel('Pixel value at location (x+1,y+1)')
  axs[1, 2].set_title('Diagonal Correlation of encrypted image (f)')

  x_diagonal, y_diagonal = diagonal_correlation(dec_img)
  axs[2, 2].scatter(x_diagonal, y_diagonal, s=1, color='blue', label='Data Points')
  axs[2, 2].set_xlabel('Pixel value at location (x,y)')
  axs[2, 2].set_ylabel('Pixel value at location (x+1,y+1)')
  axs[2, 2].set_title('Diagonal Correlation of decrypted image (i)')

  fig.savefig('Correlation/'+prefix+'correlation.png')
  plt.close(fig)

  return org_r_horizontal, org_r_vertical, org_r_diagonal, enc_r_horizontal, enc_r_vertical, enc_r_diagonal, dec_r_horizontal, dec_r_vertical, dec_r_diagonal

# This function generates histograms for original, encrypted, and decrypted images and
# calculates chi-square statistics and p-values for each histogram.
def histogram(org_hist, enc_hist, dec_hist, prefix, dimension):

  fig, axs = plt.subplots(1, 3, figsize=(24, 8))

  expected_observation = (dimension[0]*dimension[1])/256

  org_chi2, org_p_value = stats.chisquare(org_hist, f_exp=expected_observation)
  enc_chi2, enc_p_value = stats.chisquare(enc_hist, f_exp=expected_observation)
  dec_chi2, dec_p_value = stats.chisquare(dec_hist, f_exp=expected_observation)

  axs[0].bar(range(len(org_hist)), org_hist.flatten())
  axs[0].set_xlabel('Grayscale Pixel Values (0,255)')
  axs[0].set_ylabel('Frequency')
  axs[0].set_title('Original Image Histogram')

  axs[1].bar(range(len(enc_hist)), enc_hist.flatten())
  axs[1].set_xlabel('Grayscale Pixel Values (0,255)')
  axs[1].set_ylabel('Frequency')
  axs[1].set_title('Encrypted Image Histogram')

  axs[2].bar(range(len(dec_hist)), dec_hist.flatten())
  axs[2].set_xlabel('Grayscale Pixel Values (0,255)')
  axs[2].set_ylabel('Frequency')
  axs[2].set_title('Decrypted Image Histogram')

  fig.savefig('Histogram/'+prefix+'histogram.png')
  plt.close(fig)

  return org_chi2[0], org_p_value[0], enc_chi2[0], enc_p_value[0], dec_chi2[0], dec_p_value[0]

# The function `write_to_csv` writes a row of data to a master.csv, creating the file with headers if it
# is empty.
def write_to_csv(row):

  filename = 'master.csv'
  is_empty = not os.path.isfile(filename) or os.stat(filename).st_size == 0
    
  if is_empty:
    with open(filename, mode='a', newline='') as file:
      writer = csv.writer(file)
      writer.writerow(['Image Name', 'Encryption Algorithm', 'Cipher Mode', 'IV', 'Nonce', 'Key', 
                       'Encryption Time', 'Decryption Time', 
                       'Original Shannon Entopy', 'Encrypted Shannon Entopy', 'Decrypted Shannon Entopy',
                       'Original Horizontal Correlation', 'Original Vertical Correlation', 'Original Diagonal Correlation',
                       'Encrypted Horizontal Correlation', 'Encrypted Vertical Correlation', 'Encrypted Diagonal Correlation',
                       'Decrypted Horizontal Correlation', 'Decrypted Vertical Correlation', 'Decrypted Diagonal Correlation',
                       'Original Chi-squared statistic', 'Original p-value', 
                       'Encrypted Chi-squared statistic', 'Encrypted p-value', 
                       'Decrypted Chi-squared statistic', 'Decrypted p-value', 
                       'Histogram File Name', 'Correlation File Name'])

  with open(filename, mode='a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(row)


# This function processes an image by encrypting and decrypting it using a specified algorithm
# and mode, and then calculates various metrics and saves the results.
def process(image_name, algo, mode, reading_img):

  prefix = image_name+'_'+algo+'_'+mode+'_'

  org_grayscale_img = prefix + "img.png"
  enc_img = prefix + "enc.png"
  dec_img = prefix + "dec.png"
  
  # Set up key, iv, nonce in terms of the algorithim
  key = key_gen(algo)
  iv = iv_gen(algo)
  nonce = nonce_gen(algo)

  # Creating folders to store data
  if not os.path.exists('Images/'):
    path = os.path.join(os.getcwd(), 'Images')
    os.mkdir(path)

  if not os.path.exists('Correlation/'):
    path = os.path.join(os.getcwd(), 'Correlation')
    os.mkdir(path)

  if not os.path.exists('Histogram/'):
    path = os.path.join(os.getcwd(), 'Histogram')
    os.mkdir(path)
    

  # Convert image to grayscale and get image dimensions
  img_conv = cv2.imread(reading_img, cv2.IMREAD_GRAYSCALE)

  # Checking if valid image is added
  if img_conv is None:
    print(f"ERROR: Image file {reading_img} not found, process canceled for image")
    return

  dimensions = img_conv.shape

  # Checking if image size is valid
  if not (dimensions[0]*dimensions[1]%8 == 0):
    print(f"Image dimentsions dont fit in block size of 8bytes, choose another image")
    return

  # Save grayscale image
  img_res = intarray_to_image('Images/'+org_grayscale_img, img_conv)

  # read the grayscale image
  img = cv2.imread('Images/'+org_grayscale_img, cv2.IMREAD_GRAYSCALE)
  dimensions = img.shape

  # Extract original image, histogram and shannon entholpy
  hist_original = cv2.calcHist([img], [0], None, [256], [0, 256])
  sha_ent_original = shannon_entropy(img)

  img_bytes = intarray_to_bytes(dimensions[0], dimensions[1], img)

  # Set up encryption cipher and encryot image
  enc_cipher = create_cipher(algo, mode, key, iv, nonce)
  enc_bytes, enc_execution_time = enc(img_bytes, enc_cipher)

  # Save encrypted image
  img_enc = bytes_to_intarray(dimensions[0], dimensions[1], enc_bytes)
  enc_res = intarray_to_image('Images/'+enc_img, img_enc)

  # Read encrypted image
  img_enc_ext = cv2.imread('Images/'+enc_img, cv2.IMREAD_GRAYSCALE)
  dimensions = img_enc_ext.shape

  # Extract encrypted image, histogram and shannon entholpy
  hist_encrypted = cv2.calcHist([img_enc_ext], [0], None, [256], [0, 256])
  sha_ent_encrypted = shannon_entropy(img_enc_ext)

  img_enc_bytes = intarray_to_bytes(dimensions[0], dimensions[1], img_enc_ext)

  # Decrypt the encrypted image
  dec_cipher = create_cipher(algo, mode, key, iv, nonce)
  dec_bytes, dec_execution_time = dec(img_enc_bytes, dec_cipher)

  # Dave decrypted image
  img_dec = bytes_to_intarray(dimensions[0], dimensions[1], dec_bytes)
  dec_res = intarray_to_image('Images/'+dec_img, img_dec)

  # Extract decrypted image, histogram and shannon entholpy
  hist_decrypted = cv2.calcHist([img_dec], [0], None, [256], [0, 256])
  sha_ent_decrypted = shannon_entropy(img_dec)

  # Calcuating Correlation Data
  correlation_values = correlation(img, img_enc_ext, img_dec, prefix)

  # Calcuating Histogram Data
  histo_data = histogram(hist_original, hist_encrypted, hist_decrypted, prefix, dimensions)

  # Writing to CSV file
  write_to_csv([image_name, algo, mode, iv.hex(), nonce.hex(), key.hex(),
                enc_execution_time, dec_execution_time,
                sha_ent_original, sha_ent_encrypted, sha_ent_decrypted,
                correlation_values[0], correlation_values[1], correlation_values[2],
                correlation_values[3], correlation_values[4], correlation_values[5],
                correlation_values[6], correlation_values[7], correlation_values[8],
                histo_data[0], histo_data[1],
                histo_data[2], histo_data[3],
                histo_data[4], histo_data[5],
                prefix+'histogram.png', prefix+'correlation.png'])