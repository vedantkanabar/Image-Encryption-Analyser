# Crypto Module (crypto.py)

## Overview

This Python library is designed to convert an image to grayscale, encrypt the image, and then decrypt it while analyzing various aspects of the image at each step. The program provides functionality for analyzing the original grayscale image, the encrypted image, and the decrypted image for adjacent pixel correlation, histogram analysis using the chi-square test, and Shannon entropy. It all produces relevant images as correlation and histogram graphs. Additionally, it measures the encryption and decryption time for performance evaluation.

## Authors
- Nitin Satishbabu
- Vedant Kanabar

## Requirements

 - Python 3.12.2, to program the encryption and decryption scripts. 
 - OpenCV 4.9.0, an Open Source Computer Vision Python library to help with manipulating and extracting image properties. 
 - Numpy 1.26.3, a Python library for scientific computing in Python. 
 - Matplotlib 3.8.4, a Python library for creating static, animated, and interactive visualizations in Python.
 - Crypto.Cipher 1.4.1, a Python package that contains algorithms for protecting the confidentiality of data in Python. 
 - Scipy.stats 1.13.0, a Python package to calculate pearson correlation and other statistics

 Note: These are the versions of libraries that were used when programming

 All the required modules can be downloaded using pip codes below:

```bash
pip install opencv-python
pip install numpy
pip install matplotlib
pip install pycryptodome
pip install scipy
```

## Files

The crypto.py file contains all the necessary functions for image encryption and decryption, as well as for analysis. These functions include:

- 'process': Takes in an algorithim, block cipher mode and image details and runs the whole process
- 'write_to_csv': Writes numeric results to a csv file
- 'enc': Encrypts the given grayscale image
- 'dec': Decrypts the given grayscale image
- 'histogram': Performs histogram analysis using the chi-square test
- 'correlation': Analyzes the adjacent pixel correlation of the image
- 'shannon_entropy': Calculates the Shannon entropy of the image

The main.py file contains the sample calls used in our experiment, feel free to edit it and try with your images.

## Analysis
- Adjacent Pixel Correlation: This metric measures the correlation between adjacent pixels in the image. Lower correlation indicates higher randomness.
- Histogram Analysis: Histogram analysis using the chi-square test helps in understanding the distribution of pixel intensities in the image.
- Shannon Entropy: Shannon entropy measures the amount of uncertainty or randomness in the image.
- Encryption/Decryption Time: The time taken to encrypt and decrypt the image is measured to evaluate performance
- Visual Assement: Produces images for the user to judge

## Runnning the program

Currently there is a manimage.jpg file to expriment on but feel free to change the files in main.py. Running the following command executing the main.py will run the code for the selection of algoritim, mode and images.

```bash
python3 main.py
```

NOTE: Once all dependencies have been downloaded, you can run the command above without changing the main.py file, it has been setup for you to run.

