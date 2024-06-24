import image_encryption_analysis

# Set up algorithims to use here, currently supported modes below:
# modes = ["CBC", "ECB", "CTR", "CFB", "OFB"]
modes = ["CBC"]

# Set up algorithims to use here, currently supported algoritims below:
# algorithims = ["AES", "DES", "DES3", "Blowfish", "ARC2"]
algorithims = ["AES"]

# Add images in the format of a tuple, (<Image short form>, <Image sourcefile>)
# An exmaple has been given below
images = [("Man_Image", "manimage.jpg")]

for image in images:
    for algo in algorithims:
        for mode in modes:
            print(image[0]+" "+algo+" "+mode)
            image_encryption_analysis.process(image[0], algo, mode, image[1])