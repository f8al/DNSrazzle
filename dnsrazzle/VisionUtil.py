#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2023 SecurityShrimp

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


__version__ = '1.5.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

import cv2
from .IOUtil import print_error, print_status
from skimage.metrics import structural_similarity

def compare_screenshots(imageA, imageB):
    print_status(f"Comparing screenshot {imageA} with {imageB}.")
    try:
        # load the two input images
        image_A = cv2.imread(imageA)
        image_B = cv2.imread(imageB)
        # convert the images to grayscale
        grayA = cv2.cvtColor(image_A, cv2.COLOR_BGR2GRAY)
        grayB = cv2.cvtColor(image_B, cv2.COLOR_BGR2GRAY)
        # compute the Structural Similarity Index (SSIM) between the two
        # images, ensuring that the difference image is returned
        (score, diff) = structural_similarity(grayA, grayB, full=True)
        #print("SSIM: {}".format(score))
        rounded_score = round(score, 2)

        if rounded_score == 1.00 :
            print_status(f"{imageA} Is identical to {imageB} with a score of {str(rounded_score)}!")
        elif rounded_score > .90 :
            print_status(f"{imageA} Is similar to {imageB} with a score of {str(rounded_score)}!")
        elif rounded_score < .90 :
            print_status(f"{imageA} Is different from {imageB} with a score of {str(rounded_score)}!")
    except cv2.error as exception:
        print_error(f"Unable to compare screenshots.  One or more of the screenshots are missing!")
        rounded_score = None
    except ValueError as ve:
        print_error(ve)
        rounded_score = None
    return rounded_score
