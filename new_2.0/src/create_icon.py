#!/usr/bin/env python3
"""
Create a wolf icon for the proc-wolf executable
"""

import os
from PIL import Image, ImageDraw

def create_wolf_icon():
    """Create a wolf icon and save it as ICO file"""
    # Create a 256x256 transparent image
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors
    dark_gray = (60, 60, 70, 255)    # Dark fur
    medium_gray = (120, 120, 130, 255)  # Medium fur
    light_gray = (180, 180, 190, 255)  # Light fur
    eye_blue = (30, 144, 255, 255)  # Blue eyes
    black = (10, 10, 10, 255)  # For details
    
    # Draw wolf head
    # Main head shape
    draw.ellipse((50, 40, 206, 196), fill=medium_gray)
    
    # Ears
    draw.polygon([(50, 90), (20, 25), (80, 60)], fill=dark_gray)  # Left ear
    draw.polygon([(206, 90), (236, 25), (176, 60)], fill=dark_gray)  # Right ear
    
    # Inner ears
    draw.polygon([(50, 90), (30, 35), (70, 65)], fill=light_gray)  # Left inner ear
    draw.polygon([(206, 90), (226, 35), (186, 65)], fill=light_gray)  # Right inner ear
    
    # Muzzle
    draw.ellipse((85, 120, 171, 220), fill=light_gray)
    
    # Eyes
    draw.ellipse((80, 90, 115, 125), fill='white')  # Left eye socket
    draw.ellipse((141, 90, 176, 125), fill='white')  # Right eye socket
    
    # Pupils
    draw.ellipse((90, 100, 105, 115), fill=eye_blue)  # Left pupil
    draw.ellipse((151, 100, 166, 115), fill=eye_blue)  # Right pupil
    
    # Eyeshine
    draw.ellipse((95, 105, 100, 110), fill='white')  # Left eyeshine
    draw.ellipse((156, 105, 161, 110), fill='white')  # Right eyeshine
    
    # Nose
    draw.ellipse((118, 140, 138, 160), fill=black)
    
    # Mouth
    draw.line([(128, 160), (128, 180)], fill=black, width=2)
    draw.arc([(108, 165), (148, 195)], 0, 180, fill=black, width=2)
    
    # Eyebrows
    draw.arc([(75, 75), (120, 105)], 180, 270, fill=dark_gray, width=5)
    draw.arc([(136, 75), (181, 105)], 270, 0, fill=dark_gray, width=5)
    
    # Save as PNG first (for preview)
    img.save('wolf.png')
    print("Created wolf.png")
    
    # Convert to ICO format
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save('wolf.ico', sizes=sizes)
    print("Created wolf.ico")

if __name__ == "__main__":
    create_wolf_icon()
    print("Icon creation complete!")