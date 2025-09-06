"""
Create a simple icon for Shuddh
"""

from PIL import Image, ImageDraw
import os

def create_icon():
    """Create a simple icon for the application"""
    try:
        # Create a 256x256 image
        size = 256
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw a red circle (representing data destruction)
        margin = 20
        draw.ellipse([margin, margin, size-margin, size-margin], 
                    fill=(231, 76, 60, 255), outline=(192, 57, 43, 255), width=8)
        
        # Draw a white "X" in the center
        center = size // 2
        line_width = 12
        offset = 40
        
        # X lines
        draw.line([center-offset, center-offset, center+offset, center+offset], 
                 fill=(255, 255, 255, 255), width=line_width)
        draw.line([center-offset, center+offset, center+offset, center-offset], 
                 fill=(255, 255, 255, 255), width=line_width)
        
        # Save as ICO file
        img.save('shuddh_icon.ico', format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
        print("✅ Icon created: shuddh_icon.ico")
        return True
        
    except ImportError:
        print("⚠️ PIL/Pillow not available - skipping icon creation")
        return False
    except Exception as e:
        print(f"⚠️ Icon creation failed: {e}")
        return False

if __name__ == "__main__":
    create_icon()