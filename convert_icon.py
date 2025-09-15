#!/usr/bin/env python3
"""
Icon Converter - Convert JPG image to ICO format for Windows executable
"""

import sys
import os
from pathlib import Path

def convert_jpg_to_ico():
    """Convert the warning icon JPG to ICO format"""
    try:
        from PIL import Image
        
        # Define file paths
        jpg_path = "free-vector-warning-icon-danger-symbol-red_901408-575.jpg"
        ico_path = "shuddh_warning_icon.ico"
        
        # Check if source image exists
        if not os.path.exists(jpg_path):
            print(f"❌ Source image not found: {jpg_path}")
            return False
        
        # Open and convert the image
        print(f"📁 Loading image: {jpg_path}")
        img = Image.open(jpg_path)
        
        # Convert to RGBA if needed (for transparency support)
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Create multiple sizes for the ICO file (Windows standard)
        sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        
        # Resize image to multiple sizes
        icon_images = []
        for size in sizes:
            resized_img = img.resize(size, Image.Resampling.LANCZOS)
            icon_images.append(resized_img)
        
        # Save as ICO file with multiple sizes
        print(f"🔄 Converting to ICO format...")
        icon_images[0].save(
            ico_path,
            format='ICO',
            sizes=[size for size in sizes]
        )
        
        # Verify the ICO file was created
        if os.path.exists(ico_path):
            file_size = os.path.getsize(ico_path)
            print(f"✅ Icon created successfully: {ico_path} ({file_size:,} bytes)")
            print(f"📐 Sizes included: {', '.join([f'{w}x{h}' for w, h in sizes])}")
            return True
        else:
            print(f"❌ Failed to create ICO file")
            return False
            
    except ImportError:
        print("❌ PIL (Pillow) not available. Installing...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
            print("✅ Pillow installed. Retrying conversion...")
            return convert_jpg_to_ico()  # Retry after installation
        except Exception as e:
            print(f"❌ Failed to install Pillow: {e}")
            return False
    
    except Exception as e:
        print(f"❌ Error converting image: {e}")
        return False

def create_fallback_icon():
    """Create a simple fallback icon if conversion fails"""
    try:
        from PIL import Image, ImageDraw
        
        # Create a simple warning icon
        sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        icon_images = []
        
        for size in sizes:
            # Create a red warning triangle
            img = Image.new('RGBA', size, (0, 0, 0, 0))  # Transparent background
            draw = ImageDraw.Draw(img)
            
            # Calculate triangle points
            width, height = size
            margin = width // 8
            
            # Triangle coordinates
            top = (width // 2, margin)
            bottom_left = (margin, height - margin)
            bottom_right = (width - margin, height - margin)
            
            # Draw red triangle
            draw.polygon([top, bottom_left, bottom_right], fill=(220, 20, 20, 255))
            
            # Draw white exclamation mark
            if width >= 32:  # Only draw details for larger sizes
                # Exclamation line
                line_width = max(1, width // 16)
                line_start = (width // 2, height // 3)
                line_end = (width // 2, height * 2 // 3)
                draw.line([line_start, line_end], fill=(255, 255, 255, 255), width=line_width)
                
                # Exclamation dot
                dot_size = max(2, width // 12)
                dot_center = (width // 2, height * 3 // 4)
                dot_bbox = (
                    dot_center[0] - dot_size // 2,
                    dot_center[1] - dot_size // 2,
                    dot_center[0] + dot_size // 2,
                    dot_center[1] + dot_size // 2
                )
                draw.ellipse(dot_bbox, fill=(255, 255, 255, 255))
            
            icon_images.append(img)
        
        # Save fallback icon
        ico_path = "shuddh_warning_icon.ico"
        icon_images[0].save(
            ico_path,
            format='ICO',
            sizes=[size for size in sizes]
        )
        
        print(f"✅ Fallback warning icon created: {ico_path}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create fallback icon: {e}")
        return False

def main():
    print("SHUDDH Icon Converter")
    print("=" * 30)
    
    # Try to convert the original JPG
    if convert_jpg_to_ico():
        print("\n🎉 Custom warning icon ready for use!")
        return True
    
    # If that fails, create a fallback
    print("\n⚠️  JPG conversion failed. Creating fallback icon...")
    if create_fallback_icon():
        print("\n✅ Fallback warning icon ready for use!")
        return True
    
    print("\n❌ Icon creation failed. Using default icon.")
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)