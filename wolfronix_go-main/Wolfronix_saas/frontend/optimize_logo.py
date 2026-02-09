import os
from PIL import Image

# Configuration
input_path = r'e:\security\new_wfx\frontend\Wolfronix LOGO[1].png'
output_path = r'e:\security\new_wfx\frontend\Wolfronix LOGO[1].png' # Overwrite to fix in place
max_width = 200

def resize_image():
    try:
        if not os.path.exists(input_path):
            print(f"Error: File not found at {input_path}")
            return

        with Image.open(input_path) as img:
            print(f"Original size: {img.size}")
            
            # Calculate new height to maintain aspect ratio
            w_percent = (max_width / float(img.size[0]))
            h_size = int((float(img.size[1]) * float(w_percent)))
            
            # Resize
            img = img.resize((max_width, h_size), Image.Resampling.LANCZOS)
            
            # Save (optimize)
            img.save(output_path, optimize=True, quality=85)
            print(f"Resized image saved to {output_path}")
            print(f"New size: {img.size}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    resize_image()
