try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

def extract_metadata(image_path):
    if not PIL_AVAILABLE:
        return {"result": "PIL/Pillow library not installed. Run 'pip install Pillow' to enable image metadata extraction."}
    try:
        img = Image.open(image_path)
        exif_data = img._getexif()
        if not exif_data:
            return {"result": "No EXIF metadata found."}
        return {TAGS.get(k, k): v for k, v in exif_data.items()}
    except Exception as e:
        return {"error": str(e)}

def image_metadata_cli(image_path):
    """CLI interface for image metadata extraction"""
    if not PIL_AVAILABLE:
        print("❌ PIL/Pillow library not installed. Run 'pip install Pillow' to enable image metadata extraction.")
        return
    
    result = extract_metadata(image_path)
    if "error" in result:
        print(f"❌ Error: {result['error']}")
    elif "result" in result:
        print(f"ℹ️  {result['result']}")
    else:
        print("📷 Image Metadata:")
        for key, value in result.items():
            print(f"  {key}: {value}")

# Example usage:
# print(extract_metadata("test.jpg"))