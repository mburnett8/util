import json
import os


def output_file(name: str, content: str, ext: str = "json", is_json: bool = True):
    file_name = f"github/output/{name}.{ext}"
    os.makedirs(os.path.dirname(file_name), exist_ok=True)

    with open(file_name, "w") as f:
        if is_json:
            f.write(json.dumps(content, indent=4))
        else:
            f.write(content)


def load_file(name: str, ext: str = "json"):
    file_name = f"github/output/{name}.{ext}"
    with open(file_name, "r") as f:
        if ext == "json":
            return json.load(f)
        else:
            return f.read()
