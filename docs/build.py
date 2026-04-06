import os
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent

# Detect paths
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
os.chdir(root)

def get_tags():
    """Retrieve and sort all tags starting with 'v'."""
    try:
        output = subprocess.check_output(["git", "tag", "-l", "v*"]).decode("utf-8")
        tags = [t.strip() for t in output.split('\n') if t.strip()]
        
        def sort_key(tag):
            # Parse version into integer tuple for proper sorting (e.g. v3.1.0 -> (3, 1, 0))
            parts = tag.lstrip('v').split('.')
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return (0,)
                
        return sorted(tags, key=sort_key, reverse=True)
    except subprocess.CalledProcessError:
        return []

def generate_index_html(tags):
    """Generate a root index.html with a redirect and links to older versions."""
    links = ""
    for tag in tags:
        links += f'<li><a href="{tag}/">{tag}</a></li>\n'

    html = dedent(f"""\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="0; url=latest/">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PyDivert Documentation</title>
        <style>
            body {{ font-family: sans-serif; margin: 40px; line-height: 1.6; }}
            h1 {{ color: #333; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ margin-bottom: 10px; }}
            a {{ color: #0066cc; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>PyDivert Documentation</h1>
        <p>You are being redirected to the <a href="latest/">latest documentation</a>.</p>
        
        <h2>Available Versions</h2>
        <ul>
            <li><a href="latest/">latest (main)</a></li>
            {links}
        </ul>
    </body>
    </html>
    """)
    
    with open("site/index.html", "w", encoding="utf-8") as f:
        f.write(html)

def main():
    site_dir = os.path.join(root, "site")
    if os.path.exists(site_dir):
        shutil.rmtree(site_dir)
    os.makedirs(site_dir, exist_ok=True)

    tags = get_tags()
    successful_tags = []

    # Use a temporary directory for git worktrees
    with tempfile.TemporaryDirectory() as base_tmpdir:
        for tag in tags:
            print(f"Building docs for {tag}...")
            wt_dir = os.path.join(base_tmpdir, tag)
            out_dir = os.path.join(site_dir, tag)
            
            try:
                # Create a detached worktree for the tag
                subprocess.run(["git", "worktree", "add", "-d", wt_dir, tag], check=True, capture_output=True)
                
                # Build docs using the current python environment's pdoc but the tag's source
                # Use sys.executable to ensure we use the pdoc from our venv, not a global one
                subprocess.run([sys.executable, "-m", "pdoc", "pydivert", "-o", out_dir], cwd=wt_dir, check=True, capture_output=True)
                
                successful_tags.append(tag)
                print(f"  -> Successfully built {tag}")
            except subprocess.CalledProcessError as e:
                print(f"  -> Failed to build {tag}. Skipping.")
                # Clean up failed output dir if it was partially created
                if os.path.exists(out_dir):
                    shutil.rmtree(out_dir)
            finally:
                # Always remove the worktree
                if os.path.exists(wt_dir):
                    subprocess.run(["git", "worktree", "remove", "-f", wt_dir], check=False, capture_output=True)

    # Build the latest (main) documentation
    print("Building latest documentation (current branch)...")
    latest_dir = os.path.join(site_dir, "latest")
    subprocess.run([sys.executable, "-m", "pdoc", "pydivert", "-o", latest_dir], check=True)

    # Copy extra files (e.g., for README links) to latest
    print("Copying extra files to site/latest/ ...")
    for extra_file in ["LICENSE", "LICENSE-GPL-2.0-or-later", "LICENSE-LGPL-3.0-or-later", "SECURITY.md"]:
        if os.path.exists(extra_file):
            shutil.copy(extra_file, latest_dir)

    # Generate root index.html
    print("Generating site/index.html...")
    generate_index_html(successful_tags)
    print("Documentation build complete.")

if __name__ == "__main__":
    main()