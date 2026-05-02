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

def inject_version_switcher(directory, current_version, all_versions):
    """Injects a version switcher dropdown into all HTML files in the directory."""

    # Prepare the HTML snippet for the switcher, matching pdoc's sidebar style
    options = f'<option value="../latest/" {"selected" if current_version == "latest" else ""}>latest (main)</option>'
    for v in all_versions:
        options += f'<option value="../{v}/" {"selected" if current_version == v else ""}>{v}</option>'

    switcher_html = dedent(f"""
        <div id="version-switcher" style="margin-bottom: 1rem; padding-right: var(--pad);">
            <label for="v-select" style="display: block; font-weight: bold; margin-bottom: 0.5rem;
                   font-size: 0.8rem; color: var(--muted); text-transform: uppercase;
                   letter-spacing: 1px;">Documentation Version</label>
            <select id="v-select" onchange="window.location.href=this.value"
                    style="width: 100%; padding: 0.4rem; border: 1px solid var(--accent2);
                           border-radius: 4px; background: var(--pdoc-background);
                           color: var(--text); font-size: 0.9rem; cursor: pointer;">
                {options}
            </select>
        </div>
    """)

    # Script to move the switcher into the pdoc sidebar if possible, or keep it at top
    injection_script = dedent("""
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                var switcher = document.getElementById("version-switcher");
                // Try to find the sidebar container
                var container = document.querySelector("nav.pdoc > div");
                if (container) {
                    container.insertAdjacentElement('afterbegin', switcher);
                } else {
                    // Fallback for pages without standard sidebar
                    var nav = document.querySelector("nav");
                    if (nav) {
                        nav.insertAdjacentElement('afterbegin', switcher);
                    }
                }
            });
        </script>
    """)

    full_injection = switcher_html + injection_script

    for root_dir, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".html"):
                path = os.path.join(root_dir, file)
                try:
                    with open(path, encoding="utf-8") as f:
                        content = f.read()
                    if "</body>" in content and 'id="version-switcher"' not in content:
                        new_content = content.replace("</body>", full_injection + "</body>")
                        with open(path, "w", encoding="utf-8") as f:
                            f.write(new_content)
                except Exception as e:
                    print(f"      Warning: Could not inject switcher into {path}: {e}")

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
        <title>Divert Documentation</title>
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
        <h1>Divert Documentation</h1>
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
    # Check for pdoc
    try:
        import pdoc  # noqa: F401
    except ImportError:
        print("Error: 'pdoc' is not installed.")
        print("Please run the build script using: uv run --extra docs python docs/build.py")
        sys.exit(1)

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
                subprocess.run(["git", "worktree", "add", "-d", wt_dir, tag], check=True, capture_output=True)

                # Build docs using the current python environment's pdoc but the tag's source
                result = subprocess.run([sys.executable, "-m", "pdoc", "pydivert", "-o", out_dir],
                                     cwd=wt_dir, capture_output=True, text=True)

                if result.returncode == 0:
                    successful_tags.append(tag)
                    print(f"  -> Successfully built {tag}")
                else:
                    print(f"  -> Failed to build {tag}. pdoc error.")
            except subprocess.CalledProcessError:
                print(f"  -> Failed to build {tag}. git error.")
                if os.path.exists(out_dir):
                    shutil.rmtree(out_dir)
            finally:
                if os.path.exists(wt_dir):
                    subprocess.run(["git", "worktree", "remove", "-f", wt_dir], check=False, capture_output=True)

    # Build the latest (main) documentation
    print("Building latest documentation (current branch)...")
    latest_dir = os.path.join(site_dir, "latest")
    subprocess.run([sys.executable, "-m", "pdoc", "pydivert", "-o", latest_dir], check=True)

    # Post-process: Inject version switcher into all built docs
    print("Injecting version switcher...")
    all_versions = successful_tags
    inject_version_switcher(latest_dir, "latest", all_versions)
    for tag in successful_tags:
        inject_version_switcher(os.path.join(site_dir, tag), tag, all_versions)

    # Copy extra files
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
