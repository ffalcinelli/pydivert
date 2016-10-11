import os
import shutil

if os.path.exists("index.html"):
    os.remove("index.html")
os.system("sphinx-build -E -b html . build index.rst")

os.rename("build/index.html", "index.html")
shutil.rmtree("build")
