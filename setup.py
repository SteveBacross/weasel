from setuptools import setup, find_packages

setup(
    name="weasel",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "typer>=0.7.0",
        "rich>=10.11.0",
        "shellingham>=1.3.0",
        "click>=8.0.0",
        "requests",
        "packaging",
        "pipdeptree",
        "pyvis",
        "weasyprint",
        "bandit",
        "chardet",
        "pip-licenses",
        "jinja2",
    ],
    entry_points={
        "console_scripts": [
            "weasel=weasel.cli:app"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    long_description="""
        Weasel est un outil CLI complet d'analyse de sécurité pour les projets Python.
        Il scanne les dépendances, vérifie les vulnérabilités CVE, inspecte les licences,
        analyse le code source pour les mauvaises pratiques et génère des rapports professionnels.
    """,
    long_description_content_type="text/plain",
    author="Weasel Team",
    url="https://github.com/yourusername/weasel",
    project_urls={
        "Documentation": "https://github.com/yourusername/weasel/wiki",
        "Bug Tracker": "https://github.com/yourusername/weasel/issues"
    },
)
