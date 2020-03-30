import setuptools

setuptools.setup(
    name="claveunica",
    version="0.0.1",
    author="Felipe Espinoza",
    author_email="felipe.espinoza.r@uchile.cl",
    description="Authentication backend for Chile claveunica",
    long_description="Authentication backend for Chile claveunica",
    url="https://eol.uchile.cl",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],    
    entry_points={"lms.djangoapp": ["claveunica = claveunica.apps:ClaveunicaConfig"]},
)
