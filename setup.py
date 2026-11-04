from setuptools import setup
import re

_version_re = re.compile(r"(?<=^__version__ = (\"|'))(.+)(?=\"|')")


def get_version(rel_path: str) -> str:
    with open(rel_path, 'r') as f:
        matches = map(_version_re.search, f)
        filtered = filter(lambda m: m is not None, matches)
        version = next(filtered, None)
        if version is None:
            raise RuntimeError(f'Could not find __version__ in {rel_path}')
        return version.group(0)


setup(
    name='dicom_audit',
    version=get_version('dicom_audit.py'),
    description='A ChRIS plugin that records what pl-dicom_anonymize changed and scans its output for leaks',
    author='FNNDSC',
    author_email='dev@babyMRI.org',
    url='https://github.com/FNNDSC/pl-dicom_audit',
    py_modules=['dicom_audit', 'audit_engine'],
    install_requires=['chris_plugin'],
    license='MIT',
    entry_points={
        'console_scripts': [
            'dicom_audit = dicom_audit:main'
        ]
    },
    classifiers=[
        'Topic :: Scientific/Engineering',
        'Topic :: Scientific/Engineering :: Bio-Informatics',
        'Topic :: Scientific/Engineering :: Medical Science Apps.'
    ],
    extras_require={
        'none': [],
        'dev': [
            'pytest~=7.1',
            # Integration tests run the real header-anonymization engine
            # (same pin as pl-dicom_anonymize) to produce realistic trees.
            'dicom-anonymizer==1.0.13.post1',
            # End-to-end tests run the real pl-dicom_anonymize CLI. It is not
            # on PyPI; pin its release tarball. See MAINTENANCE.md.
            'dicom_anonymize @ https://github.com/FNNDSC/pl-dicom_anonymize/archive/refs/tags/1.2.0.tar.gz',
        ]
    }
)
