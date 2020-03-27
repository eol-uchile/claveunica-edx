#!/bin/dash

pip install -e /openedx/requirements/claveunica-edx

cd /openedx/requirements/claveunica-edx/claveunica
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/claveunica-edx/claveunica

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest tests.py