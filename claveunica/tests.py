from mock import patch, Mock, MagicMock
from collections import namedtuple
from django.urls import reverse
from django.test import TestCase, Client
from django.test import Client
from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from urlparse import parse_qs
from openedx.core.lib.tests.tools import assert_true
from opaque_keys.edx.locator import CourseLocator
from opaque_keys.edx.keys import CourseKey
import json
import urlparse
import six
from .views import ClaveUnicaLoginRedirect, ClaveUnicaCallback, ClaveUnicaStaff, ClaveUnicaInfo, ClaveUnicaExportData
from .models import ClaveUnicaUserCourseRegistration, ClaveUnicaUser
from student.tests.factories import UserFactory, CourseEnrollmentFactory
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from completion import models
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from lms.djangoapps.certificates.models import GeneratedCertificate

USER_COUNT = 11


class TestRedirectView(TestCase):

    def setUp(self):
        self.client = Client()

    def test_set_session(self):
        result = self.client.get(reverse('claveunica-login:login'))
        self.assertIsNotNone(self.client.session['cu_state'])

    def test_return_request(self):
        result = self.client.get(reverse('claveunica-login:login'))
        request = urlparse.urlparse(result.url)
        args = urlparse.parse_qs(request.query)

        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.netloc, 'accounts.claveunica.gob.cl')
        self.assertEqual(request.path, '/openid/authorize/')
        self.assertEqual(args['scope'][0], 'openid run name email')
        self.assertEqual(args['state'][0], self.client.session['cu_state'])
        self.assertEqual(args['response_type'][0], 'code')
        self.assertEqual(args['client_id'][0], settings.CLAVEUNICA_CLIENT_ID)
        self.assertEqual(args['redirect_uri'][0], 'http://testserver/claveunica/callback')

    def test_redirect_already_logged(self):
        user = User.objects.create_user(username='testuser', password='123')
        self.client.login(username='testuser', password='123')
        result = self.client.get(reverse('claveunica-login:login'))
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/')


def create_user(user_data):
    return User.objects.create_user(
        username=ClaveUnicaCallback().generate_username(user_data),
        email=user_data['email'])


class TestCallbackView(TestCase):
    def setUp(self):
        self.client = Client()
        result = self.client.get(reverse('claveunica-login:login'))

        self.modules = {
            'student': MagicMock(),
            'student.forms': MagicMock(),
            'student.helpers': MagicMock(),
            'student.models': MagicMock(),
        }
        self.module_patcher = patch.dict('sys.modules', self.modules)
        self.module_patcher.start()

    def tearDown(self):
        self.module_patcher.stop()

    @patch("requests.post")
    def test_login_parameters(self, post):
        state = self.client.session['cu_state']
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({'access_token': '67890'})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}}))]
        result = self.client.get(reverse('claveunica-login:callback'), data={'state': self.client.session['cu_state'], 'code': 'code'})
        self.assertEqual(result.status_code, 302)

        parameters = parse_qs(post.call_args_list[0][1]['data'])
        self.assertEqual(post.call_args_list[0][0][0], 'https://accounts.claveunica.gob.cl/openid/token')
        self.assertEqual(parameters['code'][0], 'code')
        self.assertEqual(parameters['grant_type'][0], 'authorization_code')
        self.assertEqual(parameters['state'][0], state)
        self.assertEqual(parameters['redirect_uri'][0], 'http://testserver/claveunica/callback')
        self.assertEqual(parameters['client_id'][0], settings.CLAVEUNICA_CLIENT_ID)
        self.assertEqual(parameters['client_secret'][0], settings.CLAVEUNICA_CLIENT_SECRET)
        self.assertIsNone(self.client.session.get('cu_state'))

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    @patch("requests.post")
    def test_login_create_user(self, post, mock_created_user):
        state = self.client.session['cu_state']
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({'access_token': '67890'})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}}))]
        result = self.client.get(reverse('claveunica-login:callback'), data={'state': self.client.session['cu_state'], 'code': 'code'})
        self.assertEqual(mock_created_user.call_args_list[0][0][0], {"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}})

    @patch("requests.post")
    def test_login_wrong_state(self, post):
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({'access_token': '67890'})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}}))]
        result = self.client.get(reverse('claveunica-login:callback'), data={'state': 'WRONG-STATE', 'code': 'code'}, follow=False)

        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/claveunica/login/')

    @patch("requests.post")
    def test_login_wrong_state(self, post):
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(401, json.dumps({})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}}))]
        result = self.client.get(reverse('claveunica-login:callback'), data={'state': self.client.session['cu_state'], 'code': 'code'}, follow=False)

        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/claveunica/login/')

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    def test_generate_username(self, _):
        data = {
            'RolUnico': {
                'numero': 12345,
                'DV': 5,
                'tipo': 'RUN'
            },
            'name': {
                'nombres': ['aa', 'bb'],
                'apellidos': ['cc', 'dd']
            },
            'email': 'a@b.c',
        }
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_cc')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_cc_d')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_cc_dd')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_b_cc')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_bb_cc')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_b_cc_d')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_b_cc_dd')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_bb_cc_d')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_bb_cc_dd')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_cc1')
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'aa_cc2')

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    def test_generate_username_complex(self, _):
        return
        data = {
            'RolUnico': {
                'numero': 12345,
                'DV': 5,
                'tipo': 'RUN'
            },
            'name': {
                'nombres': ['aa', 'bb', 'cc', 'dd'],
                'apellidos': ['ee', 'ff', 'gg', 'hh']
            },
            'email': 'a@b.c',
        }
        for _ in range(1000):
            ClaveUnicaCallback().create_user_by_data(data)
        self.assertTrue(User.objects.filter(username='aa_ee').exists())
        self.assertTrue(User.objects.filter(username='aa_ee_ff_gg_hh').exists())
        self.assertTrue(User.objects.filter(username='aa_bb_cc_dd_ee_ff_gg_hh').exists())
        self.assertTrue(User.objects.filter(username='aa_ee1').exists())

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    def test_long_name(self, _):
        data = {
            'RolUnico': {
                'numero': 12345,
                'DV': 5,
                'tipo': 'RUN'
            },
            'name': {
                'nombres': ['a2345678901234567890123', 'bb'],
                'apellidos': ['4567890', 'ff']
            },
            'email': 'a@b.c',
        }
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'a2345678901234567890123_41')

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    def test_long_name_middle(self, _):
        data = {
            'RolUnico': {
                'numero': 12345,
                'DV': 5,
                'tipo': 'RUN'
            },
            'name': {
                'nombres': ['a23456789012345678901234', 'bb'],
                'apellidos': ['4567890', 'ff']
            },
            'email': 'a@b.c',
        }
        self.assertEqual(ClaveUnicaCallback().create_user_by_data(data).username, 'a234567890123456789012341')

    @patch("claveunica.views.ClaveUnicaCallback.create_user_by_data", side_effect=create_user)
    @patch("requests.post")
    def test_test(self, post, _):
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=55555555,
            run_dv="5",
            run_type="RUN",
            course="course-v1:test+TEST+2019-2",
            mode="honor",
            auto_enroll=True)
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=55555555,
            run_dv="5",
            run_type="RUN",
            course="course-v1:test+TEST+2019-4",
            mode="honor",
            auto_enroll=False)
        state = self.client.session['cu_state']
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({'access_token': '67890'})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"sub": "2", "email": "a@b.c", "RolUnico": {"numero": 55555555, "DV": "5", "tipo": "RUN"}, "name": {"nombres": ['Maria', 'Carmen', 'De', 'Los', 'Angeles'], "apellidos": ['Del', ' Rio', 'Gonzalez']}}))]
        self.client.get(reverse('claveunica-login:callback'), data={'state': self.client.session['cu_state'], 'code': 'code'})

        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.count(), 0)
        self.assertEqual(self.modules['student.models'].CourseEnrollment.method_calls[0][1][1], CourseLocator.from_string("course-v1:test+TEST+2019-2"))
        _, _, kwargs = self.modules['student.models'].CourseEnrollmentAllowed.mock_calls[0]
        self.assertEqual(kwargs['course_id'], CourseLocator.from_string("course-v1:test+TEST+2019-4"))


class TestStaffView(ModuleStoreTestCase):

    def setUp(self):
        super(TestStaffView, self).setUp()
        self.course = CourseFactory.create(org='mss', course='999', display_name='2020', emit_signals=True)
        aux = CourseOverview.get_from_id(self.course.id)
        with patch('student.models.cc.User.save'):
            self.client = Client()
            user = UserFactory(username='testuser3', password='12345', email='student2@edx.org', is_staff=True)
            self.client.login(username='testuser3', password='12345')

        ClaveUnicaUser.objects.create(
            run_num=9472337,
            run_dv="K",
            run_type="RUN",
            user=user,
            first_name="test_name",
            last_name="test_lastname")

        result = self.client.get(reverse('claveunica-login:staff'))

    def test_staff_get(self):

        response = self.client.get(reverse('claveunica-login:staff'))
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['PATH_INFO'], '/claveunica/staff/')

    def test_staff_post(self):
        post_data = {
            'runs': '10-8',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)

        aux = ClaveUnicaUserCourseRegistration.objects.get(run_num="10")

        self.assertEqual(aux.run_num, 10)
        self.assertEqual(aux.run_dv, '8')
        self.assertEqual(aux.run_type, 'RUN')
        self.assertEqual(aux.mode, 'audit')
        self.assertEqual(aux.auto_enroll, True)
        self.assertEquals(ClaveUnicaUserCourseRegistration.objects.all().count(), 1)

    def test_staff_post_multiple_run(self):
        post_data = {
            'runs': '10-8\n10-8\n10-8\n10-8\n10-8',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)

        aux = ClaveUnicaUserCourseRegistration.objects.filter(run_num="0000000108")
        for var in aux:
            self.assertEqual(var.run_num, 10)
            self.assertEqual(var.run_dv, '8')
            self.assertEqual(var.run_type, 'RUN')
            self.assertEqual(var.mode, 'audit')
            self.assertEqual(var.auto_enroll, True)

        self.assertEquals(ClaveUnicaUserCourseRegistration.objects.all().count(), 5)

    def test_staff_post_sin_curso(self):
        post_data = {
            'runs': '10-8',
            'run_type': 'RUN',
            'course': '',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        assert_true("id=\"curso2\"" in response._container[0])
        self.assertEquals(ClaveUnicaUserCourseRegistration.objects.all().count(), 0)

    def test_staff_post_sin_run(self):
        post_data = {
            'runs': '',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        assert_true("id=\"no_run\"" in response._container[0])
        self.assertEquals(ClaveUnicaUserCourseRegistration.objects.all().count(), 0)

    def test_staff_post_run_malo(self):
        post_data = {
            'runs': '12345678-9',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        assert_true("id=\"run_malos\"" in response._container[0])
        self.assertEquals(ClaveUnicaUserCourseRegistration.objects.all().count(), 0)

    def test_staff_post_exits_user_enroll(self):
        post_data = {
            'runs': '9472337-k',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        request = response.request
        self.assertEquals(response.status_code, 200)
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.count(), 0)
        self.assertEqual(request['PATH_INFO'], '/claveunica/staff/')        
        assert_true("id=\"run_saved_enroll\"" in response._container[0])

    def test_staff_post_exits_user_no_enroll(self):
        post_data = {
            'runs': '9472337-k',
            'run_type': 'RUN',
            'course': self.course.id,
            'modes': 'audit'
        }

        response = self.client.post(reverse('claveunica-login:staff'), post_data)
        request = response.request
        self.assertEquals(response.status_code, 200)
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.count(), 0)
        self.assertEqual(request['PATH_INFO'], '/claveunica/staff/')
        assert_true("id=\"run_saved_enroll_no_auto\"" in response._container[0])


class TestInfoView(ModuleStoreTestCase):

    def setUp(self):
        super(TestInfoView, self).setUp()

        with patch('student.models.cc.User.save'):
            self.client = Client()
            self.user = UserFactory(username='testuser2', password='12345', email='student2@edx.org', is_staff=True)
            self.client.login(username='testuser2', password='12345')

        result = self.client.get(reverse('claveunica-login:info'))

    def test_info_get(self):

        response = self.client.get(reverse('claveunica-login:info'))
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['PATH_INFO'], '/claveunica/info/')

    def test_info_get_no_course(self):
        get_data = {
            'rut': '10-8'
        }

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['QUERY_STRING'], 'rut=10-8')
        assert_true("value=\"108\"" in response._container[0])
        assert_true("id=\"no_exists\"" in response._container[0])
        assert_true("id=\"no_info\"" in response._container[0])

    def test_info_wrong_rut(self):
        get_data = {
            'rut': '10-9'
        }

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['QUERY_STRING'], 'rut=10-9')
        assert_true("id=\"wrong_rut\"" in response._container[0])

    def test_info_error(self):
        get_data = {
            'error': 'error'
        }

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['QUERY_STRING'], 'error=error')
        assert_true("id=\"error\"" in response._container[0])

    def test_info_get_pending_course_exists(self):
        course_1 = CourseFactory.create(org='mss', course='999', display_name='2020', emit_signals=True)
        course_2 = CourseFactory.create(org='mss', course='888', display_name='2021', emit_signals=True)
        aux = CourseOverview.get_from_id(course_1.id)
        aux2 = CourseOverview.get_from_id(course_2.id)
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course=course_1.id,
            mode="audit",
            auto_enroll=True)
        id_1 = ClaveUnicaUserCourseRegistration.objects.get(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course=course_1.id,
            mode="audit",
            auto_enroll=True)
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course=course_2.id,
            mode="audit",
            auto_enroll=True)
        id_2 = ClaveUnicaUserCourseRegistration.objects.get(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course=course_2.id,
            mode="audit",
            auto_enroll=True)

        get_data = {
            'rut': '10-8'
        }

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['QUERY_STRING'], 'rut=10-8')
        assert_true("id=\"no_exists\"" in response._container[0])
        assert_true("id=\"info_student\"" in response._container[0])
        assert_true("value=\"" + str(id_1.id) + ",pending,108\"" in response._container[0])
        assert_true("value=\"" + str(id_2.id) + ",pending,108\"" in response._container[0])

    def test_info_get_enroll_course_exists(self):
        ClaveUnicaUser.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            user=self.user,
            first_name="test_name",
            last_name="test_lastname")

        CourseEnrollmentFactory(user=self.user, course_id="course-v1:test+TEST+2019-4")
        get_data = {
            'rut': '10-8'
        }

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['QUERY_STRING'], 'rut=10-8')
        assert_true("id=\"clave_user\"" in response._container[0])
        assert_true("id=\"info_student\"" in response._container[0])
        assert_true("value=\"1,enroll,108\"" in response._container[0])

    def test_info_post_pending_course_exists_unenroll(self):
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-2",
            mode="audit",
            auto_enroll=True)
        course = ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').first()
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-4",
            mode="audit",
            auto_enroll=True)

        post_data = {
            'id': str(course.id) + ',pending,108'
        }
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').count(), 2)
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').count(), 1)

    def test_info_post_pending_course_no_exists_unenroll(self):
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-2",
            mode="audit",
            auto_enroll=True)
        course = ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').first()
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-4",
            mode="audit",
            auto_enroll=True)

        post_data = {
            'id': 'test99,pending,108'
        }
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').count(), 2)

    def test_info_post_pending_course_wrong_data_unenroll(self):
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-2",
            mode="audit",
            auto_enroll=True)
        course = ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').first()
        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            course="course-v1:test+TEST+2019-4",
            mode="audit",
            auto_enroll=True)

        post_data = {
            'id': '9999,test,104'
        }
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)
        self.assertEqual(ClaveUnicaUserCourseRegistration.objects.filter(run_num=10, run_dv='8', run_type='RUN').count(), 2)

    def test_info_post_enroll_course_exists_unenroll(self):
        ClaveUnicaUser.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            user=self.user,
            first_name="test_name",
            last_name="test_lastname")

        CourseEnrollmentFactory(user=self.user, course_id="course-v1:test+TEST+2019-4")

        post_data = {
            'id': '1,enroll,108'
        }
        get_data = {
            'rut': '10-8'
        }
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)

        response = self.client.get(reverse('claveunica-login:info'), get_data)
        assert_true("id=\"no_info\"" in response._container[0])

    def test_info_post_enroll_course_no_exists_unenroll(self):
        ClaveUnicaUser.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            user=self.user,
            first_name="test_name",
            last_name="test_lastname")

        CourseEnrollmentFactory(user=self.user, course_id="course-v1:test+TEST+2019-4")

        post_data = {
            'id': 'test99,pending,108'
        }
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response._headers['location'], ('Location', '/claveunica/info/?error=error'))

    def test_info_post_enroll_course_wrong_data_unenroll(self):
        ClaveUnicaUser.objects.create(
            run_num=10,
            run_dv="8",
            run_type="RUN",
            user=self.user,
            first_name="test_name",
            last_name="test_lastname")

        CourseEnrollmentFactory(user=self.user, course_id="course-v1:test+TEST+2019-4")

        post_data = {
            'id': '9999,test,104'
        }
        response = self.client.post(reverse('claveunica-login:info'), post_data)
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response._headers['location'], ('Location', '/claveunica/info/?error=error'))


class TestExportDataView(ModuleStoreTestCase):

    def setUp(self):
        super(TestExportDataView, self).setUp()
        self.course = CourseFactory.create(org='mss', course='999', display_name='2020', emit_signals=True)

        with self.store.bulk_operations(self.course.id, emit_signals=False):
            chapter = ItemFactory.create(
                parent_location=self.course.location,
                category="chapter",
            )
            section = ItemFactory.create(
                parent_location=chapter.location,
                category="sequential",
            )
            subsection = ItemFactory.create(
                parent_location=section.location,
                category="vertical",
            )
            self.items = [
                ItemFactory.create(
                    parent_location=subsection.location,
                    category="problem"
                )
                for __ in range(USER_COUNT - 1)
            ]

        # Create users, enroll
        self.users = [UserFactory.create() for _ in range(USER_COUNT)]
        for user in self.users:
            ClaveUnicaUser.objects.create(
                run_num=user.id,
                run_dv="8",
                run_type="RUN",
                user=user,
                first_name="test_name" + str(user.id),
                last_name="test_lastname" + str(user.id))
            CourseEnrollmentFactory(user=user, course_id=self.course.id)

        with patch('student.models.cc.User.save'):
            # Create the student
            self.student = UserFactory(username='student', password='test', email='student@edx.org')
            content_type = ContentType.objects.get_for_model(ClaveUnicaUser)
            permission = Permission.objects.get(
                codename='is_staff_guest',
                content_type=content_type,
            )
            self.student.user_permissions.add(permission)
            # Log in the user staff
            self.student_client = Client()
            assert_true(self.student_client.login(username='student', password='test'))
            # Enroll the student in the course
            CourseEnrollmentFactory(user=self.student, course_id=self.course.id)
            ClaveUnicaUser.objects.create(
                run_num=99,
                run_dv="8",
                run_type="RUN",
                user=self.student,
                first_name="test_name",
                last_name="test_lastname")
            # Create the user staff
            self.staff_user = UserFactory(username='staff_user', password='test', email='staff@edx.org', is_staff=True)
            # Log in the user staff
            self.staff_client = Client()
            assert_true(self.staff_client.login(username='staff_user', password='test'))

    def test_infoexport_get(self):
        aux = CourseOverview.get_from_id(self.course.id)

        response = self.staff_client.get(reverse('claveunica-login:infoexport'))
        request = response.request

        self.assertEquals(response.status_code, 200)
        self.assertEqual(request['PATH_INFO'], '/claveunica/info/export')
        assert_true("value=\"" + str(self.course.id) + "\"" in response._container[0])

    def test_infoexport_post(self):
        post_data = {
            'id': str(self.course.id)
        }
        response = self.staff_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response._headers['content-type'], ('Content-Type', 'text/csv'))
        data = response.content.split("\r\n")
        self.assertEqual(data[0], "Run;Nombre;Email;Username;1.1.1;Puntos;Total;Certificado Generado")
        self.assertEqual(data[-5], '998;test_name test_lastname;student@edx.org;student;;0/1;0/1;No')

    def test_infoexport_post_with_pending_student(self):
        post_data = {
            'id': str(self.course.id)
        }

        pending_student = UserFactory(username='pending', password='test', email='student@edx.org')
        ClaveUnicaUser.objects.create(
            run_num=101,
            run_dv="0",
            run_type="RUN",
            user=pending_student,
            first_name="test_name",
            last_name="test_lastname")

        ClaveUnicaUserCourseRegistration.objects.create(
            run_num=101,
            run_dv="0",
            run_type="RUN",
            course=self.course.id,
            mode="audit",
            auto_enroll=True)

        response = self.staff_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response._headers['content-type'], ('Content-Type', 'text/csv'))
        data = response.content.split("\r\n")
        self.assertEqual(data[0], "Run;Nombre;Email;Username;1.1.1;Puntos;Total;Certificado Generado")
        self.assertEqual(data[-2], '1010;test_name test_lastname;student@edx.org')

    def test_infoexport_post_blockcompletion(self):
        post_data = {
            'id': str(self.course.id)
        }
        for item in self.items:
            usage_key = item.scope_ids.usage_id
            completion = models.BlockCompletion.objects.create(
                user=self.student,
                course_key=self.course.id,
                block_key=usage_key,
                completion=1.0,
            )
        response = self.staff_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response._headers['content-type'], ('Content-Type', 'text/csv'))
        data = response.content.split("\r\n")
        self.assertEqual(data[0], "Run;Nombre;Email;Username;1.1.1;Puntos;Total;Certificado Generado")
        self.assertEqual(data[-5], '998;test_name test_lastname;student@edx.org;student;X;1/1;1/1;No')

    def test_infoexport_post_certificate(self):
        GeneratedCertificate.objects.create(user=self.student, course_id=self.course.id)
        post_data = {
            'id': str(self.course.id)
        }
        response = self.staff_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response._headers['content-type'], ('Content-Type', 'text/csv'))
        data = response.content.split("\r\n")
        self.assertEqual(data[0], "Run;Nombre;Email;Username;1.1.1;Puntos;Total;Certificado Generado")
        self.assertEqual(data[-5], '998;test_name test_lastname;student@edx.org;student;;0/1;0/1;Si')

    def test_infoexport_post_wrong_id(self):
        post_data = {
            'id': "wrong_id"
        }
        response = self.staff_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response.status_code, 302)
        self.assertEquals(response._headers['location'], ('Location', '/claveunica/info/export?error=error'))
    
    def test_infoexport_get_user_is_staff_guest(self):
        response = self.student_client.get(reverse('claveunica-login:infoexport'))

        self.assertEquals(response.status_code, 200)        
    
    def test_infoexport_get_user_is_anonymous(self):
        anonymous_client = Client()
        response = anonymous_client.get(reverse('claveunica-login:infoexport'))

        self.assertEquals(response.status_code, 404)
        
    def test_infoexport_post_user_is_staff_guest(self):
        post_data = {
            'id': str(self.course.id)
        }
        response = self.student_client.post(reverse('claveunica-login:infoexport'), post_data)

        self.assertEquals(response._headers['content-type'], ('Content-Type', 'text/csv'))
        data = response.content.split("\r\n")
        self.assertEqual(data[0], "Run;Nombre;Email;Username;1.1.1;Puntos;Total;Certificado Generado")
        self.assertEqual(data[-5], '998;test_name test_lastname;student@edx.org;student;;0/1;0/1;No')

    def test_infoexport_post_user_is_anonymous(self):
        anonymous_client = Client()
        post_data = {
            'id': str(self.course.id)
        }
        response = anonymous_client.post(reverse('claveunica-login:infoexport'), post_data)
        self.assertEquals(response.status_code, 404)