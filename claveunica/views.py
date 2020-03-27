from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.generic.base import View
from django.http import HttpResponse
from models import ClaveUnicaUser, ClaveUnicaUserCourseRegistration
from urllib import urlencode
from itertools import cycle
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect

import json
import requests
import uuid
import unidecode
import logging
import sys
import csv

logger = logging.getLogger(__name__)


class ClaveUnicaLoginRedirect(View):
    REQUEST_URL = 'https://accounts.claveunica.gob.cl/openid/authorize/'

    def get(self, request):
        """
        Redirect the user to the login site of claveunica. If the user is logged in,
        redirect to the index instead.
        """
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        return HttpResponseRedirect(
            '{}?{}'.format(ClaveUnicaLoginRedirect.REQUEST_URL, urlencode(self.request_authorization(request)))
        )

    def request_authorization(self, request):
        """
        Generate and store the autorization parameters for claveunica.
        """
        state = str(uuid.uuid4())
        request.session['cu_state'] = state
        parameters = {
            'client_id': settings.CLAVEUNICA_CLIENT_ID,
            'response_type': 'code',
            'scope': settings.CLAVEUNICA_SCOPE,
            'redirect_uri': ClaveUnicaLoginRedirect.get_callback_url(request),
            'state': state,
        }
        return parameters

    @staticmethod
    def get_callback_url(request):
        """
        Get the callback url, removing the trailing / as claveunica doesn't support it
        """
        url = request.build_absolute_uri(reverse('claveunica-login:callback'))
        if url[-1] == '/':
            url = url[:-1]
        return url

class ClaveUnicaStaff(View):
    def validarRut(self, rut):
        rut = rut.upper()
        rut = rut.replace("-", "")
        rut = rut.replace(".", "")
        rut = rut.strip()
        aux = rut[:-1]
        dv = rut[-1:]

        revertido = map(int, reversed(str(aux)))
        factors = cycle(range(2, 8))
        s = sum(d * f for d, f in zip(revertido, factors))
        res = (-s) % 11

        if str(res) == dv:
            return True
        elif dv == "K" and res == 10:
            return True
        else:
            return False

    def validate_course(self, id_curso):
        from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
        try:
            aux = CourseKey.from_string(id_curso)
            return CourseOverview.objects.filter(id=aux).exists()
        except InvalidKeyError:
            return False

    def validate_data(self, request, lista_run, context):
        run_malos = ""
        # validacion de los run
        for run in lista_run:
            try:
                if not self.validarRut(run):
                    run_malos += run + " - "
            except Exception:
                run_malos += run + " - "
        run_malos = run_malos[:-3]

        # validaciones de otros campos
        # si existe run malo
        if run_malos != "":
            context['run_malos'] = run_malos

        # valida curso
        if request.POST.get("course", "") == "":
            context['curso2'] = ''
        elif not self.validate_course(request.POST.get("course", "")):  # valida si existe el curso
            context['error_curso'] = ''

        # si no se ingreso run
        if not lista_run:
            context['no_run'] = ''

        # si el modo es incorrecto
        if not request.POST.get("modes", None) in [x[0] for x in ClaveUnicaUserCourseRegistration.MODE_CHOICES]:
            context['error_mode'] = ''

        # si el RUN es incorrecto
        if request.POST.get("run_type", None) != "RUN":
            context['error_type'] = ""

        return context

    def get(self, request):
        context = {'runs': '', 'auto_enroll': True, 'modo': 'audit'}
        return render(request, 'claveunica/staff.html', context)

    def post(self, request):
        lista_run = request.POST.get("runs", "").split('\n')
        # limpieza de los run ingresados
        lista_run = [run.upper() for run in lista_run]
        lista_run = [run.replace("-", "") for run in lista_run]
        lista_run = [run.replace(".", "") for run in lista_run]
        lista_run = [run.strip() for run in lista_run]
        lista_run = [run for run in lista_run if run]

        # verifica si el checkbox de auto enroll fue seleccionado
        enroll = False
        if request.POST.getlist("enroll"):
            enroll = True

        context = {'runs': request.POST.get('runs'), 'curso': request.POST.get("course", ""), 'auto_enroll': enroll, 'modo': request.POST.get("modes", None)}
        # validacion de datos
        context = self.validate_data(request, lista_run, context)
        # retorna si hubo al menos un error
        if len(context) > 4:
            return render(request, 'claveunica/staff.html', context)

        # guarda el form
        for run in lista_run:
            registro = ClaveUnicaUserCourseRegistration()
            registro.run_num = int(run[:-1])
            registro.run_dv = run[-1:]
            registro.run_type = request.POST.get("run_type", None)
            registro.course = request.POST.get("course", "")
            registro.mode = request.POST.get("modes", None)
            registro.auto_enroll = enroll
            registro.save()

        context = {'runs': '', 'auto_enroll': True, 'modo': 'audit', 'saved': 'saved'}
        return render(request, 'claveunica/staff.html', context)

class ClaveUnicaExport(View):
    """
        Export all claveunica users to csv file
    """

    def get(self, request):
        data = []
        users_claveunica = ClaveUnicaUser.objects.all().order_by('last_name').values('run_num', 'run_dv', 'user__username', 'user__email')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="users.csv"'

        writer = csv.writer(response, delimiter=';', dialect='excel')
        data.append([])
        data[0].extend(['Run', 'Username', 'Email'])
        i = 1
        for user in users_claveunica:
            data.append([])
            data[i].extend([str(user['run_num']) + '-' + user['run_dv'], user['user__username'], user['user__email']])
            i += 1
        writer.writerows(data)

        return response

class ClaveUnicaInfo(View):
    def validarRut(self, rut):
        rut = rut.upper()
        rut = rut.replace("-", "")
        rut = rut.replace(".", "")
        rut = rut.strip()
        aux = rut[:-1]
        dv = rut[-1:]

        revertido = map(int, reversed(str(aux)))
        factors = cycle(range(2, 8))
        s = sum(d * f for d, f in zip(revertido, factors))
        res = (-s) % 11

        if str(res) == dv:
            return True
        elif dv == "K" and res == 10:
            return True
        else:
            return False

    def get(self, request):
        run = request.GET.get("rut", None)
        success = request.GET.get("success", None)
        if request.GET.get("error", None) == 'error':
            context = {'error': True}
            return render(request, 'claveunica/info.html', context)

        if run is None:
            return render(request, 'claveunica/info.html', context=None)

        context = {'rut': run, 'success': success}
        context = self.data_validation(run, context)

        return render(request, 'claveunica/info.html', context)

    def data_validation(self, run, context):
        run = run.upper()
        run = run.replace("-", "")
        run = run.replace(".", "")
        run = run.strip()

        if run != "" and self.validarRut(run):
            run_num = int(run[:-1])
            run_dv = run[-1:]
            run_type = "RUN"
            context['rut'] = run
            context['info'] = False
            aux = 0
            if ClaveUnicaUser.objects.filter(run_num=run_num, run_dv=run_dv, run_type=run_type).exists():
                clave_user = ClaveUnicaUser.objects.get(run_num=run_num, run_dv=run_dv, run_type=run_type)
                enrolled_course = self.list_course_enrolled(clave_user)
                context['enrolled_course'] = enrolled_course
                context['clave_user'] = clave_user
                aux = len(enrolled_course)
            else:
                context['no_exists'] = True

            registrations = ClaveUnicaUserCourseRegistration.objects.filter(run_num=run_num, run_dv=run_dv, run_type=run_type).values('id', 'course')
            context['registrations'] = registrations

            if registrations.count() > 0 or aux > 0:
                context['info'] = True

        else:
            context['wrong_rut'] = True

        return context

    def post(self, request):
        from student.models import CourseEnrollment, CourseEnrollmentAllowed
        data = request.POST.get('id').split(',')
        try:
            course_id = int(data[0])
            enroll = data[1]
            rut = data[2]
            if enroll == 'pending' and self.validation_pending(course_id):
                registrations = ClaveUnicaUserCourseRegistration.objects.get(id=course_id)
                registrations.delete()
                url = '{}?{}'.format(reverse('claveunica-login:info'), urlencode({'rut': rut, 'success': 'success'}))
                return redirect(url)

            if enroll == 'enroll' and self.validation_enroll(course_id):
                enrollment = CourseEnrollment.objects.get(id=course_id)
                enrollment.delete()
                url = '{}?{}'.format(reverse('claveunica-login:info'), urlencode({'rut': rut, 'success': 'success'}))
                return redirect(url)

            url = '{}?{}'.format(reverse('claveunica-login:info'), urlencode({'error': 'error'}))
            return redirect(url)

        except (IndexError, ValueError):
            url = '{}?{}'.format(reverse('claveunica-login:info'), urlencode({'error': 'error'}))
            return redirect(url)

    def validation_pending(self, course_id):
        vali = True
        if not ClaveUnicaUserCourseRegistration.objects.filter(id=course_id).exists():
            vali = False

        return vali

    def validation_enroll(self, course_id):
        from student.models import CourseEnrollment, CourseEnrollmentAllowed
        vali = True
        if not CourseEnrollment.objects.filter(id=course_id).exists():
            vali = False

        return vali

    def list_course_enrolled(self, clave_user):
        from student.models import CourseEnrollment, CourseEnrollmentAllowed

        enrolled_course = CourseEnrollment.objects.filter(
            user=clave_user.user,
            is_active=1
        ).values('id', 'course_id')

        return enrolled_course

class ClaveUnicaCallback(View):
    RESULT_CALLBACK_URL = 'https://accounts.claveunica.gob.cl/openid/token'
    USER_INFO_URL = 'https://www.claveunica.gob.cl/openid/userinfo'
    USERNAME_MAX_LENGTH = 30
    USERNAME_BANNED = []

    def get(self, request):
        """
        Verify the user data and login the user, this is done by:
        - Verify the state and code in RESULT_CALLBACK_URL
        - Get user info in USER_INFO_URL
        - Get or create the user by the rol
        - Login the user
        """
        state = request.GET.get('state')
        code = request.GET.get('code')
        if state is None or code is None:
            return HttpResponseRedirect(reverse('claveunica-login:login'))

        if not self.verify_state(request, state):
            return HttpResponseRedirect(reverse('claveunica-login:login'))

        try:
            self.login_user(request, state, code)
        except Exception:
            logger.exception("Error logging in, state: {}, code: {}".format(state, code))
            return HttpResponseRedirect(reverse('claveunica-login:login'))
        return HttpResponseRedirect('/')

    def verify_state(self, request, state):
        """
        Check the stored state in session and the url arguments are the same.
        """
        result = request.session['cu_state']
        del request.session['cu_state']
        request.session.modified = True
        return result == state

    def login_user(self, request, state, code):
        """
        Get or create the user and log him in.
        """
        token = self.get_access_token(request, state, code)
        user_data = self.get_user_data(token)
        user = self.get_or_create_user(user_data)
        login(request, user, backend="django.contrib.auth.backends.AllowAllUsersModelBackend",)

    def get_access_token(self, request, state, code):
        """
        Get the access token for the given state and code.
        """
        parameters = {
            'client_id': settings.CLAVEUNICA_CLIENT_ID,
            'client_secret': settings.CLAVEUNICA_CLIENT_SECRET,
            'redirect_uri': ClaveUnicaLoginRedirect.get_callback_url(request),
            'grant_type': 'authorization_code',
            'code': code,
            'state': state,
        }
        result = requests.post(ClaveUnicaCallback.RESULT_CALLBACK_URL, data=urlencode(parameters), headers={'content-type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.58.0'})
        if result.status_code != 200:
            logger.error("{} {}".format(result.request, result.request.headers))
            raise Exception("Wrong status code {} {}".format(result.status_code, result.text))
        return json.loads(result.text)

    def get_user_data(self, access_token):
        """
        Get the user data for the access_token
        """
        header = {
            'Authorization': 'Bearer {}'.format(access_token['access_token'])
        }
        result = requests.post(ClaveUnicaCallback.USER_INFO_URL, headers=header)
        return json.loads(result.text)

    def get_or_create_user(self, user_data):
        """
        Get or create the user given the user data.
        If the user exists, update the email address in case the users has updated it.
        """
        try:
            clave_user = ClaveUnicaUser.objects.get(run_num=user_data['RolUnico']['numero'], run_dv=user_data['RolUnico']['DV'], run_type=user_data['RolUnico']['tipo'])
            user = clave_user.user
            self.enroll_pending_courses(clave_user)
            return user
        except ClaveUnicaUser.DoesNotExist:
            with transaction.atomic():
                user = self.create_user_by_data(user_data)
                clave_unica = ClaveUnicaUser.objects.create(
                    user=user,
                    run_num=user_data['RolUnico']['numero'],
                    run_dv=user_data['RolUnico']['DV'],
                    run_type=user_data['RolUnico']['tipo'],
                    first_name=' '.join(user_data['name']['nombres']),
                    last_name=' '.join(user_data['name']['apellidos'])
                )
                self.enroll_pending_courses(clave_unica)
            return user

    def enroll_pending_courses(self, clave_unica):
        """
        Enroll the user in the pending courses, removing the enrollments when
        they are applied.
        """
        from student.models import CourseEnrollment, CourseEnrollmentAllowed
        registrations = ClaveUnicaUserCourseRegistration.objects.filter(run_num=clave_unica.run_num, run_dv=clave_unica.run_dv, run_type=clave_unica.run_type)
        for item in registrations:
            if item.auto_enroll:
                CourseEnrollment.enroll(clave_unica.user, item.course, mode=item.mode)
            else:
                CourseEnrollmentAllowed.objects.create(course_id=item.course, email=clave_unica.user.email, user=clave_unica.user)
        registrations.delete()

    def create_user_by_data(self, user_data):
        """
        Creathe the user by the Django model
        """
        from student.forms import AccountCreationForm
        from student.helpers import do_create_account

        # Check and remove email if its already registered
        if User.objects.filter(email=user_data['email']).exists():
            user_data['email'] = str(uuid.uuid4()) + '@invalid.invalid'

        form = AccountCreationForm(
            data={
                "username": self.generate_username(user_data),
                "email": user_data['email'],
                "password": "invalid",  # Temporary password
                "name": ' '.join(user_data['name']['nombres'] + user_data['name']['apellidos']),
            },
            tos_required=False,
        )

        user, _, reg = do_create_account(form)
        reg.activate()
        reg.save()
        from student.models import create_comments_service_user
        create_comments_service_user(user)

        # Invalidate the user password, as it will be never be used
        user.set_unusable_password()
        user.save()

        return user

    def generate_username(self, user_data):
        """
        Generate an username for the given user_data
        This generation will be done as follow:
        1. return first_name[0] + "_" + last_name[0]
        2. return first_name[0] + "_" + last_name[0] + "_" + last_name[1..N][0..N]
        3. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[0]
        4. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[1..N][0..N]
        5. return first_name[0] + "_" + last_name[0] + N
        """
        first_name = [unidecode.unidecode(x).replace(' ', '_') for x in user_data['name']['nombres']]
        last_name = [unidecode.unidecode(x).replace(' ', '_') for x in user_data['name']['apellidos']]

        # 1.
        test_name = first_name[0] + "_" + last_name[0]
        if len(test_name) <= ClaveUnicaCallback.USERNAME_MAX_LENGTH and not User.objects.filter(username=test_name).exists():
            return test_name

        # 2.
        for i in range(len(last_name[1:])):
            test_name = test_name + "_"
            for j in range(len(last_name[i + 1])):
                test_name = test_name + last_name[i + 1][j]
                if len(test_name) > ClaveUnicaCallback.USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 3.
        first_name_temp = first_name[0]
        for i in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for j in range(len(first_name[i + 1])):
                first_name_temp = first_name_temp + first_name[i + 1][j]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > ClaveUnicaCallback.USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 4.
        first_name_temp = first_name[0]
        for first_index in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for first_second_index in range(len(first_name[first_index + 1])):
                first_name_temp = first_name_temp + first_name[first_index + 1][first_second_index]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > ClaveUnicaCallback.USERNAME_MAX_LENGTH:
                    break
                for second_index in range(len(last_name[1:])):
                    test_name = test_name + "_"
                    for second_second_index in range(len(last_name[second_index + 1])):
                        test_name = test_name + last_name[second_index + 1][second_second_index]
                        if len(test_name) > ClaveUnicaCallback.USERNAME_MAX_LENGTH:
                            break
                        if not User.objects.filter(username=test_name).exists():
                            return test_name

        # 5.
        # Make sure we have space to add the numbers in the username
        test_name = first_name[0] + "_" + last_name[0]
        test_name = test_name[0:(ClaveUnicaCallback.USERNAME_MAX_LENGTH - 5)]
        if test_name[-1] == '_':
            test_name = test_name[:-1]
        for i in range(1, 10000):
            name_tmp = test_name + str(i)
            if not User.objects.filter(username=name_tmp).exists():
                return name_tmp

        # Username cant be generated
        raise Exception("Error generating username for name {}".format())
